"""
Emon DSL Frontend —— BPF Map 数据读取器

支持两种数据源:
  1. bpftool map dump — 通过 bpftool 命令行读取 BPF map 内容
  2. libbpf skeleton — 通过直接 attach 的 skeleton 读取 (高级模式)

所有读取操作返回 pandas DataFrame，供 Streamlit / Altair 直接使用。
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import threading
import time
from collections import deque
from dataclasses import dataclass, field
from typing import Any, Callable, Deque, Dict, List, Optional, Tuple

import pandas as pd


# =============================================================================
# 数据模型
# =============================================================================

@dataclass
class BpfMapEntry:
    """单条 BPF map entry."""
    key: Dict[str, Any]     # e.g. {"syscall": "read", "comm": "cat"}
    value: Any              # e.g. 42 (count) or {"count": 42, "sum": 1234}
    timestamp: float = field(default_factory=time.time)


@dataclass
class Snapshot:
    """一次采样快照."""
    tool_name: str
    map_name: str
    entries: List[BpfMapEntry]
    timestamp: float = field(default_factory=time.time)


# =============================================================================
# BPF Map 读取器
# =============================================================================

class BpfMapReader:
    """
    通过 bpftool 读取 BPF map 内容。

    使用方式:
        reader = BpfMapReader("file_monitor", "f_count")
        df = reader.read_as_dataframe()
    """

    def __init__(self, tool_name: str, map_name: str, key_fields: Optional[List[str]] = None):
        self.tool_name = tool_name
        self.map_name = map_name
        self.key_fields = key_fields or []
        self._bpftool_path = self._find_bpftool()

    @staticmethod
    def _find_bpftool() -> str:
        """定位 bpftool 可执行文件."""
        for candidate in ["bpftool", "/usr/sbin/bpftool", "/usr/local/sbin/bpftool"]:
            try:
                subprocess.run(
                    [candidate, "version"],
                    capture_output=True, timeout=3, check=False
                )
                return candidate
            except (FileNotFoundError, subprocess.TimeoutExpired):
                continue
        return "bpftool"  # fallback

    def _get_map_id(self) -> Optional[int]:
        """通过 map name 查找 BPF map ID."""
        try:
            result = subprocess.run(
                ["sudo", self._bpftool_path, "map", "list"],
                capture_output=True, text=True, timeout=5
            )
            for line in result.stdout.split("\n"):
                if self.map_name in line:
                    # 格式: "123: hash  name f_count  flags 0x0"
                    m = re.match(r"(\d+):", line.strip())
                    if m:
                        return int(m.group(1))
        except (subprocess.TimeoutExpired, FileNotFoundError, PermissionError):
            pass
        return None

    def read_raw(self) -> List[BpfMapEntry]:
        """读取 BPF map 原始数据."""
        map_id = self._get_map_id()
        if map_id is None:
            return []

        try:
            result = subprocess.run(
                ["sudo", self._bpftool_path, "map", "dump", "id", str(map_id)],
                capture_output=True, text=True, timeout=5
            )
            return self._parse_dump_output(result.stdout)
        except (subprocess.TimeoutExpired, FileNotFoundError, PermissionError):
            return []

    def _parse_dump_output(self, output: str) -> List[BpfMapEntry]:
        """解析 bpftool map dump 的输出."""
        entries: List[BpfMapEntry] = []
        now = time.time()

        # bpftool map dump 输出格式示例:
        # key:
        #  00 00 00 00 63 61 74 00  ...  |  ....cat.
        # value:
        #  2a 00 00 00 00 00 00 00  |  *.......
        #
        # 简化处理: 按 key/value 块分割
        lines = output.strip().split("\n")
        current_key_hex: List[str] = []
        current_val_hex: List[str] = []
        in_key = False
        in_value = False

        for line in lines:
            line = line.strip()
            if line.startswith("key:"):
                if current_key_hex and current_val_hex:
                    entry = self._hex_to_entry(current_key_hex, current_val_hex, now)
                    if entry:
                        entries.append(entry)
                current_key_hex = []
                current_val_hex = []
                in_key = True
                in_value = False
            elif line.startswith("value:"):
                in_key = False
                in_value = True
            elif in_key and line:
                # 提取十六进制部分 (在 | 之前)
                hex_part = line.split("|")[0].strip() if "|" in line else line
                current_key_hex.append(hex_part)
            elif in_value and line:
                hex_part = line.split("|")[0].strip() if "|" in line else line
                current_val_hex.append(hex_part)

        # 最后一条记录
        if current_key_hex and current_val_hex:
            entry = self._hex_to_entry(current_key_hex, current_val_hex, now)
            if entry:
                entries.append(entry)

        return entries

    def _hex_to_entry(
        self, key_hex_lines: List[str], val_hex_lines: List[str], timestamp: float
    ) -> Optional[BpfMapEntry]:
        """将 bpftool 的十六进制输出转换为 BpfMapEntry."""
        try:
            key_bytes = bytes.fromhex("".join(key_hex_lines).replace(" ", ""))
            val_bytes = bytes.fromhex("".join(val_hex_lines).replace(" ", ""))

            # 解析 key: 假设 key_fields 顺序对应 C struct 布局
            # 这是简化版, 实际需要根据 map key struct 来解析
            key: Dict[str, Any] = {}
            if self.key_fields:
                offset = 0
                for field_name in self.key_fields:
                    if field_name in ("pid", "tid", "uid", "gid", "cpu"):
                        if offset + 4 <= len(key_bytes):
                            key[field_name] = int.from_bytes(
                                key_bytes[offset:offset+4], "little"
                            )
                            offset += 4
                    elif field_name in ("comm", "syscall", "func"):
                        # 字符串字段, 通常 16 字节
                        field_len = 16
                        if offset + field_len <= len(key_bytes):
                            raw = key_bytes[offset:offset+field_len]
                            null_idx = raw.find(0)
                            key[field_name] = raw[:null_idx].decode("utf-8", errors="replace") if null_idx >= 0 else raw.decode("utf-8", errors="replace")
                            offset += field_len
                    else:
                        # 未知字段: 尝试作为 u64
                        if offset + 8 <= len(key_bytes):
                            key[field_name] = int.from_bytes(
                                key_bytes[offset:offset+8], "little"
                            )
                            offset += 8
            else:
                key["_raw"] = key_bytes.hex()

            # 解析 value: 默认作为 u64
            if len(val_bytes) >= 8:
                value = int.from_bytes(val_bytes[:8], "little")
            elif len(val_bytes) >= 4:
                value = int.from_bytes(val_bytes[:4], "little")
            else:
                value = int.from_bytes(val_bytes, "little") if val_bytes else 0

            return BpfMapEntry(key=key, value=value, timestamp=timestamp)
        except (ValueError, IndexError):
            return None

    def read_as_dataframe(self) -> pd.DataFrame:
        """读取 BPF map 数据并转为 pandas DataFrame."""
        entries = self.read_raw()
        if not entries:
            return pd.DataFrame()

        rows = []
        for entry in entries:
            row = {**entry.key, "value": entry.value, "timestamp": entry.timestamp}
            rows.append(row)
        return pd.DataFrame(rows)


# =============================================================================
# 模拟数据生成器 (开发/演示用)
# =============================================================================

class MockDataGenerator:
    """
    模拟 BPF map 数据, 用于开发和演示。
    生成类似 VFS 操作计数的时序数据。

    模拟的 VFS 操作类型:
      create, getattr, getxattr, lookup, mkdir, open, opendir,
      read, readdir, release, releasedir, rename, setattr, unlink, write
    """

    VFS_OPS = [
        "create", "getattr", "getxattr", "lookup", "mkdir",
        "open", "opendir", "read", "readdir", "release",
        "releasedir", "rename", "setattr", "unlink", "write",
    ]

    def __init__(self, seed: int = 42):
        import random
        self._rng = random.Random(seed)
        self._base_rates: Dict[str, float] = {}
        self._init_base_rates()

    def _init_base_rates(self):
        """初始化每种操作的基础速率 (events/sec)."""
        for op in self.VFS_OPS:
            # 不同操作有不同的基础频率
            if op in ("read", "write", "open"):
                self._base_rates[op] = self._rng.uniform(500, 3000)
            elif op in ("getattr", "lookup", "release"):
                self._base_rates[op] = self._rng.uniform(1000, 5000)
            elif op in ("unlink", "rename", "create"):
                self._base_rates[op] = self._rng.uniform(100, 2000)
            elif op in ("mkdir", "rmdir"):
                self._base_rates[op] = self._rng.uniform(10, 200)
            elif op in ("opendir", "readdir", "releasedir"):
                self._base_rates[op] = self._rng.uniform(200, 1500)
            elif op in ("getxattr", "setattr"):
                self._base_rates[op] = self._rng.uniform(300, 2500)
            else:
                self._base_rates[op] = self._rng.uniform(100, 1000)

    def generate_snapshot(self) -> pd.DataFrame:
        """生成一个时间点的模拟数据."""
        import random
        now = time.time()
        rows = []
        for op in self.VFS_OPS:
            # 添加随机波动 (±30%)
            base = self._base_rates[op]
            noise = self._rng.uniform(-0.3, 0.3)
            count = max(0, int(base * (1 + noise)))
            rows.append({
                "operation": op,
                "count": count,
                "timestamp": now,
            })
        return pd.DataFrame(rows)

    def generate_timeseries(self, seconds: int = 20, interval: float = 1.0) -> pd.DataFrame:
        """生成一段时间序列数据."""
        frames = []
        base_time = time.time()
        for i in range(int(seconds / interval)):
            df = self.generate_snapshot()
            df["timestamp"] = base_time - (seconds - i * interval)
            frames.append(df)
        return pd.concat(frames, ignore_index=True)


# =============================================================================
# 实时数据采集器
# =============================================================================

class RealtimeCollector:
    """
    实时数据采集器: 定期从 BPF map 读取数据并维护滑动窗口。

    使用方式:
        collector = RealtimeCollector(
            reader=BpfMapReader("file_monitor", "f_count", ["syscall", "comm"]),
            window_seconds=20,
            interval=1.0,
        )
        collector.start()
        # ... Streamlit loop ...
        df = collector.get_window_data()
    """

    def __init__(
        self,
        reader: BpfMapReader,
        window_seconds: int = 20,
        interval: float = 1.0,
        mock_mode: bool = False,
    ):
        self.reader = reader
        self.window_seconds = window_seconds
        self.interval = interval
        self.mock_mode = mock_mode
        self._mock_gen = MockDataGenerator() if mock_mode else None
        self._buffer: Deque[Snapshot] = deque()
        self._lock = threading.Lock()
        self._running = False
        self._thread: Optional[threading.Thread] = None
        self._on_new_data: Optional[Callable[[Snapshot], None]] = None

    @property
    def running(self) -> bool:
        return self._running

    def set_callback(self, callback: Callable[[Snapshot], None]):
        """设置新数据回调."""
        self._on_new_data = callback

    def start(self):
        """启动后台采集线程."""
        if self._running:
            return
        self._running = True
        self._thread = threading.Thread(target=self._collect_loop, daemon=True)
        self._thread.start()

    def stop(self):
        """停止后台采集线程."""
        self._running = False
        if self._thread:
            self._thread.join(timeout=2)
            self._thread = None

    def _collect_loop(self):
        """后台采集循环."""
        while self._running:
            try:
                snapshot = self._take_snapshot()
                with self._lock:
                    self._buffer.append(snapshot)
                    # 清理过期数据
                    cutoff = time.time() - self.window_seconds
                    while self._buffer and self._buffer[0].timestamp < cutoff:
                        self._buffer.popleft()
                if self._on_new_data:
                    self._on_new_data(snapshot)
            except Exception:
                pass
            time.sleep(self.interval)

    def _take_snapshot(self) -> Snapshot:
        """采集一次快照."""
        if self.mock_mode and self._mock_gen:
            df = self._mock_gen.generate_snapshot()
            entries = [
                BpfMapEntry(
                    key={"operation": row["operation"]},
                    value=row["count"],
                    timestamp=row["timestamp"],
                )
                for _, row in df.iterrows()
            ]
        else:
            entries = self.reader.read_raw()
        return Snapshot(
            tool_name=self.reader.tool_name,
            map_name=self.reader.map_name,
            entries=entries,
            timestamp=time.time(),
        )

    def get_window_data(self) -> pd.DataFrame:
        """获取滑动窗口内的所有数据, 转为 DataFrame."""
        with self._lock:
            snapshots = list(self._buffer)

        if not snapshots:
            return pd.DataFrame()

        rows = []
        for snap in snapshots:
            for entry in snap.entries:
                row = {**entry.key, "value": entry.value, "timestamp": snap.timestamp}
                rows.append(row)
        return pd.DataFrame(rows)

    def get_latest_snapshot(self) -> Optional[Snapshot]:
        """获取最近一次采样的快照."""
        with self._lock:
            if self._buffer:
                return self._buffer[-1]
        return None
