#!/usr/bin/env python3
"""
frontier.py — Emon DSL 用户态数据桥接脚本

对应架构图中 "frontier.py" 组件:
  - 从 BPF Map 中周期性读取数据
  - 构建 pandas DataFrame
  - 生成 Altair 图表
  - 可独立运行, 也可被 Streamlit 前端调用

使用方式:
    # 独立运行: 输出 CSV / JSON / 图表
    python frontier.py --tool file_monitor --map f_count --output csv

    # 作为库使用
    from frontier import Frontier
    f = Frontier("file_monitor", "f_count")
    df = f.collect(duration=10)
"""

from __future__ import annotations

import argparse
import json
import os
import signal
import sys
import time
from datetime import datetime
from typing import Any, Dict, List, Optional

# 将当前目录 (workspace root) 加入 path, 以便可以 import frontend 包
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import pandas as pd

from frontend.bpf_reader import BpfMapReader, MockDataGenerator


# =============================================================================
# Frontier 主类
# =============================================================================

class Frontier:
    """
    Emon DSL 数据桥接器。

    负责:
      1. 周期性从 BPF Map 采集数据
      2. 数据清洗与聚合
      3. 生成用于可视化的 DataFrame
    """

    def __init__(
        self,
        tool_name: str,
        map_name: str,
        key_fields: Optional[List[str]] = None,
        mock_mode: bool = False,
    ):
        self.tool_name = tool_name
        self.map_name = map_name
        self.key_fields = key_fields or []
        self.mock_mode = mock_mode
        self.reader = BpfMapReader(tool_name, map_name, key_fields)
        self.mock_gen = MockDataGenerator() if mock_mode else None
        self._stop_flag = False

    def collect_once(self) -> pd.DataFrame:
        """采集一次数据, 返回 DataFrame."""
        if self.mock_mode and self.mock_gen:
            return self.mock_gen.generate_snapshot()

        entries = self.reader.read_raw()
        if not entries:
            return pd.DataFrame()

        rows = []
        for entry in entries:
            row = {**entry.key, "value": entry.value, "timestamp": entry.timestamp}
            rows.append(row)
        return pd.DataFrame(rows)

    def collect(self, duration: int = 10, interval: float = 1.0) -> pd.DataFrame:
        """持续采集指定时长, 返回完整的时序 DataFrame."""
        frames: List[pd.DataFrame] = []
        start = time.time()

        print(f"🔍 开始采集: tool={self.tool_name}, map={self.map_name}, "
              f"duration={duration}s, interval={interval}s")

        while time.time() - start < duration:
            if self._stop_flag:
                break
            df = self.collect_once()
            if not df.empty:
                frames.append(df)
            time.sleep(interval)

        if frames:
            result = pd.concat(frames, ignore_index=True)
            print(f"✅ 采集完成: {len(result)} 条记录")
            return result
        return pd.DataFrame()

    def stop(self):
        """停止采集."""
        self._stop_flag = True

    def to_csv(self, df: pd.DataFrame, path: str):
        """导出为 CSV."""
        df.to_csv(path, index=False)
        print(f"📄 CSV 已保存: {path}")

    def to_json(self, df: pd.DataFrame, path: str):
        """导出为 JSON."""
        df.to_json(path, orient="records", indent=2, force_ascii=False)
        print(f"📄 JSON 已保存: {path}")

    def to_altair_chart(self, df: pd.DataFrame, output_path: Optional[str] = None):
        """生成 Altair 图表并保存为 HTML 或显示."""
        try:
            import altair as alt
        except ImportError:
            print("⚠️  需要安装 altair: pip install altair")
            return None

        if df.empty:
            print("⚠️  无数据可用于生成图表")
            return None

        # 重命名列以适应图表
        chart_df = df.copy()
        if "operation" in chart_df.columns:
            chart_df = chart_df.rename(columns={
                "operation": "操作类型",
                "count": "执行次数/秒",
            })

        chart = (
            alt.Chart(chart_df)
            .mark_area(opacity=0.3)
            .encode(
                x=alt.X("timestamp:T", title="时间"),
                y=alt.Y("执行次数/秒:Q", title="执行次数/秒", stack=None),
                color=alt.Color("操作类型:N", legend=alt.Legend(title="操作类型")),
                tooltip=["操作类型:N", "执行次数/秒:Q", "timestamp:T"],
            )
            .properties(
                title=f"Emon DSL — {self.tool_name} 监控",
                width=800,
                height=400,
            )
            .interactive()
        )

        if output_path:
            chart.save(output_path)
            print(f"📊 图表已保存: {output_path}")
        return chart


# =============================================================================
# CLI
# =============================================================================

def main():
    parser = argparse.ArgumentParser(
        description="Emon DSL Frontier — 用户态 BPF 数据桥接器",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
示例:
  python frontier.py --tool file_monitor --map f_count --output csv
  python frontier.py --tool syscall_counter --map count --duration 30 --output json
  python frontier.py --mock --duration 10 --output chart --chart-path chart.html
        """,
    )
    parser.add_argument(
        "--tool", type=str, default="file_monitor",
        help="监控工具名称 (对应 .emon 文件名)",
    )
    parser.add_argument(
        "--map", type=str, default="f_count",
        help="BPF Map 名称",
    )
    parser.add_argument(
        "--key-fields", type=str, nargs="*", default=["syscall", "comm"],
        help="Map key 的字段名列表",
    )
    parser.add_argument(
        "--duration", type=int, default=10,
        help="采集时长 (秒)",
    )
    parser.add_argument(
        "--interval", type=float, default=1.0,
        help="采集间隔 (秒)",
    )
    parser.add_argument(
        "--output", type=str, choices=["csv", "json", "chart", "print"],
        default="print",
        help="输出格式",
    )
    parser.add_argument(
        "--output-path", type=str, default=None,
        help="输出文件路径",
    )
    parser.add_argument(
        "--mock", action="store_true",
        help="使用模拟数据 (无需 root 权限)",
    )
    parser.add_argument(
        "--chart-path", type=str, default="chart.html",
        help="Altair 图表保存路径 (当 --output=chart 时)",
    )

    args = parser.parse_args()

    # 信号处理
    frontier = Frontier(
        tool_name=args.tool,
        map_name=args.map,
        key_fields=args.key_fields,
        mock_mode=args.mock,
    )

    def sigint_handler(sig, frame):
        print("\n⏹️  收到中断信号, 正在停止...")
        frontier.stop()

    signal.signal(signal.SIGINT, sigint_handler)

    # 采集数据
    df = frontier.collect(duration=args.duration, interval=args.interval)

    if df.empty:
        print("⚠️  未采集到任何数据。")
        sys.exit(1)

    # 输出
    if args.output == "csv":
        path = args.output_path or f"{args.tool}_{args.map}_{int(time.time())}.csv"
        frontier.to_csv(df, path)
    elif args.output == "json":
        path = args.output_path or f"{args.tool}_{args.map}_{int(time.time())}.json"
        frontier.to_json(df, path)
    elif args.output == "chart":
        path = args.output_path or args.chart_path
        frontier.to_altair_chart(df, path)
    else:
        # print mode
        print(df.to_string(max_rows=50))
        print(f"\n--- 共 {len(df)} 条记录 ---")


if __name__ == "__main__":
    main()
