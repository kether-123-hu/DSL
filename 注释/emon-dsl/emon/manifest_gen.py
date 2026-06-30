# ===================================================================
# manifest_gen.py —— 工具清单文件生成器（编译器第五阶段-C）
# ===================================================================
#
# 【本文件的作用】
# 从 IR（中间表示）生成 YAML 格式的工具清单（Manifest）文件。
# 清单文件以机器可读的形式描述 eBPF 工具的完整结构，
# 用于工具发现、管理和文档生成。
#
# 【清单文件包含的信息】
#   - 工具名称和版本
#   - 配置选项及其默认值
#   - BPF map 列表（名称、类型、key 结构、value 类型）
#   - 探针列表（挂载点、hook 类型、过滤条件）
#   - 事件结构定义
#   - 生命周期（begin/every/end 配置）
#   - 输出配置（格式、刷新频率）
#
# 【YAML 格式】
# YAML 是一种人类可读的数据序列化格式（类似 JSON，但更简洁）。
# 常用于配置文件和数据交换。
# ===================================================================

from typing import List
import textwrap
from emon.ir import IRProgram, IRMap, IRProbe


class ManifestGenerator:
    """
    从 IRProgram 生成 YAML 工具清单。
    
    使用方式:
        gen = ManifestGenerator(ir)
        yaml_content = gen.generate()
    """

    def __init__(self, ir: IRProgram):
        self.ir = ir

    def generate(self) -> str:
        """
        生成完整的 YAML 清单。
        
        按 YAML 文档结构依次输出各段。
        """
        parts: List[str] = []
        parts.append(self._emit_header())       # 文件头注释
        parts.append(self._emit_tool_info())    # 工具基本信息
        parts.append(self._emit_maps())         # BPF map 列表
        parts.append(self._emit_probes())       # 探针列表
        parts.append(self._emit_events())       # 事件结构
        parts.append(self._emit_lifecycle())    # 生命周期配置
        return "\n".join(parts) + "\n"

    def _emit_header(self) -> str:
        """生成 YAML 文件头注释"""
        return textwrap.dedent(f"""\
        # =====================================================================
        # Emon DSL 工具清单 —— {self.ir.tool_name}
        # 由 Emon DSL 编译器自动生成
        # 格式版本: 0.1
        # =====================================================================""")

    def _emit_tool_info(self) -> str:
        """生成工具基本信息段"""
        lines = [
            "",
            "tool:",                          # 工具信息段开始
            f"  name: {self.ir.tool_name}",   # 工具名称
            f'  version: "0.1"',              # 版本号
            f'  description: >',              # 描述（多行字符串）
            f'    Emon DSL 生成的 eBPF 可观测性工具',
            f'  language: emon-dsl',          # 源语言
            f'  target: bpf',                 # 目标平台
        ]
        # 输出配置选项
        if self.ir.options:
            lines.append("  options:")
            for opt in self.ir.options:
                lines.append(f"    {opt['name']}: {opt.get('default', '0')}")
        return "\n".join(lines)

    def _emit_maps(self) -> str:
        """生成 BPF map 段"""
        if not self.ir.maps:
            return "\nmaps: []"  # 空列表

        lines = ["", "maps:"]
        for m in self.ir.maps:
            lines.append(f"  - name: {m.name}")              # Map 名称
            lines.append(f"    type: {self._map_type_to_yaml(m.map_type)}")  # Map 类型
            lines.append(f"    key_fields: [{', '.join(m.key_fields)}]")  # Key 字段
            lines.append(f"    value_type: {m.value_type}")  # Value 类型
            lines.append(f"    max_entries: {m.max_entries}")# 最大条目数
        return "\n".join(lines)

    def _map_type_to_yaml(self, mt: str) -> str:
        """将内部 map 类型名映射为更可读的 YAML 名称"""
        mapping = {
            "HASH": "hash",                      # 普通哈希表
            "PERCPU_HASH": "percpu_hash",        # 每 CPU 哈希表
            "ARRAY": "array",                    # 数组
            "PERCPU_ARRAY": "percpu_array",      # 每 CPU 数组
            "PERF_EVENT_ARRAY": "perf_event_array", # 性能事件数组
            "RINGBUF": "ringbuf",                # Ring buffer
        }
        return mapping.get(mt, mt.lower())

    def _emit_probes(self) -> str:
        """生成探针列表段"""
        if not self.ir.probes:
            return "\nprobes: []"

        lines = ["", "probes:"]
        for p in self.ir.probes:
            lines.append(f"  - section: {p.section}")          # SEC 名称
            lines.append(f"    kind: {p.hook_kind.lower()}")   # Hook 类型
            lines.append(f"    target: {p.hook_target}")       # 目标名
            lines.append(f"    is_exit: {str(p.is_exit).lower()}")  # 是否出口探针
            lines.append(f"    measures_latency: {str(p.measures_latency).lower()}")  # 是否测延迟
            
            # where 条件列表
            if p.where_conditions:
                lines.append(f"    where: [")
                for c in p.where_conditions:
                    lines.append(f'      - "{c}"')
                lines.append(f"    ]")
            
            # when 条件列表
            if p.when_conditions:
                lines.append(f"    when: [")
                for c in p.when_conditions:
                    lines.append(f'      - "{c}"')
                lines.append(f"    ]")
            
            # 聚合操作
            if p.aggregations:
                lines.append(f"    aggregations:")
                for a in p.aggregations:
                    lines.append(f"      - map: {a.map_name}")
                    lines.append(f"        fn: {a.agg_fn}")
                    lines.append(f"        keys: [{', '.join(a.keys)}]")
                    if a.value_expr:
                        lines.append(f"        value: {a.value_expr}")
            
            # emit 事件数
            if p.emits:
                lines.append(f"    emits: {len(p.emits)} event(s)")
            
            # let 变量
            if p.lets:
                lines.append(f"    lets:")
                for let in p.lets:
                    lines.append(f"      - {let['name']}: {let['init']}")
            
            # if 语句数
            if p.if_stmts:
                lines.append(f"    if_statements: {len(p.if_stmts)}")
        
        return "\n".join(lines)

    def _emit_events(self) -> str:
        """生成事件结构段"""
        if not self.ir.events:
            return "\nevents: []"

        lines = ["", "events:"]
        for ev in self.ir.events:
            lines.append(f"  - name: {ev.name}")
            lines.append(f"    type: ringbuf")     # 事件类型：ring buffer
            lines.append(f"    fields:")
            for f in ev.fields:
                lines.append(f"      - name: {f['name']}")
                lines.append(f"        type: {f['type']}")
        return "\n".join(lines)

    def _emit_lifecycle(self) -> str:
        """生成生命周期配置段"""
        lines = ["", "lifecycle:"]

        # begin 块
        if self.ir.begin_stmts:
            lines.append("  begin:")
            for s in self.ir.begin_stmts:
                lines.append(f'    - print: {s.expr}')
        else:
            lines.append("  begin: []")

        # every 块
        if self.ir.every_tasks:
            lines.append("  every:")
            for t in self.ir.every_tasks:
                lines.append(f"    - interval: {t.interval}")
                if t.prints:
                    lines.append("      prints:")
                    for p in t.prints:
                        lines.append(f"        - {p.expr}")
                if t.agg_reads:
                    lines.append(f"      agg_reads: [{', '.join(t.agg_reads)}]")
        else:
            lines.append("  every: []")

        # end 块
        if self.ir.end_stmts:
            lines.append("  end:")
            for s in self.ir.end_stmts:
                lines.append(f'    - print: {s.expr}')
        else:
            lines.append("  end: []")

        # 输出配置
        lines.append("")
        lines.append("outputs:")
        lines.append("  - kind: stdout")      # 输出到标准输出
        lines.append("    format: table")     # 表格格式
        lines.append("    refresh: 1s")       # 每秒刷新

        return "\n".join(lines)


# ===================================================================
# 便捷函数
# ===================================================================

def generate_manifest(ir: IRProgram) -> str:
    """
    从 IRProgram 生成 YAML 清单的便捷函数。
    
    用法:
        yaml_content = generate_manifest(ir)
        with open("tool.yaml", "w") as f:
            f.write(yaml_content)
    """
    return ManifestGenerator(ir).generate()
