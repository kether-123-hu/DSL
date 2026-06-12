"""
Emon DSL Manifest Generator

Generates a YAML tool manifest from an IRProgram.
The manifest describes the tool's structure, maps, probes, and events
in a machine-readable format for tool discovery and management.

Corresponds to project plan section 5.5.
"""

from typing import List
import textwrap

from emon.ir import IRProgram, IRMap, IRProbe


class ManifestGenerator:
    """Generates a YAML manifest file describing the Emon DSL tool."""

    def __init__(self, ir: IRProgram):
        self.ir = ir

    def generate(self) -> str:
        """Generate the complete YAML manifest."""
        parts: List[str] = []
        parts.append(self._emit_header())
        parts.append(self._emit_tool_info())
        parts.append(self._emit_maps())
        parts.append(self._emit_probes())
        parts.append(self._emit_events())
        parts.append(self._emit_lifecycle())
        return "\n".join(parts) + "\n"

    def _emit_header(self) -> str:
        return textwrap.dedent(f"""\
        # =====================================================================
        # Emon DSL Tool Manifest —— {self.ir.tool_name}
        # 由 Emon DSL 编译器自动生成
        # 格式版本: 0.1
        # 生成日期: (auto-generated)
        # =====================================================================""")

    def _emit_tool_info(self) -> str:
        lines = [
            "",
            "tool:",
            f"  name: {self.ir.tool_name}",
            f'  version: "0.1"',
            f'  description: >',
            f'    Emon DSL 生成的 eBPF 可观测性工具',
            f'  language: emon-dsl',
            f'  target: bpf',
        ]
        if self.ir.options:
            lines.append("  options:")
            for opt in self.ir.options:
                lines.append(f"    {opt['name']}: {opt.get('default', '0')}")
        return "\n".join(lines)

    def _emit_maps(self) -> str:
        if not self.ir.maps:
            return "\nmaps: []"

        lines = ["", "maps:"]
        for m in self.ir.maps:
            lines.append(f"  - name: {m.name}")
            lines.append(f"    type: {self._map_type_to_yaml(m.map_type)}")
            lines.append(f"    key_fields: [{', '.join(m.key_fields)}]")
            lines.append(f"    value_type: {m.value_type}")
            lines.append(f"    max_entries: {m.max_entries}")
        return "\n".join(lines)

    def _map_type_to_yaml(self, mt: str) -> str:
        mapping = {
            "HASH": "hash",
            "PERCPU_HASH": "percpu_hash",
            "ARRAY": "array",
            "PERCPU_ARRAY": "percpu_array",
            "PERF_EVENT_ARRAY": "perf_event_array",
            "RINGBUF": "ringbuf",
        }
        return mapping.get(mt, mt.lower())

    def _emit_probes(self) -> str:
        if not self.ir.probes:
            return "\nprobes: []"

        lines = ["", "probes:"]
        for p in self.ir.probes:
            lines.append(f"  - section: {p.section}")
            lines.append(f"    kind: {p.hook_kind.lower()}")
            lines.append(f"    target: {p.hook_target}")
            lines.append(f"    is_exit: {str(p.is_exit).lower()}")
            lines.append(f"    measures_latency: {str(p.measures_latency).lower()}")
            if p.where_conditions:
                lines.append(f"    where: [")
                for c in p.where_conditions:
                    lines.append(f'      - "{c}"')
                lines.append(f"    ]")
            if p.when_conditions:
                lines.append(f"    when: [")
                for c in p.when_conditions:
                    lines.append(f'      - "{c}"')
                lines.append(f"    ]")
            if p.aggregations:
                lines.append(f"    aggregations:")
                for a in p.aggregations:
                    lines.append(f"      - map: {a.map_name}")
                    lines.append(f"        fn: {a.agg_fn}")
                    lines.append(f"        keys: [{', '.join(a.keys)}]")
                    if a.value_expr:
                        lines.append(f"        value: {a.value_expr}")
            if p.emits:
                lines.append(f"    emits: {len(p.emits)} event(s)")
            if p.lets:
                lines.append(f"    lets:")
                for let in p.lets:
                    lines.append(f"      - {let['name']}: {let['init']}")
            if p.if_stmts:
                lines.append(f"    if_statements: {len(p.if_stmts)}")
        return "\n".join(lines)

    def _emit_events(self) -> str:
        if not self.ir.events:
            return "\nevents: []"

        lines = ["", "events:"]
        for ev in self.ir.events:
            lines.append(f"  - name: {ev.name}")
            lines.append(f"    type: ringbuf")
            lines.append(f"    fields:")
            for f in ev.fields:
                lines.append(f"      - name: {f['name']}")
                lines.append(f"        type: {f['type']}")
        return "\n".join(lines)

    def _emit_lifecycle(self) -> str:
        lines = ["", "lifecycle:"]

        # Begin
        if self.ir.begin_stmts:
            lines.append("  begin:")
            for s in self.ir.begin_stmts:
                lines.append(f'    - print: {s.expr}')
        else:
            lines.append("  begin: []")

        # Every
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

        # End
        if self.ir.end_stmts:
            lines.append("  end:")
            for s in self.ir.end_stmts:
                lines.append(f'    - print: {s.expr}')
        else:
            lines.append("  end: []")

        lines.append("")
        lines.append("outputs:")
        lines.append("  - kind: stdout")
        lines.append("    format: table")
        lines.append("    refresh: 1s")

        return "\n".join(lines)


# =============================================================================
# Convenience
# =============================================================================

def generate_manifest(ir: IRProgram) -> str:
    """Generate a complete YAML manifest from an IRProgram."""
    return ManifestGenerator(ir).generate()
