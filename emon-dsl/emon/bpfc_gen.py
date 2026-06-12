"""
Emon DSL eBPF C Code Generator

Generates a compilable *.bpf.c file from an IRProgram.
The output is standard libbpf / BPF CO-RE C code intended for
clang -target bpf compilation.

Corresponds to project plan sections 5.4.1–5.4.6.
"""

from typing import List, Dict, Optional
import textwrap

from emon.ir import (
    IRProgram, IRProbe, IRMap, IRAggregation,
    IREmit, IREventStruct, IREveryTask, IRPrint,
)


# =============================================================================
# Utility
# =============================================================================

def _indent(text: str, level: int = 1, first: bool = False) -> str:
    """Indent every line by `level` * 4 spaces."""
    pad = " " * (level * 4)
    result = "\n".join(pad + line if line else "" for line in text.split("\n"))
    if first:
        return pad + result.lstrip()
    return result


def _safe_c_name(name: str) -> str:
    """Convert a name to a valid C identifier."""
    return name.replace("@", "").replace("-", "_").replace(".", "_")


# =============================================================================
# Type Helpers for Map Key Structs
# =============================================================================

# Mapping from context variable name to C type (for BPF map key structs)
_KEY_TYPE_MAP: Dict[str, str] = {
    "pid": "u32",
    "tid": "u32",
    "uid": "u32",
    "gid": "u32",
    "cpu": "u32",
    "comm": "char [16]",
    "syscall": "char [16]",
    "func": "char [64]",
    "arg0": "u64", "arg1": "u64", "arg2": "u64",
    "arg3": "u64", "arg4": "u64", "arg5": "u64",
}

# BPF map type strings → SEC annotation values
_MAP_TYPE_MAP: Dict[str, str] = {
    "HASH": "BPF_MAP_TYPE_HASH",
    "PERCPU_HASH": "BPF_MAP_TYPE_PERCPU_HASH",
    "ARRAY": "BPF_MAP_TYPE_ARRAY",
    "PERCPU_ARRAY": "BPF_MAP_TYPE_PERCPU_ARRAY",
    "PERF_EVENT_ARRAY": "BPF_MAP_TYPE_PERF_EVENT_ARRAY",
    "RINGBUF": "BPF_MAP_TYPE_RINGBUF",
}

# Value type alias mapping
_VALUE_TYPE_MAP: Dict[str, str] = {
    "u64": "__u64",
    "u32": "__u32",
    "s64": "__s64",
    "s32": "__s32",
}


# =============================================================================
# eBPF C Code Generator
# =============================================================================

class BpfCGenerator:
    """Generates a complete eBPF C source file from an IRProgram."""

    def __init__(self, ir: IRProgram):
        self.ir = ir
        self._map_name_set: set = {m.name for m in ir.maps}
        self._event_name_set: set = {e.name for e in ir.events}
        self._probe_counter: int = 0
        self._needs_start_time: bool = False
        self._seen_struct_names: set = set()
        # Build option lookup: name → value string
        self._option_values: Dict[str, str] = {}
        for opt in ir.options:
            self._option_values[opt["name"]] = opt.get("default", "0")

    def _resolve_expr(self, expr: str) -> str:
        """Replace option references and time/size literals with C values.

        Option references (like 'target_pid') are replaced with their values.
        Time literals (like '100us', '1ms') are converted to nanoseconds.
        Size literals (like '1MB') are converted to bytes.
        """
        result = expr
        for name, value in self._option_values.items():
            result = result.replace(name, value)
        # Convert time/size literals that remain in the expression
        result = self._convert_time_literals(result)
        result = self._convert_size_literals(result)
        return result

    @staticmethod
    def _convert_time_literals(expr: str) -> str:
        """Convert time literals like 100us, 1ms, 2s to nanosecond integers."""
        import re
        def _replace_time(m):
            num = int(m.group(1))
            unit = m.group(2)
            if unit == 'ns':
                return str(num)
            elif unit == 'us':
                return str(num * 1000)
            elif unit == 'ms':
                return str(num * 1000000)
            elif unit == 's':
                return str(num * 1000000000)
            return m.group(0)
        return re.sub(r'(\d+)\s*(ns|us|ms|s)', _replace_time, expr)

    @staticmethod
    def _convert_size_literals(expr: str) -> str:
        """Convert size literals like 256KB, 1MB to byte integers."""
        import re
        def _replace_size(m):
            num = int(m.group(1))
            unit = m.group(2)
            if unit == 'B':
                return str(num)
            elif unit == 'KB':
                return str(num * 1024)
            elif unit == 'MB':
                return str(num * 1024 * 1024)
            return m.group(0)
        return re.sub(r'(\d+)\s*(B|KB|MB)', _replace_size, expr)

    def generate(self) -> str:
        """Generate the complete .bpf.c source."""
        parts: List[str] = []

        parts.append(self._emit_header())
        parts.append(self._emit_license())
        parts.append(self._emit_map_key_structs())
        parts.append(self._emit_implicit_maps())
        parts.append(self._emit_event_structs())
        parts.append(self._emit_maps())
        parts.append(self._emit_probes())

        return "\n\n".join(p for p in parts if p) + "\n"

    # ------------------------------------------------------------------
    # Header
    # ------------------------------------------------------------------

    def _emit_header(self) -> str:
        tool = _safe_c_name(self.ir.tool_name)
        return textwrap.dedent(f"""\
        // =====================================================================
        // {tool}.bpf.c —— Emon DSL 生成的 eBPF C 程序
        // 工具名称: {self.ir.tool_name}
        // 编译命令: clang -O2 -g -target bpf -c {tool}.bpf.c -o {tool}.bpf.o
        // =====================================================================
        //
        // 本文件由 Emon DSL 编译器自动生成，请勿手动编辑。
        // 源 DSL 语义见项目文档 sections 5.1–5.7。

        #include "vmlinux.h"
        #include <bpf/bpf_helpers.h>
        #include <bpf/bpf_tracing.h>
        #include <bpf/bpf_core_read.h>""")

    def _emit_license(self) -> str:
        return 'char LICENSE[] SEC("license") = "Dual BSD/GPL";'

    # ------------------------------------------------------------------
    # Map Key Struct Definitions
    # ------------------------------------------------------------------

    def _emit_map_key_structs(self) -> str:
        """Generate C struct typedefs for composite BPF map keys.

        Each unique combination of key fields gets its own struct.
        Single-field keys use native types directly (no struct needed).
        """
        # Collect all unique key field combinations
        key_sigs: Dict[str, List[str]] = {}
        for m in self.ir.maps:
            sig = "|".join(m.key_fields)
            if sig not in key_sigs:
                key_sigs[sig] = m.key_fields

        parts: List[str] = []
        for sig, fields in key_sigs.items():
            if len(fields) <= 1:
                continue  # single key → use native type directly
            if sig in self._seen_struct_names:
                continue
            self._seen_struct_names.add(sig)

            struct_name = self._key_struct_name(fields)
            lines = [f"// Composite key: {', '.join(fields)}",
                     f"struct {struct_name} {{"]
            # Packed attribute for consistent layout
            lines.append("    // Packed to ensure consistent key layout")
            for fname in fields:
                ctype = _KEY_TYPE_MAP.get(fname, "u64")
                # Handle array types: "char [16]" → "char comm[16]"
                if "[" in ctype:
                    base_type, size_part = ctype.split("[", 1)
                    size_part = size_part.rstrip("] ")
                    lines.append(f"    {base_type.strip()} {_safe_c_name(fname)}[{size_part}];")
                else:
                    lines.append(f"    {ctype} {_safe_c_name(fname)};")
            lines.append("} __attribute__((packed));")
            parts.append("\n".join(lines))

        return "\n\n".join(parts)

    def _key_struct_name(self, fields: List[str]) -> str:
        """Generate a unique C struct name for a key combination."""
        parts = [_safe_c_name(f)[:8] for f in fields[:4]]
        return "key_" + "_".join(parts)

    def _key_c_type(self, fields: List[str]) -> str:
        """Return the C type for a map key."""
        if len(fields) == 1:
            return _KEY_TYPE_MAP.get(fields[0], "u64")
        return f"struct {self._key_struct_name(fields)}"

    # ------------------------------------------------------------------
    # Implicit Maps (start_time for latency measurement)
    # ------------------------------------------------------------------

    def _emit_implicit_maps(self) -> str:
        """Generate start_time maps used by latency measurement probes."""
        # Check if any probe measures latency
        for probe in self.ir.probes:
            if probe.measures_latency:
                self._needs_start_time = True
                break

        if not self._needs_start_time:
            return ""

        # One start_time map per unique hook_target (entry probes track by pid+tid)
        seen_targets: set = set()
        parts: List[str] = []
        parts.append("// ---- Latency measurement: entry probe timestamp storage ----")

        for probe in self.ir.probes:
            if not probe.measures_latency or probe.is_exit:
                continue
            if probe.hook_target in seen_targets:
                continue
            seen_targets.add(probe.hook_target)

            name = f"__start_time_{_safe_c_name(probe.hook_target)}"
            parts.append(textwrap.dedent(f"""\
            struct {{
                __uint(type, BPF_MAP_TYPE_HASH);
                __uint(max_entries, 10240);
                __type(key, __u64);   // pid_tgid
                __type(value, __u64); // timestamp in ns
            }} {name} SEC(".maps");"""))

        return "\n\n".join(parts)

    # ------------------------------------------------------------------
    # Event Struct Definitions
    # ------------------------------------------------------------------

    def _emit_event_structs(self) -> str:
        """Generate C struct definitions for ring buffer events."""
        if not self.ir.events:
            return ""

        parts: List[str] = []
        for ev in self.ir.events:
            lines = [f"// Event struct: {ev.name}",
                     f"struct {_safe_c_name(ev.name)} {{"]
            for field in ev.fields:
                ctype_raw = _KEY_TYPE_MAP.get(field["name"], "u64")
                # Handle array types for event structs
                if "[" in ctype_raw:
                    base_type, size_part = ctype_raw.split("[", 1)
                    size_part = size_part.rstrip("] ")
                    lines.append(f"    {base_type.strip()} {_safe_c_name(field['name'])}[{size_part}];")
                else:
                    # Map to proper __u64/__u32 types
                    if ctype_raw == "u64":
                        ctype_raw = "__u64"
                    elif ctype_raw == "u32":
                        ctype_raw = "__u32"
                    elif ctype_raw == "s64":
                        ctype_raw = "__s64"
                    lines.append(f"    {ctype_raw} {_safe_c_name(field['name'])};")
            lines.append("};")
            parts.append("\n".join(lines))

        return "\n\n".join(parts)

    # ------------------------------------------------------------------
    # BPF Map Definitions
    # ------------------------------------------------------------------

    def _emit_maps(self) -> str:
        """Generate the SEC(".maps") BPF map definitions."""
        if not self.ir.maps:
            return ""

        parts: List[str] = []
        parts.append("// ---- Aggregation Maps ----")

        for m in self.ir.maps:
            map_type = _MAP_TYPE_MAP.get(m.map_type, "BPF_MAP_TYPE_HASH")
            key_type = self._key_c_type(m.key_fields)
            value_type = m.value_type

            # Map value type to proper BPF type name
            if value_type in _VALUE_TYPE_MAP:
                value_type = _VALUE_TYPE_MAP[value_type]

            name = _safe_c_name(m.name)
            parts.append(textwrap.dedent(f"""\
            struct {{
                __uint(type, {map_type});
                __uint(max_entries, {m.max_entries});
                __type(key, {key_type});
                __type(value, {value_type});
            }} {name} SEC(".maps");"""))

        # Ring buffer map for emit
        if self.ir.events:
            for ev in self.ir.events:
                ring_name = _safe_c_name(f"{ev.name}_rb")
                parts.append(textwrap.dedent(f"""\
                struct {{
                    __uint(type, BPF_MAP_TYPE_RINGBUF);
                    __uint(max_entries, 256 * 1024);
                }} {ring_name} SEC(".maps");"""))

        return "\n\n".join(parts)

    # ------------------------------------------------------------------
    # Probe Functions
    # ------------------------------------------------------------------

    def _emit_probes(self) -> str:
        """Generate all BPF probe functions."""
        if not self.ir.probes:
            return "// No probes defined"

        parts: List[str] = []
        parts.append("// =====================================================================")
        parts.append("// Probe Functions")
        parts.append("// =====================================================================")

        for i, probe in enumerate(self.ir.probes):
            self._probe_counter = i + 1
            fn_code = self._emit_single_probe(probe)
            parts.append(fn_code)

        return "\n".join(parts)

    def _emit_single_probe(self, probe: IRProbe) -> str:
        """Generate the C code for one BPF probe function."""
        fn_name = f"{_safe_c_name(self.ir.tool_name)}_probe_{self._probe_counter}"
        section = probe.section

        lines: List[str] = []
        lines.append(f'SEC("{section}")')

        # Determine the proper BPF function signature based on probe type
        if probe.hook_kind == "SYSCALL":
            if probe.is_exit:
                func_sig = f"int {fn_name}(struct trace_event_raw_sys_exit *ctx)"
            else:
                func_sig = f"int {fn_name}(struct trace_event_raw_sys_enter *ctx)"
        elif probe.hook_kind in ("KERNEL", "FILE", "NET"):
            func_sig = f"int {fn_name}(struct pt_regs *ctx)"
        elif probe.hook_kind == "TRACEPOINT":
            func_sig = f"int {fn_name}(void *ctx)"
        elif probe.hook_kind == "UPROBE":
            func_sig = f"int {fn_name}(struct pt_regs *ctx)"
        else:
            func_sig = f"int {fn_name}(void *ctx)"

        lines.append(func_sig)
        lines.append("{")

        # ---- Body ----
        body_lines: List[str] = []

        # 1. Extract context variables
        ctx_code = self._emit_context_extraction(probe)
        if ctx_code:
            body_lines.append(ctx_code)

        # 2. Where conditions — only on entry probe, never on exit
        if not probe.is_exit:
            for cond in probe.where_conditions:
                resolved = self._resolve_expr(cond)
                body_lines.append(f"    // where: {cond}")
                body_lines.append(f"    if (!({resolved})) return 0;")

        # 3. Latency measurement logic
        if probe.measures_latency:
            latency_code = self._emit_latency_logic(probe)
            if latency_code:
                body_lines.append(latency_code)

        # 4. When conditions — only on exit probe (or entry if no latency)
        if probe.measures_latency:
            if probe.is_exit:
                for cond in probe.when_conditions:
                    resolved = self._resolve_expr(cond)
                    body_lines.append(f"    // when: {cond}")
                    body_lines.append(f"    if (!({resolved})) return 0;")
        else:
            # No latency measurement: when conditions go on the single entry probe
            for cond in probe.when_conditions:
                resolved = self._resolve_expr(cond)
                body_lines.append(f"    // when: {cond}")
                body_lines.append(f"    if (!({resolved})) return 0;")

        # 5. Let variable declarations
        for let in probe.lets:
            body_lines.append(f"    // let: {let['name']} = {let['init']}")
            body_lines.append(f"    __u64 {_safe_c_name(let['name'])} = {let['init']};")

        # 6. If statements (with nested actions)
        for ifs in probe.if_stmts:
            if_body = self._emit_if_block(ifs)
            body_lines.append(if_body)

        # 7. Aggregations (top-level, not inside if blocks)
        #    (Aggregations inside if blocks are handled in _emit_if_block)
        top_level_aggs = [a for a in probe.aggregations
                          if not self._is_inside_if(a, probe.if_stmts)]
        for agg in top_level_aggs:
            agg_code = self._emit_aggregation(agg)
            if agg_code:
                body_lines.append(agg_code)

        # 8. Emit (ring buffer output)
        for em in probe.emits:
            emit_code = self._emit_ringbuf_output(em)
            if emit_code:
                body_lines.append(emit_code)

        if not body_lines:
            body_lines.append("    // No actions")

        lines.extend(body_lines)
        lines.append("    return 0;")
        lines.append("}")

        return "\n".join(lines)

    def _is_inside_if(self, agg: IRAggregation, if_stmts: list) -> bool:
        """Check if an aggregation is wrapped inside an if statement."""
        for ifs in if_stmts:
            for action in ifs.get("then", []):
                if action.get("type") == "aggregation" and action.get("target") == agg.map_name:
                    return True
            for action in ifs.get("else", []):
                if action.get("type") == "aggregation" and action.get("target") == agg.map_name:
                    return True
        return False

    # ------------------------------------------------------------------
    # Context Variable Extraction
    # ------------------------------------------------------------------

    def _emit_context_extraction(self, probe: IRProbe) -> str:
        """Generate code to extract context variables (pid, tid, comm, etc.)."""
        lines: List[str] = []
        lines.append("    // --- Context extraction ---")

        # Always extract basic identifiers
        lines.append("    __u64 pid_tgid = bpf_get_current_pid_tgid();")
        lines.append("    __u32 pid = pid_tgid >> 32;")
        lines.append("    __u32 tid = (__u32)pid_tgid;")
        lines.append("    __u64 uid_gid = bpf_get_current_uid_gid();")
        lines.append("    __u32 uid = uid_gid;")
        lines.append("    __u32 gid = uid_gid >> 32;")

        # comm
        lines.append("    char comm[16];")
        lines.append("    bpf_get_current_comm(&comm, sizeof(comm));")

        # nsecs
        lines.append("    __u64 nsecs = bpf_ktime_get_ns();")

        # cpu
        lines.append("    __u32 cpu = bpf_get_smp_processor_id();")

        # Hook-specific context
        if probe.hook_kind == "SYSCALL":
            target_name = probe.hook_target
            if probe.is_exit:
                lines.append(f"    // syscall exit probe: {target_name}")
                lines.append("    unsigned long syscall_id = BPF_CORE_READ(ctx, id);")
                lines.append("    long retval = BPF_CORE_READ(ctx, ret);")
                lines.append(f'    char syscall[16] = "{target_name}";')
            else:
                lines.append(f"    // syscall target: {target_name}")
                lines.append("    unsigned long syscall_id = BPF_CORE_READ(ctx, id);")
                lines.append(f'    char syscall[16] = "{target_name}";')

        elif probe.hook_kind in ("KERNEL", "FILE", "NET"):
            target_name = probe.hook_target
            lines.append("    // PT_REGS based context")
            lines.append(f'    char func[64] = "{target_name}";')
            for i in range(5):
                lines.append(f"    __u64 arg{i} = PT_REGS_PARM{i+1}(ctx);")
            # PT_REGS_PARM6 may not be available on all kernels
            lines.append("#ifdef PT_REGS_PARM6")
            lines.append("    __u64 arg5 = PT_REGS_PARM6(ctx);")
            lines.append("#else")
            lines.append("    __u64 arg5 = 0;")
            lines.append("#endif")

        elif probe.hook_kind == "TRACEPOINT":
            lines.append("    // Generic tracepoint context")

        elif probe.hook_kind == "UPROBE":
            target_name = probe.hook_target
            lines.append("    // Uprobe context")
            lines.append(f'    char func[64] = "{target_name}";')
            for i in range(5):
                lines.append(f"    __u64 arg{i} = PT_REGS_PARM{i+1}(ctx);")
            lines.append("#ifdef PT_REGS_PARM6")
            lines.append("    __u64 arg5 = PT_REGS_PARM6(ctx);")
            lines.append("#else")
            lines.append("    __u64 arg5 = 0;")
            lines.append("#endif")

        # Provide default values for measure-dependent variables that may be needed
        lines.append("    // Default measure variables (overridden if hook provides them)")
        lines.append("    __u64 size = 0;")
        lines.append("    __u64 stack = 0;")

        return "\n".join(lines)

    # ------------------------------------------------------------------
    # Latency Measurement Logic
    # ------------------------------------------------------------------

    def _emit_latency_logic(self, probe: IRProbe) -> str:
        """Generate code for latency measurement (entry store, exit compute)."""
        target_safe = _safe_c_name(probe.hook_target)
        map_name = f"__start_time_{target_safe}"

        if not probe.is_exit:
            # Entry probe: store timestamp
            return textwrap.dedent(f"""\
                // --- Latency measurement: store entry timestamp ---
                __u64 __entry_ts = bpf_ktime_get_ns();
                bpf_map_update_elem(&{map_name}, &pid_tgid, &__entry_ts, BPF_ANY);""")
        else:
            # Exit probe: compute delta
            return textwrap.dedent(f"""\
                // --- Latency measurement: compute delta from entry ---
                __u64 *__start_ptr = bpf_map_lookup_elem(&{map_name}, &pid_tgid);
                if (!__start_ptr) return 0;
                __u64 latency = bpf_ktime_get_ns() - *__start_ptr;
                bpf_map_delete_elem(&{map_name}, &pid_tgid);""")

    # ------------------------------------------------------------------
    # If Block
    # ------------------------------------------------------------------

    def _emit_if_block(self, ifs: dict) -> str:
        """Generate C code for an if/else statement with nested actions."""
        lines: List[str] = []
        lines.append(f"    // if ({ifs['condition']})")
        lines.append(f"    if ({ifs['condition']}) {{")

        for action in ifs.get("then", []):
            action_code = self._emit_if_action(action)
            if action_code:
                lines.append(_indent(action_code, 1))

        lines.append("    }")

        if ifs.get("else"):
            lines.append("    else {")
            for action in ifs["else"]:
                action_code = self._emit_if_action(action)
                if action_code:
                    lines.append(_indent(action_code, 1))
            lines.append("    }")

        return "\n".join(lines)

    def _emit_if_action(self, action: dict) -> str:
        """Generate code for a single action inside an if/else block."""
        atype = action.get("type", "unknown")
        if atype == "aggregation":
            return self._emit_aggregation_from_action(action)
        elif atype == "emit":
            return "// emit (inside if block)"
        elif atype == "let":
            return f"__u64 {_safe_c_name(action['name'])} = {action['init']};"
        elif atype == "print":
            return f"// print({action.get('expr', '')}) — runs in userspace"
        return "// unknown action"

    def _emit_aggregation_from_action(self, action: dict) -> str:
        """Emit aggregation code from a serialized if-action dict."""
        return self._emit_agg_update(
            map_name=action["target"],
            agg_fn=action["fn"],
            keys=action.get("keys", []),
            value_expr="",
        )

    # ------------------------------------------------------------------
    # Aggregation Map Update
    # ------------------------------------------------------------------

    def _emit_aggregation(self, agg: IRAggregation) -> str:
        return self._emit_agg_update(
            map_name=agg.map_name,
            agg_fn=agg.agg_fn,
            keys=agg.keys,
            value_expr=agg.value_expr,
        )

    def _emit_agg_update(self, map_name: str, agg_fn: str,
                         keys: List[str], value_expr: str) -> str:
        """Generate the BPF map update code for one aggregation."""
        map_safe = _safe_c_name(map_name)
        lines: List[str] = []
        lines.append(f"    // @{map_name} = {agg_fn}({value_expr}) keys=[{', '.join(keys)}]")

        # ---- Build the key ----
        if len(keys) == 1:
            # Single key → native type
            key_var = _safe_c_name(keys[0])
            key_type_raw = _KEY_TYPE_MAP.get(keys[0], "u64")
            # Normalize key type for zero-init: handle array types
            if "[" in key_type_raw:
                base_type, size_part = key_type_raw.split("[", 1)
                size_part = size_part.rstrip("] ")
                lines.append(f"    static {base_type.strip()} __key_{map_safe}[{size_part}];")
                lines.append(f"    __builtin_memset(__key_{map_safe}, 0, sizeof(__key_{map_safe}));")
                lines.append(f"    __builtin_memcpy(__key_{map_safe}, {key_var}, sizeof({key_var}));")
            else:
                lines.append(f"    {key_type_raw} __key_{map_safe} = {key_var};")
            key_expr = f"&__key_{map_safe}"
        else:
            # Composite key → packed struct (already declared)
            struct_name = self._key_struct_name(keys)
            lines.append(f"    static struct {struct_name} __key_{map_safe};")
            lines.append(f"    __builtin_memset(&__key_{map_safe}, 0, sizeof(__key_{map_safe}));")
            for fname in keys:
                cvar = _safe_c_name(fname)
                ctype_raw = _KEY_TYPE_MAP.get(fname, "u64")
                if "[" in ctype_raw:
                    # Array field — use memcpy
                    lines.append(f"    __builtin_memcpy(&__key_{map_safe}.{cvar}, {cvar}, sizeof({cvar}));")
                else:
                    lines.append(f"    __key_{map_safe}.{cvar} = {cvar};")
            key_expr = f"&__key_{map_safe}"

        # ---- Build the value update ----
        lines.append(f"    __u64 *__val_{map_safe} = bpf_map_lookup_elem(&{map_safe}, {key_expr});")
        lines.append(f"    if (__val_{map_safe}) {{")

        if agg_fn == "count":
            lines.append(f"        (*__val_{map_safe})++;")
        elif agg_fn == "sum":
            lines.append(f"        *__val_{map_safe} += ({value_expr});")
        elif agg_fn == "min":
            lines.append(f"        if (({value_expr}) < *__val_{map_safe}) "
                        f"*__val_{map_safe} = ({value_expr});")
        elif agg_fn == "max":
            lines.append(f"        if (({value_expr}) > *__val_{map_safe}) "
                        f"*__val_{map_safe} = ({value_expr});")
        elif agg_fn == "avg":
            # avg uses struct { u64 sum; u64 count; }
            lines.append(f"        // avg: increment sum and count")
            lines.append(f"        __val_{map_safe}[0] += ({value_expr});  // sum")
            lines.append(f"        __val_{map_safe}[1] += 1;              // count")
        elif agg_fn == "hist":
            # hist: log2 bucketing
            lines.append(f"        // hist: log2 bucket")
            lines.append(f"        __u64 __v = ({value_expr});")
            lines.append(f"        __u32 __bucket = 0;")
            lines.append(f"        while (__v >>= 1) __bucket++;")
            lines.append(f"        if (__bucket >= 32) __bucket = 31;")
            lines.append(f"        __val_{map_safe}[__bucket]++;")
        elif agg_fn == "lhist":
            # lhist: linear bucketing (placeholder)
            lines.append(f"        // lhist: linear bucket")
            lines.append(f"        __u64 __v = ({value_expr}) / 1000;  // 1us granularity")
            lines.append(f"        if (__v >= 64) __v = 63;")
            lines.append(f"        __val_{map_safe}[__v]++;")
        else:
            lines.append(f"        (*__val_{map_safe})++;  // default: count")

        lines.append(f"    }} else {{")

        # Initialize and insert
        if agg_fn in ("avg",):
            # avg uses a 2-element struct: zero-init then assign
            lines.append(f"        static __u64 __init_{map_safe}[2];")
            lines.append(f"        __builtin_memset(__init_{map_safe}, 0, sizeof(__init_{map_safe}));")
            lines.append(f"        __init_{map_safe}[0] = ({value_expr});")
            lines.append(f"        __init_{map_safe}[1] = 1;")
            lines.append(f"        bpf_map_update_elem(&{map_safe}, {key_expr}, "
                        f"__init_{map_safe}, BPF_ANY);")
        elif agg_fn in ("hist", "lhist"):
            lines.append(f"        // First bucket entry")
            lines.append(f"        static __u64 __init_{map_safe}[32];")
            lines.append(f"        __builtin_memset(__init_{map_safe}, 0, sizeof(__init_{map_safe}));")
            if agg_fn == "hist":
                lines.append(f"        __u64 __v_init = ({value_expr});")
                lines.append(f"        __u32 __b_init = 0;")
                lines.append(f"        while (__v_init >>= 1) __b_init++;")
                lines.append(f"        if (__b_init >= 32) __b_init = 31;")
                lines.append(f"        __init_{map_safe}[__b_init] = 1;")
            else:
                lines.append(f"        __u64 __v_init = ({value_expr}) / 1000;")
                lines.append(f"        if (__v_init >= 64) __v_init = 63;")
                lines.append(f"        __init_{map_safe}[__v_init] = 1;")
            lines.append(f"        bpf_map_update_elem(&{map_safe}, {key_expr}, "
                        f"__init_{map_safe}, BPF_ANY);")
        elif agg_fn == "min":
            lines.append(f"        __u64 __init_val = ({value_expr});")
            lines.append(f"        bpf_map_update_elem(&{map_safe}, {key_expr}, "
                        f"&__init_val, BPF_ANY);")
        elif agg_fn == "max":
            lines.append(f"        __u64 __init_val = ({value_expr});")
            lines.append(f"        bpf_map_update_elem(&{map_safe}, {key_expr}, "
                        f"&__init_val, BPF_ANY);")
        elif agg_fn == "sum":
            lines.append(f"        __u64 __init_val = ({value_expr});")
            lines.append(f"        bpf_map_update_elem(&{map_safe}, {key_expr}, "
                        f"&__init_val, BPF_ANY);")
        else:
            # count: initialize to 1
            lines.append(f"        __u64 __one = 1;")
            lines.append(f"        bpf_map_update_elem(&{map_safe}, {key_expr}, "
                        f"&__one, BPF_ANY);")

        lines.append("    }")

        return "\n".join(lines)

    # ------------------------------------------------------------------
    # Ring Buffer Emit
    # ------------------------------------------------------------------

    def _emit_ringbuf_output(self, emit: IREmit) -> str:
        """Generate ring buffer output code for an emit statement."""
        event_name_safe = _safe_c_name(emit.event_name)
        ring_name = f"{event_name_safe}_rb"

        lines: List[str] = []
        lines.append(f"    // emit -> ring buffer")
        lines.append(f"    struct {event_name_safe} *__ev = "
                    f"bpf_ringbuf_reserve(&{ring_name}, "
                    f"sizeof(struct {event_name_safe}), 0);")
        lines.append(f"    if (__ev) {{")

        for field in emit.fields:
            fname = _safe_c_name(field["name"])
            expr = field["expr"]
            # Check if this field is an array type (comm, syscall, func)
            ctype = _KEY_TYPE_MAP.get(field["name"], "")
            if "[" in ctype:
                # Array field — use memcpy
                lines.append(f"        __builtin_memcpy(&__ev->{fname}, &({expr}), sizeof(__ev->{fname}));")
            else:
                lines.append(f"        __ev->{fname} = ({expr});")

        lines.append(f"        bpf_ringbuf_submit(__ev, 0);")
        lines.append(f"    }}")

        return "\n".join(lines)


# =============================================================================
# Convenience
# =============================================================================

def generate_bpf_c(ir: IRProgram) -> str:
    """Generate a complete eBPF C source file from an IRProgram."""
    return BpfCGenerator(ir).generate()
