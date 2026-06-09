"""
Emon DSL Intermediate Representation (IR)

Bridges the Python frontend AST to the C++ backend code generators.
The IR is serializable (JSON) so it can cross the Python/C++ boundary.

Design aligns with include/emon/ir.h.
"""

from dataclasses import dataclass, field, asdict
from typing import List, Optional, Dict, Any
import json

from emon.ast_nodes import (
    Program, ObserveRule, EveryStmt, BeginStmt, EndStmt,
    HookKind, Metric, AggFn,
    AggregationStmt, EmitStmt, PrintStmt, LetStmt, IfStmt,
    Expr, LitInt, LitStr, LitBool, LitTime, LitSize,
    VarRef, AggRef, BinOpExpr, UnaryOpExpr, FuncCall,
    BinOp, UnaryOp,
)


# =============================================================================
# IR Data Structures
# =============================================================================

@dataclass
class IRMap:
    """A BPF map declaration."""
    name: str
    map_type: str               # "HASH", "PERCPU_HASH", "PERF_EVENT_ARRAY", etc.
    key_fields: List[str]       # context variable names forming the key
    value_type: str             # "u64", "u32", "struct {...}"
    max_entries: int = 10240

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class IRAggregation:
    """Map update instruction."""
    map_name: str               # @count → "count"
    agg_fn: str                 # "count", "sum", "avg", "min", "max", "hist", "lhist"
    keys: List[str]             # context variable names
    value_expr: str = ""        # expression to aggregate (empty for count)


@dataclass
class IREmit:
    """Perf event output instruction."""
    event_name: str
    fields: List[Dict[str, str]]  # [{"name": "pid", "expr": "pid"}, ...]


@dataclass
class IRPrint:
    """Userspace print instruction."""
    expr: str                   # serialized expression string


@dataclass
class IRProbe:
    """A single eBPF program attachment."""
    section: str                # e.g. "tracepoint/syscalls/sys_enter_read"
    hook_kind: str              # "SYSCALL", "KERNEL", etc.
    hook_target: str            # syscall name, function name
    is_exit: bool               # True for return probe (kretprobe, sys_exit)
    where_conditions: List[str] = field(default_factory=list)
    when_conditions: List[str] = field(default_factory=list)
    measures_latency: bool = False
    aggregations: List[IRAggregation] = field(default_factory=list)
    emits: List[IREmit] = field(default_factory=list)
    lets: List[Dict[str, str]] = field(default_factory=list)  # [{"name":"x","init":"100"}]
    if_stmts: List[Dict[str, Any]] = field(default_factory=list)


@dataclass
class IREventStruct:
    """A perf event ring buffer struct definition."""
    name: str
    fields: List[Dict[str, str]]  # [{"name": "time", "type": "u64"}, ...]


@dataclass
class IREveryTask:
    """A periodic userspace task."""
    interval: str               # "1s", "interval" (option ref)
    prints: List[IRPrint] = field(default_factory=list)
    agg_reads: List[str] = field(default_factory=list)  # @agg names to read/print


@dataclass
class IRProgram:
    """Top-level IR container."""
    tool_name: str
    options: List[Dict[str, Any]] = field(default_factory=list)
    maps: List[IRMap] = field(default_factory=list)
    events: List[IREventStruct] = field(default_factory=list)
    probes: List[IRProbe] = field(default_factory=list)
    every_tasks: List[IREveryTask] = field(default_factory=list)
    begin_stmts: List[IRPrint] = field(default_factory=list)
    end_stmts: List[IRPrint] = field(default_factory=list)

    def to_dict(self) -> dict:
        """Serialize to JSON-compatible dict for Python→C++ bridge."""
        return {
            "tool_name": self.tool_name,
            "options": self.options,
            "maps": [m.to_dict() for m in self.maps],
            "events": [{"name": e.name, "fields": e.fields} for e in self.events],
            "probes": [asdict(p) for p in self.probes],
            "every_tasks": [asdict(t) for t in self.every_tasks],
            "begin_stmts": [asdict(s) for s in self.begin_stmts],
            "end_stmts": [asdict(s) for s in self.end_stmts],
        }

    def to_json(self, indent: int = 2) -> str:
        """Serialize to JSON string."""
        return json.dumps(self.to_dict(), indent=indent)


# =============================================================================
# Expression Serializer
# =============================================================================

def _serialize_expr(expr: Expr) -> str:
    """Convert an AST expression to a C-like string representation."""
    if isinstance(expr, LitInt):
        return str(expr.value)
    elif isinstance(expr, LitStr):
        return f'"{expr.value}"'
    elif isinstance(expr, LitBool):
        return "true" if expr.value else "false"
    elif isinstance(expr, LitTime):
        return expr.value
    elif isinstance(expr, LitSize):
        return expr.value
    elif isinstance(expr, VarRef):
        return expr.name
    elif isinstance(expr, AggRef):
        return f"@{expr.name}"
    elif isinstance(expr, BinOpExpr):
        op_map = {
            BinOp.ADD: "+", BinOp.SUB: "-", BinOp.MUL: "*",
            BinOp.DIV: "/", BinOp.MOD: "%",
            BinOp.LT: "<", BinOp.GT: ">",
            BinOp.LE: "<=", BinOp.GE: ">=",
            BinOp.EQ: "==", BinOp.NE: "!=",
            BinOp.AND: "&&", BinOp.OR: "||",
        }
        op_str = op_map.get(expr.op, "?")
        return f"({_serialize_expr(expr.lhs)} {op_str} {_serialize_expr(expr.rhs)})"
    elif isinstance(expr, UnaryOpExpr):
        op_map = {UnaryOp.NOT: "!", UnaryOp.NEG: "-"}
        op_str = op_map.get(expr.op, "")
        return f"({op_str}{_serialize_expr(expr.operand)})"
    elif isinstance(expr, FuncCall):
        args = ", ".join(_serialize_expr(a) for a in expr.args)
        return f"{expr.name}({args})"
    return "?"


# =============================================================================
# Section Name Generator
# =============================================================================

def _make_section(hook_kind: HookKind, target: str, is_exit: bool) -> str:
    """Generate the BPF program section name for a hook."""
    kind_map = {
        HookKind.SYSCALL:    ("tracepoint/syscalls/sys_enter_", "tracepoint/syscalls/sys_exit_"),
        HookKind.KERNEL:     ("kprobe/", "kretprobe/"),
        HookKind.TRACEPOINT: ("tracepoint/", "tracepoint/"),
        HookKind.UPROBE:     ("uprobe/", "uretprobe/"),
        HookKind.SCHED:      ("tracepoint/sched/", "tracepoint/sched/"),
        HookKind.FILE:       ("kprobe/", "kretprobe/"),
        HookKind.NET:        ("kprobe/", "kretprobe/"),
    }
    prefix = kind_map.get(hook_kind, ("kprobe/", "kretprobe/"))
    section_base = prefix[1] if is_exit else prefix[0]
    return section_base + target


# =============================================================================
# Type Inference
# =============================================================================

def _infer_value_type(agg_fn: AggFn) -> str:
    """Infer the BPF map value type for an aggregation function."""
    type_map = {
        AggFn.COUNT: "u64",
        AggFn.SUM:   "u64",
        AggFn.AVG:   "struct { u64 sum; u64 count; }",
        AggFn.MIN:   "s64",
        AggFn.MAX:   "s64",
        AggFn.HIST:  "struct { u64 slots[32]; }",
        AggFn.LHIST: "struct { u64 slots[64]; }",
    }
    return type_map.get(agg_fn, "u64")


def _infer_field_type(var_name: str) -> str:
    """Infer C type for a context variable in an event struct."""
    type_map = {
        "pid": "u32", "tid": "u32", "uid": "u32", "gid": "u32",
        "cpu": "u32",
        "comm": "char[16]",
        "nsecs": "u64",
        "syscall": "char[16]",
        "func": "char[64]",
        "latency": "u64",
        "retval": "s64",
        "size": "u64",
        "stack": "u64",
    }
    for i in range(6):
        type_map[f"arg{i}"] = "u64"
    return type_map.get(var_name, "u64")


# =============================================================================
# IR Builder
# =============================================================================

class IRBuilder:
    """Builds an IRProgram from a validated Program AST."""

    def build(self, program: Program) -> IRProgram:
        ir = IRProgram(tool_name=program.tool.name)

        # Options
        for name, value in program.tool.options:
            ir.options.append({
                "name": name,
                "default": _serialize_expr(value),
            })

        # Process each top-level statement
        for stmt in program.stmts:
            if isinstance(stmt, ObserveRule):
                probes = self._build_probes(stmt, ir)
                ir.probes.extend(probes)
            elif isinstance(stmt, EveryStmt):
                task = self._build_every_task(stmt)
                ir.every_tasks.append(task)
            elif isinstance(stmt, BeginStmt):
                ir.begin_stmts = self._build_prints(stmt.actions)
            elif isinstance(stmt, EndStmt):
                ir.end_stmts = self._build_prints(stmt.actions)

        # Deduplicate maps (same name → keep first)
        seen = set()
        unique_maps = []
        for m in ir.maps:
            if m.name not in seen:
                seen.add(m.name)
                unique_maps.append(m)
        ir.maps = unique_maps

        return ir

    # ------------------------------------------------------------------
    # Probe building
    # ------------------------------------------------------------------

    def _build_probes(self, rule: ObserveRule, ir: IRProgram) -> List[IRProbe]:
        measures_latency = any(
            Metric.LATENCY in mc.metrics for mc in rule.measures
        )
        targets = rule.hook.targets
        hook_kind = rule.hook.kind

        probes = []
        for target in targets:
            # Entry probe (always)
            entry = IRProbe(
                section=_make_section(hook_kind, target, False),
                hook_kind=hook_kind.name,
                hook_target=target,
                is_exit=False,
                measures_latency=measures_latency,
            )
            self._fill_probe_conditions(entry, rule)
            self._fill_probe_actions(entry, rule, ir, is_exit=False)
            probes.append(entry)

            # Exit probe (only when latency is measured)
            if measures_latency:
                exit_probe = IRProbe(
                    section=_make_section(hook_kind, target, True),
                    hook_kind=hook_kind.name,
                    hook_target=target,
                    is_exit=True,
                    measures_latency=True,
                )
                self._fill_probe_conditions(exit_probe, rule)
                self._fill_probe_actions(exit_probe, rule, ir, is_exit=True)
                probes.append(exit_probe)

        return probes

    def _fill_probe_conditions(self, probe: IRProbe, rule: ObserveRule):
        for wc in rule.wheres:
            probe.where_conditions.append(_serialize_expr(wc.cond))
        for wc in rule.whens:
            probe.when_conditions.append(_serialize_expr(wc.cond))

    def _fill_probe_actions(self, probe: IRProbe, rule: ObserveRule,
                            ir: IRProgram, is_exit: bool):
        self._process_actions(rule.actions, probe, ir)

    def _process_actions(self, actions: list, probe: IRProbe, ir: IRProgram):
        """Process action statements, handling nesting (if blocks)."""
        for action in actions:
            if isinstance(action, AggregationStmt):
                agg = self._build_aggregation(action, ir)
                probe.aggregations.append(agg)
            elif isinstance(action, EmitStmt):
                em = self._build_emit(action, ir)
                probe.emits.append(em)
            elif isinstance(action, LetStmt):
                probe.lets.append({
                    "name": action.name,
                    "init": _serialize_expr(action.value),
                })
            elif isinstance(action, IfStmt):
                probe.if_stmts.append({
                    "condition": _serialize_expr(action.cond),
                    "then": [self._serialize_action(a) for a in action.then_actions],
                    "else": [self._serialize_action(a) for a in (action.else_actions or [])],
                })
                # Process nested actions for map/event registration
                self._process_actions(action.then_actions, probe, ir)
                if action.else_actions:
                    self._process_actions(action.else_actions, probe, ir)

    def _serialize_action(self, action) -> dict:
        """Serialize a single action for if-stmt branches."""
        if isinstance(action, AggregationStmt):
            return {"type": "aggregation", "target": action.target,
                    "fn": action.fn.name.lower(), "keys": [k.name if isinstance(k, VarRef) else _serialize_expr(k) for k in action.keys]}
        elif isinstance(action, EmitStmt):
            return {"type": "emit"}
        elif isinstance(action, PrintStmt):
            return {"type": "print", "expr": _serialize_expr(action.expr)}
        elif isinstance(action, LetStmt):
            return {"type": "let", "name": action.name, "init": _serialize_expr(action.value)}
        return {"type": "unknown"}

    # ------------------------------------------------------------------
    # Aggregation → IRMap + IRAggregation
    # ------------------------------------------------------------------

    def _build_aggregation(self, agg: AggregationStmt,
                           ir: IRProgram) -> IRAggregation:
        key_names = []
        for key in agg.keys:
            if isinstance(key, VarRef):
                key_names.append(key.name)
            else:
                key_names.append(_serialize_expr(key))

        value_expr = _serialize_expr(agg.arg) if agg.arg else ""

        # Register the BPF map
        ir_map = IRMap(
            name=agg.target,
            map_type="PERCPU_HASH" if agg.fn != AggFn.COUNT else "HASH",
            key_fields=key_names,
            value_type=_infer_value_type(agg.fn),
        )
        ir.maps.append(ir_map)

        return IRAggregation(
            map_name=agg.target,
            agg_fn=agg.fn.name.lower(),
            keys=key_names,
            value_expr=value_expr,
        )

    # ------------------------------------------------------------------
    # Emit → IREventStruct + IREmit
    # ------------------------------------------------------------------

    def _build_emit(self, emit: EmitStmt, ir: IRProgram) -> IREmit:
        event_name = f"event_{ir.tool_name}"

        fields = []
        for f in emit.fields:
            fields.append({
                "name": f.name,
                "expr": _serialize_expr(f.value),
            })

        # Register event struct (once per unique field set)
        event_fields = []
        for f in emit.fields:
            event_fields.append({
                "name": f.name,
                "type": _infer_field_type(f.name),
            })

        # Check if event struct already exists
        existing = None
        for ev in ir.events:
            if ev.name == event_name:
                existing = ev
                break
        if existing:
            # Merge fields
            existing_names = {f["name"] for f in existing.fields}
            for ef in event_fields:
                if ef["name"] not in existing_names:
                    existing.fields.append(ef)
        else:
            ir.events.append(IREventStruct(name=event_name, fields=event_fields))

        return IREmit(event_name=event_name, fields=fields)

    # ------------------------------------------------------------------
    # Lifecycle statements
    # ------------------------------------------------------------------

    def _build_every_task(self, every: EveryStmt) -> IREveryTask:
        interval = _serialize_expr(every.interval)
        task = IREveryTask(interval=interval)

        for action in every.actions:
            if isinstance(action, PrintStmt):
                task.prints.append(IRPrint(expr=_serialize_expr(action.expr)))
                # Track @agg references
                if isinstance(action.expr, AggRef):
                    task.agg_reads.append(action.expr.name)

        return task

    def _build_prints(self, actions: list) -> List[IRPrint]:
        result = []
        for action in actions:
            if isinstance(action, PrintStmt):
                result.append(IRPrint(expr=_serialize_expr(action.expr)))
        return result


# =============================================================================
# Convenience
# =============================================================================

def build_ir(program: Program) -> IRProgram:
    """Build IRProgram from a validated Program AST."""
    return IRBuilder().build(program)


def build_ir_from_source(source: str) -> IRProgram:
    """Parse, validate, and build IR from Emon DSL source code."""
    from emon.parser import parse
    from emon.semantic import analyze

    ast = parse(source)
    errors = analyze(ast)
    if errors:
        messages = "; ".join(str(e) for e in errors)
        raise ValueError(f"Semantic errors: {messages}")
    return build_ir(ast)
