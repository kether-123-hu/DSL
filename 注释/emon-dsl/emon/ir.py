# ===================================================================
# ir.py —— Emon DSL 中间表示(IR)（编译器第四阶段）
# ===================================================================
#
# 【本文件的作用】
# 中间表示（IR, Intermediate Representation）是编译器前端（词法→语法→语义）
# 和后端（代码生成）之间的桥梁。
#
# 【为什么需要 IR？】
# AST 是对"源代码"的忠实表示，保留了很多语法细节（如括号、分号位置等）。
# IR 是对"程序语义"的精简表示，去除了语法噪音，更接近最终生成的代码结构。
# 这使代码生成器可以更简单地工作。
#
# 【IR 的设计思路】
# IR 直接对应 eBPF 程序的"蓝图"：
#   - IRMap:         对应一个 BPF map 声明
#   - IRAggregation: 对应一条 map 更新指令
#   - IREmit:        对应一条 perf event 输出
#   - IRProbe:       对应一个 eBPF 程序段（挂载点）
#   - IREventStruct: 对应 ring buffer 事件的结构体
#   - IREveryTask:   对应一个周期性用户态任务
#   - IRProgram:     整个程序的 IR 根容器
#
# 【主要功能】
#   1. IR 数据结构定义
#   2. IRBuilder — 将 AST 转换为 IR
#   3. 表达式序列化 — 将 AST 表达式转为类 C 字符串
#   4. 类型推断 — 根据上下文推断 C 类型
#   5. 编译入口 — compile_file / compile_source / build_ir_from_source
# ===================================================================

from dataclasses import dataclass, field, asdict
from typing import List, Optional, Dict, Any
import json
import os

from emon.ast_nodes import (
    Program, ObserveRule, EveryStmt, BeginStmt, EndStmt,
    HookKind, Metric, AggFn,
    AggregationStmt, EmitStmt, PrintStmt, LetStmt, IfStmt,
    Expr, LitInt, LitStr, LitBool, LitTime, LitSize,
    VarRef, AggRef, BinOpExpr, UnaryOpExpr, FuncCall,
    BinOp, UnaryOp,
)


# ===================================================================
# 第一部分：IR 数据结构定义
# ===================================================================

@dataclass
class IRMap:
    """
    BPF map 声明。
    
    eBPF map 是内核态和用户态之间共享数据的核心机制。
    每个 @agg 变量对应一个 BPF map。
    
    属性:
        name:        map 名称（即 @name 中的 name）
        map_type:    BPF map 类型（HASH、PERCPU_HASH、RINGBUF 等）
        key_fields:  map key 的字段名列表（对应上下文变量）
        value_type:  map value 的 C 类型（如 "u64"、"struct {...}"）
        max_entries: map 的最大条目数
    """
    name: str
    map_type: str               # "HASH", "PERCPU_HASH", "PERF_EVENT_ARRAY" 等
    key_fields: List[str]       # 上下文变量名列表，构成 map 的 key
    value_type: str             # "u64", "u32", "struct { u64 sum; u64 count; }" 等
    max_entries: int = 10240    # 默认 10240 条

    def to_dict(self) -> dict:
        """转换为字典（用于 JSON 序列化）"""
        return asdict(self)


@dataclass
class IRAggregation:
    """
    Map 更新指令。
    
    描述如何更新一个 BPF map：对哪个 map、用什么聚合函数、以什么为 key、
    聚合什么值。
    
    属性:
        map_name:   目标 map 名称
        agg_fn:     聚合函数名（"count", "sum", "avg", ...）
        keys:       key 的字符串表示列表
        value_expr: 被聚合的值的字符串表示（count 为空）
    """
    map_name: str               # 如 "@count" → "count"
    agg_fn: str                 # "count", "sum", "avg", "min", "max", "hist", "lhist"
    keys: List[str]             # 上下文变量名字符串列表
    value_expr: str = ""        # 聚合的值表达式（count() 不需要）


@dataclass
class IREmit:
    """
    Perf event 输出指令。
    
    描述将一个事件通过 ring buffer 发送到用户态。
    
    属性:
        event_name: 事件名称
        fields:     输出字段列表 [{"name": "pid", "expr": "pid"}, ...]
    """
    event_name: str
    fields: List[Dict[str, str]]  # [{"name": "pid", "expr": "pid"}, ...]


@dataclass
class IRPrint:
    """
    用户态打印指令。
    
    描述在用户态打印一条信息。
    
    属性:
        expr: 序列化后的表达式字符串
    """
    expr: str                   # 如 '"==== summary ===="', '@count'


@dataclass
class IRProbe:
    """
    单个 eBPF 程序的挂载信息。
    
    每个 observe 规则会展开为 1 个或 2 个 IRProbe（如果测量 latency 则需要 2 个）。
    
    属性:
        section:            eBPF 程序的 SEC 名称（如 "tracepoint/syscalls/sys_enter_read"）
        hook_kind:          观测目标类型（"SYSCALL", "KERNEL" 等）
        hook_target:        具体目标名（如 "read"）
        is_exit:            是否是函数返回探针（True=出口, False=入口）
        where_conditions:   前置过滤条件（序列化后的字符串列表）
        when_conditions:    后置过滤条件
        measures_latency:   是否测量延迟
        aggregations:       聚合操作列表
        emits:              事件输出列表
        lets:               let 变量声明 [{"name": "x", "init": "100"}, ...]
        if_stmts:           if 语句列表
    """
    section: str                # 如 "tracepoint/syscalls/sys_enter_read"
    hook_kind: str              # "SYSCALL", "KERNEL", 等
    hook_target: str            # 系统调用名、函数名
    is_exit: bool               # 是否是返回探针
    where_conditions: List[str] = field(default_factory=list)
    when_conditions: List[str] = field(default_factory=list)
    measures_latency: bool = False
    aggregations: List[IRAggregation] = field(default_factory=list)
    emits: List[IREmit] = field(default_factory=list)
    lets: List[Dict[str, str]] = field(default_factory=list)
    if_stmts: List[Dict[str, Any]] = field(default_factory=list)


@dataclass
class IREventStruct:
    """
    Ring buffer 事件结构体定义。
    
    描述 emit 产生的数据在 C 语言中的结构体布局。
    
    属性:
        name:   结构体名称
        fields: 字段列表 [{"name": "time", "type": "u64"}, ...]
    """
    name: str
    fields: List[Dict[str, str]]  # [{"name": "time", "type": "u64"}, ...]


@dataclass
class IREveryTask:
    """
    周期性用户态任务。
    
    描述一个 every 块的内容。
    
    属性:
        interval:  时间间隔字符串（如 "1s" 或 option 引用）
        prints:    打印操作列表
        agg_reads: 需要读取并打印的 @agg 名称列表
    """
    interval: str               # "1s", "interval"（option 引用）
    prints: List[IRPrint] = field(default_factory=list)
    agg_reads: List[str] = field(default_factory=list)  # @agg 名称列表


@dataclass
class IRProgram:
    """
    顶层 IR 容器 —— 整个程序的中间表示。
    
    包含程序的所有信息：工具名、选项、map、事件、探针、生命周期任务。
    
    可以序列化为 JSON 格式（to_json），便于调试和跨语言传递。
    """
    tool_name: str                                    # 工具名称
    options: List[Dict[str, Any]] = field(default_factory=list)  # 配置选项
    maps: List[IRMap] = field(default_factory=list)             # BPF map 列表
    events: List[IREventStruct] = field(default_factory=list)   # 事件结构体列表
    probes: List[IRProbe] = field(default_factory=list)         # 探针列表
    every_tasks: List[IREveryTask] = field(default_factory=list)# 周期性任务列表
    begin_stmts: List[IRPrint] = field(default_factory=list)    # begin 块语句
    end_stmts: List[IRPrint] = field(default_factory=list)      # end 块语句

    def to_dict(self) -> dict:
        """将整个 IR 序列化为 JSON 兼容的字典"""
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
        """将 IR 序列化为 JSON 字符串（便于调试查看）"""
        return json.dumps(self.to_dict(), indent=indent)


# ===================================================================
# 第二部分：表达式序列化器
# ===================================================================
# 将 AST 中的表达式节点转换为类 C 语言的字符串表示。
# 例如: BinOpExpr(ADD, VarRef("a"), LitInt(1)) → "(a + 1)"

def _serialize_expr(expr: Expr) -> str:
    """
    将 AST 表达式递归转换为 C 风格的字符串。
    
    这个方法在代码生成阶段使用，将 Emon DSL 的表达式
    转换为可以在 eBPF C 代码中直接使用的字符串。
    """
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
        # 变量引用直接返回变量名
        return expr.name
    elif isinstance(expr, AggRef):
        # 聚合引用返回 @name 形式
        return f"@{expr.name}"
    elif isinstance(expr, BinOpExpr):
        # 二元运算：转换为 (左操作数 运算符 右操作数)
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
        # 一元运算：转换为 (运算符 操作数)
        op_map = {UnaryOp.NOT: "!", UnaryOp.NEG: "-"}
        op_str = op_map.get(expr.op, "")
        return f"({op_str}{_serialize_expr(expr.operand)})"
    elif isinstance(expr, FuncCall):
        # 函数调用：转换为 函数名(参数1, 参数2, ...)
        args = ", ".join(_serialize_expr(a) for a in expr.args)
        return f"{expr.name}({args})"
    return "?"


# ===================================================================
# 第三部分：Section 名称生成器
# ===================================================================
# eBPF 程序通过 SEC 宏指定挂载点，不同 hook 类型有不同的命名规则。

def _make_section(hook_kind: HookKind, target: str, is_exit: bool) -> str:
    """
    根据 hook 类型和目标生成 BPF 程序的 section 名称。
    
    section 名称决定了 eBPF 程序如何被加载和挂载。
    例如:
      - syscall read 入口: "tracepoint/syscalls/sys_enter_read"
      - kernel tcp_v4_connect 出口: "kretprobe/tcp_v4_connect"
    
    参数:
        hook_kind: 观测类型（HookKind 枚举）
        target:    目标名称（系统调用名、函数名等）
        is_exit:   是否是返回探针（True=出口, False=入口）
    """
    kind_map = {
        #           (入口 section 前缀, 出口 section 前缀)
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


# ===================================================================
# 第四部分：类型推断
# ===================================================================

def _infer_value_type(agg_fn: AggFn) -> str:
    """
    根据聚合函数推断 BPF map 的 value 类型。
    
    不同聚合函数需要不同的存储结构：
      - count/sum: 只需要一个 u64（64位无符号整数）
      - avg:       需要 sum 和 count 两个字段来计算平均值
      - min/max:   需要 s64（64位有符号整数）
      - hist:      32 个桶的对数直方图
      - lhist:     64 个桶的线性直方图
    """
    type_map = {
        AggFn.COUNT: "u64",
        AggFn.SUM:   "u64",
        AggFn.AVG:   "struct { u64 sum; u64 count; }",  # avg = sum / count
        AggFn.MIN:   "s64",
        AggFn.MAX:   "s64",
        AggFn.HIST:  "struct { u64 slots[32]; }",       # 32 个对数桶
        AggFn.LHIST: "struct { u64 slots[64]; }",       # 64 个线性桶
    }
    return type_map.get(agg_fn, "u64")


def _infer_field_type(var_name: str) -> str:
    """
    根据上下文变量名推断其在 C 事件结构体中的类型。
    
    例如:
      pid → u32（进程 ID 是 32 位）
      nsecs → u64（时间戳是 64 位）
      comm → char [16]（进程名是 16 字节字符串）
    """
    type_map = {
        "pid": "u32", "tid": "u32", "uid": "u32", "gid": "u32",
        "cpu": "u32",
        "comm": "char [16]",
        "nsecs": "u64",
        "syscall": "char [16]",
        "func": "char [64]",
        "latency": "u64",
        "retval": "s64",
        "size": "u64",
        "stack": "u64",
    }
    # arg0~arg5 统一为 u64
    for i in range(6):
        type_map[f"arg{i}"] = "u64"
    return type_map.get(var_name, "u64")


# ===================================================================
# 第五部分：IR 构建器（AST → IR）
# ===================================================================

class IRBuilder:
    """
    IR 构建器：将验证过的 Program AST 转换为 IRProgram。
    
    这是编译器前后端之间的枢纽。它将抽象语法树中的语义信息
    重新组织为更适合代码生成的形式。
    
    使用流程:
        builder = IRBuilder()
        ir = builder.build(program_ast)
    """

    def build(self, program: Program) -> IRProgram:
        """
        从 Program AST 构建 IRProgram。
        
        工作步骤:
          1. 提取工具名和选项
          2. 处理每个顶层语句（ObserveRule → IRProbe, EveryStmt → IREveryTask 等）
          3. 去重 map（同名的 map 只保留第一个）
        """
        ir = IRProgram(tool_name=program.tool.name)

        # 步骤1: 提取选项
        for name, value in program.tool.options:
            ir.options.append({
                "name": name,
                "default": _serialize_expr(value),
            })

        # 步骤2: 处理每个顶层语句
        for stmt in program.stmts:
            if isinstance(stmt, ObserveRule):
                # 观察规则 → 展开为探针
                probes = self._build_probes(stmt, ir)
                ir.probes.extend(probes)
            elif isinstance(stmt, EveryStmt):
                # 周期性任务 → 转换为 IREveryTask
                task = self._build_every_task(stmt)
                ir.every_tasks.append(task)
            elif isinstance(stmt, BeginStmt):
                # begin 块 → 提取打印语句
                ir.begin_stmts = self._build_prints(stmt.actions)
            elif isinstance(stmt, EndStmt):
                # end 块 → 提取打印语句
                ir.end_stmts = self._build_prints(stmt.actions)

        # 步骤3: 去重 map（按名称去重，保留首次出现的）
        seen = set()
        unique_maps = []
        for m in ir.maps:
            if m.name not in seen:
                seen.add(m.name)
                unique_maps.append(m)
        ir.maps = unique_maps

        return ir

    # ----------------------------------------------------------------
    # 探针构建
    # ----------------------------------------------------------------

    def _build_probes(self, rule: ObserveRule, ir: IRProgram) -> List[IRProbe]:
        """
        将 ObserveRule 展开为 IRProbe 列表。
        
        关键逻辑：
          - 如果声明了 measure latency，需要 2 个探针（入口+出口）
          - 入口探针记录时间戳，出口探针计算延迟并执行动作
          - 如果不测量延迟，只需 1 个入口探针
          - where 条件放在入口探针，when 条件放在出口探针
        """
        # 检查是否声明了延迟测量
        measures_latency = any(
            Metric.LATENCY in mc.metrics for mc in rule.measures
        )
        targets = rule.hook.targets
        hook_kind = rule.hook.kind

        probes = []
        for target in targets:
            # ---- 入口探针（总是需要的） ----
            entry = IRProbe(
                section=_make_section(hook_kind, target, False),
                hook_kind=hook_kind.name,
                hook_target=target,
                is_exit=False,
                measures_latency=measures_latency,
            )
            self._fill_probe_conditions(entry, rule)
            # 如果不需要测量延迟，所有动作都在入口探针
            if not measures_latency:
                self._fill_probe_actions(entry, rule, ir, is_exit=False)
            probes.append(entry)

            # ---- 出口探针（仅当测量延迟时需要） ----
            if measures_latency:
                exit_probe = IRProbe(
                    section=_make_section(hook_kind, target, True),
                    hook_kind=hook_kind.name,
                    hook_target=target,
                    is_exit=True,
                    measures_latency=True,
                )
                self._fill_probe_conditions(exit_probe, rule)
                # 所有动作都在出口探针执行
                self._fill_probe_actions(exit_probe, rule, ir, is_exit=True)
                probes.append(exit_probe)

        return probes

    def _fill_probe_conditions(self, probe: IRProbe, rule: ObserveRule):
        """
        填充探针的过滤条件（where/when）。
        
        条件分配规则：
          - where 条件：总是放在入口探针（前置过滤）
          - when 条件：
              * 如果测量延迟 → 放在出口探针（可以使用延迟/返回值等）
              * 如果不测量延迟 → 也放在入口探针
        """
        if not probe.is_exit:
            # 入口探针：where 条件（前置过滤）
            for wc in rule.wheres:
                probe.where_conditions.append(_serialize_expr(wc.cond))
            # 如果不测量延迟，when 条件也放这里
            if not probe.measures_latency:
                for wc in rule.whens:
                    probe.when_conditions.append(_serialize_expr(wc.cond))
        else:
            # 出口探针：when 条件（后置过滤）
            for wc in rule.whens:
                probe.when_conditions.append(_serialize_expr(wc.cond))

    def _fill_probe_actions(self, probe: IRProbe, rule: ObserveRule,
                            ir: IRProgram, is_exit: bool):
        """填充探针的动作语句（聚合、emit、let、if）"""
        self._process_actions(rule.actions, probe, ir)

    def _process_actions(self, actions: list, probe: IRProbe, ir: IRProgram):
        """
        处理动作列表，按类型分发到对应的处理函数。
        此方法递归处理嵌套的 if 语句。
        """
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
                # 将 if 语句序列化存储
                probe.if_stmts.append({
                    "condition": _serialize_expr(action.cond),
                    "then": [self._serialize_action(a) for a in action.then_actions],
                    "else": [self._serialize_action(a) for a in (action.else_actions or [])],
                })
                # 递归处理嵌套的动作（注册其中的 map 和事件）
                self._process_actions(action.then_actions, probe, ir)
                if action.else_actions:
                    self._process_actions(action.else_actions, probe, ir)

    def _serialize_action(self, action) -> dict:
        """将单个动作序列化为字典（用于 if 分支中）"""
        if isinstance(action, AggregationStmt):
            return {"type": "aggregation", "target": action.target,
                    "fn": action.fn.name.lower(),
                    "keys": [k.name if isinstance(k, VarRef) else _serialize_expr(k) for k in action.keys]}
        elif isinstance(action, EmitStmt):
            return {"type": "emit"}
        elif isinstance(action, PrintStmt):
            return {"type": "print", "expr": _serialize_expr(action.expr)}
        elif isinstance(action, LetStmt):
            return {"type": "let", "name": action.name, "init": _serialize_expr(action.value)}
        return {"type": "unknown"}

    # ----------------------------------------------------------------
    # 聚合 → IRMap + IRAggregation
    # ----------------------------------------------------------------

    def _build_aggregation(self, agg: AggregationStmt,
                           ir: IRProgram) -> IRAggregation:
        """
        将聚合语句转换为 IRMap + IRAggregation。
        
        一个聚合语句（如 @count[comm, pid] = count()）产生：
          1. 一个 IRMap（声明 BPF map）
          2. 一个 IRAggregation（描述如何更新这个 map）
        """
        # 提取 key 字段名
        key_names = []
        for key in agg.keys:
            if isinstance(key, VarRef):
                key_names.append(key.name)
            else:
                key_names.append(_serialize_expr(key))

        value_expr = _serialize_expr(agg.arg) if agg.arg else ""

        # 注册 BPF map
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

    # ----------------------------------------------------------------
    # Emit → IREventStruct + IREmit
    # ----------------------------------------------------------------

    def _build_emit(self, emit: EmitStmt, ir: IRProgram) -> IREmit:
        """
        将 emit 语句转换为 IREventStruct + IREmit。
        
        emit 的字段会合并到事件结构体中。
        如果多个 emit 语句输出到同一事件，字段会自动合并。
        """
        event_name = f"event_{ir.tool_name}"

        fields = []
        for f in emit.fields:
            fields.append({
                "name": f.name,
                "expr": _serialize_expr(f.value),
            })

        # 构建事件结构体字段（推断每个字段的 C 类型）
        event_fields = []
        for f in emit.fields:
            event_fields.append({
                "name": f.name,
                "type": _infer_field_type(f.name),
            })

        # 检查事件结构体是否已存在（合并字段）
        existing = None
        for ev in ir.events:
            if ev.name == event_name:
                existing = ev
                break
        if existing:
            # 合并新字段（不重复添加）
            existing_names = {f["name"] for f in existing.fields}
            for ef in event_fields:
                if ef["name"] not in existing_names:
                    existing.fields.append(ef)
        else:
            ir.events.append(IREventStruct(name=event_name, fields=event_fields))

        return IREmit(event_name=event_name, fields=fields)

    # ----------------------------------------------------------------
    # 生命周期语句
    # ----------------------------------------------------------------

    def _build_every_task(self, every: EveryStmt) -> IREveryTask:
        """将 EveryStmt 转换为 IREveryTask"""
        interval = _serialize_expr(every.interval)
        task = IREveryTask(interval=interval)

        for action in every.actions:
            if isinstance(action, PrintStmt):
                task.prints.append(IRPrint(expr=_serialize_expr(action.expr)))
                # 跟踪 @agg 引用（用于自动读取 map 值）
                if isinstance(action.expr, AggRef):
                    task.agg_reads.append(action.expr.name)

        return task

    def _build_prints(self, actions: list) -> List[IRPrint]:
        """从动作列表中提取打印语句"""
        result = []
        for action in actions:
            if isinstance(action, PrintStmt):
                result.append(IRPrint(expr=_serialize_expr(action.expr)))
        return result


# ===================================================================
# 第六部分：便捷函数
# ===================================================================

def build_ir(program: Program) -> IRProgram:
    """
    从已验证的 Program AST 构建 IRProgram。
    
    最常用的调用方式：
      ir = build_ir(ast)
    """
    return IRBuilder().build(program)


def build_ir_from_source(source: str) -> IRProgram:
    """
    从 Emon DSL 源代码直接构建 IR（内部完成 解析→语义检查→IR构建）。
    
    如果语义检查失败，抛出 ValueError。
    """
    from emon.parser import parse
    from emon.semantic import analyze

    ast = parse(source)
    errors = analyze(ast)
    if errors:
        messages = "; ".join(str(e) for e in errors)
        raise ValueError(f"Semantic errors: {messages}")
    return build_ir(ast)


def compile_file(source_path: str, output_dir: str = ".") -> dict:
    """
    完整的编译流程：.emon 源文件 → 生成 .bpf.c、_loader.c、.yaml。
    
    这是编译器的"一键编译"接口。用户只需提供 .emon 文件路径，
    就能得到所有编译产物。
    
    参数:
        source_path: .emon 源文件路径
        output_dir:  输出目录（默认为当前目录）
    
    返回:
        字典，键为产物类型（"bpf_c", "loader_c", "manifest"），值为文件路径
    
    抛出:
        ValueError: 语义错误
        FileNotFoundError: 源文件不存在
    """
    from emon.bpfc_gen import generate_bpf_c
    from emon.loader_gen import generate_loader_c
    from emon.manifest_gen import generate_manifest

    # 读取源文件
    with open(source_path, "r", encoding="utf-8") as f:
        source = f.read()

    # 完整的编译流水线：解析 → 语义检查 → IR 构建
    from emon.parser import parse
    from emon.semantic import analyze

    ast = parse(source)
    errors = analyze(ast)
    if errors:
        messages = "\n".join(f"  - {e}" for e in errors)
        raise ValueError(
            f"Semantic errors in '{source_path}':\n{messages}\n"
            f"Total: {len(errors)} error(s)"
        )

    ir = build_ir(ast)

    # 确保输出目录存在
    os.makedirs(output_dir, exist_ok=True)

    # 安全的文件名（替换特殊字符）
    safe_name = ir.tool_name.replace("-", "_").replace(".", "_")

    results = {}

    # 生成 eBPF C 程序（内核态）
    bpf_c_path = os.path.join(output_dir, f"{safe_name}.bpf.c")
    with open(bpf_c_path, "w", encoding="utf-8") as f:
        f.write(generate_bpf_c(ir))
    results["bpf_c"] = bpf_c_path

    # 生成 libbpf 加载器（用户态）
    loader_c_path = os.path.join(output_dir, f"{safe_name}_loader.c")
    with open(loader_c_path, "w", encoding="utf-8") as f:
        f.write(generate_loader_c(ir))
    results["loader_c"] = loader_c_path

    # 生成 YAML 清单
    manifest_path = os.path.join(output_dir, f"{safe_name}.yaml")
    with open(manifest_path, "w", encoding="utf-8") as f:
        f.write(generate_manifest(ir))
    results["manifest"] = manifest_path

    return results


def compile_source(source: str, tool_name: str = "emon_tool",
                   output_dir: str = ".") -> dict:
    """
    从 Emon DSL 源代码字符串编译（不写入文件的版本）。
    
    返回的字典中，值是对应产物的源代码字符串（而不是文件路径）。
    """
    from emon.bpfc_gen import generate_bpf_c
    from emon.loader_gen import generate_loader_c
    from emon.manifest_gen import generate_manifest

    from emon.parser import parse
    from emon.semantic import analyze

    ast = parse(source)
    errors = analyze(ast)
    if errors:
        messages = "\n".join(f"  - {e}" for e in errors)
        raise ValueError(
            f"Semantic errors:\n{messages}\n"
            f"Total: {len(errors)} error(s)"
        )

    ir = build_ir(ast)

    results = {}
    results["bpf_c"] = generate_bpf_c(ir)        # 生成的 BPF C 代码字符串
    results["loader_c"] = generate_loader_c(ir)   # 生成的加载器 C 代码字符串
    results["manifest"] = generate_manifest(ir)    # 生成的 YAML 清单字符串
    results["ir"] = ir                             # IR 对象（用于进一步处理）

    return results
