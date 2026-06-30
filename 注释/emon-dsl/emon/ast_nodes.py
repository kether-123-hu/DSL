# ===================================================================
# ast_nodes.py —— Emon DSL 抽象语法树(AST)节点定义
# ===================================================================
#
# 【本文件的作用】
# 定义编译器中最重要的数据结构——抽象语法树（AST, Abstract Syntax Tree）。
# AST 是源代码的"树状"结构化表示，去除了括号、分号等语法噪音，
# 只保留程序的语义结构。
#
# 【什么是 AST？】
# 编译器将源代码经过词法分析得到 Token 序列后，
# 语法分析器（parser.py）会根据语法规则将 Token 组织成树状结构。
# 这个树状结构就是 AST。每个节点代表程序的一个组成部分。
#
# 【生活类比】
# 源代码: "observe syscall("read") { @count[pid] = count(); }"
# AST 就像是一棵"家谱树"：
#   Program (程序)
#   ├── ToolDecl (工具声明)
#   └── ObserveRule (观察规则)
#       ├── Hook (挂载点: syscall, read)
#       └── 代码块
#           └── AggregationStmt (聚合语句: @count[pid] = count())
#
# 【本文件中的类层次结构】
#   枚举类型（Enum）:
#     HookKind  - 观测目标类型（7种：syscall/kernel/tracepoint/uprobe/sched/file/net）
#     Metric    - 测量指标类型（5种：latency/count/size/retval/stack）
#     AggFn     - 聚合函数类型（7种：count/sum/avg/min/max/hist/lhist）
#     BinOp     - 二元运算符（13种：+,-,*,/,%,<,>,<=,>=,==,!=,&&,||）
#     UnaryOp   - 一元运算符（2种：!逻辑非, -负号）
#
#   表达式节点（Expr 子类）:
#     LitInt    - 整数字面量（如 42）
#     LitStr    - 字符串字面量（如 "hello"）
#     LitBool   - 布尔字面量（true, false）
#     LitTime   - 时间字面量（如 100us）
#     LitSize   - 大小字面量（如 256KB）
#     VarRef    - 变量引用（如 pid, comm）
#     AggRef    - 聚合变量引用（如 @count）
#     BinOpExpr - 二元运算表达式（如 a + b）
#     UnaryOpExpr- 一元运算表达式（如 !flag）
#     FuncCall  - 函数调用（如 top(@count, 10)）
#
#   语句/子句节点:
#     WhereClause     - where 过滤子句
#     WhenClause      - when 过滤子句
#     MeasureClause   - measure 测量子句
#     Hook            - 观测挂载点
#     AggregationStmt - 聚合语句（@x[keys] = fn(arg)）
#     EmitStmt        - 发射事件语句
#     EmitField       - emit 中的一个字段
#     PrintStmt       - 打印语句
#     LetStmt         - 变量声明语句
#     IfStmt          - 条件判断语句
#
#   顶层结构节点:
#     ToolDecl   - 工具声明
#     ObserveRule- 观察规则（observe 块）
#     EveryStmt  - 周期性任务（every 块）
#     BeginStmt  - 启动块（begin 块）
#     EndStmt    - 结束块（end 块）
#     Program    - 整个程序的根节点
# ===================================================================

from dataclasses import dataclass, field  # dataclass: 简化数据类; field: 定义字段默认值
from enum import Enum, auto               # Enum: 枚举; auto: 自动分配值
from typing import Optional, Union, List, Tuple  # 类型提示


# ===================================================================
# 第一部分：枚举类型定义
# ===================================================================
# 枚举类型用于限制某个字段只能取固定的几个值，
# 这样编译器可以在编译时检查错误（而不是等到运行时才发现拼写错误）。

class HookKind(Enum):
    """
    观测目标类型枚举（7种）。
    
    每种类型对应 eBPF 中不同的挂载方式：
      SYSCALL    → 通过 tracepoint 挂载到系统调用入口/出口
      KERNEL     → 通过 kprobe/kretprobe 挂载到内核函数
      TRACEPOINT → 挂载到内核预定义的静态跟踪点
      UPROBE     → 通过 uprobe/uretprobe 挂载到用户态函数
      SCHED      → 挂载到调度器相关跟踪点
      FILE       → 通过 kprobe 挂载到文件系统相关内核函数
      NET        → 通过 kprobe 挂载到网络相关内核函数
    """
    SYSCALL = auto()
    KERNEL = auto()
    TRACEPOINT = auto()
    UPROBE = auto()
    SCHED = auto()
    FILE = auto()
    NET = auto()


class Metric(Enum):
    """
    测量指标类型枚举（5种）。
    
    在 observe 块中通过 measure 子句声明要采集哪些指标：
      LATENCY → 函数执行延迟（需要成对的 entry/exit 探针计算时间差）
      COUNT   → 事件发生次数（每次触发计数+1）
      SIZE    → 数据大小（如读写字节数）
      RETVAL  → 函数返回值
      STACK   → 内核调用栈
    """
    LATENCY = auto()
    COUNT = auto()
    SIZE = auto()
    RETVAL = auto()
    STACK = auto()


class AggFn(Enum):
    """
    聚合函数类型枚举（7种）。
    
    在 eBPF map 中用于对数据进行统计聚合：
      COUNT → 计数：统计事件发生次数
      SUM   → 求和：累加所有观测值
      AVG   → 平均值：内部用 sum/count 实现
      MIN   → 最小值
      MAX   → 最大值
      HIST  → 对数直方图（桶的宽度按 2 的幂次增长）
      LHIST → 线性直方图（所有桶等宽）
    """
    COUNT = auto()
    SUM = auto()
    AVG = auto()
    MIN = auto()
    MAX = auto()
    HIST = auto()
    LHIST = auto()


class BinOp(Enum):
    """
    二元运算符枚举（13种）。
    
    二元运算符需要两个操作数（左操作数和右操作数）：
      ADD(+) SUB(-) MUL(*) DIV(/) MOD(%)  — 算术运算符
      LT(<) GT(>) LE(<=) GE(>=)           — 比较运算符
      EQ(==) NE(!=)                        — 相等运算符
      AND(&&) OR(||)                       — 逻辑运算符
    """
    ADD = auto()
    SUB = auto()
    MUL = auto()
    DIV = auto()
    MOD = auto()
    LT = auto()
    GT = auto()
    LE = auto()
    GE = auto()
    EQ = auto()
    NE = auto()
    AND = auto()
    OR = auto()


class UnaryOp(Enum):
    """
    一元运算符枚举（2种）。
    
    一元运算符只需要一个操作数：
      NOT(!) → 逻辑非（取反布尔值，如 !is_slow）
      NEG(-) → 负号（取负数，如 -100）
    """
    NOT = auto()
    NEG = auto()


# ===================================================================
# 第二部分：表达式节点（Expr 及其子类）
# ===================================================================
# 表达式是程序中"能计算出值"的部分。
# 比如 42 是一个表达式（值为 42），a + b 也是表达式（值为 a+b 的结果）。

class Expr:
    """
    所有表达式节点的抽象基类。
    
    注意：这不是 Python 的 ABC 抽象基类，而是一个简单的基类。
    所有具体的表达式类型（LitInt, BinOpExpr 等）都继承自 Expr。
    
    dump() 方法用于将 AST 以可读的缩进格式输出，便于调试。
    """
    def dump(self, indent: int = 0) -> str:
        """以缩进格式输出 AST 子树。子类必须重写此方法。"""
        raise NotImplementedError


# ---- 字面量表达式（常量值） ----

@dataclass
class LitInt(Expr):
    """整数字面量节点。例如: 42, 0, 100"""
    value: int  # 整数值

    def dump(self, indent: int = 0) -> str:
        return " " * indent + f"LitInt({self.value})"


@dataclass
class LitStr(Expr):
    """字符串字面量节点。例如: "hello", "/var/log/emon.log" """
    value: str  # 字符串值（不含引号）

    def dump(self, indent: int = 0) -> str:
        return " " * indent + f"LitStr({self.value!r})"


@dataclass
class LitBool(Expr):
    """布尔字面量节点。例如: true, false"""
    value: bool  # True 或 False

    def dump(self, indent: int = 0) -> str:
        # 输出为小写的 true/false（与 Emon 语法一致）
        return " " * indent + f"LitBool({str(self.value).lower()})"


@dataclass
class LitTime(Expr):
    """时间字面量节点。例如: 100us, 1ms, 2s"""
    value: str  # 时间值字符串（包含单位），如 "100us"

    def dump(self, indent: int = 0) -> str:
        return " " * indent + f"LitTime({self.value})"


@dataclass
class LitSize(Expr):
    """大小字面量节点。例如: 256KB, 1MB"""
    value: str  # 大小值字符串（包含单位），如 "256KB"

    def dump(self, indent: int = 0) -> str:
        return " " * indent + f"LitSize({self.value})"


# ---- 变量引用表达式 ----

@dataclass
class VarRef(Expr):
    """
    普通变量引用节点。
    
    可以引用:
      - eBPF 上下文变量（如 pid, comm, cpu, nsecs）
      - 用户通过 let 声明的变量
      - 工具选项（option 定义的配置值）
    """
    name: str  # 变量名

    def dump(self, indent: int = 0) -> str:
        return " " * indent + f"VarRef({self.name})"


@dataclass
class AggRef(Expr):
    """
    聚合变量引用节点。
    
    聚合变量以 @ 开头，存储在 eBPF map 中。
    例如: @count, @avg_latency, @latency_hist
    
    与普通变量的区别：
      - 聚合变量存储在 BPF map 中，可以在多个事件之间累积数据
      - 普通变量是临时的，仅在当前事件处理中有效
    """
    name: str  # 聚合变量名（不含 @ 前缀）

    def dump(self, indent: int = 0) -> str:
        return " " * indent + f"AggRef(@{self.name})"


# ---- 运算表达式 ----

@dataclass
class BinOpExpr(Expr):
    """
    二元运算表达式节点。
    
    表示一个二元运算，如 a + b, x > 10, pid == 0 && comm == "bash"
    
    属性:
        op:  运算符类型（BinOp 枚举值）
        lhs: 左操作数（Left Hand Side）
        rhs: 右操作数（Right Hand Side）
    """
    op: BinOp   # 运算符
    lhs: Expr   # 左操作数（也是一个表达式）
    rhs: Expr   # 右操作数（也是一个表达式）

    def dump(self, indent: int = 0) -> str:
        prefix = " " * indent
        # 递归输出：先输出运算符，再缩进输出左右操作数
        return (f"{prefix}BinOp({self.op.name})\n"
                f"{self.lhs.dump(indent + 2)}\n"
                f"{self.rhs.dump(indent + 2)}")


@dataclass
class UnaryOpExpr(Expr):
    """
    一元运算表达式节点。
    
    表示一个一元运算，如 !flag（逻辑非）, -x（取负）
    
    属性:
        op:      运算符类型（UnaryOp 枚举值）
        operand: 操作数（被运算的表达式）
    """
    op: UnaryOp  # 运算符
    operand: Expr  # 操作数

    def dump(self, indent: int = 0) -> str:
        prefix = " " * indent
        return (f"{prefix}UnaryOp({self.op.name})\n"
                f"{self.operand.dump(indent + 2)}")


@dataclass
class FuncCall(Expr):
    """
    函数调用表达式节点。
    
    例如: top(@count, 10), count()
    
    属性:
        name: 函数名
        args: 参数列表（每个参数是一个表达式）
    """
    name: str              # 函数名
    args: List[Expr] = field(default_factory=list)  # 参数列表

    def dump(self, indent: int = 0) -> str:
        prefix = " " * indent
        lines = [f"{prefix}FuncCall({self.name})"]
        for arg in self.args:
            lines.append(arg.dump(indent + 2))
        return "\n".join(lines)


# ===================================================================
# 第三部分：子句节点（Clause Nodes）
# ===================================================================
# 子句是 observe 规则中的可选组成部分。

@dataclass
class WhereClause:
    """
    Where 子句节点。
    
    where 子句是"前置过滤条件"——在测量之前过滤原始事件。
    只有满足 where 条件的事件才会进入后续的度量和处理流程。
    
    例如: where pid > 0  → 只处理 pid > 0 的进程产生的事件
    
    注意：where 子句中不能使用仅在函数返回时才可用的变量（如 retval），
    因为这些变量在函数入口处还不存在。
    """
    cond: Expr  # 过滤条件表达式

    def dump(self, indent: int = 0) -> str:
        return " " * indent + "WhereClause\n" + self.cond.dump(indent + 2)


@dataclass
class WhenClause:
    """
    When 子句节点。
    
    when 子句是"后置过滤条件"——在测量之后过滤事件。
    when 可以使用测量结果（如 latency, retval）作为过滤条件。
    
    例如: when latency > 1ms  → 只保留延迟超过 1 毫秒的事件
    
    与 where 的区别:
      - where: 前置过滤，在测量之前，不能用测量结果
      - when:  后置过滤，在测量之后，可以使用测量结果
    """
    cond: Expr  # 过滤条件表达式

    def dump(self, indent: int = 0) -> str:
        return " " * indent + "WhenClause\n" + self.cond.dump(indent + 2)


@dataclass
class MeasureClause:
    """
    Measure 子句节点。
    
    声明要测量的指标类型。例如:
      measure latency        → 只测量延迟
      measure latency, retval → 测量延迟和返回值
    
    测量声明决定了哪些上下文变量可以在后续的 when 和 action 中使用。
    """
    metrics: List[Metric]  # 要测量的指标列表

    def dump(self, indent: int = 0) -> str:
        names = ", ".join(m.name for m in self.metrics)
        return " " * indent + f"MeasureClause({names})"


# ===================================================================
# 第四部分：观测挂载点（Hook）
# ===================================================================

@dataclass
class Hook:
    """
    观测挂载点节点。
    
    描述 eBPF 程序应该挂载到哪里进行观测。
    
    属性:
        kind:        观测目标类型（HookKind 枚举：syscall/kernel/tracepoint 等）
        targets:     要监控的具体目标列表（如系统调用名列表 ["read", "write"]）
        binary_path: 仅用于 uprobe 类型，指定用户态可执行文件路径
    
    示例:
        syscall("read", "write") → Hook(SYSCALL, ["read", "write"])
        kernel("tcp_v4_connect") → Hook(KERNEL, ["tcp_v4_connect"])
        uprobe("/bin/bash", "readline") → Hook(UPROBE, ["readline"], "/bin/bash")
    """
    kind: HookKind           # 观测目标类型
    targets: List[str]       # 监控目标列表
    binary_path: Optional[str] = None  # 用户态程序的路径（仅 uprobe 使用）

    def dump(self, indent: int = 0) -> str:
        prefix = " " * indent
        lines = [f"{prefix}Hook(kind={self.kind.name})"]
        if self.binary_path:
            lines.append(f"{prefix}  binary={self.binary_path!r}")
        for t in self.targets:
            lines.append(f"{prefix}  target={t!r}")
        return "\n".join(lines)


# ===================================================================
# 第五部分：动作语句节点（Action Statement Nodes）
# ===================================================================
# 动作语句是 observe/every/begin/end 块中的可执行语句。

@dataclass
class AggregationStmt:
    """
    聚合语句节点。
    
    语法: @name[keys] = agg_func(arg);
    
    这是 Emon DSL 最核心的语句。它在 eBPF map 中以 keys 为键，
    对 arg 执行聚合函数操作。
    
    示例:
      @count[comm, pid, syscall] = count();
        → 以(进程名, 进程ID, 系统调用名)为键，统计事件次数
      
      @avg_latency[comm, pid] = avg(latency);
        → 以(进程名, 进程ID)为键，计算延迟的平均值
    
    属性:
        target: 聚合变量名（不含 @ 前缀），也用作 BPF map 名
        keys:   作为 map key 的表达式列表（通常是上下文变量）
        fn:     聚合函数类型（AggFn 枚举）
        arg:    聚合函数的参数（count() 没有参数，avg(latency) 的参数是 latency）
    """
    target: str                # 聚合目标名称（即 @name 中的 name）
    keys: List[Expr]           # map key 列表
    fn: AggFn                  # 聚合函数
    arg: Optional[Expr] = None # 聚合参数（count() 不需要参数时为 None）

    def dump(self, indent: int = 0) -> str:
        prefix = " " * indent
        lines = [f"{prefix}AggregationStmt(@{self.target}, fn={self.fn.name})"]
        if self.keys:
            lines.append(f"{prefix}  keys:")
            for k in self.keys:
                lines.append(k.dump(indent + 4))
        if self.arg:
            lines.append(f"{prefix}  arg:")
            lines.append(self.arg.dump(indent + 4))
        return "\n".join(lines)


@dataclass
class EmitField:
    """
    Emit 字段节点。
    
    emit 语句中的每个字段赋值。例如:
      pid = pid;     → EmitField(name="pid", value=VarRef("pid"))
      latency = latency; → EmitField(name="latency", value=VarRef("latency"))
    
    属性:
        name:  输出字段名
        value: 字段的值表达式
    """
    name: str   # 字段名
    value: Expr  # 字段值

    def dump(self, indent: int = 0) -> str:
        return " " * indent + f"EmitField({self.name})"


@dataclass
class EmitStmt:
    """
    Emit 语句节点。
    
    emit 语句将数据通过 ring buffer 从内核态发送到用户态。
    这是 eBPF 程序向用户态输出"每个事件"详细数据的方式。
    
    示例:
      emit {
          time    = nsecs;
          pid     = pid;
          comm    = comm;
      };
    
    属性:
        fields: 要输出的字段列表
    """
    fields: List[EmitField] = field(default_factory=list)

    def dump(self, indent: int = 0) -> str:
        prefix = " " * indent
        lines = [f"{prefix}EmitStmt"]
        for f in self.fields:
            lines.append(f.dump(indent + 2))
            lines.append(f.value.dump(indent + 4))
        return "\n".join(lines)


@dataclass
class PrintStmt:
    """
    Print 语句节点。
    
    print 语句在用户态输出信息。与 emit 不同，print 不是每个事件触发，
    而是在 every/begin/end 生命周期块中使用。
    
    示例:
      print("==== summary ====");     → 打印静态字符串
      print(top(@count, 10));          → 打印 top-10 统计
      print(@avg_latency);             → 打印聚合变量的值
    """
    expr: Expr  # 要打印的表达式

    def dump(self, indent: int = 0) -> str:
        return " " * indent + "PrintStmt\n" + self.expr.dump(indent + 2)


@dataclass
class LetStmt:
    """
    Let 语句节点。
    
    let 声明一个局部变量并赋值。变量只在当前的 observe 块内有效。
    
    示例:
      let threshold = 1000000;           → 数值变量
      let is_slow = latency > threshold; → 布尔变量
      let proc_name = comm;              → 字符串变量
    
    属性:
        name:  变量名
        value: 初始值表达式
    """
    name: str   # 变量名
    value: Expr  # 初始值

    def dump(self, indent: int = 0) -> str:
        return " " * indent + f"LetStmt({self.name})\n" + self.value.dump(indent + 2)


@dataclass
class IfStmt:
    """
    If 语句节点。
    
    条件分支语句，支持可选的 else 分支。
    
    示例:
      if (latency > 1000000) {
          @slow[comm] = count();
      } else {
          @fast[comm] = count();
      }
    
    属性:
        cond:         条件表达式
        then_actions: 条件为真时执行的动作列表
        else_actions: 条件为假时执行的动作列表（None 表示没有 else 分支）
    """
    cond: Expr                        # 条件
    then_actions: List = field(default_factory=list)    # then 分支的动作列表
    else_actions: Optional[List] = None                  # else 分支的动作列表

    def dump(self, indent: int = 0) -> str:
        prefix = " " * indent
        lines = [f"{prefix}IfStmt"]
        lines.append(f"{prefix}  cond:")
        lines.append(self.cond.dump(indent + 4))
        lines.append(f"{prefix}  then:")
        for a in self.then_actions:
            lines.append(a.dump(indent + 4))
        if self.else_actions:
            lines.append(f"{prefix}  else:")
            for a in self.else_actions:
                lines.append(a.dump(indent + 4))
        return "\n".join(lines)


# ===================================================================
# 第六部分：顶层语句节点（Top-level Statement Nodes）
# ===================================================================

@dataclass
class ObserveRule:
    """
    观察规则节点。
    
    observe 是 Emon DSL 的核心语句。它描述了一条完整的监控规则：
      挂载到哪里（hook）→ 过滤什么（where）→ 测量什么（measure）
      → 再过滤（when）→ 执行什么动作（actions）
    
    示例:
      observe syscall("read", "write")
      where pid > 0
      measure latency
      when latency > 1ms
      {
          @count[comm, pid] = count();
          @avg_lat[comm, pid] = avg(latency);
          emit { time = nsecs; pid = pid; };
      }
    """
    hook: Hook                         # 观测挂载点
    wheres: List[WhereClause] = field(default_factory=list)     # where 子句列表
    measures: List[MeasureClause] = field(default_factory=list) # measure 子句列表
    whens: List[WhenClause] = field(default_factory=list)       # when 子句列表
    actions: List = field(default_factory=list)                 # 代码块中的动作列表

    def dump(self, indent: int = 0) -> str:
        prefix = " " * indent
        lines = [f"{prefix}ObserveRule"]
        lines.append(self.hook.dump(indent + 2))
        for w in self.wheres:
            lines.append(w.dump(indent + 2))
        for m in self.measures:
            lines.append(m.dump(indent + 2))
        for w in self.whens:
            lines.append(w.dump(indent + 2))
        lines.append(f"{prefix}  block:")
        for a in self.actions:
            lines.append(a.dump(indent + 4))
        return "\n".join(lines)


@dataclass
class EveryStmt:
    """
    周期性任务节点。
    
    every 声明一个在用户态周期性执行的任务。
    与 observe 不同，every 不是由内核事件触发的，而是按时间间隔执行。
    
    示例:
      every 1s {
          print(@count);
          print(@avg_latency);
      }
    
    属性:
        interval: 时间间隔（可以是时间字面量如 1s，或引用 option 变量）
        actions:  周期性执行的动作列表
    """
    interval: Expr               # 执行间隔
    actions: List = field(default_factory=list)  # 动作列表

    def dump(self, indent: int = 0) -> str:
        prefix = " " * indent
        lines = [f"{prefix}EveryStmt"]
        lines.append(f"{prefix}  interval:")
        lines.append(self.interval.dump(indent + 4))
        for a in self.actions:
            lines.append(a.dump(indent + 2))
        return "\n".join(lines)


@dataclass
class BeginStmt:
    """
    启动初始化块节点。
    
    begin 块中的代码在工具启动时执行一次。
    通常用于打印启动信息和初始化操作。
    
    示例:
      begin {
          print("Monitoring started.");
      }
    """
    actions: List = field(default_factory=list)  # 初始化动作列表

    def dump(self, indent: int = 0) -> str:
        prefix = " " * indent
        lines = [f"{prefix}BeginStmt"]
        for a in self.actions:
            lines.append(a.dump(indent + 2))
        return "\n".join(lines)


@dataclass
class EndStmt:
    """
    退出清理块节点。
    
    end 块中的代码在工具退出时执行一次（收到 SIGINT/SIGTERM 信号时）。
    通常用于打印最终统计报告和清理操作。
    
    示例:
      end {
          print("Final report:");
          print(@count);
      }
    """
    actions: List = field(default_factory=list)  # 清理动作列表

    def dump(self, indent: int = 0) -> str:
        prefix = " " * indent
        lines = [f"{prefix}EndStmt"]
        for a in self.actions:
            lines.append(a.dump(indent + 2))
        return "\n".join(lines)


# ===================================================================
# 第七部分：程序根节点（Program Node）
# ===================================================================

@dataclass
class ToolDecl:
    """
    工具声明节点。
    
    每个 Emon 程序以 tool 声明开始，定义工具名称和配置选项。
    
    示例:
      tool syscall_counter {
          option top_n = 20;
          option interval = 1s;
      }
    
    属性:
        name:    工具名称
        options: 选项列表，每个选项是 (名称, 值表达式) 的元组
    """
    name: str                                 # 工具名
    options: List[Tuple[str, Expr]] = field(default_factory=list)  # 选项列表

    def dump(self, indent: int = 0) -> str:
        prefix = " " * indent
        lines = [f"{prefix}ToolDecl(name={self.name!r})"]
        for opt_name, opt_val in self.options:
            lines.append(f"{prefix}  option {opt_name} =")
            lines.append(opt_val.dump(indent + 4))
        return "\n".join(lines)


@dataclass
class Program:
    """
    程序根节点 —— 整个 AST 的根。
    
    Program 是整个 Emon DSL 程序的顶层结构。
    它包含一个工具声明和若干顶层语句。
    
    属性:
        tool:  工具声明
        stmts: 顶层语句列表（ObserveRule / EveryStmt / BeginStmt / EndStmt）
    """
    tool: ToolDecl                   # 工具声明
    stmts: List = field(default_factory=list)  # 顶层语句列表

    def dump(self, indent: int = 0) -> str:
        """输出整个 AST 的缩进文本表示（用于调试）。"""
        prefix = " " * indent
        lines = [f"{prefix}Program", self.tool.dump(indent + 2)]
        for s in self.stmts:
            lines.append(s.dump(indent + 2))
        return "\n".join(lines)
