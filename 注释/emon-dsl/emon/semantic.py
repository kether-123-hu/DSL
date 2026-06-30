# ===================================================================
# semantic.py —— Emon DSL 语义分析器（编译器第三阶段）
# ===================================================================
#
# 【本文件的作用】
# 语义分析器（Semantic Analyzer）在语法分析（Parser）完成后运行，
# 检查 AST 的"逻辑正确性"。如果说 Parser 检查的是"语法对不对"，
# 那么 Semantic Analyzer 检查的是"意思对不对"。
#
# 【类比】
# 语法分析: "Colorless green ideas sleep furiously." ✓ 语法正确
# 语义分析: 这句话逻辑不通 → ✗ 语义错误（无色的东西不能是绿色的）
#
# 【本分析器检查的内容（9类检查）】
#   1. 变量作用域：使用的变量是否已声明？
#   2. 上下文变量可用性：某些变量只在特定 hook 类型下可用
#      （如 syscall 变量只在 observe syscall 中可用）
#   3. 度量依赖：使用了 latency 但没有 measure latency？
#   4. 阶段限制：retval 不能在 where 子句中使用
#      （因为 where 在函数入口处执行，而返回值只有出口处才知道）
#   5. 聚合函数参数：count() 不应有参数，avg() 必须有参数
#   6. 重复标识符检测：不能声明两个同名的 @agg 或 let 变量
#   7. 生命周期约束：every 的间隔必须是时间字面量或已知的 option
#   8. Option 引用：引用的 option 是否存在？
#   9. 未知标识符：使用了完全未定义的变量名
# ===================================================================

from dataclasses import dataclass, field
from typing import List, Set, Optional

# 导入 AST 节点类型
from emon.ast_nodes import (
    Program, ToolDecl, ObserveRule, EveryStmt, BeginStmt, EndStmt,
    HookKind, Metric, AggFn,
    AggregationStmt, EmitStmt, EmitField,
    PrintStmt, LetStmt, IfStmt,
    Expr, LitInt, LitStr, LitBool, LitTime, LitSize,
    VarRef, AggRef, BinOpExpr, UnaryOpExpr, FuncCall,
)


# ===================================================================
# 第一部分：上下文变量可用性表
# ===================================================================
# 这些表定义了在不同上下文中哪些变量是可用的。

# 全局上下文变量：无论什么 hook 类型，这些变量始终可用。
# 它们由 eBPF 基础设施提供，不需要额外的 measure 声明。
_GLOBAL_CTX: Set[str] = {
    "pid",      # 当前进程 ID
    "tid",      # 当前线程 ID
    "uid",      # 当前用户 ID
    "gid",      # 当前组 ID
    "cpu",      # 当前 CPU 编号
    "comm",     # 当前进程名（command name）
    "nsecs",    # 当前时间戳（纳秒）
}

# 按 Hook 类型分类的上下文变量：只在特定观测目标下可用。
_HOOK_CTX = {
    HookKind.SYSCALL:    {"syscall"},  # syscall 变量仅在系统调用观测中可用
    HookKind.KERNEL:     {"func", "arg0", "arg1", "arg2", "arg3", "arg4", "arg5"},
    HookKind.TRACEPOINT: set(),        # 跟踪点没有特定的额外上下文变量
    HookKind.UPROBE:     {"func", "arg0", "arg1", "arg2", "arg3", "arg4", "arg5"},
    HookKind.SCHED:      set(),
    HookKind.FILE:       {"func", "arg0", "arg1", "arg2", "arg3", "arg4", "arg5"},
    HookKind.NET:        {"func", "arg0", "arg1", "arg2", "arg3", "arg4", "arg5"},
}

# 度量依赖的上下文变量：这些变量只有在声明了对应的 measure 后才可用。
# 例如：要使用 latency 变量，必须先写 measure latency。
_MEASURE_CTX = {
    Metric.LATENCY: {"latency"},  # 需要 measure latency 才能用 latency
    Metric.RETVAL:  {"retval"},   # 需要 measure retval 才能用 retval
    Metric.SIZE:    {"size"},     # 需要 measure size 才能用 size
    Metric.STACK:   {"stack"},    # 需要 measure stack 才能用 stack
    Metric.COUNT:   set(),        # count 不需要额外的上下文变量
}

# "出口专用"上下文变量：这些变量在函数返回时才产生，不能在 where 子句中使用。
# where 子句在函数入口处执行，此时返回值还不存在。
_EXIT_ONLY_CTX: Set[str] = {"retval"}

# 需要参数的聚合函数：这些聚合函数必须提供一个参数。
# count() 是唯一不需要参数的聚合函数。
_AGG_REQUIRES_ARG = {AggFn.SUM, AggFn.AVG, AggFn.MIN, AggFn.MAX,
                     AggFn.HIST, AggFn.LHIST}


# ===================================================================
# 第二部分：语义错误类型
# ===================================================================

@dataclass
class SemanticError:
    """
    语义分析错误。
    
    属性:
        message:  人类可读的错误描述
        category: 错误类别（用于分类显示）：
                  - "duplicate":  重复定义
                  - "aggregation": 聚合函数参数错误
                  - "lifecycle":  生命周期约束违反
                  - "phase":      阶段限制违反（如 retval 用在 where 中）
                  - "measure":    缺少 measure 声明
                  - "scope":      作用域错误
                  - "unknown":    未知标识符
                  - "general":    其他一般错误
    """
    message: str
    category: str = "general"

    def __str__(self) -> str:
        """格式化错误信息：[类别] 描述"""
        return f"[{self.category}] {self.message}"


# ===================================================================
# 第三部分：语义分析器
# ===================================================================

class SemanticAnalyzer:
    """
    Emon DSL 语义分析器。
    
    使用方法:
        analyzer = SemanticAnalyzer()
        errors = analyzer.check(program_ast)
        if errors:
            for e in errors:
                print(e)
    
    工作原理:
        遍历 AST，在每个节点上执行相应的语义检查规则。
        内部维护状态（如当前 hook 类型、已声明的 measure、let 变量等），
        用于跨节点的上下文检查。
    """

    def __init__(self):
        self.errors: List[SemanticError] = []  # 收集到的所有错误
        # 以下是分析过程中的状态变量
        self._options: Set[str] = set()              # 已声明的 option 名称集合
        self._hook_kind: Optional[HookKind] = None   # 当前所在的 hook 类型
        self._declared_measures: Set[Metric] = set()  # 当前 observe 块中声明的度量
        self._let_vars: Set[str] = set()             # 当前 observe 块中 let 的变量名
        self._agg_targets: Set[str] = set()          # 当前 observe 块中的 @agg 名称

    # ================================================================
    # 公共入口
    # ================================================================

    def check(self, program: Program) -> List[SemanticError]:
        """
        对完整的 Program AST 执行所有语义检查。

        参数:
            program: 语法分析阶段产生的 Program AST

        返回:
            SemanticError 列表。空列表表示没有错误。
        """
        self.errors = []
        
        # 收集所有 option 名称（用于后续的 option 引用检查）
        self._options = {name for name, _ in program.tool.options}

        # 遍历每个顶层语句，根据类型调用对应的检查函数
        for stmt in program.stmts:
            if isinstance(stmt, ObserveRule):
                self._check_observe_rule(stmt)    # 检查观察规则
            elif isinstance(stmt, EveryStmt):
                self._check_every_stmt(stmt)       # 检查周期性任务
            elif isinstance(stmt, BeginStmt):
                self._check_block_actions(stmt.actions)  # 检查 begin 块
            elif isinstance(stmt, EndStmt):
                self._check_block_actions(stmt.actions)  # 检查 end 块

        return self.errors

    # ================================================================
    # Observe 规则检查
    # ================================================================

    def _check_observe_rule(self, rule: ObserveRule):
        """
        检查 observe 规则的语义正确性。
        
        设置当前分析上下文（hook 类型、已声明度量），
        然后依次检查 where/when 子句和代码块中的动作。
        """
        # 设置上下文状态
        self._hook_kind = rule.hook.kind           # 记录当前 hook 类型
        self._declared_measures = set()             # 重置已声明度量
        for mc in rule.measures:
            self._declared_measures.update(mc.metrics)  # 收集所有声明的度量
        self._let_vars = set()                     # 重置 let 变量集合
        self._agg_targets = set()                  # 重置聚合目标集合

        # 检查 where 子句（前置过滤条件）
        # phase="where" 表示这些表达式在函数入口处求值
        for wc in rule.wheres:
            self._check_expr(wc.cond, phase="where")

        # 检查 when 子句（后置过滤条件）
        # phase="when" 表示这些表达式在函数返回处求值
        for wc in rule.whens:
            self._check_expr(wc.cond, phase="when")

        # 检查代码块中的动作语句
        self._check_block_actions(rule.actions)

        # 离开 observe 块时重置上下文（避免影响下一个 observe 块）
        self._hook_kind = None
        self._declared_measures = set()
        self._let_vars = set()
        self._agg_targets = set()

    # ================================================================
    # 动作块检查
    # ================================================================

    def _check_block_actions(self, actions: list):
        """
        检查代码块中的所有动作语句。
        
        对每种动作类型调用对应的检查函数。
        """
        for action in actions:
            if isinstance(action, AggregationStmt):
                self._check_aggregation(action)
            elif isinstance(action, EmitStmt):
                self._check_emit(action)
            elif isinstance(action, PrintStmt):
                self._check_expr(action.expr, phase="action")
            elif isinstance(action, LetStmt):
                self._check_let(action)
            elif isinstance(action, IfStmt):
                self._check_if(action)

    # ================================================================
    # 各类语句的检查
    # ================================================================

    def _check_aggregation(self, agg: AggregationStmt):
        """
        检查聚合语句。
        
        规则:
          1. 同一 observe 块中不能重复声明同名的 @agg
          2. count() 不能有参数
          3. sum/avg/min/max/hist/lhist 必须有参数
        """
        # 规则1: 重复 @agg 检测
        if agg.target in self._agg_targets:
            self.errors.append(SemanticError(
                f"duplicate aggregation target '@{agg.target}'",
                category="duplicate",
            ))
        self._agg_targets.add(agg.target)

        # 规则2: count() 不接受参数
        if agg.fn == AggFn.COUNT:
            if agg.arg is not None:
                self.errors.append(SemanticError(
                    f"count() does not accept an argument, got one",
                    category="aggregation",
                ))
        # 规则3: 其他聚合函数必须提供参数
        elif agg.fn in _AGG_REQUIRES_ARG:
            if agg.arg is None:
                self.errors.append(SemanticError(
                    f"{agg.fn.name.lower()}() requires an argument, none given",
                    category="aggregation",
                ))

        # 检查 key 列表中的表达式
        for key in agg.keys:
            self._check_expr(key, phase="action")

        # 检查可选的聚合参数
        if agg.arg is not None:
            self._check_expr(agg.arg, phase="action")

    def _check_emit(self, emit: EmitStmt):
        """检查 emit 语句中的每个字段值表达式"""
        for field in emit.fields:
            self._check_expr(field.value, phase="action")

    def _check_let(self, let: LetStmt):
        """
        检查 let 语句。
        
        规则:
          1. 同一 observe 块中不能有同名的 let 变量
          2. 初始值表达式必须有效
        """
        if let.name in self._let_vars:
            self.errors.append(SemanticError(
                f"duplicate let variable '{let.name}'",
                category="duplicate",
            ))
        self._let_vars.add(let.name)
        self._check_expr(let.value, phase="action")

    def _check_if(self, ifs: IfStmt):
        """递归检查 if 语句的条件和两个分支"""
        self._check_expr(ifs.cond, phase="action")
        self._check_block_actions(ifs.then_actions)
        if ifs.else_actions:
            self._check_block_actions(ifs.else_actions)

    def _check_every_stmt(self, every: EveryStmt):
        """
        检查 every 周期性任务语句。
        
        规则:
          1. 时间间隔应该是时间字面量（如 1s）或合法的 option 引用
          2. 引用 option 时，option 必须存在
        """
        self._check_expr(every.interval, phase="action")
        
        # 检查间隔表达式类型
        if isinstance(every.interval, VarRef):
            # 是 option 引用 → 检查 option 是否存在
            if every.interval.name not in self._options:
                self.errors.append(SemanticError(
                    f"'every' interval references unknown option '{every.interval.name}'",
                    category="lifecycle",
                ))
        elif not isinstance(every.interval, LitTime):
            # 既不是 option 引用也不是时间字面量 → 错误
            self.errors.append(SemanticError(
                "'every' interval should be a time literal (e.g., 1s) or an option reference",
                category="lifecycle",
            ))
        
        self._check_block_actions(every.actions)

    # ================================================================
    # 表达式递归检查（核心）
    # ================================================================

    def _check_expr(self, expr: Expr, phase: str):
        """
        递归检查表达式子树的语义正确性。

        这是语义分析器最核心的方法。它根据表达式的类型，
        递归地检查每个子表达式。

        参数:
            expr:  要检查的表达式节点
            phase: 当前阶段："where"（前置过滤）、"when"（后置过滤）或 "action"（动作）
        """
        if isinstance(expr, VarRef):
            # 变量引用 → 检查该变量是否可用（核心检查逻辑）
            self._check_var_ref(expr, phase)
        elif isinstance(expr, BinOpExpr):
            # 二元运算 → 递归检查左右操作数
            self._check_expr(expr.lhs, phase)
            self._check_expr(expr.rhs, phase)
        elif isinstance(expr, UnaryOpExpr):
            # 一元运算 → 递归检查操作数
            self._check_expr(expr.operand, phase)
        elif isinstance(expr, FuncCall):
            # 函数调用 → 递归检查所有参数
            for arg in expr.args:
                self._check_expr(arg, phase)
        elif isinstance(expr, AggRef):
            # 聚合引用（@xxx）→ 在 AST 级别始终有效，不检查
            pass
        elif isinstance(expr, (LitInt, LitStr, LitBool, LitTime, LitSize)):
            # 字面量 → 始终有效，不检查
            pass

    # ================================================================
    # 变量引用检查（9 步检查流程）
    # ================================================================

    def _check_var_ref(self, var: VarRef, phase: str):
        """
        检查变量引用的有效性。
        
        按以下优先级逐级检查，找到匹配的即通过：
          1. 是否是 let 绑定的局部变量？
          2. 是否是 option 引用？
          3. 是否是全局上下文变量（pid, comm 等）？
          4. 是否是当前 hook 类型特定的上下文变量？
          5. 是否是度量依赖的上下文变量（需要先 measure）？
          6. 是否是已存在的度量变量但未声明 measure？
          7. 是否是 hook 特定变量但用错了 hook 类型？
          8. 是否是阶段限制变量（retval 用在 where 中）？
          9. 完全未知的标识符 → 报错
        """
        name = var.name

        # 步骤1: 检查 let 变量
        if name in self._let_vars:
            return  # 合法，通过

        # 步骤2: 检查 option 引用
        if name in self._options:
            return  # 合法，通过

        # 步骤3: 检查全局上下文变量
        if name in _GLOBAL_CTX:
            return  # 如 pid, comm, cpu 等，始终可用

        # 步骤4: 检查 hook 特定的上下文变量
        if self._hook_kind is not None:
            hook_ctx = _HOOK_CTX.get(self._hook_kind, set())
            if name in hook_ctx:
                return  # 当前 hook 类型下可用

        # 步骤5: 检查度量依赖的上下文变量
        for metric in self._declared_measures:
            measure_ctx = _MEASURE_CTX.get(metric, set())
            if name in measure_ctx:
                # 阶段限制检查：retval 不能在 where 子句中使用
                if name in _EXIT_ONLY_CTX and phase == "where":
                    self.errors.append(SemanticError(
                        f"'{name}' is not available in 'where' clause "
                        f"(only available at return probe, use in 'when' or action block)",
                        category="phase",
                    ))
                return  # 变量可用

        # 步骤6: 变量存在但缺少对应的 measure 声明
        all_measure_ctx: Set[str] = set()
        for ctx_set in _MEASURE_CTX.values():
            all_measure_ctx.update(ctx_set)
        if name in all_measure_ctx:
            self.errors.append(SemanticError(
                f"'{name}' requires a corresponding 'measure' declaration "
                f"(e.g., 'measure latency' for 'latency')",
                category="measure",
            ))
            return

        # 步骤7: hook 类型的特定变量，但用于错误的 hook 类型
        all_hook_ctx: Set[str] = set()
        for ctx_set in _HOOK_CTX.values():
            all_hook_ctx.update(ctx_set)
        if name in all_hook_ctx:
            if self._hook_kind is None:
                # 在 observe 块外部使用了 hook 特定变量
                self.errors.append(SemanticError(
                    f"'{name}' is only available inside an 'observe' block",
                    category="scope",
                ))
            else:
                # 用错了 hook 类型（如在 observe syscall 中使用了 func 变量）
                valid_hooks = [hk.name for hk, ctx in _HOOK_CTX.items()
                              if name in ctx]
                self.errors.append(SemanticError(
                    f"'{name}' is only available in observe {', '.join(valid_hooks)} contexts, "
                    f"not in observe {self._hook_kind.name}",
                    category="scope",
                ))
            return

        # 步骤8: 阶段限制（即使没有在 measures 中声明，retval 也不能在 where 中用）
        if name in _EXIT_ONLY_CTX and phase == "where":
            self.errors.append(SemanticError(
                f"'{name}' is not available in 'where' clause",
                category="phase",
            ))
            return

        # 步骤9: 完全未知的标识符
        self.errors.append(SemanticError(
            f"unknown identifier '{name}' — not a context variable, option, or let binding",
            category="unknown",
        ))


# ===================================================================
# 第四部分：便捷函数
# ===================================================================

def analyze(program: Program) -> List[SemanticError]:
    """
    对 Program AST 执行语义分析的便捷函数。
    
    用法:
        from emon.parser import parse
        from emon.semantic import analyze
        
        ast = parse(source_code)
        errors = analyze(ast)
        if errors:
            for e in errors:
                print(e)
        else:
            print("No semantic errors!")
    
    参数:
        program: 由 parser.parse() 产生的 Program AST
    
    返回:
        SemanticError 列表。空列表 = 没有错误。
    """
    return SemanticAnalyzer().check(program)
