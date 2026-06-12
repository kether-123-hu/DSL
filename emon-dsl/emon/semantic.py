"""
Emon DSL Semantic Analyzer

Validates a typed AST (from parser.py) against language rules:
  - Variable scope and reachability
  - Hook-specific context variable availability
  - Measure-dependent variable access
  - Phase restrictions (retval in where clauses)
  - Aggregation function argument counts
  - Duplicate identifier detection (aggregations, let bindings)
  - Lifecycle statement constraints

Design aligns with include/emon/semantic.h and the checks listed
in the project plan sections 4.1.2 / 5.4.
"""

from dataclasses import dataclass, field
from typing import List, Set, Optional

from emon.ast_nodes import (
    Program, ToolDecl, ObserveRule, EveryStmt, BeginStmt, EndStmt,
    HookKind, Metric, AggFn,
    AggregationStmt, EmitStmt, EmitField,
    PrintStmt, LetStmt, IfStmt,
    Expr, LitInt, LitStr, LitBool, LitTime, LitSize,
    VarRef, AggRef, BinOpExpr, UnaryOpExpr, FuncCall,
)


# =============================================================================
# Context Variable Availability Tables
# =============================================================================

# Always available regardless of hook type.
_GLOBAL_CTX: Set[str] = {
    "pid", "tid", "uid", "gid", "cpu", "comm", "nsecs",
}

# Hook-type-specific context variables.
_HOOK_CTX = {
    HookKind.SYSCALL:    {"syscall"},
    HookKind.KERNEL:     {"func", "arg0", "arg1", "arg2", "arg3", "arg4", "arg5"},
    HookKind.TRACEPOINT: set(),
    HookKind.UPROBE:     {"func", "arg0", "arg1", "arg2", "arg3", "arg4", "arg5"},
    HookKind.SCHED:      set(),
    HookKind.FILE:       {"func", "arg0", "arg1", "arg2", "arg3", "arg4", "arg5"},
    HookKind.NET:        {"func", "arg0", "arg1", "arg2", "arg3", "arg4", "arg5"},
}

# Measure-dependent context variables.
_MEASURE_CTX = {
    Metric.LATENCY: {"latency"},
    Metric.RETVAL:  {"retval"},
    Metric.SIZE:    {"size"},
    Metric.STACK:   {"stack"},
    Metric.COUNT:   set(),
}

# Context variables that are only valid after the probe's return point.
# They must not appear in "where" clauses (pre-measurement filters).
_EXIT_ONLY_CTX: Set[str] = {"retval"}

# Aggregation functions that require one argument.
_AGG_REQUIRES_ARG = {AggFn.SUM, AggFn.AVG, AggFn.MIN, AggFn.MAX,
                     AggFn.HIST, AggFn.LHIST}


# =============================================================================
# Error Types
# =============================================================================

@dataclass
class SemanticError:
    """A semantic analysis error with message and severity."""
    message: str
    category: str = "general"

    def __str__(self) -> str:
        return f"[{self.category}] {self.message}"


# =============================================================================
# Semantic Analyzer
# =============================================================================

class SemanticAnalyzer:
    """Validates a typed Emon DSL AST."""

    def __init__(self):
        self.errors: List[SemanticError] = []
        self._options: Set[str] = set()
        self._hook_kind: Optional[HookKind] = None
        self._declared_measures: Set[Metric] = set()
        self._let_vars: Set[str] = set()
        self._agg_targets: Set[str] = set()

    # ------------------------------------------------------------------
    # Public entry point
    # ------------------------------------------------------------------

    def check(self, program: Program) -> List[SemanticError]:
        """Run all semantic checks on a Program AST.

        Returns:
            List of SemanticError objects (empty means valid).
        """
        self.errors = []
        self._options = {name for name, _ in program.tool.options}

        for stmt in program.stmts:
            if isinstance(stmt, ObserveRule):
                self._check_observe_rule(stmt)
            elif isinstance(stmt, EveryStmt):
                self._check_every_stmt(stmt)
            elif isinstance(stmt, BeginStmt):
                self._check_block_actions(stmt.actions)
            elif isinstance(stmt, EndStmt):
                self._check_block_actions(stmt.actions)

        return self.errors

    # ------------------------------------------------------------------
    # Observe rule checks
    # ------------------------------------------------------------------

    def _check_observe_rule(self, rule: ObserveRule):
        self._hook_kind = rule.hook.kind
        self._declared_measures = set()
        for mc in rule.measures:
            self._declared_measures.update(mc.metrics)
        self._let_vars = set()
        self._agg_targets = set()

        # Check where clauses (pre-measurement filter)
        for wc in rule.wheres:
            self._check_expr(wc.cond, phase="where")

        # Check when clauses (post-measurement filter)
        for wc in rule.whens:
            self._check_expr(wc.cond, phase="when")

        # Check action statements in block
        self._check_block_actions(rule.actions)

        self._hook_kind = None
        self._declared_measures = set()
        self._let_vars = set()
        self._agg_targets = set()

    # ------------------------------------------------------------------
    # Action block checks
    # ------------------------------------------------------------------

    def _check_block_actions(self, actions: list):
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

    # ------------------------------------------------------------------
    # Statement-level checks
    # ------------------------------------------------------------------

    def _check_aggregation(self, agg: AggregationStmt):
        # Duplicate @name check
        if agg.target in self._agg_targets:
            self.errors.append(SemanticError(
                f"duplicate aggregation target '@{agg.target}'",
                category="duplicate",
            ))
        self._agg_targets.add(agg.target)

        # Check aggregation function argument count
        if agg.fn == AggFn.COUNT:
            if agg.arg is not None:
                self.errors.append(SemanticError(
                    f"count() does not accept an argument, got one",
                    category="aggregation",
                ))
        elif agg.fn in _AGG_REQUIRES_ARG:
            if agg.arg is None:
                self.errors.append(SemanticError(
                    f"{agg.fn.name.lower()}() requires an argument, none given",
                    category="aggregation",
                ))

        # Check key list expressions
        for key in agg.keys:
            self._check_expr(key, phase="action")

        # Check optional aggregation argument
        if agg.arg is not None:
            self._check_expr(agg.arg, phase="action")

    def _check_emit(self, emit: EmitStmt):
        for field in emit.fields:
            self._check_expr(field.value, phase="action")

    def _check_let(self, let: LetStmt):
        if let.name in self._let_vars:
            self.errors.append(SemanticError(
                f"duplicate let variable '{let.name}'",
                category="duplicate",
            ))
        self._let_vars.add(let.name)
        self._check_expr(let.value, phase="action")

    def _check_if(self, ifs: IfStmt):
        self._check_expr(ifs.cond, phase="action")
        self._check_block_actions(ifs.then_actions)
        if ifs.else_actions:
            self._check_block_actions(ifs.else_actions)

    def _check_every_stmt(self, every: EveryStmt):
        # Every interval should be a time literal or option reference.
        self._check_expr(every.interval, phase="action")
        if isinstance(every.interval, VarRef):
            if every.interval.name not in self._options:
                self.errors.append(SemanticError(
                    f"'every' interval references unknown option '{every.interval.name}'",
                    category="lifecycle",
                ))
        elif not isinstance(every.interval, LitTime):
            self.errors.append(SemanticError(
                "'every' interval should be a time literal (e.g., 1s) or an option reference",
                category="lifecycle",
            ))
        self._check_block_actions(every.actions)

    # ------------------------------------------------------------------
    # Expression-level checks
    # ------------------------------------------------------------------

    def _check_expr(self, expr: Expr, phase: str):
        """Recursively validate an expression subtree.

        Args:
            expr: The expression node to check.
            phase: One of 'where', 'when', or 'action'.
        """
        if isinstance(expr, VarRef):
            self._check_var_ref(expr, phase)
        elif isinstance(expr, BinOpExpr):
            self._check_expr(expr.lhs, phase)
            self._check_expr(expr.rhs, phase)
        elif isinstance(expr, UnaryOpExpr):
            self._check_expr(expr.operand, phase)
        elif isinstance(expr, FuncCall):
            for arg in expr.args:
                self._check_expr(arg, phase)
        elif isinstance(expr, AggRef):
            pass  # @agg references are always valid at AST level
        elif isinstance(expr, (LitInt, LitStr, LitBool, LitTime, LitSize)):
            pass  # literals always valid

    def _check_var_ref(self, var: VarRef, phase: str):
        name = var.name

        # 1. Check if it's a let-bound variable (in scope)
        if name in self._let_vars:
            return

        # 2. Check if it's an option reference
        if name in self._options:
            return

        # 3. Check if it's a global context variable
        if name in _GLOBAL_CTX:
            return

        # 4. Check if it's a hook-specific context variable
        if self._hook_kind is not None:
            hook_ctx = _HOOK_CTX.get(self._hook_kind, set())
            if name in hook_ctx:
                return

        # 5. Check if it's a measure-dependent context variable
        for metric in self._declared_measures:
            measure_ctx = _MEASURE_CTX.get(metric, set())
            if name in measure_ctx:
                # Phase restriction: retval cannot appear in where clause.
                if name in _EXIT_ONLY_CTX and phase == "where":
                    self.errors.append(SemanticError(
                        f"'{name}' is not available in 'where' clause "
                        f"(only available at return probe, use in 'when' or action block)",
                        category="phase",
                    ))
                return

        # 6. Check if the variable exists but hasn't been declared via measure
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

        # 7. Check if it's a hook-specific variable used outside its hook
        all_hook_ctx: Set[str] = set()
        for ctx_set in _HOOK_CTX.values():
            all_hook_ctx.update(ctx_set)
        if name in all_hook_ctx:
            if self._hook_kind is None:
                self.errors.append(SemanticError(
                    f"'{name}' is only available inside an 'observe' block",
                    category="scope",
                ))
            else:
                # Find which hook it belongs to
                valid_hooks = [hk.name for hk, ctx in _HOOK_CTX.items()
                              if name in ctx]
                self.errors.append(SemanticError(
                    f"'{name}' is only available in observe {', '.join(valid_hooks)} contexts, "
                    f"not in observe {self._hook_kind.name}",
                    category="scope",
                ))
            return

        # 8. Check phase restriction on exit-only vars (even if not in measures)
        if name in _EXIT_ONLY_CTX and phase == "where":
            self.errors.append(SemanticError(
                f"'{name}' is not available in 'where' clause",
                category="phase",
            ))
            return

        # 9. Unknown identifier
        self.errors.append(SemanticError(
            f"unknown identifier '{name}' — not a context variable, option, or let binding",
            category="unknown",
        ))


# =============================================================================
# Convenience function
# =============================================================================

def analyze(program: Program) -> List[SemanticError]:
    """Run semantic analysis on a Program AST.

    Args:
        program: A typed Program AST from parser.parse().

    Returns:
        List of SemanticError objects.  Empty list means no errors found.
    """
    return SemanticAnalyzer().check(program)
