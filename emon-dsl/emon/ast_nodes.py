"""
Emon DSL Abstract Syntax Tree Nodes

Type-safe AST node definitions mapped from include/emon/ast_nodes.h.
All node types support dump() for debugging and round-trip verification.
"""

from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Optional, Union, List, Tuple


# =============================================================================
# Enumerations
# =============================================================================

class HookKind(Enum):
    """Observation target type (7 kinds)."""
    SYSCALL = auto()
    KERNEL = auto()
    TRACEPOINT = auto()
    UPROBE = auto()
    SCHED = auto()
    FILE = auto()
    NET = auto()


class Metric(Enum):
    """Measure item type (5 kinds)."""
    LATENCY = auto()
    COUNT = auto()
    SIZE = auto()
    RETVAL = auto()
    STACK = auto()


class AggFn(Enum):
    """Aggregation function (7 kinds)."""
    COUNT = auto()
    SUM = auto()
    AVG = auto()
    MIN = auto()
    MAX = auto()
    HIST = auto()
    LHIST = auto()


class BinOp(Enum):
    """Binary operators."""
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
    """Unary operators."""
    NOT = auto()
    NEG = auto()


# =============================================================================
# Expression Nodes
# =============================================================================

class Expr:
    """Base class for all expression nodes."""
    def dump(self, indent: int = 0) -> str:
        raise NotImplementedError


@dataclass
class LitInt(Expr):
    value: int

    def dump(self, indent: int = 0) -> str:
        return " " * indent + f"LitInt({self.value})"


@dataclass
class LitStr(Expr):
    value: str

    def dump(self, indent: int = 0) -> str:
        return " " * indent + f"LitStr({self.value!r})"


@dataclass
class LitBool(Expr):
    value: bool

    def dump(self, indent: int = 0) -> str:
        return " " * indent + f"LitBool({str(self.value).lower()})"


@dataclass
class LitTime(Expr):
    value: str

    def dump(self, indent: int = 0) -> str:
        return " " * indent + f"LitTime({self.value})"


@dataclass
class LitSize(Expr):
    value: str

    def dump(self, indent: int = 0) -> str:
        return " " * indent + f"LitSize({self.value})"


@dataclass
class VarRef(Expr):
    name: str

    def dump(self, indent: int = 0) -> str:
        return " " * indent + f"VarRef({self.name})"


@dataclass
class AggRef(Expr):
    name: str

    def dump(self, indent: int = 0) -> str:
        return " " * indent + f"AggRef(@{self.name})"


@dataclass
class BinOpExpr(Expr):
    op: BinOp
    lhs: Expr
    rhs: Expr

    def dump(self, indent: int = 0) -> str:
        prefix = " " * indent
        return (f"{prefix}BinOp({self.op.name})\n"
                f"{self.lhs.dump(indent + 2)}\n"
                f"{self.rhs.dump(indent + 2)}")


@dataclass
class UnaryOpExpr(Expr):
    op: UnaryOp
    operand: Expr

    def dump(self, indent: int = 0) -> str:
        prefix = " " * indent
        return (f"{prefix}UnaryOp({self.op.name})\n"
                f"{self.operand.dump(indent + 2)}")


@dataclass
class FuncCall(Expr):
    name: str
    args: List[Expr] = field(default_factory=list)

    def dump(self, indent: int = 0) -> str:
        prefix = " " * indent
        lines = [f"{prefix}FuncCall({self.name})"]
        for arg in self.args:
            lines.append(arg.dump(indent + 2))
        return "\n".join(lines)


# =============================================================================
# Clause Nodes
# =============================================================================

@dataclass
class WhereClause:
    cond: Expr

    def dump(self, indent: int = 0) -> str:
        return " " * indent + "WhereClause\n" + self.cond.dump(indent + 2)


@dataclass
class WhenClause:
    cond: Expr

    def dump(self, indent: int = 0) -> str:
        return " " * indent + "WhenClause\n" + self.cond.dump(indent + 2)


@dataclass
class MeasureClause:
    metrics: List[Metric]

    def dump(self, indent: int = 0) -> str:
        names = ", ".join(m.name for m in self.metrics)
        return " " * indent + f"MeasureClause({names})"


# =============================================================================
# Hook Description
# =============================================================================

@dataclass
class Hook:
    kind: HookKind
    targets: List[str]
    binary_path: Optional[str] = None

    def dump(self, indent: int = 0) -> str:
        prefix = " " * indent
        lines = [f"{prefix}Hook(kind={self.kind.name})"]
        if self.binary_path:
            lines.append(f"{prefix}  binary={self.binary_path!r}")
        for t in self.targets:
            lines.append(f"{prefix}  target={t!r}")
        return "\n".join(lines)


# =============================================================================
# Action Statement Nodes
# =============================================================================

@dataclass
class AggregationStmt:
    target: str
    keys: List[Expr]
    fn: AggFn
    arg: Optional[Expr] = None

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
    name: str
    value: Expr

    def dump(self, indent: int = 0) -> str:
        return " " * indent + f"EmitField({self.name})"


@dataclass
class EmitStmt:
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
    expr: Expr

    def dump(self, indent: int = 0) -> str:
        return " " * indent + "PrintStmt\n" + self.expr.dump(indent + 2)


@dataclass
class LetStmt:
    name: str
    value: Expr

    def dump(self, indent: int = 0) -> str:
        return " " * indent + f"LetStmt({self.name})\n" + self.value.dump(indent + 2)


@dataclass
class IfStmt:
    cond: Expr
    then_actions: List = field(default_factory=list)
    else_actions: Optional[List] = None

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


# =============================================================================
# Top-level Statement Nodes
# =============================================================================

@dataclass
class ObserveRule:
    hook: Hook
    wheres: List[WhereClause] = field(default_factory=list)
    measures: List[MeasureClause] = field(default_factory=list)
    whens: List[WhenClause] = field(default_factory=list)
    actions: List = field(default_factory=list)

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
    interval: Expr
    actions: List = field(default_factory=list)

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
    actions: List = field(default_factory=list)

    def dump(self, indent: int = 0) -> str:
        prefix = " " * indent
        lines = [f"{prefix}BeginStmt"]
        for a in self.actions:
            lines.append(a.dump(indent + 2))
        return "\n".join(lines)


@dataclass
class EndStmt:
    actions: List = field(default_factory=list)

    def dump(self, indent: int = 0) -> str:
        prefix = " " * indent
        lines = [f"{prefix}EndStmt"]
        for a in self.actions:
            lines.append(a.dump(indent + 2))
        return "\n".join(lines)


# =============================================================================
# Program Node
# =============================================================================

@dataclass
class ToolDecl:
    name: str
    options: List[Tuple[str, Expr]] = field(default_factory=list)

    def dump(self, indent: int = 0) -> str:
        prefix = " " * indent
        lines = [f"{prefix}ToolDecl(name={self.name!r})"]
        for opt_name, opt_val in self.options:
            lines.append(f"{prefix}  option {opt_name} =")
            lines.append(opt_val.dump(indent + 4))
        return "\n".join(lines)


@dataclass
class Program:
    tool: ToolDecl
    stmts: List = field(default_factory=list)

    def dump(self, indent: int = 0) -> str:
        prefix = " " * indent
        lines = [f"{prefix}Program", self.tool.dump(indent + 2)]
        for s in self.stmts:
            lines.append(s.dump(indent + 2))
        return "\n".join(lines)
