"""
Emon DSL Parser (Lark-based)

Parses Emon DSL source code into a typed AST defined in ast_nodes.py.
Uses the Lark parser with keep_all_tokens=True to preserve operator
information in expression trees.

Usage:
    from parser import parse
    ast = parse(source_code)
    print(ast.dump())
"""

from pathlib import Path
from typing import Optional

from lark import Lark, Token, Transformer

from emon.ast_nodes import (
    Program, ToolDecl,
    ObserveRule, EveryStmt, BeginStmt, EndStmt,
    Hook, HookKind,
    WhereClause, WhenClause, MeasureClause,
    Metric, AggFn,
    AggregationStmt, EmitStmt, EmitField,
    PrintStmt, LetStmt, IfStmt,
    Expr, LitInt, LitStr, LitBool, LitTime, LitSize,
    VarRef, AggRef, BinOpExpr, UnaryOpExpr, FuncCall,
    BinOp, UnaryOp,
)


def _load_grammar() -> Lark:
    grammar_path = Path(__file__).parent.parent / "emon-dsl" / "grammar" / "emon.lark"
    with open(grammar_path, "r", encoding="utf-8") as f:
        grammar_text = f.read()
    return Lark(
        grammar_text,
        start="program",
        parser="lalr",
        propagate_positions=True,
        maybe_placeholders=False,
        keep_all_tokens=True,
    )


_BINOP_MAP = {
    "+": BinOp.ADD, "-": BinOp.SUB,
    "*": BinOp.MUL, "/": BinOp.DIV, "%": BinOp.MOD,
    "<": BinOp.LT, ">": BinOp.GT,
    "<=": BinOp.LE, ">=": BinOp.GE,
    "==": BinOp.EQ, "!=": BinOp.NE,
    "&&": BinOp.AND, "||": BinOp.OR,
}

_UNARYOP_MAP = {"!": UnaryOp.NOT, "-": UnaryOp.NEG}

_METRIC_MAP = {
    "latency": Metric.LATENCY, "count": Metric.COUNT,
    "size": Metric.SIZE, "retval": Metric.RETVAL, "stack": Metric.STACK,
}

_AGGFN_MAP = {
    "count": AggFn.COUNT, "sum": AggFn.SUM, "avg": AggFn.AVG,
    "min": AggFn.MIN, "max": AggFn.MAX, "hist": AggFn.HIST, "lhist": AggFn.LHIST,
}

_TOKEN_TYPE_MAP = {
    "LPAR": "(", "RPAR": ")",
    "LBRACE": "{", "RBRACE": "}",
    "LSQB": "[", "RSQB": "]",
    "EQUAL": "=", "SEMICOLON": ";",
    "COMMA": ",", "COLON": ":",
    "PLUS": "+", "MINUS": "-",
    "STAR": "*", "SLASH": "/", "PERCENT": "%",
    "MORETHAN": ">", "LESSTHAN": "<",
    "LESSEQUAL": "<=", "MOREEQUAL": ">=",
    "EQEQUAL": "==", "NOTEQUAL": "!=",
    "AND": "&&", "OR": "||", "NOT": "!",
}


def _token_val(token: Token) -> str:
    if token.type in _TOKEN_TYPE_MAP:
        return _TOKEN_TYPE_MAP[token.type]
    return token.value


def _build_binary(items: list) -> Expr:
    if len(items) == 1:
        return items[0]
    result = items[0]
    i = 1
    while i < len(items):
        op_str = _token_val(items[i])
        rhs = items[i + 1]
        result = BinOpExpr(op=_BINOP_MAP[op_str], lhs=result, rhs=rhs)
        i += 2
    return result


def _filter_tokens(items: list) -> list:
    return [item for item in items if not isinstance(item, Token)]


class EmonTransformer(Transformer):

    def program(self, items):
        return Program(tool=items[0], stmts=list(items[1:]))

    def tool_decl(self, items):
        name = items[1].value
        options = [item for item in items[3:-1] if not isinstance(item, Token)]
        return ToolDecl(name=name, options=options)

    def option_decl(self, items):
        return (items[1].value, items[3])

    def const_int(self, items):
        return LitInt(int(items[0].value))

    def const_string(self, items):
        raw = items[0].value
        return LitStr(raw[1:-1] if raw.startswith('"') else raw)

    def const_bool(self, items):
        return LitBool(items[0].value == "true")

    def const_time(self, items):
        return LitTime(items[0].value)

    def const_size(self, items):
        return LitSize(items[0].value)

    def top_stmt(self, items):
        return items[0]

    def observe_stmt(self, items):
        hook = items[1]
        wheres, measures, whens, actions = [], [], [], []
        for item in items[2:]:
            if isinstance(item, WhereClause):
                wheres.append(item)
            elif isinstance(item, MeasureClause):
                measures.append(item)
            elif isinstance(item, WhenClause):
                whens.append(item)
            elif isinstance(item, list):
                actions = item
        return ObserveRule(hook=hook, wheres=wheres, measures=measures, whens=whens, actions=actions)

    def observe_target(self, items):
        return items[0]

    def syscall_target(self, items):
        return Hook(kind=HookKind.SYSCALL, targets=items[2])

    def kernel_target(self, items):
        return Hook(kind=HookKind.KERNEL, targets=items[2])

    def tracepoint_target(self, items):
        return Hook(kind=HookKind.TRACEPOINT, targets=items[2])

    def sched_target(self, items):
        return Hook(kind=HookKind.SCHED, targets=items[2])

    def file_target(self, items):
        return Hook(kind=HookKind.FILE, targets=items[2])

    def net_target(self, items):
        return Hook(kind=HookKind.NET, targets=items[2])

    def uprobe_target(self, items):
        raw = items[2].value
        binary = raw[1:-1] if raw.startswith('"') else raw
        return Hook(kind=HookKind.UPROBE, targets=items[4], binary_path=binary)

    def string_list(self, items):
        result = []
        for item in items:
            if isinstance(item, Token):
                val = item.value
                if val == ",":
                    continue
                if val.startswith('"') and val.endswith('"'):
                    val = val[1:-1]
                result.append(val)
        return result

    def where_clause(self, items):
        return WhereClause(cond=items[1])

    def when_clause(self, items):
        return WhenClause(cond=items[1])

    def measure_clause(self, items):
        metrics = [item for item in items[1:] if isinstance(item, Metric)]
        return MeasureClause(metrics=metrics)

    def measure_item(self, items):
        return _METRIC_MAP[items[0].value]

    def block(self, items):
        return list(items[1:-1])

    def action_stmt(self, items):
        return items[0]

    def aggregation_stmt(self, items):
        name = items[0].value.lstrip("@")
        keys = items[2]
        fn = items[5]
        arg = None
        for item in items[7:]:
            if isinstance(item, Expr):
                arg = item
                break
        return AggregationStmt(target=name, keys=keys, fn=fn, arg=arg)

    def key_list(self, items):
        return [item for item in items if isinstance(item, Expr)]

    def agg_func(self, items):
        return _AGGFN_MAP[items[0].value]

    def emit_stmt(self, items):
        fields = [item for item in items if isinstance(item, EmitField)]
        return EmitStmt(fields=fields)

    def field_assign(self, items):
        return EmitField(name=items[0].value, value=items[2])

    def print_stmt(self, items):
        for item in items:
            if isinstance(item, Expr):
                return PrintStmt(expr=item)
        return PrintStmt(expr=LitStr(""))

    def let_stmt(self, items):
        return LetStmt(name=items[1].value, value=items[3])

    def if_stmt(self, items):
        cond = items[2]
        then_block = items[4]
        else_block = None
        if len(items) > 5:
            rest = _filter_tokens(items[5:])
            if rest:
                else_block = rest[0]
        return IfStmt(cond=cond, then_actions=then_block, else_actions=else_block)

    def every_stmt(self, items):
        return EveryStmt(interval=items[1], actions=items[2])

    def begin_stmt(self, items):
        return BeginStmt(actions=items[1])

    def end_stmt(self, items):
        return EndStmt(actions=items[1])

    def var_ref(self, items):
        return VarRef(name=items[0].value)

    def int_lit(self, items):
        return LitInt(int(items[0].value))

    def string_lit(self, items):
        raw = items[0].value
        return LitStr(raw[1:-1] if raw.startswith('"') else raw)

    def bool_lit(self, items):
        return LitBool(items[0].value == "true")

    def time_lit(self, items):
        return LitTime(items[0].value)

    def size_lit(self, items):
        return LitSize(items[0].value)

    def agg_ref(self, items):
        return AggRef(name=items[0].value.lstrip("@"))

    def func_call(self, items):
        name = items[0].value
        args = []
        for item in items:
            if isinstance(item, list):
                args = item
                break
        return FuncCall(name=name, args=args)

    def arg_list(self, items):
        return [item for item in items if isinstance(item, Expr)]

    def unary_op(self, items):
        return UnaryOpExpr(op=_UNARYOP_MAP[_token_val(items[0])], operand=items[1])

    def or_expr(self, items):
        return _build_binary(items)

    def and_expr(self, items):
        return _build_binary(items)

    def eq_expr(self, items):
        return _build_binary(items)

    def rel_expr(self, items):
        return _build_binary(items)

    def add_expr(self, items):
        return _build_binary(items)

    def mul_expr(self, items):
        return _build_binary(items)


_parser: Optional[Lark] = None
_transformer = EmonTransformer()


def _get_parser() -> Lark:
    global _parser
    if _parser is None:
        _parser = _load_grammar()
    return _parser


def parse(source: str) -> Program:
    p = _get_parser()
    tree = p.parse(source)
    return _transformer.transform(tree)


def parse_file(filepath: str) -> Program:
    with open(filepath, "r", encoding="utf-8") as f:
        source = f.read()
    return parse(source)
