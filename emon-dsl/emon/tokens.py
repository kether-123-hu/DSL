"""
Emon DSL Token Types and Data Structures
Defines all token types, keywords, operators, and delimiters
used in the Emon DSL lexer.
"""

from enum import Enum, auto
from dataclasses import dataclass
from typing import Optional


class TokenType(Enum):
    """Token type enumeration for Emon DSL."""
    KEYWORD = auto()
    IDENTIFIER = auto()
    AGG_IDENT = auto()       # @count, @avg_latency
    INTEGER = auto()
    STRING = auto()
    TIME_LIT = auto()        # 100us, 1ms, 2s
    SIZE_LIT = auto()        # 256KB, 1MB
    BOOL_LIT = auto()        # true, false
    OPERATOR = auto()
    DELIMITER = auto()
    COMMENT = auto()
    NEWLINE = auto()
    WHITESPACE = auto()
    EOF = auto()
    ERROR = auto()


# ---- Emon DSL Keywords (aligned with project plan 4.1.1) ----
STRUCT_KEYWORDS = {
    'tool', 'option', 'observe', 'every', 'begin', 'end',
}
CLAUSE_KEYWORDS = {
    'where', 'measure', 'when',
}
TARGET_KEYWORDS = {
    'syscall', 'kernel', 'tracepoint', 'uprobe',
    'sched', 'file', 'net',
}
MEASURE_KEYWORDS = {
    'latency', 'count', 'size', 'retval', 'stack',
}
AGG_FUNC_KEYWORDS = {
    'count', 'sum', 'avg', 'min', 'max', 'hist', 'lhist',
}
ACTION_KEYWORDS = {
    'emit', 'print', 'let', 'if', 'else',
}
BUILTIN_CONSTANTS = {
    'true', 'false',
}
EMON_KEYWORDS = (
    STRUCT_KEYWORDS | CLAUSE_KEYWORDS | TARGET_KEYWORDS |
    MEASURE_KEYWORDS | AGG_FUNC_KEYWORDS | ACTION_KEYWORDS |
    BUILTIN_CONSTANTS
)

CONTEXT_VARIABLES = {
    'pid', 'tid', 'uid', 'gid', 'comm', 'cpu', 'nsecs',
    'syscall', 'func', 'retval', 'latency', 'size', 'stack',
    'arg0', 'arg1', 'arg2', 'arg3', 'arg4', 'arg5',
}

SINGLE_CHAR_OPERATORS = {
    '+': 'PLUS', '-': 'MINUS', '*': 'MULTIPLY', '/': 'DIVIDE',
    '%': 'MODULO', '=': 'ASSIGN', '<': 'LESS', '>': 'GREATER',
    '!': 'NOT',
}

MULTI_CHAR_OPERATORS = {
    '==': 'EQUAL', '!=': 'NOTEQUAL', '<=': 'LESSEQUAL',
    '>=': 'GREATEREQUAL', '&&': 'AND', '||': 'OR',
}

DELIMITERS = {
    '(': 'LPAREN', ')': 'RPAREN', '{': 'LBRACE', '}': 'RBRACE',
    '[': 'LBRACKET', ']': 'RBRACKET', ',': 'COMMA',
    ';': 'SEMICOLON', ':': 'COLON', '.': 'DOT',
}

TIME_UNITS = {'ns', 'us', 'ms', 's'}
SIZE_UNITS = {'B', 'KB', 'MB'}


@dataclass
class Token:
    """Token data structure for Emon DSL lexer output."""
    type: TokenType
    value: str
    line: int
    column: int
    length: int

    def __repr__(self) -> str:
        return (
            f"Token(type={self.type.name}, "
            f"value={repr(self.value)}, "
            f"line={self.line}, column={self.column})"
        )

    def is_keyword(self) -> bool:
        return self.type == TokenType.KEYWORD

    def is_identifier(self) -> bool:
        return self.type == TokenType.IDENTIFIER

    def is_agg_ident(self) -> bool:
        return self.type == TokenType.AGG_IDENT

    def is_literal(self) -> bool:
        return self.type in (
            TokenType.INTEGER, TokenType.STRING,
            TokenType.TIME_LIT, TokenType.SIZE_LIT, TokenType.BOOL_LIT
        )

    def is_operator(self, op: Optional[str] = None) -> bool:
        if self.type != TokenType.OPERATOR:
            return False
        if op is None:
            return True
        return self.value == op

    def is_context_var(self) -> bool:
        return (
            self.type == TokenType.IDENTIFIER and
            self.value in CONTEXT_VARIABLES
        )
