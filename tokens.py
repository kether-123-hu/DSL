"""
Token 类型定义模块
定义词法分析器中使用的所有 Token 类型和数据结构
"""

from enum import Enum, auto
from dataclasses import dataclass
from typing import Optional


class TokenType(Enum):
    """Token 类型枚举"""
    # 基础类型
    KEYWORD = auto()      # 关键字
    IDENTIFIER = auto()   # 标识符
    INTEGER = auto()      # 整数常量
    FLOAT = auto()        # 浮点常量
    STRING = auto()       # 字符串常量
    OPERATOR = auto()     # 运算符
    DELIMITER = auto()    # 分隔符
    COMMENT = auto()      # 注释
    NEWLINE = auto()       # 换行符
    WHITESPACE = auto()   # 空白字符
    EOF = auto()          # 文件结束
    ERROR = auto()        # 错误


# 关键字列表
KEYWORDS = {
    'if', 'else', 'while', 'for', 'do', 'switch', 'case', 'default',
    'break', 'continue', 'return', 'goto', 'sizeof', 'typeof',
    'int', 'long', 'short', 'char', 'float', 'double', 'void',
    'signed', 'unsigned', 'const', 'static', 'extern', 'register',
    'volatile', 'struct', 'union', 'enum', 'typedef',
    'TRUE', 'FALSE', 'NULL', 'true', 'false', 'null'
}

# 单字符运算符映射
SINGLE_CHAR_OPERATORS = {
    '+': 'PLUS',
    '-': 'MINUS',
    '*': 'MULTIPLY',
    '/': 'DIVIDE',
    '%': 'MODULO',
    '=': 'ASSIGN',
    '<': 'LESS',
    '>': 'GREATER',
    '!': 'NOT',
    '&': 'BITAND',
    '|': 'BITOR',
    '^': 'XOR',
    '~': 'BITNOT',
}

# 多字符运算符
MULTI_CHAR_OPERATORS = {
    '==': 'EQUAL',
    '!=': 'NOTEQUAL',
    '<=': 'LESSEQUAL',
    '>=': 'GREATEREQUAL',
    '++': 'INCREMENT',
    '--': 'DECREMENT',
    '+=': 'PLUSASSIGN',
    '-=': 'MINUSASSIGN',
    '*=': 'MULTIPLYASSIGN',
    '/=': 'DIVIDEASSIGN',
    '%=': 'MODULOASSIGN',
    '&&': 'AND',
    '||': 'OR',
    '<<': 'LEFTSHIFT',
    '>>': 'RIGHTSHIFT',
    '<<=': 'LEFTSHIFTASSIGN',
    '>>=': 'RIGHTSHIFTASSIGN',
    '&=': 'BITANDASSIGN',
    '|=': 'BITORASSIGN',
    '^=': 'XORASSIGN',
    '->': 'ARROW',
}

# 分隔符
DELIMITERS = {
    '(': 'LPAREN',
    ')': 'RPAREN',
    '{': 'LBRACE',
    '}': 'RBRACE',
    '[': 'LBRACKET',
    ']': 'RBRACKET',
    ',': 'COMMA',
    ';': 'SEMICOLON',
    ':': 'COLON',
    '.': 'DOT',
    '?': 'QUESTION',
    '...': 'ELLIPSIS',
}


@dataclass
class Token:
    """Token 数据结构"""
    type: TokenType
    value: str
    line: int
    column: int
    length: int

    def __repr__(self) -> str:
        return f"Token(type={self.type.name}, value={repr(self.value)}, line={self.line}, column={self.column})"

    def is_keyword(self) -> bool:
        """检查是否为关键字"""
        return self.type == TokenType.KEYWORD

    def is_identifier(self) -> bool:
        """检查是否为标识符"""
        return self.type == TokenType.IDENTIFIER

    def is_number(self) -> bool:
        """检查是否为数字常量"""
        return self.type in (TokenType.INTEGER, TokenType.FLOAT)

    def is_operator(self, op: Optional[str] = None) -> bool:
        """检查是否为运算符，可指定具体运算符"""
        if self.type != TokenType.OPERATOR:
            return False
        if op is None:
            return True
        return self.value == op
