# ===================================================================
# tokens.py —— Emon DSL 词法单元(Token)类型定义
# ===================================================================
#
# 【本文件的作用】
# 定义 Emon DSL 语言中所有的"单词"类型。
# 词法分析器（lexer.py）读入源代码文本后，
# 会将文本拆分为一个个 Token（词法单元），
# 每个 Token 都有一个类型（如 KEYWORD、INTEGER）和一个值（如 "observe"、"42"）。
#
# 类比：英文中的单词有名词、动词、形容词等词性，
#       Emon DSL 中的 Token 有关键字、标识符、数字、字符串等类型。
#
# 【技术背景】
# - Enum（枚举）：定义一组固定的命名常量，如 TokenType.KEYWORD
# - dataclass：Python 的数据类，自动生成 __init__ 等方法，简洁定义数据结构
# ===================================================================

# ---- 导入依赖 ----
from enum import Enum, auto          # Enum: 枚举类型; auto: 自动分配枚举值
from dataclasses import dataclass     # dataclass: 简化数据类定义
from typing import Optional           # Optional: 表示可选类型（可以是某类型或 None）


# ===================================================================
# TokenType 枚举 —— 定义所有可能的 Token 类型
# ===================================================================
class TokenType(Enum):
    """
    Token 类型枚举。
    每种 Token 属于以下 15 种类型之一。
    auto() 会自动分配一个唯一整数值，我们不关心具体数值，只关心类型本身。
    """
    KEYWORD = auto()       # 关键字：如 tool, observe, where, emit, if, else
    IDENTIFIER = auto()    # 普通标识符：用户定义的变量名，如 my_var
    AGG_IDENT = auto()     # 聚合标识符：以 @ 开头的变量，如 @count, @avg_latency
                           # 聚合标识符用于在 eBPF map 中累积统计数据
    INTEGER = auto()       # 整数：如 42, 0, 100
    STRING = auto()        # 字符串：用双引号包围，如 "hello world"
    TIME_LIT = auto()      # 时间字面量：数字+时间单位，如 100us(微秒), 1ms(毫秒), 2s(秒)
    SIZE_LIT = auto()      # 大小字面量：数字+大小单位，如 256KB, 1MB
    BOOL_LIT = auto()      # 布尔字面量：true 或 false
    OPERATOR = auto()      # 运算符：如 +, -, *, ==, !=, &&, ||
    DELIMITER = auto()     # 分隔符：如 (, ), {, }, [, ], ,, ;, :
    COMMENT = auto()       # 注释：// 单行注释 或 /* 多行注释 */
    NEWLINE = auto()       # 换行符（词法分析中通常被跳过）
    WHITESPACE = auto()    # 空白字符（空格、制表符等，通常被跳过）
    EOF = auto()           # 文件结束标记（End Of File）：表示源代码读取完毕
    ERROR = auto()         # 错误 Token：词法分析遇到无法识别的字符


# ===================================================================
# 关键字分类定义
# ===================================================================
# Emon DSL 的关键字按功能分为几组，便于管理和检查。

# ---- 结构关键字 ----
# 用于定义 Emon 程序的整体结构（类似 C 语言中的 struct、if、while）
STRUCT_KEYWORDS = {
    'tool',      # 声明一个监控工具（程序的入口）
    'option',    # 在 tool 块内声明配置选项
    'observe',   # 声明一个观测规则（监控什么、怎么监控）
    'every',     # 声明周期性任务（每隔多久执行一次）
    'begin',     # 声明启动时执行的初始化代码块
    'end',       # 声明退出时执行的清理代码块
}

# ---- 子句关键字 ----
# 用于在 observe 块内附加过滤和测量条件
CLAUSE_KEYWORDS = {
    'where',     # 前置过滤条件（在测量之前过滤事件）
    'measure',   # 声明要测量的指标（延迟、次数、大小等）
    'when',      # 后置过滤条件（在测量之后过滤事件）
}

# ---- 观测目标关键字 ----
# 指定要监控的内核子系统类型（7种观测目标）
TARGET_KEYWORDS = {
    'syscall',    # 系统调用（如 read, write, open）
    'kernel',     # 内核函数（kprobe 动态探针）
    'tracepoint', # 内核静态跟踪点（预定义的跟踪事件）
    'uprobe',     # 用户态函数探针（监控用户程序中的函数）
    'sched',      # 调度器事件（进程切换等）
    'file',       # 文件系统操作
    'net',        # 网络相关操作
}

# ---- 测量指标关键字 ----
# 声明要采集的指标类型
MEASURE_KEYWORDS = {
    'latency',    # 延迟（函数执行耗时）
    'count',      # 计数（事件发生次数）
    'size',       # 大小（如读写字节数）
    'retval',     # 返回值
    'stack',      # 调用栈
}

# ---- 聚合函数关键字 ----
# 用于在 eBPF map 中对数据进行统计聚合
AGG_FUNC_KEYWORDS = {
    'count',      # 计数：统计事件发生次数
    'sum',        # 求和：累加数值
    'avg',        # 平均值：计算平均值
    'min',        # 最小值
    'max',        # 最大值
    'hist',       # 直方图（对数分桶）
    'lhist',      # 线性直方图（等宽分桶）
}

# ---- 动作关键字 ----
# 在 observe 块的代码体中使用
ACTION_KEYWORDS = {
    'emit',       # 发射/输出事件（将数据发送到用户态 ring buffer）
    'print',      # 打印输出（在用户态打印信息）
    'let',        # 声明局部变量
    'if',         # 条件判断
    'else',       # 条件分支
}

# ---- 内置常量 ----
BUILTIN_CONSTANTS = {
    'true',       # 布尔真
    'false',      # 布尔假
}

# ---- 所有 Emon 关键字的并集 ----
# 词法分析器用这个集合来判断一个标识符是否是关键字
EMON_KEYWORDS = (
    STRUCT_KEYWORDS | CLAUSE_KEYWORDS | TARGET_KEYWORDS |
    MEASURE_KEYWORDS | AGG_FUNC_KEYWORDS | ACTION_KEYWORDS |
    BUILTIN_CONSTANTS
)

# ===================================================================
# 上下文变量定义
# ===================================================================
# 上下文变量是 eBPF 运行时自动提供的"环境变量"。
# 在 Emon 代码中可以直接使用这些变量名，它们会被映射到 eBPF 辅助函数读取的实际数据。
CONTEXT_VARIABLES = {
    'pid',        # 进程 ID（Process ID）
    'tid',        # 线程 ID（Thread ID）
    'uid',        # 用户 ID（User ID）
    'gid',        # 组 ID（Group ID）
    'comm',       # 进程名（Command name，最多 16 字符）
    'cpu',        # CPU 编号（当前在哪个 CPU 上运行）
    'nsecs',      # 纳秒时间戳（自启动以来的时间）
    'syscall',    # 系统调用名称（仅在 syscall 观测目标下可用）
    'func',       # 内核函数名（仅在 kernel/uprobe 等观测目标下可用）
    'retval',     # 函数返回值（仅在声明了 measure retval 时可用）
    'latency',    # 延迟值（仅在声明了 measure latency 时可用）
    'size',       # 大小值（仅在声明了 measure size 时可用）
    'stack',      # 调用栈（仅在声明了 measure stack 时可用）
    'arg0',       # 函数参数 0（仅在 kernel/uprobe/file/net 等观测目标下可用）
    'arg1',       # 函数参数 1
    'arg2',       # 函数参数 2
    'arg3',       # 函数参数 3
    'arg4',       # 函数参数 4
    'arg5',       # 函数参数 5
}

# ===================================================================
# 运算符定义
# ===================================================================

# ---- 单字符运算符 ----
# 键 = 运算符字符, 值 = 运算符名称
SINGLE_CHAR_OPERATORS = {
    '+': 'PLUS',          # 加法
    '-': 'MINUS',         # 减法/负号
    '*': 'MULTIPLY',      # 乘法
    '/': 'DIVIDE',        # 除法
    '%': 'MODULO',        # 取模（求余数）
    '=': 'ASSIGN',        # 赋值（仅在 emit 字段赋值中使用）
    '<': 'LESS',          # 小于
    '>': 'GREATER',       # 大于
    '!': 'NOT',           # 逻辑非
}

# ---- 双字符运算符 ----
# 键 = 运算符字符, 值 = 运算符名称
MULTI_CHAR_OPERATORS = {
    '==': 'EQUAL',         # 等于（比较）
    '!=': 'NOTEQUAL',      # 不等于
    '<=': 'LESSEQUAL',     # 小于等于
    '>=': 'GREATEREQUAL',  # 大于等于
    '&&': 'AND',           # 逻辑与
    '||': 'OR',            # 逻辑或
}

# ===================================================================
# 分隔符定义
# ===================================================================
DELIMITERS = {
    '(': 'LPAREN',         # 左圆括号
    ')': 'RPAREN',         # 右圆括号
    '{': 'LBRACE',         # 左花括号（代码块开始）
    '}': 'RBRACE',         # 右花括号（代码块结束）
    '[': 'LBRACKET',       # 左方括号（聚合 key 列表）
    ']': 'RBRACKET',       # 右方括号
    ',': 'COMMA',          # 逗号（分隔列表项）
    ';': 'SEMICOLON',      # 分号（语句结束）
    ':': 'COLON',          # 冒号
    '.': 'DOT',            # 点号
}

# ===================================================================
# 时间单位和大小单位
# ===================================================================
# 用于解析时间字面量（如 100us）和大小字面量（如 256KB）
TIME_UNITS = {'ns', 'us', 'ms', 's'}  # 纳秒、微秒、毫秒、秒
SIZE_UNITS = {'B', 'KB', 'MB'}        # 字节、千字节、兆字节


# ===================================================================
# Token 数据类 —— 表示词法分析器输出的一个词法单元
# ===================================================================
@dataclass
class Token:
    """
    Token 是词法分析的最小输出单元。
    每个 Token 记录了：它是什么类型、它的原始文本值、
    它在源代码中的位置（行号、列号）、它的文本长度。
    """
    type: TokenType       # Token 的类型（属于上面的 15 种类型之一）
    value: str            # Token 的原始字符串值，如 "observe", "42", "@count"
    line: int             # Token 在源代码中的行号（从 1 开始）
    column: int           # Token 在源代码中的列号（从 1 开始）
    length: int           # Token 的字符长度

    def __repr__(self) -> str:
        """
        返回 Token 的可读字符串表示，用于调试输出。
        例如: Token(type=KEYWORD, value='observe', line=1, column=1)
        """
        return (
            f"Token(type={self.type.name}, "
            f"value={repr(self.value)}, "
            f"line={self.line}, column={self.column})"
        )

    # ---- 以下是便捷判断方法，用于快速检查 Token 的类型 ----

    def is_keyword(self) -> bool:
        """判断这个 Token 是否是关键字"""
        return self.type == TokenType.KEYWORD

    def is_identifier(self) -> bool:
        """判断这个 Token 是否是普通标识符（用户定义的变量名）"""
        return self.type == TokenType.IDENTIFIER

    def is_agg_ident(self) -> bool:
        """判断这个 Token 是否是聚合标识符（以 @ 开头，如 @count）"""
        return self.type == TokenType.AGG_IDENT

    def is_literal(self) -> bool:
        """
        判断这个 Token 是否是字面量（常量值）。
        包括：整数、字符串、时间字面量、大小字面量、布尔值
        """
        return self.type in (
            TokenType.INTEGER, TokenType.STRING,
            TokenType.TIME_LIT, TokenType.SIZE_LIT, TokenType.BOOL_LIT
        )

    def is_operator(self, op: Optional[str] = None) -> bool:
        """
        判断这个 Token 是否是运算符。
        如果提供了 op 参数，还会检查具体的运算符符号。
        例如: token.is_operator("==") 检查是否等于运算符
        """
        if self.type != TokenType.OPERATOR:
            return False
        if op is None:
            return True          # 是运算符即可，不限制具体符号
        return self.value == op  # 必须是特定的运算符符号

    def is_context_var(self) -> bool:
        """
        判断这个 Token 是否是 eBPF 上下文变量。
        上下文变量是 eBPF 运行时自动提供的环境变量（如 pid, comm, cpu）。
        """
        return (
            self.type == TokenType.IDENTIFIER and
            self.value in CONTEXT_VARIABLES
        )
