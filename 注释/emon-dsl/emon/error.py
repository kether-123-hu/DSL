# ===================================================================
# error.py —— Emon DSL 词法分析错误类型定义
# ===================================================================
#
# 【本文件的作用】
# 定义词法分析阶段可能遇到的各种错误类型。
# 当词法分析器（lexer.py）扫描源代码时，如果遇到无法识别的字符、
# 未闭合的字符串等问题，就会创建对应的错误对象。
#
# 【为什么需要专门的错误类？】
# - 不同类型的错误需要不同的错误信息
# - 记录错误发生的位置（行号、列号），方便用户定位问题
# - ErrorRecorder 收集所有错误，而不是遇到第一个错误就停止，
#   这样用户可以一次性看到所有问题
#
# 【类的继承关系】
#   LexerError (基类：所有词法错误的公共父类)
#     ├── IllegalCharacterError  (非法字符错误)
#     ├── UnclosedStringError    (未闭合的字符串)
#     ├── UnclosedCommentError   (未闭合的块注释)
#     ├── InvalidNumberError     (无效数字格式)
#     ├── InvalidTimeLiteralError(无效时间字面量)
#     └── InvalidSizeLiteralError(无效大小字面量)
# ===================================================================


# ===================================================================
# LexerError 基类 —— 所有词法错误的父类
# ===================================================================
class LexerError(Exception):
    """
    词法错误的基类，继承自 Python 内置的 Exception。
    所有具体的词法错误类型都继承自这个类。

    属性:
        message: 错误描述信息
        line:    错误发生的行号（0 表示未知）
        column:  错误发生的列号（0 表示未知）
    """

    def __init__(self, message: str, line: int = 0, column: int = 0):
        """
        初始化词法错误。

        参数:
            message: 人类可读的错误描述
            line:    错误在源代码中的行号（从 1 开始）
            column:  错误在源代码中的列号（从 1 开始）
        """
        self.message = message
        self.line = line
        self.column = column
        # 调用父类 Exception 的初始化，传入格式化后的完整错误信息
        super().__init__(self._format_message())

    def _format_message(self) -> str:
        """
        将错误信息格式化为带位置的完整描述。
        例如: "Lexer error [line 5, col 12]: Illegal character '@'"
        """
        if self.line > 0:
            return f"Lexer error [line {self.line}, col {self.column}]: {self.message}"
        return f"Lexer error: {self.message}"


# ===================================================================
# 具体错误类型
# ===================================================================

class IllegalCharacterError(LexerError):
    """
    非法字符错误。
    当词法分析器遇到不属于任何已知 Token 类型的字符时抛出。
    例如：源代码中出现 '$' 或 '#' 等 Emon 语言不识别的字符。
    """
    def __init__(self, char: str, line: int, column: int):
        self.char = char  # 记录是非法的哪个字符
        super().__init__(f"Illegal character '{char}'", line, column)


class UnclosedStringError(LexerError):
    """
    未闭合的字符串错误。
    当字符串以双引号 " 开始，但在行尾或文件末尾都没有找到配对的结束引号时抛出。
    例如: "hello world （缺少结束的 "）
    """
    def __init__(self, line: int, column: int):
        super().__init__("Unclosed string literal", line, column)


class UnclosedCommentError(LexerError):
    """
    未闭合的块注释错误。
    当块注释以 /* 开始，但在文件末尾都没有找到 */ 结束时抛出。
    例如: /* 这是一个永远不会结束的注释
    """
    def __init__(self, line: int, column: int):
        super().__init__("Unclosed block comment, missing '*/'", line, column)


class InvalidNumberError(LexerError):
    """
    无效的数字格式错误。
    当遇到不符合数字格式的内容时抛出。
    （当前 Emon DSL 只支持十进制整数，这个错误主要预留给未来扩展）
    """
    def __init__(self, number: str, line: int, column: int):
        super().__init__(f"Invalid number format '{number}'", line, column)


class InvalidTimeLiteralError(LexerError):
    """
    无效的时间字面量错误。
    当数字后跟的不是合法时间单位时抛出。
    合法的时间单位: ns(纳秒), us(微秒), ms(毫秒), s(秒)
    例如: 100xx （xx 不是合法时间单位）
    """
    def __init__(self, value: str, line: int, column: int):
        super().__init__(f"Invalid time literal '{value}'", line, column)


class InvalidSizeLiteralError(LexerError):
    """
    无效的大小字面量错误。
    当数字后跟的不是合法大小单位时抛出。
    合法的大小单位: B(字节), KB(千字节), MB(兆字节)
    """
    def __init__(self, value: str, line: int, column: int):
        super().__init__(f"Invalid size literal '{value}'", line, column)


# ===================================================================
# ErrorRecorder —— 错误收集器
# ===================================================================
class ErrorRecorder:
    """
    错误收集器，用于在词法分析过程中收集所有遇到的错误。
    
    设计理念：我们不希望词法分析器在遇到第一个错误时就崩溃退出。
    相反，我们继续扫描剩余的源代码，收集所有错误，
    这样用户可以一次性看到所有问题，提高调试效率。

    用法:
        recorder = ErrorRecorder()
        recorder.record(some_error)     # 记录一个错误
        if recorder.has_errors():       # 检查是否有错误
            for e in recorder.get_errors():  # 获取所有错误
                print(e)
    """

    def __init__(self):
        self.errors: list[LexerError] = []  # 存储所有错误的列表

    def record(self, error: LexerError):
        """
        记录一个词法错误。
        参数 error: 要记录的 LexerError 对象
        """
        self.errors.append(error)

    def has_errors(self) -> bool:
        """检查是否收集到了任何错误。返回 True 表示有错误。"""
        return len(self.errors) > 0

    def get_errors(self) -> list[LexerError]:
        """
        获取所有已记录错误的副本。
        返回副本而不是原始列表，防止外部代码意外修改内部数据。
        """
        return self.errors.copy()

    def clear(self):
        """清空所有已记录的错误（用于重新开始分析）。"""
        self.errors.clear()

    def __len__(self) -> int:
        """
        支持 len(recorder) 语法。
        返回已记录的错误数量。
        """
        return len(self.errors)

    def __repr__(self) -> str:
        """
        返回错误收集器的可读表示。
        如果没有错误，返回 "No errors"；
        否则返回所有错误信息，每个一行。
        """
        if not self.errors:
            return "No errors"
        return "\n".join(str(e) for e in self.errors)
