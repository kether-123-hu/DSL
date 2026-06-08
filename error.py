"""
词法分析器错误处理模块
定义词法分析过程中可能出现的错误类型
"""


class LexerError(Exception):
    """词法分析器基础错误类"""

    def __init__(self, message: str, line: int = 0, column: int = 0):
        self.message = message
        self.line = line
        self.column = column
        super().__init__(self._format_message())

    def _format_message(self) -> str:
        if self.line > 0:
            return f"词法错误 [行 {self.line}, 列 {self.column}]: {self.message}"
        return f"词法错误: {self.message}"


class IllegalCharacterError(LexerError):
    """非法字符错误"""

    def __init__(self, char: str, line: int, column: int):
        self.char = char
        super().__init__(f"非法字符 '{char}'", line, column)


class UnclosedStringError(LexerError):
    """未闭合的字符串错误"""

    def __init__(self, line: int, column: int):
        super().__init__(f"字符串未闭合，缺少结束引号", line, column)


class UnclosedCommentError(LexerError):
    """未闭合的注释错误"""

    def __init__(self, line: int, column: int):
        super().__init__(f"多行注释未闭合，缺少 '*/'", line, column)


class InvalidNumberError(LexerError):
    """无效的数字格式错误"""

    def __init__(self, number: str, line: int, column: int):
        super().__init__(f"无效的数字格式 '{number}'", line, column)


class InvalidEscapeSequenceError(LexerError):
    """无效的转义序列错误"""

    def __init__(self, escape: str, line: int, column: int):
        super().__init__(f"无效的转义序列 '\\{escape}'", line, column)


class ErrorRecorder:
    """错误记录器，收集词法分析过程中的所有错误"""

    def __init__(self):
        self.errors: list[LexerError] = []

    def record(self, error: LexerError):
        """记录一个错误"""
        self.errors.append(error)

    def has_errors(self) -> bool:
        """检查是否有错误"""
        return len(self.errors) > 0

    def get_errors(self) -> list[LexerError]:
        """获取所有错误"""
        return self.errors.copy()

    def clear(self):
        """清空错误列表"""
        self.errors.clear()

    def __len__(self) -> int:
        return len(self.errors)

    def __repr__(self) -> str:
        if not self.errors:
            return "无错误"
        return "\n".join(str(e) for e in self.errors)
