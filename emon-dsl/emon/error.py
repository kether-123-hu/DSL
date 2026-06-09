"""
Emon DSL Lexer Error Handling
Defines error types for the Emon DSL lexer.
"""


class LexerError(Exception):
    """Base lexer error class."""

    def __init__(self, message: str, line: int = 0, column: int = 0):
        self.message = message
        self.line = line
        self.column = column
        super().__init__(self._format_message())

    def _format_message(self) -> str:
        if self.line > 0:
            return f"Lexer error [line {self.line}, col {self.column}]: {self.message}"
        return f"Lexer error: {self.message}"


class IllegalCharacterError(LexerError):
    def __init__(self, char: str, line: int, column: int):
        self.char = char
        super().__init__(f"Illegal character '{char}'", line, column)


class UnclosedStringError(LexerError):
    def __init__(self, line: int, column: int):
        super().__init__("Unclosed string literal", line, column)


class UnclosedCommentError(LexerError):
    def __init__(self, line: int, column: int):
        super().__init__("Unclosed block comment, missing '*/'", line, column)


class InvalidNumberError(LexerError):
    def __init__(self, number: str, line: int, column: int):
        super().__init__(f"Invalid number format '{number}'", line, column)


class InvalidTimeLiteralError(LexerError):
    def __init__(self, value: str, line: int, column: int):
        super().__init__(f"Invalid time literal '{value}'", line, column)


class InvalidSizeLiteralError(LexerError):
    def __init__(self, value: str, line: int, column: int):
        super().__init__(f"Invalid size literal '{value}'", line, column)


class ErrorRecorder:
    """Collects all lexer errors during scanning."""

    def __init__(self):
        self.errors: list[LexerError] = []

    def record(self, error: LexerError):
        self.errors.append(error)

    def has_errors(self) -> bool:
        return len(self.errors) > 0

    def get_errors(self) -> list[LexerError]:
        return self.errors.copy()

    def clear(self):
        self.errors.clear()

    def __len__(self) -> int:
        return len(self.errors)

    def __repr__(self) -> str:
        if not self.errors:
            return "No errors"
        return "\n".join(str(e) for e in self.errors)
