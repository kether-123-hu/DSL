"""
Emon DSL Lexer
Tokenizes Emon DSL source code into a stream of tokens.

Supports:
  - Emon DSL keywords (tool, observe, emit, every, etc.)
  - Aggregation identifiers (@count, @avg_latency)
  - Time literals (100us, 1ms, 2s)
  - Size literals (256KB, 1MB)
  - Built-in context variables
  - Comments (// and /* */)
  - Error recovery
"""

from typing import Optional
from emon.tokens import (
    Token, TokenType,
    EMON_KEYWORDS, SINGLE_CHAR_OPERATORS, MULTI_CHAR_OPERATORS,
    DELIMITERS, TIME_UNITS, SIZE_UNITS,
)
from emon.error import (
    LexerError, IllegalCharacterError, UnclosedStringError,
    UnclosedCommentError, InvalidNumberError,
    InvalidTimeLiteralError, InvalidSizeLiteralError,
    ErrorRecorder,
)


class Lexer:
    """Emon DSL Lexer."""

    def __init__(self, source: str):
        self.source = source
        self.length = len(source)
        self.position = 0
        self.line = 1
        self.column = 1
        self.tokens: list[Token] = []
        self.errors = ErrorRecorder()

    def tokenize(self) -> list[Token]:
        """Run lexical analysis and return token list."""
        self.tokens = []
        self.errors.clear()
        self.position = 0
        self.line = 1
        self.column = 1

        while self.position < self.length:
            try:
                self._scan_token()
            except LexerError as e:
                self.errors.record(e)
                self._advance()

        self.tokens.append(Token(
            type=TokenType.EOF, value='',
            line=self.line, column=self.column, length=0
        ))
        return self.tokens

    def _current_char(self) -> Optional[str]:
        if self.position >= self.length:
            return None
        return self.source[self.position]

    def _peek(self, offset: int = 0) -> Optional[str]:
        pos = self.position + offset
        if pos >= self.length:
            return None
        return self.source[pos]

    def _advance(self) -> Optional[str]:
        char = self._current_char()
        if char is not None:
            self.position += 1
            if char == '\n':
                self.line += 1
                self.column = 1
            else:
                self.column += 1
        return char

    def _skip_whitespace(self):
        while True:
            char = self._current_char()
            if char is None or char not in ' \t\r':
                break
            self._advance()

    def _scan_token(self):
        char = self._current_char()
        if char is None:
            return

        start_line = self.line
        start_column = self.column

        # Skip whitespace
        if char in ' \t\r':
            self._skip_whitespace()
            return

        # Skip newlines
        if char == '\n':
            self._advance()
            return

        # Aggregation identifier: @name
        if char == '@':
            token = self._read_agg_ident()
            self.tokens.append(token)
            return

        # Identifier or keyword
        if char.isalpha() or char == '_':
            token = self._read_identifier()
            self.tokens.append(token)
            return

        # Number (integer, time literal, size literal)
        if char.isdigit():
            token = self._read_number()
            self.tokens.append(token)
            return

        # String literal
        if char == '"':
            token = self._read_string()
            self.tokens.append(token)
            return

        # Comments
        if char == '/' and self._peek(1) in ('/', '*'):
            token = self._read_comment()
            self.tokens.append(token)
            return

        # Operators
        if char in SINGLE_CHAR_OPERATORS or char in '|&':
            token = self._read_operator()
            self.tokens.append(token)
            return

        # Delimiters
        if char in DELIMITERS:
            token = self._read_delimiter()
            self.tokens.append(token)
            return

        # Illegal character
        self._advance()
        error = IllegalCharacterError(char, start_line, start_column)
        self.errors.record(error)
        self.tokens.append(Token(
            type=TokenType.ERROR, value=char,
            line=start_line, column=start_column, length=1
        ))

    # ---- Aggregation Identifier (@name) ----
    def _read_agg_ident(self) -> Token:
        start_line = self.line
        start_column = self.column
        start_pos = self.position
        self._advance()  # consume '@'
        value = '@'
        while True:
            char = self._current_char()
            if char is None or not (char.isalnum() or char == '_'):
                break
            value += char
            self._advance()
        if len(value) == 1:  # just '@' with no name
            return Token(
                type=TokenType.ERROR, value=value,
                line=start_line, column=start_column,
                length=self.position - start_pos
            )
        return Token(
            type=TokenType.AGG_IDENT, value=value,
            line=start_line, column=start_column,
            length=self.position - start_pos
        )

    # ---- Identifier / Keyword ----
    def _read_identifier(self) -> Token:
        start_line = self.line
        start_column = self.column
        start_pos = self.position
        value = ''
        while True:
            char = self._current_char()
            if char is None or not (char.isalnum() or char == '_'):
                break
            value += char
            self._advance()

        if value in EMON_KEYWORDS:
            if value in ('true', 'false'):
                tt = TokenType.BOOL_LIT
            else:
                tt = TokenType.KEYWORD
        else:
            tt = TokenType.IDENTIFIER

        return Token(
            type=tt, value=value,
            line=start_line, column=start_column,
            length=self.position - start_pos
        )

    # ---- Number / Time Literal / Size Literal ----
    def _read_number(self) -> Token:
        start_line = self.line
        start_column = self.column
        start_pos = self.position
        value = ''

        # Read digits
        while True:
            char = self._current_char()
            if char is None or not char.isdigit():
                break
            value += char
            self._advance()

        # Skip optional whitespace before time/size unit suffix
        # (Lark grammar allows "100 us", "256 KB", etc.)
        ws_start = self.position
        while True:
            char = self._current_char()
            if char is None or char not in ' \t':
                break
            self._advance()

        # Check for time or size unit suffix
        suffix_start = self.position
        suffix = ''
        while True:
            char = self._current_char()
            if char is None or not char.isalpha():
                break
            suffix += char
            self._advance()

        if suffix in TIME_UNITS:
            return Token(
                type=TokenType.TIME_LIT, value=value + suffix,
                line=start_line, column=start_column,
                length=self.position - start_pos
            )
        elif suffix in SIZE_UNITS:
            return Token(
                type=TokenType.SIZE_LIT, value=value + suffix,
                line=start_line, column=start_column,
                length=self.position - start_pos
            )
        elif suffix:
            # Rollback: not a valid unit suffix (also undo whitespace skip)
            self.position = ws_start
            return Token(
                type=TokenType.INTEGER, value=value,
                line=start_line, column=start_column,
                length=self.position - start_pos
            )

        return Token(
            type=TokenType.INTEGER, value=value,
            line=start_line, column=start_column,
            length=self.position - start_pos
        )

    # ---- String Literal ----
    def _read_string(self) -> Token:
        start_line = self.line
        start_column = self.column
        start_pos = self.position
        self._advance()  # consume opening '"'
        result = '"'

        while True:
            char = self._current_char()
            if char is None:
                error = UnclosedStringError(start_line, start_column)
                self.errors.record(error)
                return Token(
                    type=TokenType.ERROR, value=result,
                    line=start_line, column=start_column,
                    length=self.position - start_pos
                )
            if char == '\\':
                result += self._advance()
                next_c = self._current_char()
                if next_c is not None:
                    result += self._advance()
                continue
            if char == '"':
                result += self._advance()
                return Token(
                    type=TokenType.STRING, value=result,
                    line=start_line, column=start_column,
                    length=self.position - start_pos
                )
            if char == '\n':
                error = UnclosedStringError(start_line, start_column)
                self.errors.record(error)
                self._advance()
                return Token(
                    type=TokenType.ERROR, value=result,
                    line=start_line, column=start_column,
                    length=self.position - start_pos
                )
            result += self._advance()

    # ---- Comments ----
    def _read_comment(self) -> Token:
        start_line = self.line
        start_column = self.column
        start_pos = self.position
        self._advance()  # consume first '/'
        second_char = self._current_char()

        if second_char == '/':
            value = '//'
            self._advance()
            while True:
                char = self._current_char()
                if char is None or char == '\n':
                    break
                value += self._advance()
            return Token(
                type=TokenType.COMMENT, value=value,
                line=start_line, column=start_column,
                length=self.position - start_pos
            )

        if second_char == '*':
            value = '/*'
            self._advance()
            while True:
                char = self._current_char()
                if char is None:
                    error = UnclosedCommentError(start_line, start_column)
                    self.errors.record(error)
                    return Token(
                        type=TokenType.ERROR, value=value,
                        line=start_line, column=start_column,
                        length=self.position - start_pos
                    )
                if char == '*' and self._peek(1) == '/':
                    value += self._advance()
                    value += self._advance()
                    return Token(
                        type=TokenType.COMMENT, value=value,
                        line=start_line, column=start_column,
                        length=self.position - start_pos
                    )
                value += self._advance()

        return Token(
            type=TokenType.ERROR, value='/',
            line=start_line, column=start_column, length=1
        )

    # ---- Operators ----
    def _read_operator(self) -> Token:
        start_line = self.line
        start_column = self.column
        start_pos = self.position
        char = self._current_char()

        two_char = char + (self._peek(1) or '')
        if two_char in MULTI_CHAR_OPERATORS:
            self._advance()
            self._advance()
            return Token(
                type=TokenType.OPERATOR, value=two_char,
                line=start_line, column=start_column, length=2
            )

        if char in SINGLE_CHAR_OPERATORS:
            self._advance()
            return Token(
                type=TokenType.OPERATOR, value=char,
                line=start_line, column=start_column, length=1
            )

        return Token(
            type=TokenType.ERROR, value=char,
            line=start_line, column=start_column, length=1
        )

    # ---- Delimiters ----
    def _read_delimiter(self) -> Token:
        start_line = self.line
        start_column = self.column
        start_pos = self.position
        char = self._current_char()

        if char in DELIMITERS:
            self._advance()
            return Token(
                type=TokenType.DELIMITER, value=char,
                line=start_line, column=start_column, length=1
            )

        return Token(
            type=TokenType.ERROR, value=char,
            line=start_line, column=start_column, length=1
        )


def tokenize(source: str) -> tuple[list[Token], list[LexerError]]:
    """Convenience function: lex source and return (tokens, errors)."""
    lexer = Lexer(source)
    tokens = lexer.tokenize()
    return tokens, lexer.errors.get_errors()
