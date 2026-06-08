"""
词法分析器核心实现模块
对源代码进行词法分析，识别并提取各类词法单元（Token）
"""

from typing import Optional
from tokens import Token, TokenType, KEYWORDS, SINGLE_CHAR_OPERATORS, MULTI_CHAR_OPERATORS, DELIMITERS
from error import (
    LexerError, IllegalCharacterError, UnclosedStringError,
    UnclosedCommentError, InvalidNumberError, ErrorRecorder
)


class Lexer:
    """词法分析器类"""

    def __init__(self, source: str):
        self.source = source
        self.length = len(source)
        self.position = 0
        self.line = 1
        self.column = 1
        self.tokens: list[Token] = []
        self.errors = ErrorRecorder()

    def tokenize(self) -> list[Token]:
        """执行词法分析，返回 Token 列表"""
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
            type=TokenType.EOF,
            value='',
            line=self.line,
            column=self.column,
            length=0
        ))

        return self.tokens

    def _current_char(self) -> Optional[str]:
        """获取当前字符"""
        if self.position >= self.length:
            return None
        return self.source[self.position]

    def _peek(self, offset: int = 0) -> Optional[str]:
        """查看指定偏移量的字符，不移动位置"""
        pos = self.position + offset
        if pos >= self.length:
            return None
        return self.source[pos]

    def _advance(self) -> Optional[str]:
        """前进到下一个字符，返回当前字符"""
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
        """跳过空白字符（不包括换行符）"""
        while True:
            char = self._current_char()
            if char is None:
                break
            if char in ' \t\r':
                self._advance()
            else:
                break

    def _scan_token(self):
        """扫描单个 Token"""
        char = self._current_char()

        if char is None:
            return

        start_line = self.line
        start_column = self.column

        # 空白字符（跳过）
        if char in ' \t\r':
            self._skip_whitespace()
            return

        # 换行符
        if char == '\n':
            self._advance()
            return

        # 字母或下划线 -> 标识符或关键字
        if char.isalpha() or char == '_':
            token = self._read_identifier()
            self.tokens.append(token)
            return

        # 数字 -> 数字常量
        if char.isdigit():
            token = self._read_number()
            self.tokens.append(token)
            return

        # 字符串
        if char in '"\'':
            token = self._read_string()
            self.tokens.append(token)
            return

        # 注释
        if char == '/' and self._peek(1) in ('/', '*'):
            token = self._read_comment()
            self.tokens.append(token)
            return

        # 运算符或多字符运算符
        if char in SINGLE_CHAR_OPERATORS or char in '|&':
            token = self._read_operator()
            self.tokens.append(token)
            return

        # 分隔符
        if char in DELIMITERS or (char == '.' and self._peek(1) == '.' and self._peek(2) == '.'):
            token = self._read_delimiter()
            self.tokens.append(token)
            return

        # 其他字符 -> 错误
        self._advance()
        error = IllegalCharacterError(char, start_line, start_column)
        self.errors.record(error)
        self.tokens.append(Token(
            type=TokenType.ERROR,
            value=char,
            line=start_line,
            column=start_column,
            length=1
        ))

    def _read_identifier(self) -> Token:
        """读取标识符或关键字"""
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

        # 检查是否为关键字
        if value in KEYWORDS:
            token_type = TokenType.KEYWORD
        else:
            token_type = TokenType.IDENTIFIER

        return Token(
            type=token_type,
            value=value,
            line=start_line,
            column=start_column,
            length=self.position - start_pos
        )

    def _read_number(self) -> Token:
        """读取数字常量（整数或浮点数）"""
        start_line = self.line
        start_column = self.column
        start_pos = self.position
        value = ''
        has_dot = False
        has_exponent = False

        # 检查进制前缀
        if self._current_char() == '0' and self._peek(1) in ('x', 'X', 'b', 'B'):
            prefix = self._advance() + self._advance()
            value = prefix
            # 十六进制或二进制数字
            while True:
                char = self._current_char()
                if char is None or not char.upper() in '0123456789ABCDEF':
                    break
                value += char
                self._advance()
            return Token(
                type=TokenType.INTEGER,
                value=value,
                line=start_line,
                column=start_column,
                length=self.position - start_pos
            )

        # 读取整数部分
        while True:
            char = self._current_char()
            if char is None or not char.isdigit():
                break
            value += char
            self._advance()

        # 检查小数点
        if self._current_char() == '.' and self._peek(1) and self._peek(1).isdigit():
            has_dot = True
            value += self._advance()  # 消费小数点
            while True:
                char = self._current_char()
                if char is None or not char.isdigit():
                    break
                value += char
                self._advance()

        # 检查指数部分
        if self._current_char() in ('e', 'E'):
            has_exponent = True
            value += self._advance()  # 消费 e/E
            if self._current_char() in ('+', '-'):
                value += self._advance()  # 消费符号
            if not self._current_char() or not self._current_char().isdigit():
                # 指数后没有数字，报错
                self._advance()
                error = InvalidNumberError(value, start_line, start_column)
                self.errors.record(error)
                return Token(
                    type=TokenType.ERROR,
                    value=value,
                    line=start_line,
                    column=start_column,
                    length=self.position - start_pos
                )
            while True:
                char = self._current_char()
                if char is None or not char.isdigit():
                    break
                value += char
                self._advance()

        # 浮点数
        if has_dot or has_exponent:
            return Token(
                type=TokenType.FLOAT,
                value=value,
                line=start_line,
                column=start_column,
                length=self.position - start_pos
            )

        # 整数
        return Token(
            type=TokenType.INTEGER,
            value=value,
            line=start_line,
            column=start_column,
            length=self.position - start_pos
        )

    def _read_string(self) -> Token:
        """读取字符串常量"""
        start_line = self.line
        start_column = self.column
        start_pos = self.position
        quote_char = self._advance()  # 记录引号类型并消费
        result = quote_char

        while True:
            char = self._current_char()
            if char is None:
                error = UnclosedStringError(start_line, start_column)
                self.errors.record(error)
                return Token(
                    type=TokenType.ERROR,
                    value=result,
                    line=start_line,
                    column=start_column,
                    length=self.position - start_pos
                )

            if char == '\\':
                # 转义字符
                result += self._advance()  # 添加 '\'
                result += self._advance()  # 添加转义字符
                continue

            if char == quote_char:
                # 结束引号
                result += self._advance()
                return Token(
                    type=TokenType.STRING,
                    value=result,
                    line=start_line,
                    column=start_column,
                    length=self.position - start_pos
                )

            if char == '\n':
                # 字符串内不允许换行（除非用转义）
                error = UnclosedStringError(start_line, start_column)
                self.errors.record(error)
                self._advance()
                return Token(
                    type=TokenType.ERROR,
                    value=result,
                    line=start_line,
                    column=start_column,
                    length=self.position - start_pos
                )

            result += self._advance()

    def _read_comment(self) -> Token:
        """读取注释"""
        start_line = self.line
        start_column = self.column
        start_pos = self.position
        first_char = self._advance()  # 消费第一个 /
        second_char = self._current_char()

        # 单行注释
        if second_char == '/':
            value = '//'
            self._advance()  # 消费第二个 /
            while True:
                char = self._current_char()
                if char is None or char == '\n':
                    break
                value += self._advance()
            return Token(
                type=TokenType.COMMENT,
                value=value,
                line=start_line,
                column=start_column,
                length=self.position - start_pos
            )

        # 多行注释
        if second_char == '*':
            value = '/*'
            self._advance()  # 消费 *
            while True:
                char = self._current_char()
                if char is None:
                    error = UnclosedCommentError(start_line, start_column)
                    self.errors.record(error)
                    return Token(
                        type=TokenType.ERROR,
                        value=value,
                        line=start_line,
                        column=start_column,
                        length=self.position - start_pos
                    )

                if char == '*' and self._peek(1) == '/':
                    value += self._advance()
                    value += self._advance()
                    return Token(
                        type=TokenType.COMMENT,
                        value=value,
                        line=start_line,
                        column=start_column,
                        length=self.position - start_pos
                    )

                value += self._advance()

        # 不应该到达这里
        return Token(
            type=TokenType.ERROR,
            value='/',
            line=start_line,
            column=start_column,
            length=1
        )

    def _read_operator(self) -> Token:
        """读取运算符"""
        start_line = self.line
        start_column = self.column
        start_pos = self.position
        char = self._current_char()

        # 先检查三字符运算符
        three_char = char + (self._peek(1) or '') + (self._peek(2) or '')
        if three_char in MULTI_CHAR_OPERATORS:
            self._advance()
            self._advance()
            self._advance()
            return Token(
                type=TokenType.OPERATOR,
                value=three_char,
                line=start_line,
                column=start_column,
                length=3
            )

        # 检查两字符运算符
        two_char = char + (self._peek(1) or '')
        if two_char in MULTI_CHAR_OPERATORS:
            self._advance()
            self._advance()
            return Token(
                type=TokenType.OPERATOR,
                value=two_char,
                line=start_line,
                column=start_column,
                length=2
            )

        # 单字符运算符
        if char in SINGLE_CHAR_OPERATORS:
            self._advance()
            return Token(
                type=TokenType.OPERATOR,
                value=char,
                line=start_line,
                column=start_column,
                length=1
            )

        # 不应该到达这里
        return Token(
            type=TokenType.ERROR,
            value=char,
            line=start_line,
            column=start_column,
            length=1
        )

    def _read_delimiter(self) -> Token:
        """读取分隔符"""
        start_line = self.line
        start_column = self.column
        start_pos = self.position
        char = self._current_char()

        # 检查省略号
        if char == '.' and self._peek(1) == '.' and self._peek(2) == '.':
            self._advance()
            self._advance()
            self._advance()
            return Token(
                type=TokenType.DELIMITER,
                value='...',
                line=start_line,
                column=start_column,
                length=3
            )

        # 其他分隔符
        if char in DELIMITERS:
            self._advance()
            return Token(
                type=TokenType.DELIMITER,
                value=char,
                line=start_line,
                column=start_column,
                length=1
            )

        # 不应该到达这里
        return Token(
            type=TokenType.ERROR,
            value=char,
            line=start_line,
            column=start_column,
            length=1
        )


def tokenize(source: str) -> tuple[list[Token], list[LexerError]]:
    """
    便捷函数：对源代码进行词法分析

    Args:
        source: 源代码字符串

    Returns:
        (tokens, errors) 元组
    """
    lexer = Lexer(source)
    tokens = lexer.tokenize()
    return tokens, lexer.errors.get_errors()


if __name__ == '__main__':
    # 简单测试
    test_code = '''
    int main() {
        int a = 42;
        float b = 3.14;
        char* s = "hello";
        // this is a comment
        return 0;
    }
    '''

    tokens, errors = tokenize(test_code)

    print("=== Tokens ===")
    for token in tokens:
        print(token)

    if errors:
        print("\n=== Errors ===")
        for error in errors:
            print(error)
