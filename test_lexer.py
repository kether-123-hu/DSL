"""
词法分析器测试模块
验证词法分析器的各项功能
"""

import unittest
from lexer import Lexer, tokenize
from tokens import TokenType, Token
from error import LexerError


class TestLexerBasic(unittest.TestCase):
    """基础功能测试"""

    def test_empty_input(self):
        """测试空输入"""
        tokens, errors = tokenize("")
        self.assertEqual(len(tokens), 1)  # 只有 EOF
        self.assertEqual(tokens[0].type, TokenType.EOF)
        self.assertEqual(len(errors), 0)

    def test_whitespace_only(self):
        """测试仅空白字符"""
        tokens, errors = tokenize("   \t\t   ")
        self.assertEqual(len(tokens), 1)  # 只有 EOF
        self.assertEqual(tokens[0].type, TokenType.EOF)
        self.assertEqual(len(errors), 0)

    def test_newline_only(self):
        """测试仅换行符"""
        tokens, errors = tokenize("\n\n\n")
        self.assertEqual(len(tokens), 1)
        self.assertEqual(tokens[0].type, TokenType.EOF)


class TestLexerKeywords(unittest.TestCase):
    """关键字测试"""

    def test_single_keyword(self):
        """测试单个关键字"""
        tokens, errors = tokenize("if")
        self.assertEqual(len(tokens), 2)  # if + EOF
        self.assertEqual(tokens[0].type, TokenType.KEYWORD)
        self.assertEqual(tokens[0].value, "if")

    def test_all_keywords(self):
        """测试所有关键字"""
        keywords = "if else while for do switch case default break continue return goto sizeof typeof int long short char float double void signed unsigned const static extern register volatile struct union enum typedef TRUE FALSE NULL"
        tokens, errors = tokenize(keywords)
        keyword_tokens = [t for t in tokens if t.type == TokenType.KEYWORD]
        self.assertEqual(len(keyword_tokens), len(keywords.split()))

    def test_keyword_case_sensitive(self):
        """测试关键字大小写敏感"""
        tokens, errors = tokenize("IF If iF if")
        values = [t.value for t in tokens if t.type == TokenType.KEYWORD]
        self.assertEqual(values, ["if"])  # 只有小写 if 是关键字


class TestLexerIdentifier(unittest.TestCase):
    """标识符测试"""

    def test_simple_identifier(self):
        """测试简单标识符"""
        tokens, errors = tokenize("variable")
        self.assertEqual(tokens[0].type, TokenType.IDENTIFIER)
        self.assertEqual(tokens[0].value, "variable")

    def test_identifier_with_underscore(self):
        """测试带下划线的标识符"""
        tokens, errors = tokenize("_private_var")
        self.assertEqual(tokens[0].type, TokenType.IDENTIFIER)
        self.assertEqual(tokens[0].value, "_private_var")

    def test_identifier_with_numbers(self):
        """测试带数字的标识符"""
        tokens, errors = tokenize("var123")
        self.assertEqual(tokens[0].type, TokenType.IDENTIFIER)
        self.assertEqual(tokens[0].value, "var123")

    def test_camel_case_identifier(self):
        """测试驼峰命名标识符"""
        tokens, errors = tokenize("myVariableName123")
        self.assertEqual(tokens[0].type, TokenType.IDENTIFIER)
        self.assertEqual(tokens[0].value, "myVariableName123")


class TestLexerNumbers(unittest.TestCase):
    """数字常量测试"""

    def test_integer(self):
        """测试十进制整数"""
        tokens, errors = tokenize("42")
        self.assertEqual(tokens[0].type, TokenType.INTEGER)
        self.assertEqual(tokens[0].value, "42")

    def test_negative_integer(self):
        """测试负整数"""
        tokens, errors = tokenize("-17")
        # - 是运算符，17 是整数
        self.assertEqual(tokens[0].type, TokenType.OPERATOR)
        self.assertEqual(tokens[1].type, TokenType.INTEGER)
        self.assertEqual(tokens[1].value, "17")

    def test_hex_integer(self):
        """测试十六进制整数"""
        tokens, errors = tokenize("0xFF")
        self.assertEqual(tokens[0].type, TokenType.INTEGER)
        self.assertEqual(tokens[0].value, "0xFF")

    def test_binary_integer(self):
        """测试二进制整数"""
        tokens, errors = tokenize("0b1010")
        self.assertEqual(tokens[0].type, TokenType.INTEGER)
        self.assertEqual(tokens[0].value, "0b1010")

    def test_float(self):
        """测试浮点数"""
        tokens, errors = tokenize("3.14")
        self.assertEqual(tokens[0].type, TokenType.FLOAT)
        self.assertEqual(tokens[0].value, "3.14")

    def test_float_with_exponent(self):
        """测试带指数的浮点数"""
        tokens, errors = tokenize("1e10")
        self.assertEqual(tokens[0].type, TokenType.FLOAT)
        self.assertEqual(tokens[0].value, "1e10")

    def test_float_negative_exponent(self):
        """测试负指数浮点数"""
        tokens, errors = tokenize("1.5e-3")
        self.assertEqual(tokens[0].type, TokenType.FLOAT)
        self.assertEqual(tokens[0].value, "1.5e-3")


class TestLexerStrings(unittest.TestCase):
    """字符串常量测试"""

    def test_simple_string(self):
        """测试简单字符串"""
        tokens, errors = tokenize('"hello"')
        self.assertEqual(tokens[0].type, TokenType.STRING)
        self.assertEqual(tokens[0].value, '"hello"')

    def test_single_quote_string(self):
        """测试单引号字符串"""
        tokens, errors = tokenize("'world'")
        self.assertEqual(tokens[0].type, TokenType.STRING)
        self.assertEqual(tokens[0].value, "'world'")

    def test_string_with_escape(self):
        """测试带转义字符的字符串"""
        tokens, errors = tokenize('"hello\\nworld"')
        self.assertEqual(tokens[0].type, TokenType.STRING)
        self.assertEqual(tokens[0].value, '"hello\\nworld"')

    def test_unclosed_string(self):
        """测试未闭合的字符串"""
        tokens, errors = tokenize('"hello')
        self.assertEqual(len(errors), 1)
        self.assertIn("未闭合", str(errors[0]))


class TestLexerOperators(unittest.TestCase):
    """运算符测试"""

    def test_arithmetic_operators(self):
        """测试算术运算符"""
        tokens, errors = tokenize("+ - * / %")
        ops = [t.value for t in tokens if t.type == TokenType.OPERATOR]
        self.assertEqual(ops, ["+", "-", "*", "/", "%"])

    def test_comparison_operators(self):
        """测试比较运算符"""
        tokens, errors = tokenize("== != < > <= >=")
        ops = [t.value for t in tokens if t.type == TokenType.OPERATOR]
        self.assertEqual(ops, ["==", "!=", "<", ">", "<=", ">="])

    def test_logical_operators(self):
        """测试逻辑运算符"""
        tokens, errors = tokenize("&& || !")
        ops = [t.value for t in tokens if t.type == TokenType.OPERATOR]
        self.assertEqual(ops, ["&&", "||", "!"])

    def test_increment_decrement(self):
        """测试自增自减运算符"""
        tokens, errors = tokenize("++ --")
        ops = [t.value for t in tokens if t.type == TokenType.OPERATOR]
        self.assertEqual(ops, ["++", "--"])

    def test_bitwise_operators(self):
        """测试位运算符"""
        tokens, errors = tokenize("& | ^ ~ << >>")
        ops = [t.value for t in tokens if t.type == TokenType.OPERATOR]
        self.assertEqual(ops, ["&", "|", "^", "~", "<<", ">>"])


class TestLexerDelimiters(unittest.TestCase):
    """分隔符测试"""

    def test_braces(self):
        """测试大括号"""
        tokens, errors = tokenize("{}")
        dels = [t.value for t in tokens if t.type == TokenType.DELIMITER]
        self.assertEqual(dels, ["{", "}"])

    def test_brackets(self):
        """测试中括号"""
        tokens, errors = tokenize("[]")
        dels = [t.value for t in tokens if t.type == TokenType.DELIMITER]
        self.assertEqual(dels, ["[", "]"])

    def test_parentheses(self):
        """测试小括号"""
        tokens, errors = tokenize("()")
        dels = [t.value for t in tokens if t.type == TokenType.DELIMITER]
        self.assertEqual(dels, ["(", ")"])

    def test_ellipsis(self):
        """测试省略号"""
        tokens, errors = tokenize("...")
        self.assertEqual(tokens[0].type, TokenType.DELIMITER)
        self.assertEqual(tokens[0].value, "...")


class TestLexerComments(unittest.TestCase):
    """注释测试"""

    def test_single_line_comment(self):
        """测试单行注释"""
        tokens, errors = tokenize("// this is a comment\nint a;")
        # 注释应该被识别
        comment_tokens = [t for t in tokens if t.type == TokenType.COMMENT]
        self.assertEqual(len(comment_tokens), 1)
        self.assertEqual(comment_tokens[0].value, "// this is a comment")

    def test_multi_line_comment(self):
        """测试多行注释"""
        tokens, errors = tokenize("/* comment\n   spanning\n   lines */int a;")
        comment_tokens = [t for t in tokens if t.type == TokenType.COMMENT]
        self.assertEqual(len(comment_tokens), 1)

    def test_unclosed_multi_line_comment(self):
        """测试未闭合的多行注释"""
        tokens, errors = tokenize("/* comment not closed")
        self.assertGreaterEqual(len(errors), 1)
        self.assertIn("未闭合", str(errors[0]))


class TestLexerPosition(unittest.TestCase):
    """位置信息测试"""

    def test_line_number(self):
        """测试行号"""
        tokens, errors = tokenize("a\nb\nc")
        a_token = tokens[0]
        b_token = tokens[1]
        c_token = tokens[2]
        self.assertEqual(a_token.line, 1)
        self.assertEqual(b_token.line, 2)
        self.assertEqual(c_token.line, 3)

    def test_column_number(self):
        """测试列号"""
        # "abc" 是一个标识符，整个在 column 1，长度 3
        tokens, errors = tokenize("abc")
        self.assertEqual(tokens[0].type, TokenType.IDENTIFIER)
        self.assertEqual(tokens[0].column, 1)
        self.assertEqual(tokens[0].length, 3)
        # EOF 在 column 4
        self.assertEqual(tokens[1].column, 4)


class TestLexerErrors(unittest.TestCase):
    """错误处理测试"""

    def test_illegal_character(self):
        """测试非法字符"""
        tokens, errors = tokenize("@#$")
        error_tokens = [t for t in tokens if t.type == TokenType.ERROR]
        self.assertEqual(len(error_tokens), 3)
        self.assertEqual(len(errors), 3)


class TestLexerCompleteExamples(unittest.TestCase):
    """完整示例测试"""

    def test_simple_function(self):
        """测试简单函数"""
        code = '''
        int add(int a, int b) {
            return a + b;
        }
        '''
        tokens, errors = tokenize(code)
        self.assertEqual(len(errors), 0)
        # 检查关键字
        keyword_count = len([t for t in tokens if t.type == TokenType.KEYWORD])
        self.assertGreater(keyword_count, 0)

    def test_if_statement(self):
        """测试 if 语句"""
        code = '''
        if (x > 0) {
            return x;
        } else {
            return -x;
        }
        '''
        tokens, errors = tokenize(code)
        self.assertEqual(len(errors), 0)
        # 检查标识符
        identifiers = [t.value for t in tokens if t.type == TokenType.IDENTIFIER]
        self.assertIn("x", identifiers)

    def test_complex_expression(self):
        """测试复杂表达式"""
        code = "result = (a + b) * c - d / e % f;"
        tokens, errors = tokenize(code)
        self.assertEqual(len(errors), 0)
        # 验证运算符
        ops = [t.value for t in tokens if t.type == TokenType.OPERATOR]
        self.assertIn("=", ops)
        self.assertIn("+", ops)
        self.assertIn("*", ops)


class TestLexerIntegration(unittest.TestCase):
    """集成测试"""

    def test_full_c_program(self):
        """测试完整的 C 程序片段"""
        code = '''
        // Calculate factorial
        int factorial(int n) {
            if (n <= 1) {
                return 1;
            }
            return n * factorial(n - 1);
        }

        int main() {
            int result = factorial(5);
            printf("Result: %d\\n", result);
            return 0;
        }
        '''
        tokens, errors = tokenize(code)
        # 不应该有严重错误
        critical_errors = [e for e in errors if not isinstance(e, (UnclosedCommentError,))]
        self.assertEqual(len(critical_errors), 0)


class TestTokenHelpers(unittest.TestCase):
    """Token 辅助方法测试"""

    def test_token_is_keyword(self):
        """测试 is_keyword 方法"""
        tokens, _ = tokenize("if while for")
        self.assertTrue(tokens[0].is_keyword())
        self.assertTrue(tokens[1].is_keyword())
        self.assertTrue(tokens[2].is_keyword())

    def test_token_is_identifier(self):
        """测试 is_identifier 方法"""
        tokens, _ = tokenize("variable")
        self.assertTrue(tokens[0].is_identifier())

    def test_token_is_number(self):
        """测试 is_number 方法"""
        tokens, _ = tokenize("42 3.14")
        self.assertTrue(tokens[0].is_number())
        self.assertTrue(tokens[1].is_number())

    def test_token_is_operator(self):
        """测试 is_operator 方法"""
        tokens, _ = tokenize("+ - * /")
        self.assertTrue(tokens[0].is_operator())
        self.assertTrue(tokens[0].is_operator("+"))
        self.assertFalse(tokens[0].is_operator("-"))


if __name__ == '__main__':
    unittest.main()
