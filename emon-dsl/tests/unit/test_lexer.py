"""
Emon DSL Lexer Tests
Validates tokenization of Emon DSL programs.
"""

import unittest
from emon.lexer import Lexer, tokenize
from emon.tokens import TokenType, Token


class TestLexerKeywords(unittest.TestCase):
    """Test Emon DSL keyword recognition."""

    def test_struct_keywords(self):
        for kw in ['tool', 'option', 'observe', 'every', 'begin', 'end']:
            tokens, errors = tokenize(kw)
            self.assertEqual(len(errors), 0)
            self.assertEqual(tokens[0].type, TokenType.KEYWORD)
            self.assertEqual(tokens[0].value, kw)

    def test_clause_keywords(self):
        for kw in ['where', 'measure', 'when']:
            tokens, errors = tokenize(kw)
            self.assertEqual(len(errors), 0)
            self.assertEqual(tokens[0].type, TokenType.KEYWORD)

    def test_target_keywords(self):
        for kw in ['syscall', 'kernel', 'tracepoint', 'uprobe',
                    'sched', 'file', 'net']:
            tokens, errors = tokenize(kw)
            self.assertEqual(len(errors), 0)
            self.assertEqual(tokens[0].type, TokenType.KEYWORD)

    def test_measure_keywords(self):
        for kw in ['latency', 'count', 'size', 'retval', 'stack']:
            tokens, errors = tokenize(kw)
            self.assertEqual(len(errors), 0)
            self.assertEqual(tokens[0].type, TokenType.KEYWORD)

    def test_agg_func_keywords(self):
        for kw in ['count', 'sum', 'avg', 'min', 'max', 'hist', 'lhist']:
            tokens, errors = tokenize(kw)
            self.assertEqual(len(errors), 0)
            self.assertEqual(tokens[0].type, TokenType.KEYWORD)

    def test_action_keywords(self):
        for kw in ['emit', 'print', 'let', 'if', 'else']:
            tokens, errors = tokenize(kw)
            self.assertEqual(len(errors), 0)
            self.assertEqual(tokens[0].type, TokenType.KEYWORD)


class TestLexerLiterals(unittest.TestCase):
    """Test literal token recognition."""

    def test_integer(self):
        tokens, errors = tokenize("42")
        self.assertEqual(tokens[0].type, TokenType.INTEGER)
        self.assertEqual(tokens[0].value, "42")

    def test_time_literals(self):
        cases = [("100us", "100us"), ("1ms", "1ms"), ("2s", "2s"),
                 ("500ns", "500ns")]
        for src, expected in cases:
            tokens, errors = tokenize(src)
            self.assertEqual(len(errors), 0, f"Failed on {src}")
            self.assertEqual(tokens[0].type, TokenType.TIME_LIT)
            self.assertEqual(tokens[0].value, expected)

    def test_size_literals(self):
        cases = [("256KB", "256KB"), ("1MB", "1MB"), ("4096B", "4096B")]
        for src, expected in cases:
            tokens, errors = tokenize(src)
            self.assertEqual(len(errors), 0)
            self.assertEqual(tokens[0].type, TokenType.SIZE_LIT)

    def test_bool_literals(self):
        for val in ['true', 'false']:
            tokens, errors = tokenize(val)
            self.assertEqual(len(errors), 0)
            self.assertEqual(tokens[0].type, TokenType.BOOL_LIT)

    def test_string(self):
        tokens, errors = tokenize('"hello world"')
        self.assertEqual(len(errors), 0)
        self.assertEqual(tokens[0].type, TokenType.STRING)

    def test_unclosed_string(self):
        tokens, errors = tokenize('"hello')
        self.assertGreater(len(errors), 0)


class TestLexerAggIdent(unittest.TestCase):
    """Test aggregation identifier (@name) recognition."""

    def test_agg_ident(self):
        cases = ['@count', '@avg_latency', '@latency_hist', '@x']
        for src in cases:
            tokens, errors = tokenize(src)
            self.assertEqual(len(errors), 0)
            self.assertEqual(tokens[0].type, TokenType.AGG_IDENT)
            self.assertEqual(tokens[0].value, src)


class TestLexerOperators(unittest.TestCase):
    """Test operator recognition."""

    def test_arithmetic(self):
        tokens, errors = tokenize("+ - * / %")
        ops = [t.value for t in tokens if t.type == TokenType.OPERATOR]
        self.assertEqual(ops, ['+', '-', '*', '/', '%'])

    def test_comparison(self):
        tokens, errors = tokenize("== != < > <= >=")
        ops = [t.value for t in tokens if t.type == TokenType.OPERATOR]
        self.assertEqual(ops, ['==', '!=', '<', '>', '<=', '>='])

    def test_logical(self):
        tokens, errors = tokenize("&& || !")
        ops = [t.value for t in tokens if t.type == TokenType.OPERATOR]
        self.assertEqual(ops, ['&&', '||', '!'])

    def test_assignment(self):
        tokens, errors = tokenize("=")
        self.assertEqual(tokens[0].type, TokenType.OPERATOR)
        self.assertEqual(tokens[0].value, '=')


class TestLexerDelimiters(unittest.TestCase):
    """Test delimiter recognition."""

    def test_braces(self):
        tokens, errors = tokenize("{}")
        dels = [t.value for t in tokens if t.type == TokenType.DELIMITER]
        self.assertEqual(dels, ['{', '}'])

    def test_brackets(self):
        tokens, errors = tokenize("[]")
        dels = [t.value for t in tokens if t.type == TokenType.DELIMITER]
        self.assertEqual(dels, ['[', ']'])

    def test_parens(self):
        tokens, errors = tokenize("()")
        dels = [t.value for t in tokens if t.type == TokenType.DELIMITER]
        self.assertEqual(dels, ['(', ')'])

    def test_semicolon_comma(self):
        tokens, errors = tokenize(";,.")
        dels = [t.value for t in tokens if t.type == TokenType.DELIMITER]
        self.assertEqual(dels, [';', ',', '.'])


class TestLexerComments(unittest.TestCase):
    """Test comment handling."""

    def test_line_comment(self):
        tokens, errors = tokenize("// this is a comment\nobserve")
        comment_tokens = [t for t in tokens if t.type == TokenType.COMMENT]
        self.assertEqual(len(comment_tokens), 1)

    def test_block_comment(self):
        tokens, errors = tokenize("/* block\ncomment */observe")
        comment_tokens = [t for t in tokens if t.type == TokenType.COMMENT]
        self.assertEqual(len(comment_tokens), 1)

    def test_unclosed_block_comment(self):
        tokens, errors = tokenize("/* not closed")
        self.assertGreater(len(errors), 0)


class TestLexerCompleteProgram(unittest.TestCase):
    """Test tokenization of complete Emon DSL programs."""

    def test_tool_declaration(self):
        code = 'tool syscall_latency_monitor { option target_pid = 0; }'
        tokens, errors = tokenize(code)
        self.assertEqual(len(errors), 0)
        types = [t.type for t in tokens if t.type != TokenType.EOF]
        self.assertIn(TokenType.KEYWORD, types)
        self.assertIn(TokenType.IDENTIFIER, types)
        self.assertIn(TokenType.INTEGER, types)

    def test_observe_syscall(self):
        code = (
            "observe syscall(\"read\", \"write\")\n"
            "where pid == 100\n"
            "measure latency\n"
            "when latency > 1ms\n"
            "{\n"
            "    @count[comm] = count();\n"
            "}"
        )
        tokens, errors = tokenize(code)
        self.assertEqual(len(errors), 0)
        non_eof = [t for t in tokens if t.type != TokenType.EOF]
        self.assertGreater(len(non_eof), 10)

    def test_emit_statement(self):
        code = (
            "emit {\n"
            "    time = nsecs;\n"
            "    comm = comm;\n"
            "    pid = pid;\n"
            "};"
        )
        tokens, errors = tokenize(code)
        self.assertEqual(len(errors), 0)

    def test_every_statement(self):
        code = 'every 1s { print(@count); }'
        tokens, errors = tokenize(code)
        self.assertEqual(len(errors), 0)
        agg_tokens = [t for t in tokens if t.type == TokenType.AGG_IDENT]
        self.assertEqual(len(agg_tokens), 1)

    def test_full_syscall_monitor(self):
        code = (
            "tool syscall_latency_monitor {\n"
            "    option target_pid   = 0;\n"
            "    option min_latency  = 100us;\n"
            "    option interval     = 1s;\n"
            "    option top_n        = 10;\n"
            "}\n"
            "\n"
            "observe syscall(\"read\", \"write\", \"openat\")\n"
            "where target_pid == 0 || pid == target_pid\n"
            "measure latency\n"
            "when latency > min_latency\n"
            "{\n"
            "    @count[comm, pid, syscall]        = count();\n"
            "    @avg_latency[comm, pid, syscall]  = avg(latency);\n"
            "    @latency_hist[comm, pid, syscall] = hist(latency);\n"
            "\n"
            "    emit {\n"
            "        time    = nsecs;\n"
            "        comm    = comm;\n"
            "        pid     = pid;\n"
            "        latency = latency;\n"
            "    };\n"
            "}\n"
            "\n"
            "every interval {\n"
            '    print("==== summary ====");\n'
            "    print(top(@count, top_n));\n"
            "    print(@avg_latency);\n"
            "}"
        )
        tokens, errors = tokenize(code)
        self.assertEqual(len(errors), 0)
        non_eof = [t for t in tokens if t.type != TokenType.EOF]
        self.assertGreater(len(non_eof), 50)
        types_found = {t.type for t in tokens}
        self.assertIn(TokenType.AGG_IDENT, types_found)
        self.assertIn(TokenType.TIME_LIT, types_found)
        self.assertIn(TokenType.STRING, types_found)


class TestLexerPosition(unittest.TestCase):
    """Test accurate position tracking."""

    def test_line_numbers(self):
        tokens, errors = tokenize("a\nb\nc")
        self.assertEqual(tokens[0].line, 1)
        self.assertEqual(tokens[1].line, 2)
        self.assertEqual(tokens[2].line, 3)


if __name__ == '__main__':
    unittest.main()
