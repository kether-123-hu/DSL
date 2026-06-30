# ===================================================================
# test_lexer.py —— Emon DSL 词法分析器测试
# ===================================================================
#
# 【本文件的作用】
# 对词法分析器（lexer.py）进行单元测试，验证 Token 识别的正确性。
# 词法分析是编译器的第一阶段——如果这里出错，后续所有阶段都会偏离。
#
# 【测试覆盖范围】
#   1. 关键字识别        — tool, observe, emit, every 等是否被正确识别
#   2. 字面量识别        — 整数、字符串、时间(1ms)、大小(1MB)、布尔值
#   3. 聚合标识符识别    — @count, @avg_latency 等
#   4. 运算符识别        — 算术(+,-,*,/,%)、比较(==,!=,<,>)、逻辑(&&,||,!)
#   5. 分隔符识别        — 花括号{}、方括号[]、圆括号()、分号;、逗号,
#   6. 注释处理          — 单行注释 // 和块注释 /* */
#   7. 完整程序分词      — 对完整 .emon 程序进行端到端分词验证
#   8. 位置追踪          — 验证 Token 的行号是否正确
#
# 【测试运行方式】
#   python3 -m pytest tests/test_lexer.py -v
#   或: python3 -m unittest tests.test_lexer -v
# ===================================================================

import unittest
from emon.lexer import Lexer, tokenize
from emon.tokens import TokenType, Token


# ===================================================================
# TestLexerKeywords —— 关键字识别测试
# ===================================================================

class TestLexerKeywords(unittest.TestCase):
    """
    测试 Emon DSL 所有关键字的词法识别。
    
    关键字是语言的"骨架"，词法分析器必须能区分：
    - 结构关键字（tool, observe, every, begin, end）
    - 子句关键字（where, measure, when）
    - 目标关键字（syscall, kernel, tracepoint 等）
    - 度量关键字（latency, count, size 等）
    - 聚合函数关键字（count, sum, avg 等）
    - 动作关键字（emit, print, let, if, else）
    """

    def test_struct_keywords(self):
        """测试结构关键字: tool, option, observe, every, begin, end"""
        for kw in ['tool', 'option', 'observe', 'every', 'begin', 'end']:
            tokens, errors = tokenize(kw)
            self.assertEqual(len(errors), 0)
            self.assertEqual(tokens[0].type, TokenType.KEYWORD)
            self.assertEqual(tokens[0].value, kw)

    def test_clause_keywords(self):
        """测试子句关键字: where, measure, when"""
        for kw in ['where', 'measure', 'when']:
            tokens, errors = tokenize(kw)
            self.assertEqual(len(errors), 0)
            self.assertEqual(tokens[0].type, TokenType.KEYWORD)

    def test_target_keywords(self):
        """测试观测目标关键字: syscall, kernel, tracepoint, uprobe, sched, file, net"""
        for kw in ['syscall', 'kernel', 'tracepoint', 'uprobe',
                    'sched', 'file', 'net']:
            tokens, errors = tokenize(kw)
            self.assertEqual(len(errors), 0)
            self.assertEqual(tokens[0].type, TokenType.KEYWORD)

    def test_measure_keywords(self):
        """测试度量关键字: latency, count, size, retval, stack"""
        for kw in ['latency', 'count', 'size', 'retval', 'stack']:
            tokens, errors = tokenize(kw)
            self.assertEqual(len(errors), 0)
            self.assertEqual(tokens[0].type, TokenType.KEYWORD)

    def test_agg_func_keywords(self):
        """测试聚合函数关键字: count, sum, avg, min, max, hist, lhist"""
        for kw in ['count', 'sum', 'avg', 'min', 'max', 'hist', 'lhist']:
            tokens, errors = tokenize(kw)
            self.assertEqual(len(errors), 0)
            self.assertEqual(tokens[0].type, TokenType.KEYWORD)

    def test_action_keywords(self):
        """测试动作关键字: emit, print, let, if, else"""
        for kw in ['emit', 'print', 'let', 'if', 'else']:
            tokens, errors = tokenize(kw)
            self.assertEqual(len(errors), 0)
            self.assertEqual(tokens[0].type, TokenType.KEYWORD)


# ===================================================================
# TestLexerLiterals —— 字面量识别测试
# ===================================================================

class TestLexerLiterals(unittest.TestCase):
    """
    测试各种字面量的 Token 识别。
    
    字面量是直接写在源码中的常量值，包括：
    - 整数（42）
    - 时间（100us, 1ms, 2s）
    - 大小（256KB, 1MB）
    - 布尔值（true, false）
    - 字符串（"hello world"）
    """

    def test_integer(self):
        """测试整数识别: 42 → TokenType.INTEGER"""
        tokens, errors = tokenize("42")
        self.assertEqual(tokens[0].type, TokenType.INTEGER)
        self.assertEqual(tokens[0].value, "42")

    def test_time_literals(self):
        """测试时间字面量: 100us, 1ms, 2s, 500ns → TokenType.TIME_LIT"""
        cases = [("100us", "100us"), ("1ms", "1ms"), ("2s", "2s"),
                 ("500ns", "500ns")]
        for src, expected in cases:
            tokens, errors = tokenize(src)
            self.assertEqual(len(errors), 0, f"Failed on {src}")
            self.assertEqual(tokens[0].type, TokenType.TIME_LIT)
            self.assertEqual(tokens[0].value, expected)

    def test_size_literals(self):
        """测试大小字面量: 256KB, 1MB, 4096B → TokenType.SIZE_LIT"""
        cases = [("256KB", "256KB"), ("1MB", "1MB"), ("4096B", "4096B")]
        for src, expected in cases:
            tokens, errors = tokenize(src)
            self.assertEqual(len(errors), 0)
            self.assertEqual(tokens[0].type, TokenType.SIZE_LIT)

    def test_bool_literals(self):
        """测试布尔字面量: true, false → TokenType.BOOL_LIT"""
        for val in ['true', 'false']:
            tokens, errors = tokenize(val)
            self.assertEqual(len(errors), 0)
            self.assertEqual(tokens[0].type, TokenType.BOOL_LIT)

    def test_string(self):
        """测试字符串字面量: "hello world" → TokenType.STRING"""
        tokens, errors = tokenize('"hello world"')
        self.assertEqual(len(errors), 0)
        self.assertEqual(tokens[0].type, TokenType.STRING)

    def test_unclosed_string(self):
        """测试未闭合字符串: '"hello 应产生词法错误（UnclosedStringError）"""
        tokens, errors = tokenize('"hello')
        self.assertGreater(len(errors), 0)


# ===================================================================
# TestLexerAggIdent —— 聚合标识符识别测试
# ===================================================================

class TestLexerAggIdent(unittest.TestCase):
    """
    测试以 @ 开头的聚合标识符的识别。
    
    在 Emon DSL 中，@name 表示一个聚合变量（对应 eBPF map）。
    例如：@count 表示一个名为 count 的聚合计数器。
    """

    def test_agg_ident(self):
        """测试 @count, @avg_latency, @latency_hist, @x → TokenType.AGG_IDENT"""
        cases = ['@count', '@avg_latency', '@latency_hist', '@x']
        for src in cases:
            tokens, errors = tokenize(src)
            self.assertEqual(len(errors), 0)
            self.assertEqual(tokens[0].type, TokenType.AGG_IDENT)
            self.assertEqual(tokens[0].value, src)


# ===================================================================
# TestLexerOperators —— 运算符识别测试
# ===================================================================

class TestLexerOperators(unittest.TestCase):
    """
    测试各类运算符的 Token 识别。
    
    运算符分为三类：
    - 算术运算符: +, -, *, /, %
    - 比较运算符: ==, !=, <, >, <=, >=
    - 逻辑运算符: &&, ||, !
    - 赋值运算符: =
    """

    def test_arithmetic(self):
        """测试算术运算符: + - * / % → TokenType.OPERATOR"""
        tokens, errors = tokenize("+ - * / %")
        ops = [t.value for t in tokens if t.type == TokenType.OPERATOR]
        self.assertEqual(ops, ['+', '-', '*', '/', '%'])

    def test_comparison(self):
        """测试比较运算符: == != < > <= >= → TokenType.OPERATOR"""
        tokens, errors = tokenize("== != < > <= >=")
        ops = [t.value for t in tokens if t.type == TokenType.OPERATOR]
        self.assertEqual(ops, ['==', '!=', '<', '>', '<=', '>='])

    def test_logical(self):
        """测试逻辑运算符: && || ! → TokenType.OPERATOR"""
        tokens, errors = tokenize("&& || !")
        ops = [t.value for t in tokens if t.type == TokenType.OPERATOR]
        self.assertEqual(ops, ['&&', '||', '!'])

    def test_assignment(self):
        """测试赋值运算符: = → TokenType.OPERATOR"""
        tokens, errors = tokenize("=")
        self.assertEqual(tokens[0].type, TokenType.OPERATOR)
        self.assertEqual(tokens[0].value, '=')


# ===================================================================
# TestLexerDelimiters —— 分隔符识别测试
# ===================================================================

class TestLexerDelimiters(unittest.TestCase):
    """
    测试各类分隔符的 Token 识别。
    
    分隔符用于界定代码块、参数列表等结构：
    - 花括号 {}: 代码块
    - 方括号 []: 聚合 key 列表
    - 圆括号 (): 函数参数
    - 分号 ;: 语句结束
    - 逗号 ,: 参数/列表分隔
    - 点 .: 类别分隔（如 tracepoint 中的 cat:name）
    """

    def test_braces(self):
        """测试花括号: {} → TokenType.DELIMITER"""
        tokens, errors = tokenize("{}")
        dels = [t.value for t in tokens if t.type == TokenType.DELIMITER]
        self.assertEqual(dels, ['{', '}'])

    def test_brackets(self):
        """测试方括号: [] → TokenType.DELIMITER"""
        tokens, errors = tokenize("[]")
        dels = [t.value for t in tokens if t.type == TokenType.DELIMITER]
        self.assertEqual(dels, ['[', ']'])

    def test_parens(self):
        """测试圆括号: () → TokenType.DELIMITER"""
        tokens, errors = tokenize("()")
        dels = [t.value for t in tokens if t.type == TokenType.DELIMITER]
        self.assertEqual(dels, ['(', ')'])

    def test_semicolon_comma(self):
        """测试分号和逗号: ; , . → TokenType.DELIMITER"""
        tokens, errors = tokenize(";,.")
        dels = [t.value for t in tokens if t.type == TokenType.DELIMITER]
        self.assertEqual(dels, [';', ',', '.'])


# ===================================================================
# TestLexerComments —— 注释处理测试
# ===================================================================

class TestLexerComments(unittest.TestCase):
    """
    测试注释的正确处理。
    
    Emon DSL 支持两种注释：
    - 单行注释: // 这是一行注释
    - 块注释:   /* 这是
                  多行注释 */
    注释在词法阶段被识别为 COMMENT Token，后续阶段会忽略它们。
    """

    def test_line_comment(self):
        """测试单行注释: // this is a comment → TokenType.COMMENT"""
        tokens, errors = tokenize("// this is a comment\nobserve")
        comment_tokens = [t for t in tokens if t.type == TokenType.COMMENT]
        self.assertEqual(len(comment_tokens), 1)

    def test_block_comment(self):
        """测试块注释: /* block\ncomment */ → TokenType.COMMENT"""
        tokens, errors = tokenize("/* block\ncomment */observe")
        comment_tokens = [t for t in tokens if t.type == TokenType.COMMENT]
        self.assertEqual(len(comment_tokens), 1)

    def test_unclosed_block_comment(self):
        """测试未闭合的块注释: /* not closed 应产生词法错误"""
        tokens, errors = tokenize("/* not closed")
        self.assertGreater(len(errors), 0)


# ===================================================================
# TestLexerCompleteProgram —— 完整程序分词测试
# ===================================================================

class TestLexerCompleteProgram(unittest.TestCase):
    """
    测试对完整 Emon DSL 程序的端到端分词。
    
    这些测试不检查每个 Token 的具体值，而是验证：
    - 分词过程不产生错误
    - 产生了足够多的 Token
    - 关键 Token 类型（如 AGG_IDENT, TIME_LIT, STRING）出现在结果中
    """

    def test_tool_declaration(self):
        """测试 tool 声明的分词"""
        code = 'tool syscall_latency_monitor { option target_pid = 0; }'
        tokens, errors = tokenize(code)
        self.assertEqual(len(errors), 0)
        types = [t.type for t in tokens if t.type != TokenType.EOF]
        self.assertIn(TokenType.KEYWORD, types)
        self.assertIn(TokenType.IDENTIFIER, types)
        self.assertIn(TokenType.INTEGER, types)

    def test_observe_syscall(self):
        """测试 observe syscall 语句的完整分词"""
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
        """测试 emit 语句的分词"""
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
        """测试 every 语句的分词: 验证 @count 被识别为 AGG_IDENT"""
        code = 'every 1s { print(@count); }'
        tokens, errors = tokenize(code)
        self.assertEqual(len(errors), 0)
        agg_tokens = [t for t in tokens if t.type == TokenType.AGG_IDENT]
        self.assertEqual(len(agg_tokens), 1)

    def test_full_syscall_monitor(self):
        """测试完整系统调用监控程序的分词（综合场景）"""
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


# ===================================================================
# TestLexerPosition —— 位置追踪测试
# ===================================================================

class TestLexerPosition(unittest.TestCase):
    """
    测试词法分析器的行号追踪功能。
    
    准确的错误位置信息对用户体验至关重要——
    当源代码有错误时，编译器应该能指出具体的行号。
    """

    def test_line_numbers(self):
        """测试多行输入时 Token 的行号是否正确递增"""
        tokens, errors = tokenize("a\nb\nc")
        self.assertEqual(tokens[0].line, 1)
        self.assertEqual(tokens[1].line, 2)
        self.assertEqual(tokens[2].line, 3)


# ===================================================================
# 测试入口
# ===================================================================

if __name__ == '__main__':
    unittest.main()
