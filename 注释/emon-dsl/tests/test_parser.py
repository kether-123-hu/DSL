# ===================================================================
# test_parser.py —— Emon DSL 语法分析器测试
# ===================================================================
#
# 【本文件的作用】
# 对语法分析器（parser.py）进行单元测试，验证 AST 构建的正确性。
# 语法分析是编译器的第二阶段，将 Token 序列转换为抽象语法树（AST）。
#
# 【测试覆盖范围】
#   1. 顶层程序结构    — tool 声明、option 列表
#   2. observe 语句    — 7 种观测目标（syscall, kernel, tracepoint, uprobe, sched, file, net）
#   3. 子句解析        — where, measure, when 子句
#   4. 动作语句        — 聚合(@agg)、emit、print、let、if/else
#   5. 生命周期语句    — every, begin, end
#   6. 表达式树        — 字面量、变量引用、二元/一元运算、函数调用
#   7. 示例文件        — 验证所有内置 .emon 示例都能正确解析
#
# 【AST 节点类型速查】
#   Program       — 根节点: 整个程序
#   ObserveRule   — observe 语句
#   EveryStmt     — every 周期任务
#   AggregationStmt — 聚合语句 @name[key] = fn(arg)
#   EmitStmt      — 事件输出语句
#   BinOpExpr     — 二元表达式 (a + b)
#   UnaryOpExpr   — 一元表达式 (!cond)
#   FuncCall      — 函数调用 top(@c, 10)
# ===================================================================

import unittest

from emon.parser import parse
from emon.ast_nodes import (
    Program, ToolDecl, ObserveRule, EveryStmt, BeginStmt, EndStmt,
    Hook, HookKind, WhereClause, WhenClause, MeasureClause,
    Metric, AggFn,
    AggregationStmt, EmitStmt, EmitField,
    PrintStmt, LetStmt, IfStmt,
    LitInt, LitStr, LitBool, LitTime, LitSize,
    VarRef, AggRef, BinOpExpr, UnaryOpExpr, FuncCall,
    BinOp, UnaryOp,
)


# ===================================================================
# TestParserProgram —— 顶层程序结构测试
# ===================================================================

class TestParserProgram(unittest.TestCase):
    """
    测试 tool 声明的解析。
    
    tool 是 Emon DSL 程序的根元素，语法为:
        tool <name> { (option <name> = <value>;)* }
    """

    def test_empty_tool(self):
        """测试空 tool 声明: tool t {} → Program 节点，无 option 无 stmts"""
        ast = parse("tool t {}")
        self.assertIsInstance(ast, Program)
        self.assertEqual(ast.tool.name, "t")
        self.assertEqual(ast.tool.options, [])
        self.assertEqual(ast.stmts, [])

    def test_tool_with_options(self):
        """测试带多种 option 的 tool: 支持整数、字符串、布尔、时间、大小五种类型"""
        src = """tool demo {
    option pid = 0;
    option name = "emon";
    option debug = true;
    option interval = 1s;
    option buf_size = 256KB;
}"""
        ast = parse(src)
        self.assertEqual(ast.tool.name, "demo")
        self.assertEqual(len(ast.tool.options), 5)
        self.assertEqual(ast.tool.options[0], ("pid", LitInt(0)))
        self.assertEqual(ast.tool.options[1], ("name", LitStr("emon")))
        self.assertEqual(ast.tool.options[2], ("debug", LitBool(True)))
        self.assertEqual(ast.tool.options[3], ("interval", LitTime("1s")))
        self.assertEqual(ast.tool.options[4], ("buf_size", LitSize("256KB")))


# ===================================================================
# TestParserObserve —— observe 语句解析测试
# ===================================================================

class TestParserObserve(unittest.TestCase):
    """
    测试 observe 语句的解析。
    
    observe 是 Emon DSL 的核心语句，用于声明要观测的事件源。
    支持 7 种 hook 类型: syscall, kernel, tracepoint, uprobe, sched, file, net。
    每种类型的解析结果应正确反映其 HookKind。
    """

    def test_syscall_target(self):
        """测试 syscall 观测: 多个目标、HookKind=SYSCALL"""
        src = 'tool t {} observe syscall("read", "write") { @c[pid] = count(); }'
        ast = parse(src)
        self.assertEqual(len(ast.stmts), 1)
        rule = ast.stmts[0]
        self.assertIsInstance(rule, ObserveRule)
        self.assertEqual(rule.hook.kind, HookKind.SYSCALL)
        self.assertEqual(rule.hook.targets, ["read", "write"])

    def test_kernel_target(self):
        """测试 kernel 观测: HookKind=KERNEL"""
        src = 'tool t {} observe kernel("tcp_v4_connect") { @k[func] = count(); }'
        ast = parse(src)
        rule = ast.stmts[0]
        self.assertEqual(rule.hook.kind, HookKind.KERNEL)
        self.assertEqual(rule.hook.targets, ["tcp_v4_connect"])

    def test_tracepoint_target(self):
        """测试 tracepoint 观测: HookKind=TRACEPOINT"""
        src = 'tool t {} observe tracepoint("sched:sched_switch") { @t[cpu] = count(); }'
        ast = parse(src)
        rule = ast.stmts[0]
        self.assertEqual(rule.hook.kind, HookKind.TRACEPOINT)

    def test_uprobe_target(self):
        """测试 uprobe 观测: 包含 binary_path 和函数名、HookKind=UPROBE"""
        src = 'tool t {} observe uprobe("/bin/bash", "readline") { @u[pid] = count(); }'
        ast = parse(src)
        rule = ast.stmts[0]
        self.assertEqual(rule.hook.kind, HookKind.UPROBE)
        self.assertEqual(rule.hook.binary_path, "/bin/bash")
        self.assertEqual(rule.hook.targets, ["readline"])

    def test_sched_target(self):
        """测试 sched 观测: HookKind=SCHED"""
        src = 'tool t {} observe sched("sched_switch") { @s[cpu] = count(); }'
        ast = parse(src)
        rule = ast.stmts[0]
        self.assertEqual(rule.hook.kind, HookKind.SCHED)

    def test_file_target(self):
        """测试 file 观测: HookKind=FILE"""
        src = 'tool t {} observe file("vfs_read", "vfs_write") { @f[pid] = count(); }'
        ast = parse(src)
        rule = ast.stmts[0]
        self.assertEqual(rule.hook.kind, HookKind.FILE)

    def test_net_target(self):
        """测试 net 观测: HookKind=NET"""
        src = 'tool t {} observe net("tcp_sendmsg") { @n[pid] = count(); }'
        ast = parse(src)
        rule = ast.stmts[0]
        self.assertEqual(rule.hook.kind, HookKind.NET)


# ===================================================================
# TestParserClauses —— 子句解析测试
# ===================================================================

class TestParserClauses(unittest.TestCase):
    """
    测试 where / measure / when 三个子句的解析。
    
    这些子句在 observe 语句中修饰观测行为:
    - where: 事件触发前的过滤条件（在函数入口处执行）
    - measure: 声明要测量的指标（latency, retval, size, count, stack）
    - when: 事件触发后的过滤条件（在函数出口处执行，可使用 retval, latency）
    """

    def test_where_clause(self):
        """测试 where 子句: 条件表达式被正确解析为 BinOpExpr"""
        src = 'tool t {} observe syscall("r") where pid > 0 { @c[pid] = count(); }'
        ast = parse(src)
        rule = ast.stmts[0]
        self.assertEqual(len(rule.wheres), 1)
        self.assertIsInstance(rule.wheres[0], WhereClause)
        self.assertIsInstance(rule.wheres[0].cond, BinOpExpr)

    def test_measure_clause(self):
        """测试 measure 子句: 多个指标 (latency, retval) 用逗号分隔"""
        src = 'tool t {} observe syscall("r") measure latency, retval { @c[pid] = count(); }'
        ast = parse(src)
        rule = ast.stmts[0]
        self.assertEqual(len(rule.measures), 1)
        self.assertEqual(rule.measures[0].metrics, [Metric.LATENCY, Metric.RETVAL])

    def test_when_clause(self):
        """测试 when 子句: 出口条件，如 when latency > 1ms"""
        src = 'tool t {} observe syscall("r") when latency > 1ms { @c[pid] = count(); }'
        ast = parse(src)
        rule = ast.stmts[0]
        self.assertEqual(len(rule.whens), 1)
        self.assertIsInstance(rule.whens[0], WhenClause)

    def test_all_clauses(self):
        """测试三个子句同时出现: where + measure + when"""
        src = """tool t {}
observe syscall("read", "write")
where pid > 0
measure latency, retval
when latency > 100us
{
    @c[comm, pid] = count();
}"""
        ast = parse(src)
        rule = ast.stmts[0]
        self.assertEqual(len(rule.wheres), 1)
        self.assertEqual(len(rule.measures), 1)
        self.assertEqual(len(rule.whens), 1)


# ===================================================================
# TestParserActions —— 动作语句解析测试
# ===================================================================

class TestParserActions(unittest.TestCase):
    """
    测试 observe 块内的动作语句解析。
    
    动作语句是实际执行测量和输出的代码，包括:
    - AggregationStmt: @name[key] = fn(arg);  聚合统计
    - EmitStmt:        emit { field = expr; }; 事件输出
    - PrintStmt:       print(expr);            用户态打印
    - LetStmt:         let name = expr;        变量定义
    - IfStmt:          if (cond) { ... }       条件分支
    """

    def test_aggregation_count(self):
        """测试 count() 聚合: @c[pid, comm] = count(); — 无参数聚合函数"""
        src = 'tool t {} observe syscall("r") { @c[pid, comm] = count(); }'
        ast = parse(src)
        actions = ast.stmts[0].actions
        self.assertEqual(len(actions), 1)
        agg = actions[0]
        self.assertIsInstance(agg, AggregationStmt)
        self.assertEqual(agg.target, "c")
        self.assertEqual(agg.fn, AggFn.COUNT)
        self.assertEqual(len(agg.keys), 2)
        self.assertIsNone(agg.arg)

    def test_aggregation_with_arg(self):
        """测试带参数的聚合: @avg_lat[pid] = avg(latency); — arg 为 VarRef"""
        src = 'tool t {} observe syscall("r") { @avg_lat[pid] = avg(latency); }'
        ast = parse(src)
        agg = ast.stmts[0].actions[0]
        self.assertEqual(agg.fn, AggFn.AVG)
        self.assertIsInstance(agg.arg, VarRef)
        self.assertEqual(agg.arg.name, "latency")

    def test_all_agg_functions(self):
        """测试全部 7 种聚合函数: count, sum, avg, min, max, hist, lhist"""
        fn_names = ["count()", "sum(size)", "avg(latency)", "min(latency)",
                     "max(latency)", "hist(latency)", "lhist(latency)"]
        for i, fn_expr in enumerate(fn_names):
            src = f'tool t {{}} observe syscall("r") {{ @a[pid] = {fn_expr}; }}'
            ast = parse(src)
            self.assertIsInstance(ast.stmts[0].actions[0], AggregationStmt)

    def test_emit_stmt(self):
        """测试 emit 语句: 多个字段 (time, pid) 被正确解析为 EmitField"""
        src = """tool t {}
observe syscall("r") {
    emit { time = nsecs; pid = pid; };
}"""
        ast = parse(src)
        emit = ast.stmts[0].actions[0]
        self.assertIsInstance(emit, EmitStmt)
        self.assertEqual(len(emit.fields), 2)
        self.assertEqual(emit.fields[0].name, "time")
        self.assertEqual(emit.fields[1].name, "pid")

    def test_print_stmt(self):
        """测试 print 语句: 支持字符串和 @agg 引用"""
        src = 'tool t {} begin { print("hello"); print(@count); }'
        ast = parse(src)
        begin = ast.stmts[0]
        self.assertIsInstance(begin.actions[0], PrintStmt)
        self.assertIsInstance(begin.actions[1], PrintStmt)

    def test_let_stmt(self):
        """测试 let 语句: 变量定义 let x = 100; let slow = latency > 1000000;"""
        src = 'tool t {} observe syscall("r") { let x = 100; let slow = latency > 1000000; }'
        ast = parse(src)
        actions = ast.stmts[0].actions
        self.assertIsInstance(actions[0], LetStmt)
        self.assertEqual(actions[0].name, "x")
        self.assertIsInstance(actions[1], LetStmt)
        self.assertEqual(actions[1].name, "slow")

    def test_if_stmt(self):
        """测试 if 语句: 含 then 块，无 else 块"""
        src = """tool t {}
observe syscall("r") {
    if (latency > 1000) {
        @slow[pid] = count();
    }
}"""
        ast = parse(src)
        ifs = ast.stmts[0].actions[0]
        self.assertIsInstance(ifs, IfStmt)
        self.assertEqual(len(ifs.then_actions), 1)
        self.assertIsNone(ifs.else_actions)

    def test_if_else_stmt(self):
        """测试 if-else 语句: 同时包含 then 和 else 块"""
        src = """tool t {}
observe syscall("r") {
    if (latency > 1000) {
        @slow[pid] = count();
    } else {
        @fast[pid] = count();
    }
}"""
        ast = parse(src)
        ifs = ast.stmts[0].actions[0]
        self.assertIsInstance(ifs, IfStmt)
        self.assertEqual(len(ifs.else_actions), 1)


# ===================================================================
# TestParserLifecycle —— 生命周期语句测试
# ===================================================================

class TestParserLifecycle(unittest.TestCase):
    """
    测试 every / begin / end 生命周期语句的解析。
    
    生命周期语句定义了程序运行期间的非观测行为:
    - every <interval>: 周期性执行的用户态任务
    - begin:            程序启动时执行一次
    - end:              程序退出时执行一次
    """

    def test_every_stmt(self):
        """测试 every 语句: 间隔为时间字面量 (1s)"""
        src = """tool t {}
observe syscall("r") { @c[pid] = count(); }
every 1s { print(@c); }"""
        ast = parse(src)
        self.assertIsInstance(ast.stmts[1], EveryStmt)
        self.assertIsInstance(ast.stmts[1].interval, LitTime)

    def test_begin_stmt(self):
        """测试 begin 语句: 启动时打印"""
        src = 'tool t {} begin { print("start"); }'
        ast = parse(src)
        self.assertIsInstance(ast.stmts[0], BeginStmt)

    def test_end_stmt(self):
        """测试 end 语句: 退出时执行多个动作"""
        src = 'tool t {} end { print("done"); print(@c); }'
        ast = parse(src)
        self.assertIsInstance(ast.stmts[0], EndStmt)
        self.assertEqual(len(ast.stmts[0].actions), 2)


# ===================================================================
# TestParserExpressions —— 表达式树测试
# ===================================================================

class TestParserExpressions(unittest.TestCase):
    """
    测试各类表达式的 AST 树结构。
    
    表达式是 Emon DSL 中计算值的语法结构，包括:
    - 字面量: 整数(42), 字符串("hello"), 布尔(true/false)
    - 变量引用: pid, comm, latency
    - 聚合引用: @count, @my_counter
    - 二元运算: pid > 0, latency < 1ms
    - 一元运算: !true, -x
    - 函数调用: top(@c, 10)
    """

    def test_integer_literal(self):
        """测试整数字面量: 42 → LitInt(42)"""
        src = 'tool t {} observe syscall("r") { let x = 42; }'
        ast = parse(src)
        let_stmt = ast.stmts[0].actions[0]
        self.assertIsInstance(let_stmt.value, LitInt)
        self.assertEqual(let_stmt.value.value, 42)

    def test_string_literal(self):
        """测试字符串字面量: "hello world" → LitStr("hello world")"""
        src = 'tool t {} begin { print("hello world"); }'
        ast = parse(src)
        ps = ast.stmts[0].actions[0]
        self.assertIsInstance(ps.expr, LitStr)
        self.assertEqual(ps.expr.value, "hello world")

    def test_boolean_literal(self):
        """测试布尔字面量: true/false → LitBool(True/False)"""
        src = 'tool t { option debug = true; option trace = false; }'
        ast = parse(src)
        self.assertIsInstance(ast.tool.options[0][1], LitBool)
        self.assertEqual(ast.tool.options[0][1].value, True)
        self.assertIsInstance(ast.tool.options[1][1], LitBool)
        self.assertEqual(ast.tool.options[1][1].value, False)

    def test_comparison_operators(self):
        """测试全部 6 种比较运算符: >, <, >=, <=, ==, !="""
        ops = [
            ("pid > 0", BinOp.GT),
            ("pid < 10", BinOp.LT),
            ("pid >= 1", BinOp.GE),
            ("pid <= 100", BinOp.LE),
            ("pid == 5", BinOp.EQ),
            ("pid != 0", BinOp.NE),
        ]
        for expr_str, expected_op in ops:
            src = f'tool t {{}} observe syscall("r") where {expr_str} {{ @c[pid] = count(); }}'
            ast = parse(src)
            cond = ast.stmts[0].wheres[0].cond
            self.assertIsInstance(cond, BinOpExpr, f"Failed for {expr_str}")
            self.assertEqual(cond.op, expected_op, f"Wrong op for {expr_str}")

    def test_logical_operators(self):
        '''测试逻辑与运算符 &&: pid > 0 && comm == "bash"'''
        src = 'tool t {} observe syscall("r") where pid > 0 && comm == "bash" { @c[pid] = count(); }'
        ast = parse(src)
        cond = ast.stmts[0].wheres[0].cond
        self.assertIsInstance(cond, BinOpExpr)
        self.assertEqual(cond.op, BinOp.AND)
        self.assertIsInstance(cond.lhs, BinOpExpr)
        self.assertEqual(cond.lhs.op, BinOp.GT)
        self.assertIsInstance(cond.rhs, BinOpExpr)
        self.assertEqual(cond.rhs.op, BinOp.EQ)

    def test_arithmetic_operators(self):
        """测试算术运算: pid + 1 > 10 → 加法是 > 的左子树"""
        src = 'tool t {} observe syscall("r") where pid + 1 > 10 { @c[pid] = count(); }'
        ast = parse(src)
        cond = ast.stmts[0].wheres[0].cond
        self.assertIsInstance(cond, BinOpExpr)
        self.assertEqual(cond.op, BinOp.GT)
        self.assertIsInstance(cond.lhs, BinOpExpr)
        self.assertEqual(cond.lhs.op, BinOp.ADD)

    def test_unary_operators(self):
        """测试逻辑非: !true → UnaryOpExpr(NOT)"""
        src = 'tool t {} observe syscall("r") where !true { @c[pid] = count(); }'
        ast = parse(src)
        cond = ast.stmts[0].wheres[0].cond
        self.assertIsInstance(cond, UnaryOpExpr)
        self.assertEqual(cond.op, UnaryOp.NOT)

    def test_func_call(self):
        """测试函数调用: top(@c, 10) → FuncCall 含 2 个参数"""
        src = 'tool t {} begin { print(top(@c, 10)); }'
        ast = parse(src)
        ps = ast.stmts[0].actions[0]
        fc = ps.expr
        self.assertIsInstance(fc, FuncCall)
        self.assertEqual(fc.name, "top")
        self.assertEqual(len(fc.args), 2)

    def test_agg_ref(self):
        """测试聚合引用: @my_counter → AggRef"""
        src = 'tool t {} begin { print(@my_counter); }'
        ast = parse(src)
        ps = ast.stmts[0].actions[0]
        self.assertIsInstance(ps.expr, AggRef)
        self.assertEqual(ps.expr.name, "my_counter")


# ===================================================================
# TestParserExamples —— 示例文件解析测试
# ===================================================================

class TestParserExamples(unittest.TestCase):
    """
    验证所有内置 .emon 示例文件都能被正确解析。
    
    这些是集成测试，确保解析器能处理真实场景下的完整程序。
    如果某个示例解析失败，说明解析器存在兼容性问题。
    """

    def _parse_example(self, name):
        """辅助方法: 解析 examples/ 目录下的示例文件"""
        from emon.parser import parse_file
        return parse_file(f"examples/{name}")

    def test_syscall_count(self):
        """测试 syscall_count.emon 示例"""
        ast = self._parse_example("syscall_count.emon")
        self.assertIsInstance(ast, Program)
        self.assertGreater(len(ast.stmts), 0)

    def test_syscall_latency(self):
        """测试 syscall_latency.emon 示例"""
        ast = self._parse_example("syscall_latency.emon")
        self.assertIsInstance(ast, Program)
        self.assertGreater(len(ast.stmts), 0)

    def test_full_feature(self):
        """测试 full_feature_test.emon 示例: 应包含 7 种 hook 类型的 observe 语句"""
        ast = self._parse_example("full_feature_test.emon")
        self.assertIsInstance(ast, Program)
        self.assertEqual(len(ast.stmts), 10)
        kinds = [s.hook.kind for s in ast.stmts if isinstance(s, ObserveRule)]
        self.assertEqual(kinds, [
            HookKind.SYSCALL, HookKind.KERNEL, HookKind.TRACEPOINT,
            HookKind.UPROBE, HookKind.SCHED, HookKind.FILE, HookKind.NET,
        ])


# ===================================================================
# 测试入口
# ===================================================================

if __name__ == '__main__':
    unittest.main()
