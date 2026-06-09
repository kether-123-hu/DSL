"""
Emon DSL Parser Tests

Validates the Lark-based parser produces correct typed ASTs for a
variety of Emon DSL programs.
"""

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


class TestParserProgram(unittest.TestCase):
    """Test top-level program structure parsing."""

    def test_empty_tool(self):
        ast = parse("tool t {}")
        self.assertIsInstance(ast, Program)
        self.assertEqual(ast.tool.name, "t")
        self.assertEqual(ast.tool.options, [])
        self.assertEqual(ast.stmts, [])

    def test_tool_with_options(self):
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


class TestParserObserve(unittest.TestCase):
    """Test observe statement parsing for all 7 target types."""

    def test_syscall_target(self):
        src = 'tool t {} observe syscall("read", "write") { @c[pid] = count(); }'
        ast = parse(src)
        self.assertEqual(len(ast.stmts), 1)
        rule = ast.stmts[0]
        self.assertIsInstance(rule, ObserveRule)
        self.assertEqual(rule.hook.kind, HookKind.SYSCALL)
        self.assertEqual(rule.hook.targets, ["read", "write"])

    def test_kernel_target(self):
        src = 'tool t {} observe kernel("tcp_v4_connect") { @k[func] = count(); }'
        ast = parse(src)
        rule = ast.stmts[0]
        self.assertEqual(rule.hook.kind, HookKind.KERNEL)
        self.assertEqual(rule.hook.targets, ["tcp_v4_connect"])

    def test_tracepoint_target(self):
        src = 'tool t {} observe tracepoint("sched:sched_switch") { @t[cpu] = count(); }'
        ast = parse(src)
        rule = ast.stmts[0]
        self.assertEqual(rule.hook.kind, HookKind.TRACEPOINT)

    def test_uprobe_target(self):
        src = 'tool t {} observe uprobe("/bin/bash", "readline") { @u[pid] = count(); }'
        ast = parse(src)
        rule = ast.stmts[0]
        self.assertEqual(rule.hook.kind, HookKind.UPROBE)
        self.assertEqual(rule.hook.binary_path, "/bin/bash")
        self.assertEqual(rule.hook.targets, ["readline"])

    def test_sched_target(self):
        src = 'tool t {} observe sched("sched_switch") { @s[cpu] = count(); }'
        ast = parse(src)
        rule = ast.stmts[0]
        self.assertEqual(rule.hook.kind, HookKind.SCHED)

    def test_file_target(self):
        src = 'tool t {} observe file("vfs_read", "vfs_write") { @f[pid] = count(); }'
        ast = parse(src)
        rule = ast.stmts[0]
        self.assertEqual(rule.hook.kind, HookKind.FILE)

    def test_net_target(self):
        src = 'tool t {} observe net("tcp_sendmsg") { @n[pid] = count(); }'
        ast = parse(src)
        rule = ast.stmts[0]
        self.assertEqual(rule.hook.kind, HookKind.NET)


class TestParserClauses(unittest.TestCase):
    """Test where / measure / when clause parsing."""

    def test_where_clause(self):
        src = 'tool t {} observe syscall("r") where pid > 0 { @c[pid] = count(); }'
        ast = parse(src)
        rule = ast.stmts[0]
        self.assertEqual(len(rule.wheres), 1)
        self.assertIsInstance(rule.wheres[0], WhereClause)
        self.assertIsInstance(rule.wheres[0].cond, BinOpExpr)

    def test_measure_clause(self):
        src = 'tool t {} observe syscall("r") measure latency, retval { @c[pid] = count(); }'
        ast = parse(src)
        rule = ast.stmts[0]
        self.assertEqual(len(rule.measures), 1)
        self.assertEqual(rule.measures[0].metrics, [Metric.LATENCY, Metric.RETVAL])

    def test_when_clause(self):
        src = 'tool t {} observe syscall("r") when latency > 1ms { @c[pid] = count(); }'
        ast = parse(src)
        rule = ast.stmts[0]
        self.assertEqual(len(rule.whens), 1)
        self.assertIsInstance(rule.whens[0], WhenClause)

    def test_all_clauses(self):
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


class TestParserActions(unittest.TestCase):
    """Test action statement parsing."""

    def test_aggregation_count(self):
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
        src = 'tool t {} observe syscall("r") { @avg_lat[pid] = avg(latency); }'
        ast = parse(src)
        agg = ast.stmts[0].actions[0]
        self.assertEqual(agg.fn, AggFn.AVG)
        self.assertIsInstance(agg.arg, VarRef)
        self.assertEqual(agg.arg.name, "latency")

    def test_all_agg_functions(self):
        fn_names = ["count()", "sum(size)", "avg(latency)", "min(latency)",
                     "max(latency)", "hist(latency)", "lhist(latency)"]
        for i, fn_expr in enumerate(fn_names):
            src = f'tool t {{}} observe syscall("r") {{ @a[pid] = {fn_expr}; }}'
            ast = parse(src)
            self.assertIsInstance(ast.stmts[0].actions[0], AggregationStmt)

    def test_emit_stmt(self):
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
        src = 'tool t {} begin { print("hello"); print(@count); }'
        ast = parse(src)
        begin = ast.stmts[0]
        self.assertIsInstance(begin.actions[0], PrintStmt)
        self.assertIsInstance(begin.actions[1], PrintStmt)

    def test_let_stmt(self):
        src = 'tool t {} observe syscall("r") { let x = 100; let slow = latency > 1000000; }'
        ast = parse(src)
        actions = ast.stmts[0].actions
        self.assertIsInstance(actions[0], LetStmt)
        self.assertEqual(actions[0].name, "x")
        self.assertIsInstance(actions[1], LetStmt)
        self.assertEqual(actions[1].name, "slow")

    def test_if_stmt(self):
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


class TestParserLifecycle(unittest.TestCase):
    """Test every / begin / end statement parsing."""

    def test_every_stmt(self):
        src = """tool t {}
observe syscall("r") { @c[pid] = count(); }
every 1s { print(@c); }"""
        ast = parse(src)
        self.assertIsInstance(ast.stmts[1], EveryStmt)
        self.assertIsInstance(ast.stmts[1].interval, LitTime)

    def test_begin_stmt(self):
        src = 'tool t {} begin { print("start"); }'
        ast = parse(src)
        self.assertIsInstance(ast.stmts[0], BeginStmt)

    def test_end_stmt(self):
        src = 'tool t {} end { print("done"); print(@c); }'
        ast = parse(src)
        self.assertIsInstance(ast.stmts[0], EndStmt)
        self.assertEqual(len(ast.stmts[0].actions), 2)


class TestParserExpressions(unittest.TestCase):
    """Test expression tree construction."""

    def test_integer_literal(self):
        src = 'tool t {} observe syscall("r") { let x = 42; }'
        ast = parse(src)
        let_stmt = ast.stmts[0].actions[0]
        self.assertIsInstance(let_stmt.value, LitInt)
        self.assertEqual(let_stmt.value.value, 42)

    def test_string_literal(self):
        src = 'tool t {} begin { print("hello world"); }'
        ast = parse(src)
        ps = ast.stmts[0].actions[0]
        self.assertIsInstance(ps.expr, LitStr)
        self.assertEqual(ps.expr.value, "hello world")

    def test_boolean_literal(self):
        src = 'tool t { option debug = true; option trace = false; }'
        ast = parse(src)
        self.assertIsInstance(ast.tool.options[0][1], LitBool)
        self.assertEqual(ast.tool.options[0][1].value, True)
        self.assertIsInstance(ast.tool.options[1][1], LitBool)
        self.assertEqual(ast.tool.options[1][1].value, False)

    def test_comparison_operators(self):
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
        src = 'tool t {} observe syscall("r") where pid + 1 > 10 { @c[pid] = count(); }'
        ast = parse(src)
        cond = ast.stmts[0].wheres[0].cond
        self.assertIsInstance(cond, BinOpExpr)
        self.assertEqual(cond.op, BinOp.GT)
        self.assertIsInstance(cond.lhs, BinOpExpr)
        self.assertEqual(cond.lhs.op, BinOp.ADD)

    def test_unary_operators(self):
        # NOT
        src = 'tool t {} observe syscall("r") where !true { @c[pid] = count(); }'
        ast = parse(src)
        cond = ast.stmts[0].wheres[0].cond
        self.assertIsInstance(cond, UnaryOpExpr)
        self.assertEqual(cond.op, UnaryOp.NOT)

    def test_func_call(self):
        src = 'tool t {} begin { print(top(@c, 10)); }'
        ast = parse(src)
        ps = ast.stmts[0].actions[0]
        fc = ps.expr
        self.assertIsInstance(fc, FuncCall)
        self.assertEqual(fc.name, "top")
        self.assertEqual(len(fc.args), 2)

    def test_agg_ref(self):
        src = 'tool t {} begin { print(@my_counter); }'
        ast = parse(src)
        ps = ast.stmts[0].actions[0]
        self.assertIsInstance(ps.expr, AggRef)
        self.assertEqual(ps.expr.name, "my_counter")


class TestParserExamples(unittest.TestCase):
    """Verify the bundled example files parse without errors."""

    def _parse_example(self, name):
        from emon.parser import parse_file
        return parse_file(f"emon-dsl/examples/{name}")

    def test_syscall_count(self):
        ast = self._parse_example("syscall_count.emon")
        self.assertIsInstance(ast, Program)
        self.assertGreater(len(ast.stmts), 0)

    def test_syscall_latency(self):
        ast = self._parse_example("syscall_latency.emon")
        self.assertIsInstance(ast, Program)
        self.assertGreater(len(ast.stmts), 0)

    def test_full_feature(self):
        ast = self._parse_example("full_feature_test.emon")
        self.assertIsInstance(ast, Program)
        self.assertEqual(len(ast.stmts), 10)
        kinds = [s.hook.kind for s in ast.stmts if isinstance(s, ObserveRule)]
        self.assertEqual(kinds, [
            HookKind.SYSCALL, HookKind.KERNEL, HookKind.TRACEPOINT,
            HookKind.UPROBE, HookKind.SCHED, HookKind.FILE, HookKind.NET,
        ])


if __name__ == '__main__':
    unittest.main()
