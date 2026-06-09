"""
Emon DSL IR Builder Tests

Validates IR generation from typed AST:
  - Probe generation (entry / exit for latency)
  - BPF map declarations
  - Event struct generation
  - Expression serialization
  - Lifecycle statement handling
  - JSON serialization round-trip
"""

import json
import unittest

from emon.parser import parse
from emon.semantic import analyze
from emon.ir import build_ir, IRBuilder, IRProgram, _serialize_expr
from emon.ast_nodes import LitInt, LitStr, LitBool, LitTime, VarRef, BinOpExpr, BinOp


class TestIRExpressionSerialization(unittest.TestCase):
    """Test expression → C-like string conversion."""

    def test_literals(self):
        self.assertEqual(_serialize_expr(LitInt(42)), "42")
        self.assertEqual(_serialize_expr(LitStr("hello")), '"hello"')
        self.assertEqual(_serialize_expr(LitBool(True)), "true")
        self.assertEqual(_serialize_expr(LitBool(False)), "false")
        self.assertEqual(_serialize_expr(LitTime("100us")), "100us")

    def test_var_ref(self):
        self.assertEqual(_serialize_expr(VarRef("pid")), "pid")
        self.assertEqual(_serialize_expr(VarRef("latency")), "latency")

    def test_binary_ops(self):
        expr = BinOpExpr(op=BinOp.GT, lhs=VarRef("pid"), rhs=LitInt(0))
        self.assertEqual(_serialize_expr(expr), "(pid > 0)")

        expr2 = BinOpExpr(
            op=BinOp.AND,
            lhs=BinOpExpr(op=BinOp.GT, lhs=VarRef("pid"), rhs=LitInt(0)),
            rhs=BinOpExpr(op=BinOp.EQ, lhs=VarRef("comm"), rhs=LitStr("bash")),
        )
        result = _serialize_expr(expr2)
        self.assertIn("&&", result)
        self.assertIn("pid", result)
        self.assertIn('"bash"', result)


class TestIRProbeGeneration(unittest.TestCase):
    """Test probe (eBPF program) generation from observe rules."""

    def test_syscall_without_latency(self):
        src = 'tool t {} observe syscall("read") { @c[pid] = count(); }'
        ast = parse(src)
        ir = build_ir(ast)

        self.assertEqual(len(ir.probes), 1)
        probe = ir.probes[0]
        self.assertFalse(probe.is_exit)
        self.assertFalse(probe.measures_latency)
        self.assertIn("read", probe.section)
        self.assertEqual(probe.hook_kind, "SYSCALL")

    def test_syscall_with_latency(self):
        src = 'tool t {} observe syscall("read") measure latency { @c[pid] = count(); }'
        ast = parse(src)
        ir = build_ir(ast)

        self.assertEqual(len(ir.probes), 2)
        entry = ir.probes[0]
        exit_p = ir.probes[1]
        self.assertFalse(entry.is_exit)
        self.assertTrue(exit_p.is_exit)
        self.assertTrue(entry.measures_latency)
        self.assertTrue(exit_p.measures_latency)

    def test_multiple_targets(self):
        src = 'tool t {} observe syscall("read", "write") { @c[pid] = count(); }'
        ast = parse(src)
        ir = build_ir(ast)

        self.assertEqual(len(ir.probes), 2)
        self.assertEqual(ir.probes[0].hook_target, "read")
        self.assertEqual(ir.probes[1].hook_target, "write")

    def test_kernel_hook(self):
        src = 'tool t {} observe kernel("tcp_v4_connect") { @k[func] = count(); }'
        ast = parse(src)
        ir = build_ir(ast)

        self.assertEqual(len(ir.probes), 1)
        self.assertEqual(ir.probes[0].hook_kind, "KERNEL")
        self.assertIn("kprobe", ir.probes[0].section)

    def test_all_hook_types(self):
        hooks = [
            ('observe syscall("r")', "SYSCALL"),
            ('observe kernel("f")', "KERNEL"),
            ('observe tracepoint("t")', "TRACEPOINT"),
            ('observe uprobe("/bin/sh", "fn")', "UPROBE"),
            ('observe sched("s")', "SCHED"),
            ('observe file("f")', "FILE"),
            ('observe net("n")', "NET"),
        ]
        for observe_expr, expected_kind in hooks:
            src = f'tool t {{}} {observe_expr} {{ @c[pid] = count(); }}'
            ast = parse(src)
            ir = build_ir(ast)
            self.assertEqual(ir.probes[0].hook_kind, expected_kind,
                             f"Failed for {observe_expr}")

    def test_where_conditions(self):
        src = 'tool t {} observe syscall("r") where pid > 0 && comm == "bash" { @c[pid] = count(); }'
        ast = parse(src)
        ir = build_ir(ast)

        probe = ir.probes[0]
        self.assertEqual(len(probe.where_conditions), 1)
        cond = probe.where_conditions[0]
        self.assertIn("pid", cond)
        self.assertIn("&&", cond)
        self.assertIn('"bash"', cond)

    def test_when_conditions(self):
        src = 'tool t {} observe syscall("r") measure latency when latency > 1000 { @c[pid] = count(); }'
        ast = parse(src)
        ir = build_ir(ast)

        exit_probe = ir.probes[1]
        self.assertEqual(len(exit_probe.when_conditions), 1)
        self.assertIn("latency", exit_probe.when_conditions[0])


class TestIRMapGeneration(unittest.TestCase):
    """Test BPF map declarations from aggregation statements."""

    def test_count_map(self):
        src = 'tool t {} observe syscall("r") { @mycount[pid, comm] = count(); }'
        ast = parse(src)
        ir = build_ir(ast)

        self.assertEqual(len(ir.maps), 1)
        m = ir.maps[0]
        self.assertEqual(m.name, "mycount")
        self.assertEqual(m.key_fields, ["pid", "comm"])
        self.assertIn("HASH", m.map_type)

    def test_avg_map(self):
        src = 'tool t {} observe syscall("r") measure latency { @avg_lat[pid] = avg(latency); }'
        ast = parse(src)
        ir = build_ir(ast)

        self.assertEqual(len(ir.maps), 1)
        m = ir.maps[0]
        self.assertEqual(m.name, "avg_lat")
        self.assertIn("sum", m.value_type)
        self.assertIn("count", m.value_type)

    def test_multiple_aggregations(self):
        src = """tool t {}
observe syscall("r") measure latency {
    @c[pid] = count();
    @s[pid] = sum(latency);
    @a[pid] = avg(latency);
    @mn[pid] = min(latency);
    @mx[pid] = max(latency);
}"""
        ast = parse(src)
        ir = build_ir(ast)

        self.assertEqual(len(ir.maps), 5)
        names = {m.name for m in ir.maps}
        self.assertEqual(names, {"c", "s", "a", "mn", "mx"})

    def test_map_deduplication(self):
        src = """tool t {}
observe syscall("a") { @c[pid] = count(); }
observe syscall("b") { @c[pid] = count(); }"""
        ast = parse(src)
        ir = build_ir(ast)

        # Same @c name → should be deduplicated to 1 map
        self.assertEqual(len(ir.maps), 1)


class TestIREmitGeneration(unittest.TestCase):
    """Test event struct and emit generation."""

    def test_emit_event(self):
        src = """tool t {}
observe syscall("r") {
    emit { time = nsecs; pid = pid; };
}"""
        ast = parse(src)
        ir = build_ir(ast)

        self.assertEqual(len(ir.events), 1)
        event = ir.events[0]
        self.assertIn("event_t", event.name)
        field_names = {f["name"] for f in event.fields}
        self.assertIn("time", field_names)
        self.assertIn("pid", field_names)

    def test_events_merged(self):
        src = """tool demo {}
observe syscall("a") {
    emit { time = nsecs; };
}
observe syscall("b") {
    emit { pid = pid; latency = latency; };
}"""
        ast = parse(src)
        ir = build_ir(ast)

        # Events with same tool name should merge fields
        self.assertEqual(len(ir.events), 1)
        field_names = {f["name"] for f in ir.events[0].fields}
        self.assertIn("time", field_names)
        self.assertIn("pid", field_names)
        self.assertIn("latency", field_names)


class TestIRLifecycle(unittest.TestCase):
    """Test every/begin/end IR generation."""

    def test_every_task(self):
        src = """tool t { option interval = 1s; }
observe syscall("r") { @c[pid] = count(); }
every interval { print(@c); }"""
        ast = parse(src)
        ir = build_ir(ast)

        self.assertEqual(len(ir.every_tasks), 1)
        task = ir.every_tasks[0]
        self.assertEqual(task.interval, "interval")
        self.assertEqual(len(task.prints), 1)
        self.assertEqual(task.agg_reads, ["c"])

    def test_begin_end(self):
        src = """tool t {}
begin { print("start"); }
end { print("done"); print(@c); }"""
        ast = parse(src)
        ir = build_ir(ast)

        self.assertEqual(len(ir.begin_stmts), 1)
        self.assertEqual(ir.begin_stmts[0].expr, '"start"')
        self.assertEqual(len(ir.end_stmts), 2)
        self.assertEqual(ir.end_stmts[0].expr, '"done"')


class TestIROptions(unittest.TestCase):
    """Test option serialization in IR."""

    def test_options(self):
        src = """tool demo {
    option pid = 0;
    option threshold = 1ms;
    option debug = true;
    option name = "emon";
}"""
        ast = parse(src)
        ir = build_ir(ast)

        self.assertEqual(len(ir.options), 4)
        names = {o["name"] for o in ir.options}
        self.assertEqual(names, {"pid", "threshold", "debug", "name"})


class TestIRJsonSerialization(unittest.TestCase):
    """Test JSON serialization of IR."""

    def test_to_json(self):
        src = 'tool t {} observe syscall("r") { @c[pid] = count(); }'
        ast = parse(src)
        ir = build_ir(ast)

        json_str = ir.to_json()
        data = json.loads(json_str)

        self.assertEqual(data["tool_name"], "t")
        self.assertEqual(len(data["probes"]), 1)
        self.assertEqual(len(data["maps"]), 1)

    def test_full_feature_json(self):
        from emon.parser import parse_file
        ast = parse_file("examples/full_feature_test.emon")
        ir = build_ir(ast)

        json_str = ir.to_json()
        data = json.loads(json_str)

        self.assertEqual(data["tool_name"], "full_feature_test")
        self.assertEqual(len(data["options"]), 7)
        self.assertGreater(len(data["probes"]), 0)
        self.assertGreater(len(data["maps"]), 0)
        self.assertEqual(len(data["every_tasks"]), 1)
        self.assertEqual(len(data["begin_stmts"]), 2)
        self.assertEqual(len(data["end_stmts"]), 8)


class TestIRFullPipeline(unittest.TestCase):
    """End-to-end: parse → semantic → IR."""

    def test_pipeline(self):
        from emon.parser import parse
        from emon.semantic import analyze
        from emon.ir import build_ir

        src = """tool pipeline_test {
    option threshold = 100us;
}
observe syscall("read", "write")
where pid > 0
measure latency
when latency > threshold
{
    @count[pid, comm] = count();
    @avg[pid] = avg(latency);

    emit {
        time = nsecs;
        pid = pid;
        latency = latency;
    };

    let slow = latency > 1000000;
    if (slow) {
        @slow_count[pid] = count();
    }
}
every 2s {
    print("=== report ===");
    print(@count);
}"""

        ast = parse(src)
        errors = analyze(ast)
        self.assertEqual(errors, [], f"Semantic errors: {errors}")

        ir = build_ir(ast)
        self.assertEqual(ir.tool_name, "pipeline_test")
        self.assertEqual(len(ir.options), 1)
        self.assertEqual(len(ir.probes), 4)  # 2 targets × 2 (entry+exit)
        self.assertEqual(len(ir.maps), 3)     # count, avg, slow_count
        self.assertEqual(len(ir.events), 1)
        self.assertEqual(len(ir.every_tasks), 1)

        # Verify JSON round-trip
        json_str = ir.to_json()
        self.assertIsInstance(json_str, str)
        data = json.loads(json_str)
        self.assertEqual(data["tool_name"], "pipeline_test")


if __name__ == '__main__':
    unittest.main()
