"""
Emon DSL Integration Tests - Compiler Pipeline
Tests the complete compiler pipeline:
  parse → semantic analysis → IR generation → JSON serialization
"""

import json
import unittest

from emon.parser import parse, parse_file
from emon.semantic import analyze
from emon.ir import build_ir


class TestParserSemanticIntegration(unittest.TestCase):
    """Test parser and semantic analyzer integration."""

    def test_valid_program_no_errors(self):
        """Valid program should produce no semantic errors."""
        src = """tool valid {
    option target = 100;
    option interval = 1s;
}
observe syscall("read", "write")
where pid > 0
measure latency
when latency > 100us
{
    @count[pid, comm] = count();
    @avg[pid] = avg(latency);
    emit { time = nsecs; pid = pid; };
}
every interval {
    print(@count);
}"""
        ast = parse(src)
        errors = analyze(ast)
        self.assertEqual(errors, [])

    def test_invalid_program_has_errors(self):
        """Invalid program should produce semantic errors."""
        src = 'tool t {} observe syscall("r") { @c[pid] = avg(); }'
        ast = parse(src)
        errors = analyze(ast)
        self.assertGreater(len(errors), 0)

    def test_latency_without_measure(self):
        """Using latency without measure clause should fail."""
        src = 'tool t {} observe syscall("r") { @c[pid] = avg(latency); }'
        ast = parse(src)
        errors = analyze(ast)
        self.assertGreater(len(errors), 0)


class TestFullCompilerPipeline(unittest.TestCase):
    """Test the complete compilation pipeline."""

    def test_simple_syscall_monitor(self):
        """End-to-end test for simple syscall monitor."""
        src = """tool syscall_monitor {
    option threshold = 100us;
}
observe syscall("read", "write", "openat")
where pid > 0
measure latency
when latency > threshold
{
    @count[comm, pid] = count();
    @lat_hist[comm] = hist(latency);
    
    emit {
        time = nsecs;
        pid = pid;
        comm = comm;
        latency = latency;
    };
}
every 1s {
    print("=== Summary ===");
    print(@count);
    print(@lat_hist);
}"""

        ast = parse(src)
        errors = analyze(ast)
        self.assertEqual(errors, [], f"Semantic errors: {errors}")

        ir = build_ir(ast)
        
        self.assertEqual(ir.tool_name, "syscall_monitor")
        self.assertEqual(len(ir.options), 1)
        self.assertEqual(len(ir.probes), 6)  # 3 targets × 2 (entry+exit)
        self.assertEqual(len(ir.maps), 2)    # count, lat_hist
        self.assertEqual(len(ir.events), 1)
        self.assertEqual(len(ir.every_tasks), 1)

        json_str = ir.to_json()
        data = json.loads(json_str)
        self.assertEqual(data["tool_name"], "syscall_monitor")
        self.assertEqual(len(data["probes"]), 6)
        self.assertEqual(len(data["maps"]), 2)

    def test_kernel_function_monitor(self):
        """End-to-end test for kernel function monitoring."""
        src = """tool kernel_monitor {
    option target_func = "tcp_v4_connect";
}
observe kernel("tcp_v4_connect", "tcp_v4_disconnect")
{
    @calls[func] = count();
    @arg0[func] = sum(arg0);
}
every 500ms {
    print(@calls);
}"""

        ast = parse(src)
        errors = analyze(ast)
        self.assertEqual(errors, [], f"Semantic errors: {errors}")

        ir = build_ir(ast)
        self.assertEqual(ir.tool_name, "kernel_monitor")
        self.assertEqual(len(ir.probes), 2)
        self.assertEqual(len(ir.maps), 2)

    def test_tracepoint_monitor(self):
        """End-to-end test for tracepoint monitoring."""
        src = """tool sched_monitor {
    option cpu_filter = 0;
}
observe tracepoint("sched:sched_switch")
where cpu == cpu_filter
{
    @switches[pid, comm] = count();
}
every 2s {
    print(@switches);
}"""

        ast = parse(src)
        errors = analyze(ast)
        self.assertEqual(errors, [], f"Semantic errors: {errors}")

        ir = build_ir(ast)
        self.assertEqual(len(ir.probes), 1)
        self.assertEqual(len(ir.maps), 1)

    def test_uprobe_monitor(self):
        """End-to-end test for uprobe monitoring."""
        src = """tool user_func_monitor {
    option binary = "/bin/bash";
}
observe uprobe("/bin/bash", "readline", "rl_completion_matches")
{
    @calls[func] = count();
}
every 1s {
    print(@calls);
}"""

        ast = parse(src)
        errors = analyze(ast)
        self.assertEqual(errors, [], f"Semantic errors: {errors}")

        ir = build_ir(ast)
        self.assertEqual(len(ir.probes), 2)
        self.assertEqual(len(ir.maps), 1)


class TestConditionalLogicPipeline(unittest.TestCase):
    """Test complex conditional logic in the pipeline."""

    def test_if_else_statements(self):
        """Test if-else statements in action block."""
        src = """tool conditional_test {
    option threshold = 1000000;
}
observe syscall("read")
measure latency
{
    let slow = latency > threshold;
    if (slow) {
        @slow_count[pid] = count();
        emit { pid = pid; latency = latency; };
    } else {
        @fast_count[pid] = count();
    }
}
every 1s {
    print(@slow_count);
    print(@fast_count);
}"""

        ast = parse(src)
        errors = analyze(ast)
        self.assertEqual(errors, [], f"Semantic errors: {errors}")

        ir = build_ir(ast)
        self.assertEqual(len(ir.maps), 2)  # slow_count, fast_count
        self.assertEqual(len(ir.events), 1)

    def test_nested_conditions(self):
        """Test nested where/when conditions."""
        src = """tool nested_test {
    option min_pid = 100;
    option max_pid = 1000;
}
observe syscall("read", "write")
where pid > min_pid && pid < max_pid && comm != "systemd"
measure latency
when latency > 100us && latency < 1s
{
    @count[comm] = count();
}"""

        ast = parse(src)
        errors = analyze(ast)
        self.assertEqual(errors, [], f"Semantic errors: {errors}")

        ir = build_ir(ast)
        self.assertEqual(len(ir.probes), 4)  # 2 targets × 2
        self.assertEqual(len(ir.maps), 1)


class TestLifecyclePipeline(unittest.TestCase):
    """Test begin/end/every lifecycle statements."""

    def test_complete_lifecycle(self):
        """Test all lifecycle statements together."""
        src = """tool lifecycle_test {
    option interval = 1s;
}
begin {
    print("Starting monitor...");
    print("Options loaded");
}
observe syscall("openat")
{
    @opens[pid] = count();
}
every interval {
    print(@opens);
}
end {
    print("Stopping monitor...");
    print("Final stats:");
    print(@opens);
}"""

        ast = parse(src)
        errors = analyze(ast)
        self.assertEqual(errors, [], f"Semantic errors: {errors}")

        ir = build_ir(ast)
        self.assertEqual(len(ir.begin_stmts), 2)
        self.assertEqual(len(ir.end_stmts), 3)
        self.assertEqual(len(ir.every_tasks), 1)


if __name__ == '__main__':
    unittest.main()
