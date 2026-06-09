"""
Emon DSL Integration Tests - Example Programs
Tests that all bundled example programs compile successfully
and produce valid IR.
"""

import json
import unittest

from emon.parser import parse_file
from emon.semantic import analyze
from emon.ir import build_ir


class TestExamplePrograms(unittest.TestCase):
    """Test all example programs in the examples/ directory."""

    def test_syscall_count(self):
        """Test syscall_count.emon example."""
        ast = parse_file("examples/syscall_count.emon")
        errors = analyze(ast)
        self.assertEqual(errors, [], f"Semantic errors: {errors}")
        
        ir = build_ir(ast)
        self.assertEqual(ir.tool_name, "syscall_counter")
        self.assertEqual(len(ir.probes), 5)  # 5 syscalls
        self.assertEqual(len(ir.maps), 1)

    def test_syscall_latency(self):
        """Test syscall_latency.emon example."""
        ast = parse_file("examples/syscall_latency.emon")
        errors = analyze(ast)
        self.assertEqual(errors, [], f"Semantic errors: {errors}")
        
        ir = build_ir(ast)
        self.assertEqual(ir.tool_name, "syscall_latency_monitor")
        self.assertEqual(len(ir.options), 4)
        self.assertEqual(len(ir.probes), 6)  # 3 syscalls × 2 (entry+exit)
        self.assertEqual(len(ir.maps), 3)
        self.assertEqual(len(ir.events), 1)
        self.assertEqual(len(ir.every_tasks), 1)

    def test_full_feature_test(self):
        """Test full_feature_test.emon example (all 7 hook types)."""
        ast = parse_file("examples/full_feature_test.emon")
        errors = analyze(ast)
        self.assertEqual(errors, [], f"Semantic errors: {errors}")
        
        ir = build_ir(ast)
        self.assertEqual(ir.tool_name, "full_feature_test")
        self.assertEqual(len(ir.options), 7)
        
        # Verify all 7 hook types are present
        hook_kinds = {p.hook_kind for p in ir.probes}
        expected_kinds = {"SYSCALL", "KERNEL", "TRACEPOINT", "UPROBE", 
                          "SCHED", "FILE", "NET"}
        self.assertEqual(hook_kinds, expected_kinds)


class TestIRJsonCompatibility(unittest.TestCase):
    """Test IR JSON serialization compatibility."""

    def test_json_roundtrip_preserves_all_data(self):
        """JSON serialization and deserialization should preserve data."""
        ast = parse_file("examples/syscall_latency.emon")
        analyze(ast)
        ir = build_ir(ast)
        
        json_str = ir.to_json()
        data = json.loads(json_str)
        
        self.assertEqual(data["tool_name"], "syscall_latency_monitor")
        self.assertEqual(len(data["options"]), 4)
        self.assertEqual(len(data["probes"]), 6)
        self.assertEqual(len(data["maps"]), 3)
        self.assertEqual(len(data["events"]), 1)
        self.assertEqual(len(data["every_tasks"]), 1)
        
        # Verify map names
        map_names = {m["name"] for m in data["maps"]}
        self.assertEqual(map_names, {"count", "avg_latency", "latency_hist"})
        
        # Verify probe sections
        sections = {p["section"] for p in data["probes"]}
        self.assertIn("tracepoint/syscalls/sys_enter_read", sections)
        self.assertIn("tracepoint/syscalls/sys_exit_read", sections)

    def test_json_output_format(self):
        """JSON output should have correct format for downstream tools."""
        ast = parse_file("examples/syscall_count.emon")
        analyze(ast)
        ir = build_ir(ast)
        
        json_str = ir.to_json()
        data = json.loads(json_str)
        
        # Check required fields
        self.assertIn("tool_name", data)
        self.assertIn("options", data)
        self.assertIn("probes", data)
        self.assertIn("maps", data)
        self.assertIn("events", data)
        self.assertIn("every_tasks", data)
        self.assertIn("begin_stmts", data)
        self.assertIn("end_stmts", data)
        
        # Check probe structure
        if data["probes"]:
            probe = data["probes"][0]
            self.assertIn("hook_kind", probe)
            self.assertIn("hook_target", probe)
            self.assertIn("section", probe)
            self.assertIn("is_exit", probe)
            self.assertIn("measures_latency", probe)
            self.assertIn("where_conditions", probe)
            self.assertIn("when_conditions", probe)
        
        # Check map structure
        if data["maps"]:
            m = data["maps"][0]
            self.assertIn("name", m)
            self.assertIn("map_type", m)
            self.assertIn("key_fields", m)
            self.assertIn("value_type", m)
            self.assertIn("max_entries", m)


class TestEndToEndWorkflow(unittest.TestCase):
    """Test the complete end-to-end workflow."""

    def test_complete_workflow(self):
        """Complete workflow: parse → analyze → generate IR → serialize."""
        ast = parse_file("examples/syscall_latency.emon")
        
        # Semantic analysis
        errors = analyze(ast)
        self.assertEqual(errors, [], f"Semantic errors: {errors}")
        
        # IR generation
        ir = build_ir(ast)
        
        # JSON serialization
        json_str = ir.to_json()
        self.assertIsInstance(json_str, str)
        self.assertGreater(len(json_str), 0)
        
        # Verify JSON is valid
        try:
            data = json.loads(json_str)
            self.assertIsInstance(data, dict)
        except json.JSONDecodeError as e:
            self.fail(f"Invalid JSON: {e}")


if __name__ == '__main__':
    unittest.main()
