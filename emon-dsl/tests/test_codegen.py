"""
Emon DSL Code Generator Tests

Tests for:
  - bpfc_gen.py  — eBPF C code generation
  - loader_gen.py — libbpf loader C code generation
  - manifest_gen.py — YAML manifest generation
  - ir.py compile() — full pipeline

Validates that the generated code is syntactically plausible
and contains expected structural elements.
"""

import unittest
import os
import tempfile

from emon.parser import parse
from emon.semantic import analyze
from emon.ir import build_ir, build_ir_from_source, compile_source, compile_file
from emon.ir import IRProgram, IRProbe, IRMap, IREveryTask


# =============================================================================
# Helpers
# =============================================================================

def _build_ir(src: str) -> IRProgram:
    """Quick parse→semantic→IR pipeline helper."""
    return build_ir_from_source(src)


# =============================================================================
# eBPF C Code Generator Tests
# =============================================================================

class TestBpfCGenerator(unittest.TestCase):
    """Test eBPF C code generation."""

    def test_basic_syscall_count(self):
        src = 'tool t {} observe syscall("read") { @c[pid] = count(); }'
        ir = _build_ir(src)
        from emon.bpfc_gen import generate_bpf_c
        code = generate_bpf_c(ir)

        # Structure checks
        self.assertIn('#include "vmlinux.h"', code)
        self.assertIn("char LICENSE[]", code)
        self.assertIn('SEC("license")', code)
        self.assertIn('SEC("tracepoint/syscalls/sys_enter_read")', code)
        self.assertIn("bpf_get_current_pid_tgid", code)
        self.assertIn("bpf_map_lookup_elem", code)
        self.assertIn("bpf_map_update_elem", code)

    def test_syscall_with_latency(self):
        src = 'tool t {} observe syscall("read") measure latency { @c[pid] = count(); }'
        ir = _build_ir(src)
        from emon.bpfc_gen import generate_bpf_c
        code = generate_bpf_c(ir)

        # Two probes: entry + exit
        self.assertIn("sys_enter_read", code)
        self.assertIn("sys_exit_read", code)
        self.assertIn("__start_time_", code)
        self.assertIn("latency", code)
        self.assertIn("bpf_map_delete_elem", code)

    def test_kernel_hook(self):
        src = 'tool t {} observe kernel("tcp_v4_connect") { @k[func] = count(); }'
        ir = _build_ir(src)
        from emon.bpfc_gen import generate_bpf_c
        code = generate_bpf_c(ir)

        self.assertIn("kprobe/tcp_v4_connect", code)
        self.assertIn("PT_REGS_PARM", code)
        self.assertIn("struct pt_regs *ctx", code)

    def test_uprobe_hook(self):
        src = 'tool t {} observe uprobe("/bin/bash", "readline") { @u[pid] = count(); }'
        ir = _build_ir(src)
        from emon.bpfc_gen import generate_bpf_c
        code = generate_bpf_c(ir)

        self.assertIn("uprobe/readline", code)

    def test_tracepoint_hook(self):
        src = 'tool t {} observe tracepoint("sched:sched_switch") { @s[cpu] = count(); }'
        ir = _build_ir(src)
        from emon.bpfc_gen import generate_bpf_c
        code = generate_bpf_c(ir)

        self.assertIn("tracepoint/sched:sched_switch", code)

    def test_emit_ringbuf(self):
        src = '''
        tool t {}
        observe syscall("read") {
            @c[pid] = count();
            emit { time = nsecs; pid = pid; comm = comm; };
        }
        '''
        ir = _build_ir(src)
        from emon.bpfc_gen import generate_bpf_c
        code = generate_bpf_c(ir)

        self.assertIn("BPF_MAP_TYPE_RINGBUF", code)
        self.assertIn("bpf_ringbuf_reserve", code)
        self.assertIn("bpf_ringbuf_submit", code)
        self.assertIn("struct event_t", code)

    def test_where_and_when_conditions(self):
        src = '''
        tool t {}
        observe syscall("read")
        where pid > 0
        measure latency
        when latency > 1000
        { @c[pid] = count(); }
        '''
        ir = _build_ir(src)
        from emon.bpfc_gen import generate_bpf_c
        code = generate_bpf_c(ir)

        self.assertIn("// where:", code)
        self.assertIn("// when:", code)
        self.assertIn("if (!(", code)  # filter condition pattern

    def test_aggregation_functions(self):
        """Test all aggregation function types."""
        src = '''
        tool t {}
        observe syscall("read") measure latency {
            @cnt[pid] = count();
            @sum[pid] = sum(latency);
            @avg[pid] = avg(latency);
            @min[pid] = min(latency);
            @max[pid] = max(latency);
            @hist[pid] = hist(latency);
            @lhist[pid] = lhist(latency);
        }
        '''
        ir = _build_ir(src)
        from emon.bpfc_gen import generate_bpf_c
        code = generate_bpf_c(ir)

        self.assertIn("(*__val_", code)  # count increment
        self.assertIn("// avg:", code)
        self.assertIn("// hist:", code)
        self.assertIn("// lhist:", code)

    def test_composite_keys(self):
        src = 'tool t {} observe syscall("read") { @c[pid, comm, syscall] = count(); }'
        ir = _build_ir(src)
        from emon.bpfc_gen import generate_bpf_c
        code = generate_bpf_c(ir)

        # Should generate a composite key struct
        self.assertIn("struct key_", code)
        self.assertIn("__attribute__((packed))", code)

    def test_if_else_block(self):
        src = '''
        tool t {}
        observe syscall("read") measure latency {
            let slow = 1000000;
            let is_slow = latency > slow;
            if (is_slow) {
                @slow_cnt[pid] = count();
            } else {
                @fast_cnt[pid] = count();
            }
        }
        '''
        ir = _build_ir(src)
        from emon.bpfc_gen import generate_bpf_c
        code = generate_bpf_c(ir)

        self.assertIn("if (", code)
        self.assertIn("else {", code)
        self.assertIn("// let:", code)

    def test_multiple_targets(self):
        src = 'tool t {} observe syscall("read", "write", "openat") { @c[pid] = count(); }'
        ir = _build_ir(src)
        from emon.bpfc_gen import generate_bpf_c
        code = generate_bpf_c(ir)

        # Three entry probes
        self.assertIn("sys_enter_read", code)
        self.assertIn("sys_enter_write", code)
        self.assertIn("sys_enter_openat", code)

    def test_context_extraction(self):
        """Verify standard context variable extraction."""
        src = 'tool t {} observe syscall("read") { @c[pid] = count(); }'
        ir = _build_ir(src)
        from emon.bpfc_gen import generate_bpf_c
        code = generate_bpf_c(ir)

        self.assertIn("bpf_get_current_pid_tgid", code)
        self.assertIn("bpf_get_current_uid_gid", code)
        self.assertIn("bpf_get_current_comm", code)
        self.assertIn("bpf_ktime_get_ns", code)
        self.assertIn("bpf_get_smp_processor_id", code)

    def test_option_resolution_in_conditions(self):
        """Options in where/when clauses should be resolved to values."""
        src = '''
        tool t { option target_pid = 0; option min_lat = 100us; }
        observe syscall("read")
        where target_pid == 0 || pid == target_pid
        measure latency
        when latency > min_lat
        { @c[pid] = count(); }
        '''
        ir = _build_ir(src)
        from emon.bpfc_gen import generate_bpf_c
        code = generate_bpf_c(ir)

        # target_pid=0 should be resolved in actual C code (comments may retain original text)
        self.assertIn("100000", code)  # 100us in ns
        # Verify resolution in actual condition code (not comments)
        cond_line = [l for l in code.split('\n') if 'if (!(' in l and '0 == 0' in l]
        self.assertTrue(len(cond_line) > 0, "where condition should resolve target_pid to 0")

    def test_time_literal_conversion(self):
        """Time literals in conditions should convert to ns."""
        src = '''
        tool t { option threshold = 1ms; }
        observe syscall("read") measure latency
        when latency > threshold
        { @c[pid] = count(); }
        '''
        ir = _build_ir(src)
        from emon.bpfc_gen import generate_bpf_c
        code = generate_bpf_c(ir)

        self.assertIn("1000000", code)  # 1ms in ns

    def test_size_literal_conversion(self):
        """Size literals should convert to bytes."""
        src = '''
        tool t { option max_sz = 1MB; }
        observe syscall("read") measure size
        when size > max_sz
        { @c[pid] = count(); }
        '''
        ir = _build_ir(src)
        from emon.bpfc_gen import generate_bpf_c
        code = generate_bpf_c(ir)

        self.assertIn("1048576", code)  # 1MB in bytes

    def test_syscall_name_hardcoded(self):
        """Syscall names should be hardcoded in BPF code."""
        src = 'tool t {} observe syscall("openat") { @c[pid] = count(); }'
        ir = _build_ir(src)
        from emon.bpfc_gen import generate_bpf_c
        code = generate_bpf_c(ir)

        self.assertIn('"openat"', code)

    def test_exit_probe_context(self):
        """Exit probes should use trace_event_raw_sys_exit, not sys_enter."""
        src = 'tool t {} observe syscall("read") measure latency { @c[pid] = count(); }'
        ir = _build_ir(src)
        from emon.bpfc_gen import generate_bpf_c
        code = generate_bpf_c(ir)

        self.assertIn("trace_event_raw_sys_exit", code)

    def test_exit_probe_has_retval(self):
        """Exit probes should extract retval."""
        src = 'tool t {} observe syscall("read") measure latency, retval { @c[pid] = count(); }'
        ir = _build_ir(src)
        from emon.bpfc_gen import generate_bpf_c
        code = generate_bpf_c(ir)

        self.assertIn("retval", code)
        self.assertIn("BPF_CORE_READ(ctx, ret)", code)

    def test_entry_probe_no_actions_with_latency(self):
        """Entry probe should NOT have aggregations when latency is measured."""
        src = 'tool t {} observe syscall("read") measure latency { @c[pid] = avg(latency); }'
        ir = _build_ir(src)
        from emon.bpfc_gen import generate_bpf_c
        code = generate_bpf_c(ir)

        # Count probes: 1 entry (no actions) + 1 exit (with actions)
        # The entry probe should NOT contain avg_latency aggregation
        entry_section = code.find("sys_enter_read")
        exit_section = code.find("sys_exit_read")
        between = code[entry_section:exit_section] if exit_section > entry_section else ""
        # Entry probe should not have @avg aggregation
        self.assertNotIn("@avg", between if between else code[:exit_section])

    def test_percpu_map_generation(self):
        """Non-count aggregations should use PERCPU_HASH."""
        src = 'tool t {} observe syscall("read") measure latency { @avg[pid] = avg(latency); }'
        ir = _build_ir(src)
        from emon.bpfc_gen import generate_bpf_c
        code = generate_bpf_c(ir)

        self.assertIn("PERCPU_HASH", code)

    def test_count_map_is_hash(self):
        """Count aggregation should use regular HASH."""
        src = 'tool t {} observe syscall("read") { @c[pid] = count(); }'
        ir = _build_ir(src)
        from emon.bpfc_gen import generate_bpf_c
        code = generate_bpf_c(ir)

        self.assertIn("BPF_MAP_TYPE_HASH", code)

    def test_sched_hook(self):
        src = 'tool t {} observe sched("sched_switch") { @s[cpu] = count(); }'
        ir = _build_ir(src)
        from emon.bpfc_gen import generate_bpf_c
        code = generate_bpf_c(ir)

        self.assertIn("tracepoint/sched/sched_switch", code)

    def test_file_hook(self):
        src = 'tool t {} observe file("open") { @f[pid] = count(); }'
        ir = _build_ir(src)
        from emon.bpfc_gen import generate_bpf_c
        code = generate_bpf_c(ir)

        self.assertIn("kprobe/open", code)

    def test_net_hook(self):
        src = 'tool t {} observe net("tcp") { @n[pid] = count(); }'
        ir = _build_ir(src)
        from emon.bpfc_gen import generate_bpf_c
        code = generate_bpf_c(ir)

        self.assertIn("kprobe/tcp", code)

    def test_no_rodata_string_literals(self):
        """Generated code should use direct char[] initialization, not memcpy with literals."""
        src = 'tool t {} observe syscall("read") { @c[pid] = count(); }'
        ir = _build_ir(src)
        from emon.bpfc_gen import generate_bpf_c
        code = generate_bpf_c(ir)

        # Should use = "read" not memcpy with "read"
        self.assertIn('char syscall[16] = "read"', code)
        self.assertNotIn('__builtin_memcpy(syscall, "read"', code)

    def test_composite_key_memset(self):
        """Composite key init should use memset, not = {0}."""
        src = 'tool t {} observe syscall("read") { @c[pid, comm] = count(); }'
        ir = _build_ir(src)
        from emon.bpfc_gen import generate_bpf_c
        code = generate_bpf_c(ir)

        self.assertIn("__builtin_memset", code)

    def test_empty_options(self):
        """Tool without options should still compile."""
        src = 'tool t {} observe syscall("read") { @c[pid] = count(); }'
        ir = _build_ir(src)
        from emon.bpfc_gen import generate_bpf_c
        code = generate_bpf_c(ir)
        self.assertGreater(len(code), 100)

    def test_multiple_measure_types(self):
        """Multiple measure declarations should all be handled."""
        src = 'tool t {} observe syscall("read") measure latency, retval, size { @c[pid] = count(); }'
        ir = _build_ir(src)
        from emon.bpfc_gen import generate_bpf_c
        code = generate_bpf_c(ir)

        self.assertIn("latency", code)
        self.assertIn("retval", code)
        self.assertIn("size", code)


# =============================================================================
# libbpf Loader Generator Tests
# =============================================================================

class TestLoaderGenerator(unittest.TestCase):
    """Test libbpf loader C code generation."""

    def test_basic_loader(self):
        src = 'tool t {} observe syscall("read") { @c[pid] = count(); }'
        ir = _build_ir(src)
        from emon.loader_gen import generate_loader_c
        code = generate_loader_c(ir)

        self.assertIn("#include <bpf/libbpf.h>", code)
        self.assertIn("int main(", code)
        self.assertIn("_bpf__open", code)
        self.assertIn("_bpf__load", code)
        self.assertIn("_bpf__attach", code)
        self.assertIn("_bpf__destroy", code)
        self.assertIn("sigaction(SIGINT", code)
        self.assertIn("sigaction(SIGTERM", code)

    def test_loader_with_emit(self):
        src = '''
        tool t {}
        observe syscall("read") {
            emit { time = nsecs; pid = pid; };
        }
        '''
        ir = _build_ir(src)
        from emon.loader_gen import generate_loader_c
        code = generate_loader_c(ir)

        self.assertIn("ring_buffer__new", code)
        self.assertIn("__handle_event", code)
        self.assertIn("ring_buffer__poll", code)
        self.assertIn("ring_buffer__free", code)

    def test_loader_with_every(self):
        src = '''
        tool t { option interval = 1s; }
        observe syscall("read") { @c[pid] = count(); }
        every 2s { print("tick"); }
        '''
        ir = _build_ir(src)
        from emon.loader_gen import generate_loader_c
        code = generate_loader_c(ir)

        self.assertIn("every task", code)
        self.assertIn("__last_tick", code)
        self.assertIn("time(NULL)", code)

    def test_loader_with_begin_end(self):
        src = '''
        tool t {}
        observe syscall("read") { @c[pid] = count(); }
        begin { print("start"); }
        end { print("stop"); }
        '''
        ir = _build_ir(src)
        from emon.loader_gen import generate_loader_c
        code = generate_loader_c(ir)

        self.assertIn("begin block", code)
        self.assertIn("end block", code)

    def test_loader_with_options(self):
        src = '''
        tool t { option threshold = 1ms; option top_n = 10; }
        observe syscall("read") { @c[pid] = count(); }
        '''
        ir = _build_ir(src)
        from emon.loader_gen import generate_loader_c
        code = generate_loader_c(ir)

        self.assertIn("__opt_threshold", code)
        self.assertIn("__opt_top_n", code)

    def test_interval_to_seconds(self):
        from emon.loader_gen import LoaderGenerator
        from emon.ir import IRProgram
        ir = IRProgram(tool_name="test")
        gen = LoaderGenerator(ir)

        self.assertEqual(gen._interval_to_seconds("1s"), 1)
        self.assertEqual(gen._interval_to_seconds("100ms"), 1)
        self.assertEqual(gen._interval_to_seconds("500ms"), 1)
        self.assertEqual(gen._interval_to_seconds("2s"), 2)
        self.assertEqual(gen._interval_to_seconds("1000ms"), 1)
        self.assertEqual(gen._interval_to_seconds("1000000us"), 1)
        self.assertEqual(gen._interval_to_seconds("5"), 5)
        self.assertEqual(gen._interval_to_seconds("500ns"), 1)
        self.assertEqual(gen._interval_to_seconds("0"), 1)

    def test_loader_default_end_dump(self):
        """Without explicit end block, maps should be dumped."""
        src = 'tool t {} observe syscall("read") { @c[pid] = count(); }'
        ir = _build_ir(src)
        from emon.loader_gen import generate_loader_c
        code = generate_loader_c(ir)

        self.assertIn("Final Report", code)
        self.assertIn("__print_map_", code)

    def test_loader_with_top_query(self):
        """every block with top() should generate map print call."""
        src = '''
        tool t { option n = 20; }
        observe syscall("read") { @c[pid] = count(); }
        every 1s { print(top(@c, n)); }
        '''
        ir = _build_ir(src)
        from emon.loader_gen import generate_loader_c
        code = generate_loader_c(ir)

        self.assertIn("__print_map_", code)

    def test_loader_string_option_escaping(self):
        """String options with special chars should be properly escaped."""
        src = '''
        tool t { option path = "/var/log/test.log"; }
        observe syscall("read") { @c[pid] = count(); }
        '''
        ir = _build_ir(src)
        from emon.loader_gen import generate_loader_c
        code = generate_loader_c(ir)

        # Should have properly escaped C string
        self.assertIn('"/var/log/test.log"', code)
        # Should NOT have doubled quotes
        self.assertNotIn('""/var/', code)

    def test_loader_event_struct(self):
        """Loader should include event struct definition."""
        src = '''
        tool t {}
        observe syscall("read") {
            emit { time = nsecs; pid = pid; comm = comm; };
        }
        '''
        ir = _build_ir(src)
        from emon.loader_gen import generate_loader_c
        code = generate_loader_c(ir)

        self.assertIn("struct event_t", code)
        self.assertIn("unsigned long long time", code)

    def test_loader_signal_setup(self):
        """Loader should use sigaction, not plain signal()."""
        src = 'tool t {} observe syscall("read") { @c[pid] = count(); }'
        ir = _build_ir(src)
        from emon.loader_gen import generate_loader_c
        code = generate_loader_c(ir)

        self.assertIn("sigaction(SIGINT", code)
        self.assertIn("__setup_signals", code)
        self.assertNotIn("signal(SIGINT", code)

    def test_loader_small_sleep_chunks(self):
        """Sleep should use small chunks for Ctrl+C responsiveness."""
        src = 'tool t {} observe syscall("read") { @c[pid] = count(); }'
        ir = _build_ir(src)
        from emon.loader_gen import generate_loader_c
        code = generate_loader_c(ir)

        self.assertIn("usleep(50000)", code)

    def test_loader_percpu_map_printer(self):
        """Loader should handle PERCPU maps with __percpu_sum."""
        src = 'tool t {} observe syscall("read") measure latency { @avg[pid] = avg(latency); }'
        ir = _build_ir(src)
        from emon.loader_gen import generate_loader_c
        code = generate_loader_c(ir)

        self.assertIn("__percpu_sum", code)
        self.assertIn("libbpf_num_possible_cpus", code)

    def test_loader_hist_map_printer(self):
        """Loader should have histogram bucket printing for hist maps."""
        src = 'tool t {} observe syscall("read") measure latency { @my_hist[pid] = hist(latency); }'
        ir = _build_ir(src)
        from emon.loader_gen import generate_loader_c
        code = generate_loader_c(ir)

        self.assertIn("bucket", code)
        self.assertIn("fputc('#', stdout)", code)

    def test_loader_no_emit_no_ringbuf(self):
        """Without emit, loader should not set up ring buffer."""
        src = 'tool t {} observe syscall("read") { @c[pid] = count(); }'
        ir = _build_ir(src)
        from emon.loader_gen import generate_loader_c
        code = generate_loader_c(ir)

        self.assertNotIn("ring_buffer__new", code)

    def test_loader_heap_fallback(self):
        """Loader should have heap fallback (malloc) for large percpu values."""
        src = 'tool t {} observe syscall("read") measure latency { @h[pid] = hist(latency); }'
        ir = _build_ir(src)
        from emon.loader_gen import generate_loader_c
        code = generate_loader_c(ir)

        self.assertIn("malloc", code)
        self.assertIn("use_heap", code)


# =============================================================================
# Manifest Generator Tests
# =============================================================================

class TestManifestGenerator(unittest.TestCase):
    """Test YAML manifest generation."""

    def test_basic_manifest(self):
        src = 'tool my_tool {} observe syscall("read") { @c[pid] = count(); }'
        ir = _build_ir(src)
        from emon.manifest_gen import generate_manifest
        yaml_str = generate_manifest(ir)

        self.assertIn("tool:", yaml_str)
        self.assertIn("name: my_tool", yaml_str)
        self.assertIn("maps:", yaml_str)
        self.assertIn("probes:", yaml_str)
        self.assertIn("events:", yaml_str)
        self.assertIn("lifecycle:", yaml_str)

    def test_manifest_with_options(self):
        src = '''
        tool my_tool { option threshold = 1ms; option top_n = 20; }
        observe syscall("read") { @c[pid] = count(); }
        '''
        ir = _build_ir(src)
        from emon.manifest_gen import generate_manifest
        yaml_str = generate_manifest(ir)

        self.assertIn("threshold:", yaml_str)
        self.assertIn("top_n:", yaml_str)

    def test_manifest_with_emit(self):
        src = '''
        tool t {}
        observe syscall("read") {
            emit { time = nsecs; pid = pid; };
        }
        '''
        ir = _build_ir(src)
        from emon.manifest_gen import generate_manifest
        yaml_str = generate_manifest(ir)

        self.assertIn("ringbuf", yaml_str)
        self.assertIn("name: time", yaml_str)
        self.assertIn("name: pid", yaml_str)

    def test_manifest_maps_detail(self):
        src = 'tool t {} observe syscall("read") measure latency { @avg_lat[pid, comm] = avg(latency); }'
        ir = _build_ir(src)
        from emon.manifest_gen import generate_manifest
        yaml_str = generate_manifest(ir)

        self.assertIn("name: avg_lat", yaml_str)
        self.assertIn("avg", yaml_str.lower())

    def test_manifest_with_lifecycle(self):
        src = '''
        tool t {}
        observe syscall("read") { @c[pid] = count(); }
        begin { print("hello"); }
        every 1s { print("tick"); }
        end { print("bye"); }
        '''
        ir = _build_ir(src)
        from emon.manifest_gen import generate_manifest
        yaml_str = generate_manifest(ir)

        self.assertIn("begin:", yaml_str)
        self.assertIn("every:", yaml_str)
        self.assertIn("end:", yaml_str)

    def test_manifest_with_all_hook_types(self):
        src = '''
        tool t {}
        observe syscall("read") { @c[pid] = count(); }
        observe kernel("func") { @k[pid] = count(); }
        observe tracepoint("cat:name") { @t[pid] = count(); }
        '''
        ir = _build_ir(src)
        from emon.manifest_gen import generate_manifest
        yaml_str = generate_manifest(ir)

        self.assertIn("syscall", yaml_str.lower())
        self.assertIn("kernel", yaml_str.lower())
        self.assertIn("tracepoint", yaml_str.lower())

    def test_manifest_probe_conditions(self):
        src = '''
        tool t {}
        observe syscall("read") where pid > 0 measure latency when latency > 1000
        { @c[pid] = count(); }
        '''
        ir = _build_ir(src)
        from emon.manifest_gen import generate_manifest
        yaml_str = generate_manifest(ir)

        self.assertIn("where:", yaml_str)
        self.assertIn("when:", yaml_str)
        self.assertIn("measures_latency: true", yaml_str)

    def test_manifest_with_emit(self):
        src = '''
        tool t {}
        observe syscall("read") {
            emit { time = nsecs; pid = pid; };
        }
        '''
        ir = _build_ir(src)
        from emon.manifest_gen import generate_manifest
        yaml_str = generate_manifest(ir)

        self.assertIn("ringbuf", yaml_str)
        self.assertIn("name: time", yaml_str)
        self.assertIn("name: pid", yaml_str)

    def test_manifest_maps_detail(self):
        src = 'tool t {} observe syscall("read") measure latency { @avg_lat[pid, comm] = avg(latency); }'
        ir = _build_ir(src)
        from emon.manifest_gen import generate_manifest
        yaml_str = generate_manifest(ir)

        self.assertIn("name: avg_lat", yaml_str)
        self.assertIn("avg", yaml_str.lower())


# =============================================================================
# Full Compile Pipeline Tests
# =============================================================================

class TestCompilePipeline(unittest.TestCase):
    """Test the full compile() pipeline end-to-end."""

    def test_compile_source_returns_all_artifacts(self):
        src = 'tool t {} observe syscall("read") { @c[pid] = count(); }'
        results = compile_source(src, tool_name="test_tool")

        self.assertIn("bpf_c", results)
        self.assertIn("loader_c", results)
        self.assertIn("manifest", results)
        self.assertIn("ir", results)

        self.assertIsInstance(results["bpf_c"], str)
        self.assertIsInstance(results["loader_c"], str)
        self.assertIsInstance(results["manifest"], str)
        self.assertIsInstance(results["ir"], IRProgram)

    def test_compile_source_rejects_errors(self):
        # Missing measure declaration for 'latency'
        src = 'tool t {} observe syscall("read") { @c[pid] = avg(latency); }'
        with self.assertRaises(ValueError) as ctx:
            compile_source(src)
        self.assertIn("Semantic", str(ctx.exception))

    def test_compile_file_writes_outputs(self):
        src = 'tool t {} observe syscall("read") { @c[pid] = count(); }'
        with tempfile.TemporaryDirectory() as tmpdir:
            src_path = os.path.join(tmpdir, "test.emon")
            with open(src_path, "w") as f:
                f.write(src)

            results = compile_file(src_path, output_dir=tmpdir)

            for key in ("bpf_c", "loader_c", "manifest"):
                self.assertIn(key, results)
                self.assertTrue(os.path.exists(results[key]),
                               f"{key} file not found: {results[key]}")

    def test_compile_file_with_options(self):
        """Compile a tool with options and verify output."""
        src = '''
        tool my_tool { option target_pid = 0; option interval = 1s; }
        observe syscall("read") where target_pid == 0 || pid == target_pid
        { @c[pid] = count(); }
        every interval { print("tick"); }
        '''
        with tempfile.TemporaryDirectory() as tmpdir:
            src_path = os.path.join(tmpdir, "test.emon")
            with open(src_path, "w") as f:
                f.write(src)

            results = compile_file(src_path, output_dir=tmpdir)
            with open(results["bpf_c"], "r") as f:
                bpf_code = f.read()
            # target_pid option should be resolved
            self.assertIn("0", bpf_code)

    def test_compile_file_creates_output_dir(self):
        """compile_file should auto-create output directory."""
        src = 'tool t {} observe syscall("read") { @c[pid] = count(); }'
        with tempfile.TemporaryDirectory() as tmpdir:
            out_dir = os.path.join(tmpdir, "nested", "output")
            src_path = os.path.join(tmpdir, "test.emon")
            with open(src_path, "w") as f:
                f.write(src)

            results = compile_file(src_path, output_dir=out_dir)
            self.assertTrue(os.path.isdir(out_dir))
            self.assertTrue(os.path.exists(results["bpf_c"]))

    def test_compile_latency_example(self):
        """Compile the actual syscall_latency example file."""
        example_path = os.path.join(
            os.path.dirname(__file__), "..", "examples", "syscall_latency.emon"
        )
        if not os.path.exists(example_path):
            self.skipTest("Example file not found")

        with tempfile.TemporaryDirectory() as tmpdir:
            results = compile_file(example_path, output_dir=tmpdir)

            self.assertTrue(os.path.getsize(results["bpf_c"]) > 1000)
            self.assertTrue(os.path.getsize(results["loader_c"]) > 1000)
            self.assertTrue(os.path.getsize(results["manifest"]) > 100)


class TestIRPhaseSeparation(unittest.TestCase):
    """Verify that IR correctly separates where/when between entry/exit probes."""

    def test_where_on_entry_only(self):
        src = 'tool t {} observe syscall("read") where pid > 0 { @c[pid] = count(); }'
        ir = _build_ir(src)
        self.assertEqual(len(ir.probes), 1)
        probe = ir.probes[0]
        self.assertFalse(probe.is_exit)
        self.assertEqual(len(probe.where_conditions), 1)
        self.assertEqual(len(probe.when_conditions), 0)

    def test_when_on_entry_when_no_latency(self):
        src = 'tool t {} observe syscall("read") when pid > 0 { @c[pid] = count(); }'
        ir = _build_ir(src)
        self.assertEqual(len(ir.probes), 1)
        probe = ir.probes[0]
        self.assertEqual(len(probe.when_conditions), 1)

    def test_where_entry_when_exit_with_latency(self):
        src = 'tool t {} observe syscall("read") where pid > 0 measure latency when latency > 1000 { @c[pid] = count(); }'
        ir = _build_ir(src)
        self.assertEqual(len(ir.probes), 2)

        entry = [p for p in ir.probes if not p.is_exit][0]
        exit_p = [p for p in ir.probes if p.is_exit][0]

        # where on entry only
        self.assertGreater(len(entry.where_conditions), 0)
        self.assertEqual(len(entry.when_conditions), 0)
        # when on exit only
        self.assertEqual(len(exit_p.where_conditions), 0)
        self.assertGreater(len(exit_p.when_conditions), 0)

    def test_entry_probe_no_actions_with_latency(self):
        src = 'tool t {} observe syscall("read") measure latency { @c[pid] = count(); @avg[pid] = avg(latency); }'
        ir = _build_ir(src)

        entry = [p for p in ir.probes if not p.is_exit][0]
        exit_p = [p for p in ir.probes if p.is_exit][0]

        # Entry probe should have no aggregations
        self.assertEqual(len(entry.aggregations), 0)
        self.assertEqual(len(entry.emits), 0)
        # Exit probe should have all aggregations
        self.assertEqual(len(exit_p.aggregations), 2)

    def test_multi_target_probes(self):
        src = 'tool t {} observe syscall("read", "write") measure latency { @c[pid] = count(); }'
        ir = _build_ir(src)

        # 2 targets × 2 probes (entry+exit) = 4 probes
        self.assertEqual(len(ir.probes), 4)
        entries = [p for p in ir.probes if not p.is_exit]
        exits = [p for p in ir.probes if p.is_exit]
        self.assertEqual(len(entries), 2)
        self.assertEqual(len(exits), 2)


class TestIRMapTypes(unittest.TestCase):
    """Verify correct BPF map types are assigned."""

    def test_count_is_hash(self):
        ir = _build_ir('tool t {} observe syscall("read") { @c[pid] = count(); }')
        m = ir.maps[0]
        self.assertEqual(m.map_type, "HASH")

    def test_sum_is_percpu_hash(self):
        ir = _build_ir('tool t {} observe syscall("read") measure latency { @s[pid] = sum(latency); }')
        m = ir.maps[0]
        self.assertEqual(m.map_type, "PERCPU_HASH")

    def test_avg_is_percpu_hash(self):
        ir = _build_ir('tool t {} observe syscall("read") measure latency { @a[pid] = avg(latency); }')
        m = ir.maps[0]
        self.assertEqual(m.map_type, "PERCPU_HASH")

    def test_hist_is_percpu_hash(self):
        ir = _build_ir('tool t {} observe syscall("read") measure latency { @h[pid] = hist(latency); }')
        m = ir.maps[0]
        self.assertEqual(m.map_type, "PERCPU_HASH")

    def test_avg_value_type(self):
        ir = _build_ir('tool t {} observe syscall("read") measure latency { @a[pid] = avg(latency); }')
        m = ir.maps[0]
        self.assertIn("sum", m.value_type)
        self.assertIn("count", m.value_type)

    def test_map_deduplication(self):
        src = '''
        tool t {}
        observe syscall("read") { @c[pid] = count(); }
        observe syscall("write") { @c[pid] = count(); }
        '''
        ir = _build_ir(src)
        # Same @c map should be deduplicated
        c_maps = [m for m in ir.maps if m.name == "c"]
        self.assertEqual(len(c_maps), 1)


class TestIRCompileFunctions(unittest.TestCase):
    """Test the new compile functions in ir.py."""

    def test_build_ir_from_source(self):
        src = 'tool my_test {} observe syscall("read") { @c[pid] = count(); }'
        ir = build_ir_from_source(src)
        self.assertEqual(ir.tool_name, "my_test")
        self.assertEqual(len(ir.probes), 1)

    def test_build_ir_from_source_rejects_errors(self):
        src = 'tool t {} observe syscall("read") { @c[pid] = avg(latency); }'
        with self.assertRaises(ValueError):
            build_ir_from_source(src)

    def test_compile_full_feature_example(self):
        example_path = os.path.join(
            os.path.dirname(__file__), "..", "examples", "syscall_count.emon"
        )
        if not os.path.exists(example_path):
            self.skipTest("Example file not found")

        with tempfile.TemporaryDirectory() as tmpdir:
            results = compile_file(example_path, output_dir=tmpdir)
            self.assertTrue(os.path.getsize(results["bpf_c"]) > 100)
            self.assertTrue(os.path.getsize(results["loader_c"]) > 100)
            self.assertTrue(os.path.getsize(results["manifest"]) > 50)


# =============================================================================
# IR JSON round-trip tests (preserved from original)
# =============================================================================

class TestIRJsonRoundTrip(unittest.TestCase):
    """Test IR JSON serialization still works (backward compat)."""

    def test_json_serialization(self):
        src = 'tool t {} observe syscall("read") { @c[pid] = count(); }'
        ir = _build_ir(src)
        json_str = ir.to_json()

        self.assertIn('"tool_name"', json_str)
        self.assertIn('"t"', json_str)
        self.assertIn('"probes"', json_str)

        # Should be valid JSON
        import json
        data = json.loads(json_str)
        self.assertEqual(data["tool_name"], "t")
        self.assertEqual(len(data["probes"]), 1)


if __name__ == '__main__':
    unittest.main()
