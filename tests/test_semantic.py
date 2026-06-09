"""
Emon DSL Semantic Analyzer Tests

Validates each category of semantic check:
  - Unknown identifiers
  - Hook scope violations
  - Measure scope violations
  - Phase restrictions
  - Aggregation argument counts
  - Duplicate detection
  - Lifecycle statement constraints
"""

import unittest

from emon.parser import parse
from emon.semantic import analyze, SemanticError


class TestSemanticValid(unittest.TestCase):
    """Programs that should pass with zero errors."""

    def test_minimal_observe(self):
        src = 'tool t {} observe syscall("read") { @c[pid] = count(); }'
        errors = analyze(parse(src))
        self.assertEqual(errors, [])

    def test_syscall_with_latency(self):
        src = """tool t { option x = 1s; }
observe syscall("read") measure latency {
    @avg[pid] = avg(latency);
}"""
        errors = analyze(parse(src))
        self.assertEqual(errors, [])

    def test_kernel_with_func_and_args(self):
        src = 'tool t {} observe kernel("func1") { @k[func, arg0] = count(); }'
        errors = analyze(parse(src))
        self.assertEqual(errors, [])

    def test_uprobe_with_func(self):
        src = 'tool t {} observe uprobe("/bin/bash", "readline") { @u[func, pid] = count(); }'
        errors = analyze(parse(src))
        self.assertEqual(errors, [])

    def test_all_agg_functions(self):
        src = """tool t {}
observe syscall("r") measure latency, size {
    @c[pid] = count();
    @s[pid] = sum(latency);
    @a[pid] = avg(latency);
    @mn[pid] = min(latency);
    @mx[pid] = max(latency);
    @h[pid] = hist(latency);
    @lh[pid] = lhist(latency);
}"""
        errors = analyze(parse(src))
        self.assertEqual(errors, [])

    def test_let_and_if(self):
        src = """tool t {}
observe syscall("r") measure latency {
    let threshold = 1000;
    if (latency > threshold) {
        @slow[pid] = count();
    } else {
        @fast[pid] = count();
    }
}"""
        errors = analyze(parse(src))
        self.assertEqual(errors, [])

    def test_emit_with_context_vars(self):
        src = """tool t {}
observe syscall("read") measure latency {
    @c[pid] = count();
    emit {
        time = nsecs;
        pid = pid;
        comm = comm;
        cpu = cpu;
    };
}"""
        errors = analyze(parse(src))
        self.assertEqual(errors, [])

    def test_lifecycle_with_options(self):
        src = """tool t { option interval = 2s; }
observe syscall("r") { @c[pid] = count(); }
every interval { print(@c); }
begin { print("start"); }
end { print("done"); print(@c); }"""
        errors = analyze(parse(src))
        self.assertEqual(errors, [])

    def test_full_feature_example(self):
        from emon.parser import parse_file
        ast = parse_file("emon-dsl/examples/full_feature_test.emon")
        errors = analyze(ast)
        self.assertEqual(errors, [])


class TestSemanticUnknown(unittest.TestCase):
    """Detect references to non-existent variables."""

    def test_unknown_variable(self):
        src = 'tool t {} observe syscall("r") where foobar > 0 { @c[pid] = count(); }'
        errors = analyze(parse(src))
        self.assertTrue(any(e.category == "unknown" for e in errors))

    def test_typo_in_measure_var(self):
        src = 'tool t {} observe syscall("r") where latenc > 0 measure latency { @c[pid] = count(); }'
        errors = analyze(parse(src))
        self.assertTrue(any(e.category == "unknown" for e in errors))


class TestSemanticHookScope(unittest.TestCase):
    """Detect hook-specific context variables used in wrong hook type."""

    def test_syscall_var_in_kernel(self):
        src = 'tool t {} observe kernel("f") where syscall == "read" { @c[arg0] = count(); }'
        errors = analyze(parse(src))
        self.assertTrue(any(e.category == "scope" for e in errors))

    def test_func_var_in_syscall(self):
        src = 'tool t {} observe syscall("r") where func > 0 { @c[pid] = count(); }'
        errors = analyze(parse(src))
        self.assertTrue(any(e.category == "scope" for e in errors))

    def test_arg0_in_syscall(self):
        src = 'tool t {} observe syscall("r") { @c[arg0] = count(); }'
        errors = analyze(parse(src))
        self.assertTrue(any(e.category == "scope" for e in errors))

    def test_func_outside_observe(self):
        src = 'tool t {} begin { print(func); }'
        errors = analyze(parse(src))
        self.assertTrue(any(e.category == "scope" for e in errors))


class TestSemanticMeasureScope(unittest.TestCase):
    """Detect measure-dependent variables used without declaring the measure."""

    def test_latency_without_measure(self):
        src = 'tool t {} observe syscall("r") where latency > 1000 { @c[pid] = count(); }'
        errors = analyze(parse(src))
        self.assertTrue(any(e.category == "measure" for e in errors))

    def test_size_without_measure(self):
        src = 'tool t {} observe syscall("r") { @s[pid] = sum(size); }'
        errors = analyze(parse(src))
        self.assertTrue(any(e.category == "measure" for e in errors))

    def test_retval_without_measure(self):
        src = 'tool t {} observe syscall("r") when retval < 0 { @c[pid] = count(); }'
        errors = analyze(parse(src))
        self.assertTrue(any(e.category == "measure" for e in errors))

    def test_latency_with_measure_passes(self):
        src = 'tool t {} observe syscall("r") where latency > 0 measure latency { @c[pid] = count(); }'
        errors = analyze(parse(src))
        self.assertFalse(any(e.category == "measure" for e in errors))


class TestSemanticPhase(unittest.TestCase):
    """Detect phase-restricted variables used in wrong phase."""

    def test_retval_in_where(self):
        src = 'tool t {} observe syscall("r") where retval == 0 measure retval { @c[pid] = count(); }'
        errors = analyze(parse(src))
        self.assertTrue(any(e.category == "phase" for e in errors))

    def test_retval_in_when_allowed(self):
        src = 'tool t {} observe syscall("r") measure retval when retval < 0 { @c[pid] = count(); }'
        errors = analyze(parse(src))
        self.assertFalse(any(e.category == "phase" for e in errors))

    def test_retval_in_action_allowed(self):
        src = """tool t {}
observe syscall("r") measure retval {
    let x = retval;
}"""
        errors = analyze(parse(src))
        self.assertFalse(any(e.category == "phase" for e in errors))


class TestSemanticAggregation(unittest.TestCase):
    """Detect aggregation function argument count errors."""

    def test_count_with_arg(self):
        src = 'tool t {} observe syscall("r") { @c[pid] = count(latency); }'
        errors = analyze(parse(src))
        self.assertTrue(any(e.category == "aggregation" for e in errors))

    def test_sum_without_arg(self):
        src = 'tool t {} observe syscall("r") { @s[pid] = sum(); }'
        errors = analyze(parse(src))
        self.assertTrue(any(e.category == "aggregation" for e in errors))

    def test_avg_without_arg(self):
        src = 'tool t {} observe syscall("r") { @a[pid] = avg(); }'
        errors = analyze(parse(src))
        self.assertTrue(any(e.category == "aggregation" for e in errors))

    def test_count_without_arg_passes(self):
        src = 'tool t {} observe syscall("r") { @c[pid] = count(); }'
        errors = analyze(parse(src))
        self.assertFalse(any(e.category == "aggregation" for e in errors))

    def test_sum_with_arg_passes(self):
        src = 'tool t {} observe syscall("r") measure latency { @s[pid] = sum(latency); }'
        errors = analyze(parse(src))
        self.assertFalse(any(e.category == "aggregation" for e in errors))


class TestSemanticDuplicate(unittest.TestCase):
    """Detect duplicate identifiers."""

    def test_duplicate_agg(self):
        src = 'tool t {} observe syscall("r") { @c[pid] = count(); @c[pid] = count(); }'
        errors = analyze(parse(src))
        self.assertTrue(any(e.category == "duplicate" for e in errors))

    def test_unique_aggs_pass(self):
        src = 'tool t {} observe syscall("r") { @c1[pid] = count(); @c2[pid] = count(); }'
        errors = analyze(parse(src))
        self.assertFalse(any(e.category == "duplicate" for e in errors))

    def test_duplicate_let(self):
        src = 'tool t {} observe syscall("r") { let x = 1; let x = 2; }'
        errors = analyze(parse(src))
        self.assertTrue(any(e.category == "duplicate" for e in errors))

    def test_unique_lets_pass(self):
        src = 'tool t {} observe syscall("r") { let x = 1; let y = 2; }'
        errors = analyze(parse(src))
        self.assertFalse(any(e.category == "duplicate" for e in errors))


class TestSemanticLifecycle(unittest.TestCase):
    """Detect lifecycle statement errors."""

    def test_every_with_unknown_option(self):
        src = """tool t {}
observe syscall("r") { @c[pid] = count(); }
every unknown_opt { print(@c); }"""
        errors = analyze(parse(src))
        self.assertTrue(any(e.category == "lifecycle" for e in errors))

    def test_every_with_integer(self):
        src = """tool t {}
observe syscall("r") { @c[pid] = count(); }
every 100 { print(@c); }"""
        errors = analyze(parse(src))
        self.assertTrue(any(e.category == "lifecycle" for e in errors))

    def test_every_with_time_literal_passes(self):
        src = """tool t {}
observe syscall("r") { @c[pid] = count(); }
every 1s { print(@c); }"""
        errors = analyze(parse(src))
        self.assertFalse(any(e.category == "lifecycle" for e in errors))

    def test_every_with_valid_option_passes(self):
        src = """tool t { option interval = 2s; }
observe syscall("r") { @c[pid] = count(); }
every interval { print(@c); }"""
        errors = analyze(parse(src))
        self.assertFalse(any(e.category == "lifecycle" for e in errors))


if __name__ == '__main__':
    unittest.main()
