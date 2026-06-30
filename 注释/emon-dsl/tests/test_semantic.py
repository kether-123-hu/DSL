# ===================================================================
# test_semantic.py —— Emon DSL 语义分析器测试
# ===================================================================
#
# 【本文件的作用】
# 对语义分析器（semantic.py）进行单元测试，验证各类语义检查的正确性。
# 语义分析是编译器的第三阶段，检查 AST 的"逻辑正确性"。
#
# 【测试覆盖的 7 类语义检查】
#   1. 合法程序        — 确认正确的程序通过所有检查（零错误）
#   2. 未知标识符      — 检测未定义的变量引用
#   3. Hook 作用域     — 检测 hook 专属变量在错误的 hook 类型中使用
#   4. Measure 依赖    — 检测未声明 measure 就使用 latency/retval/size
#   5. 阶段限制        — 检测 retval 等出口变量在 where 子句中使用
#   6. 聚合函数参数    — 检测 count() 带参 / avg() 无参等错误
#   7. 重复标识符      — 检测同名 @agg 或 let 变量
#   8. 生命周期约束    — 检测 every 间隔的合法性
#
# 【测试设计原则】
# 每个测试类负责一类语义检查，其中:
#   - test_*_passes: 验证合法程序不产生错误
#   - 其余 test_*:   验证各类非法程序正确产生对应 category 的错误
# ===================================================================

import unittest

from emon.parser import parse
from emon.semantic import analyze, SemanticError


# ===================================================================
# TestSemanticValid —— 合法程序测试
# ===================================================================

class TestSemanticValid(unittest.TestCase):
    """
    测试语义正确的程序能通过全部检查（零错误）。
    
    这些测试确保语义分析器不会误报——
    即不会把正确的程序标记为有错误（false positive）。
    """

    def test_minimal_observe(self):
        """最简 observe 程序: 单个 syscall + count 聚合"""
        src = 'tool t {} observe syscall("read") { @c[pid] = count(); }'
        errors = analyze(parse(src))
        self.assertEqual(errors, [])

    def test_syscall_with_latency(self):
        """带 latency 测量的 syscall 程序: measure latency + avg(latency)"""
        src = """tool t { option x = 1s; }
observe syscall("read") measure latency {
    @avg[pid] = avg(latency);
}"""
        errors = analyze(parse(src))
        self.assertEqual(errors, [])

    def test_kernel_with_func_and_args(self):
        """kernel hook 中使用 func 和 arg0 上下文变量"""
        src = 'tool t {} observe kernel("func1") { @k[func, arg0] = count(); }'
        errors = analyze(parse(src))
        self.assertEqual(errors, [])

    def test_uprobe_with_func(self):
        """uprobe hook 中使用 func 和 pid 上下文变量"""
        src = 'tool t {} observe uprobe("/bin/bash", "readline") { @u[func, pid] = count(); }'
        errors = analyze(parse(src))
        self.assertEqual(errors, [])

    def test_all_agg_functions(self):
        """全部 7 种聚合函数组合使用，应零错误"""
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
        """let 变量 + if-else 条件分支，应零错误"""
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
        """emit 中使用多种上下文变量 (nsecs, pid, comm, cpu)"""
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
        """完整的生命周期语句: every + begin + end + option 引用"""
        src = """tool t { option interval = 2s; }
observe syscall("r") { @c[pid] = count(); }
every interval { print(@c); }
begin { print("start"); }
end { print("done"); print(@c); }"""
        errors = analyze(parse(src))
        self.assertEqual(errors, [])

    def test_full_feature_example(self):
        """集成测试: 验证 full_feature_test.emon 示例零语义错误"""
        from emon.parser import parse_file
        ast = parse_file("examples/full_feature_test.emon")
        errors = analyze(ast)
        self.assertEqual(errors, [])


# ===================================================================
# TestSemanticUnknown —— 未知标识符检测
# ===================================================================

class TestSemanticUnknown(unittest.TestCase):
    """
    测试对未定义变量引用的检测。
    
    如果程序使用了从未声明过的变量名（不在全局上下文、hook 上下文、
    measure 上下文、let 变量或 option 中），语义分析器应报告错误。
    """

    def test_unknown_variable(self):
        '''使用完全未定义的变量 foobar → category="unknown"'''
        src = 'tool t {} observe syscall("r") where foobar > 0 { @c[pid] = count(); }'
        errors = analyze(parse(src))
        self.assertTrue(any(e.category == "unknown" for e in errors))

    def test_typo_in_measure_var(self):
        '''拼写错误 latenc（应为 latency）→ category="unknown"'''
        src = 'tool t {} observe syscall("r") where latenc > 0 measure latency { @c[pid] = count(); }'
        errors = analyze(parse(src))
        self.assertTrue(any(e.category == "unknown" for e in errors))


# ===================================================================
# TestSemanticHookScope —— Hook 作用域检查
# ===================================================================

class TestSemanticHookScope(unittest.TestCase):
    """
    测试 hook 专属上下文变量的作用域检查。
    
    某些变量只在特定 hook 类型中可用:
    - syscall: 仅在 observe syscall 中可用
    - func, arg0~arg5: 仅在 kernel/uprobe/file/net 中可用
    
    如果在错误的 hook 类型中使用这些变量，应产生 scope 错误。
    """

    def test_syscall_var_in_kernel(self):
        '''在 kernel hook 中使用 syscall 变量 → category="scope"'''
        src = 'tool t {} observe kernel("f") where syscall == "read" { @c[arg0] = count(); }'
        errors = analyze(parse(src))
        self.assertTrue(any(e.category == "scope" for e in errors))

    def test_func_var_in_syscall(self):
        '''在 syscall hook 中使用 func 变量 → category="scope"'''
        src = 'tool t {} observe syscall("r") where func > 0 { @c[pid] = count(); }'
        errors = analyze(parse(src))
        self.assertTrue(any(e.category == "scope" for e in errors))

    def test_arg0_in_syscall(self):
        '''在 syscall hook 中使用 arg0 变量 → category="scope"'''
        src = 'tool t {} observe syscall("r") { @c[arg0] = count(); }'
        errors = analyze(parse(src))
        self.assertTrue(any(e.category == "scope" for e in errors))

    def test_func_outside_observe(self):
        '''在 begin 块中使用 func（不在任何 hook 上下文中）→ category="scope"'''
        src = 'tool t {} begin { print(func); }'
        errors = analyze(parse(src))
        self.assertTrue(any(e.category == "scope" for e in errors))


# ===================================================================
# TestSemanticMeasureScope —— Measure 依赖检查
# ===================================================================

class TestSemanticMeasureScope(unittest.TestCase):
    """
    测试对 measure 依赖变量的检查。
    
    latency、retval、size 这些变量必须先在 measure 子句中声明才能使用。
    如果未声明就使用，应产生 measure 错误。
    """

    def test_latency_without_measure(self):
        '''使用 latency 但未 measure latency → category="measure"'''
        src = 'tool t {} observe syscall("r") where latency > 1000 { @c[pid] = count(); }'
        errors = analyze(parse(src))
        self.assertTrue(any(e.category == "measure" for e in errors))

    def test_size_without_measure(self):
        '''使用 size 但未 measure size → category="measure"'''
        src = 'tool t {} observe syscall("r") { @s[pid] = sum(size); }'
        errors = analyze(parse(src))
        self.assertTrue(any(e.category == "measure" for e in errors))

    def test_retval_without_measure(self):
        '''使用 retval 但未 measure retval → category="measure"'''
        src = 'tool t {} observe syscall("r") when retval < 0 { @c[pid] = count(); }'
        errors = analyze(parse(src))
        self.assertTrue(any(e.category == "measure" for e in errors))

    def test_latency_with_measure_passes(self):
        """声明了 measure latency 后再使用 latency → 不应有 measure 错误（回归测试）"""
        src = 'tool t {} observe syscall("r") where latency > 0 measure latency { @c[pid] = count(); }'
        errors = analyze(parse(src))
        self.assertFalse(any(e.category == "measure" for e in errors))


# ===================================================================
# TestSemanticPhase —— 阶段限制检查
# ===================================================================

class TestSemanticPhase(unittest.TestCase):
    """
    测试变量的阶段使用限制。
    
    某些变量（如 retval）只在函数返回时才知道值，
    因此不能在函数入口阶段（where 子句）中使用。
    
    阶段划分:
    - 入口阶段 (where):  可使用全局上下文变量和 hook 上下文变量
    - 出口阶段 (when):   可使用所有变量（包括 retval, latency）
    - 动作阶段 (action): 可使用所有变量
    """

    def test_retval_in_where(self):
        """在 where 中使用 retval → category="phase"（retval 在入口时不存在）"""
        src = 'tool t {} observe syscall("r") where retval == 0 measure retval { @c[pid] = count(); }'
        errors = analyze(parse(src))
        self.assertTrue(any(e.category == "phase" for e in errors))

    def test_retval_in_when_allowed(self):
        """在 when 中使用 retval → 合法（when 在出口处执行）"""
        src = 'tool t {} observe syscall("r") measure retval when retval < 0 { @c[pid] = count(); }'
        errors = analyze(parse(src))
        self.assertFalse(any(e.category == "phase" for e in errors))

    def test_retval_in_action_allowed(self):
        """在 let 中使用 retval → 合法（action 在出口处执行）"""
        src = """tool t {}
observe syscall("r") measure retval {
    let x = retval;
}"""
        errors = analyze(parse(src))
        self.assertFalse(any(e.category == "phase" for e in errors))


# ===================================================================
# TestSemanticAggregation —— 聚合函数参数检查
# ===================================================================

class TestSemanticAggregation(unittest.TestCase):
    """
    测试聚合函数参数数量的检查。
    
    不同聚合函数对参数有不同的要求:
    - count():  不需要参数（只计数）
    - sum/avg/min/max/hist/lhist: 需要一个参数（被聚合的值）
    
    参数数量不匹配应产生 aggregation 错误。
    """

    def test_count_with_arg(self):
        '''count(latency) — count 不应有参数 → category="aggregation"'''
        src = 'tool t {} observe syscall("r") { @c[pid] = count(latency); }'
        errors = analyze(parse(src))
        self.assertTrue(any(e.category == "aggregation" for e in errors))

    def test_sum_without_arg(self):
        '''sum() — sum 需要参数 → category="aggregation"'''
        src = 'tool t {} observe syscall("r") { @s[pid] = sum(); }'
        errors = analyze(parse(src))
        self.assertTrue(any(e.category == "aggregation" for e in errors))

    def test_avg_without_arg(self):
        '''avg() — avg 需要参数 → category="aggregation"'''
        src = 'tool t {} observe syscall("r") { @a[pid] = avg(); }'
        errors = analyze(parse(src))
        self.assertTrue(any(e.category == "aggregation" for e in errors))

    def test_count_without_arg_passes(self):
        """count() — count 无参是合法的（回归测试）"""
        src = 'tool t {} observe syscall("r") { @c[pid] = count(); }'
        errors = analyze(parse(src))
        self.assertFalse(any(e.category == "aggregation" for e in errors))

    def test_sum_with_arg_passes(self):
        """sum(latency) — sum 带参是合法的（回归测试）"""
        src = 'tool t {} observe syscall("r") measure latency { @s[pid] = sum(latency); }'
        errors = analyze(parse(src))
        self.assertFalse(any(e.category == "aggregation" for e in errors))


# ===================================================================
# TestSemanticDuplicate —— 重复标识符检测
# ===================================================================

class TestSemanticDuplicate(unittest.TestCase):
    """
    测试对重复标识符的检测。
    
    在同一作用域内，不能声明两个同名的:
    - 聚合变量 (@agg): 会导致 map 名称冲突
    - let 变量:       会导致变量遮蔽
    """

    def test_duplicate_agg(self):
        '''同一 observe 块内声明两个 @c → category="duplicate"'''
        src = 'tool t {} observe syscall("r") { @c[pid] = count(); @c[pid] = count(); }'
        errors = analyze(parse(src))
        self.assertTrue(any(e.category == "duplicate" for e in errors))

    def test_unique_aggs_pass(self):
        """不同名的聚合变量应通过检查（回归测试）"""
        src = 'tool t {} observe syscall("r") { @c1[pid] = count(); @c2[pid] = count(); }'
        errors = analyze(parse(src))
        self.assertFalse(any(e.category == "duplicate" for e in errors))

    def test_duplicate_let(self):
        '''同一 observe 块内声明两个 let x → category="duplicate"'''
        src = 'tool t {} observe syscall("r") { let x = 1; let x = 2; }'
        errors = analyze(parse(src))
        self.assertTrue(any(e.category == "duplicate" for e in errors))

    def test_unique_lets_pass(self):
        """不同名的 let 变量应通过检查（回归测试）"""
        src = 'tool t {} observe syscall("r") { let x = 1; let y = 2; }'
        errors = analyze(parse(src))
        self.assertFalse(any(e.category == "duplicate" for e in errors))


# ===================================================================
# TestSemanticLifecycle —— 生命周期约束检查
# ===================================================================

class TestSemanticLifecycle(unittest.TestCase):
    """
    测试生命周期语句的语义约束。
    
    every 语句的间隔必须是:
    - 时间字面量（如 1s, 100ms）
    - 已声明的 option 引用（如 option interval = 2s; every interval）
    
    使用未声明的标识符或非时间的字面量应产生 lifecycle 错误。
    """

    def test_every_with_unknown_option(self):
        '''every 引用未声明的 option → category="lifecycle"'''
        src = """tool t {}
observe syscall("r") { @c[pid] = count(); }
every unknown_opt { print(@c); }"""
        errors = analyze(parse(src))
        self.assertTrue(any(e.category == "lifecycle" for e in errors))

    def test_every_with_integer(self):
        '''every 使用裸整数（非时间）→ category="lifecycle"'''
        src = """tool t {}
observe syscall("r") { @c[pid] = count(); }
every 100 { print(@c); }"""
        errors = analyze(parse(src))
        self.assertTrue(any(e.category == "lifecycle" for e in errors))

    def test_every_with_time_literal_passes(self):
        """every 使用时间字面量 → 合法（回归测试）"""
        src = """tool t {}
observe syscall("r") { @c[pid] = count(); }
every 1s { print(@c); }"""
        errors = analyze(parse(src))
        self.assertFalse(any(e.category == "lifecycle" for e in errors))

    def test_every_with_valid_option_passes(self):
        """every 引用已声明的 option → 合法（回归测试）"""
        src = """tool t { option interval = 2s; }
observe syscall("r") { @c[pid] = count(); }
every interval { print(@c); }"""
        errors = analyze(parse(src))
        self.assertFalse(any(e.category == "lifecycle" for e in errors))


# ===================================================================
# 测试入口
# ===================================================================

if __name__ == '__main__':
    unittest.main()
