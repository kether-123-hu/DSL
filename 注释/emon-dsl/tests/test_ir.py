# ===================================================================
# test_ir.py —— Emon DSL 中间表示（IR）构建测试
# ===================================================================
#
# 【本文件的作用】
# 对 IR 构建器（ir.py 中的 IRBuilder）进行单元测试，验证 AST→IR 转换的正确性。
# IR 是编译器前端和后端之间的桥梁——如果 IR 构建出错，代码生成必然出错。
#
# 【测试覆盖范围】
#   1. 表达式序列化    — AST 表达式 → 类 C 字符串
#   2. Probe 生成      — observe 语句 → IRProbe（entry/exit 分离）
#   3. Map 生成        — 聚合语句 → IRMap（类型推导、去重）
#   4. Emit 生成       — emit 语句 → IREmit / IREventStruct（字段合并）
#   5. 生命周期生成    — every/begin/end → IREveryTask / IRPrint
#   6. Option 序列化   — tool option → IR 中的 options 列表
#   7. JSON 序列化     — IR → JSON 字符串的往返验证
#   8. 全管线集成      — parse → semantic → IR 的端到端测试
#
# 【IR 数据结构速查】
#   IRProbe        — 一个 eBPF 程序挂载点（section + hook_kind + 条件 + 动作）
#   IRMap          — 一个 BPF map 声明（名称、类型、key/value 结构）
#   IRAggregation  — 一条 map 更新指令（map_name + agg_fn + keys + value_expr）
#   IREmit         — 一条 perf event 输出指令
#   IREventStruct  — ring buffer 事件结构体定义
#   IREveryTask    — 一个周期性用户态任务
#   IRProgram      — IR 根容器
# ===================================================================

import json
import unittest

from emon.parser import parse
from emon.semantic import analyze
from emon.ir import build_ir, IRBuilder, IRProgram, _serialize_expr
from emon.ast_nodes import LitInt, LitStr, LitBool, LitTime, VarRef, BinOpExpr, BinOp


# ===================================================================
# TestIRExpressionSerialization —— 表达式序列化测试
# ===================================================================

class TestIRExpressionSerialization(unittest.TestCase):
    """
    测试表达式 → 类 C 字符串的序列化（_serialize_expr）。
    
    表达式序列化是 IR 构建的基础操作——它将 AST 表达式节点转换为
    可用于代码生成的字符串。这个函数需要在各种表达式类型上正确工作。
    """

    def test_literals(self):
        """测试字面量序列化: 整数、字符串、布尔、时间"""
        self.assertEqual(_serialize_expr(LitInt(42)), "42")
        self.assertEqual(_serialize_expr(LitStr("hello")), '"hello"')
        self.assertEqual(_serialize_expr(LitBool(True)), "true")
        self.assertEqual(_serialize_expr(LitBool(False)), "false")
        self.assertEqual(_serialize_expr(LitTime("100us")), "100us")

    def test_var_ref(self):
        """测试变量引用序列化: VarRef("pid") → "pid" """
        self.assertEqual(_serialize_expr(VarRef("pid")), "pid")
        self.assertEqual(_serialize_expr(VarRef("latency")), "latency")

    def test_binary_ops(self):
        """测试二元表达式序列化: pid > 0 → "(pid > 0)" """
        expr = BinOpExpr(op=BinOp.GT, lhs=VarRef("pid"), rhs=LitInt(0))
        self.assertEqual(_serialize_expr(expr), "(pid > 0)")

        # 嵌套二元表达式: pid > 0 && comm == "bash"
        expr2 = BinOpExpr(
            op=BinOp.AND,
            lhs=BinOpExpr(op=BinOp.GT, lhs=VarRef("pid"), rhs=LitInt(0)),
            rhs=BinOpExpr(op=BinOp.EQ, lhs=VarRef("comm"), rhs=LitStr("bash")),
        )
        result = _serialize_expr(expr2)
        self.assertIn("&&", result)
        self.assertIn("pid", result)
        self.assertIn('"bash"', result)


# ===================================================================
# TestIRProbeGeneration —— Probe 生成测试
# ===================================================================

class TestIRProbeGeneration(unittest.TestCase):
    """
    测试 observe 语句到 IRProbe 的转换。
    
    关键规则:
    - 不测量 latency 时: 1 个 observe → 1 个 IRProbe（entry）
    - 测量 latency 时:    1 个 observe → 2 个 IRProbe（entry + exit）
    - 多个目标时:         每个目标独立生成 probe(s)
    """

    def test_syscall_without_latency(self):
        """不测 latency → 只有 entry probe, measures_latency=False"""
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
        """测 latency → 生成 entry + exit 两个 probe"""
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
        """多个 syscall 目标: read, write → 各自生成独立 probe"""
        src = 'tool t {} observe syscall("read", "write") { @c[pid] = count(); }'
        ast = parse(src)
        ir = build_ir(ast)

        self.assertEqual(len(ir.probes), 2)
        self.assertEqual(ir.probes[0].hook_target, "read")
        self.assertEqual(ir.probes[1].hook_target, "write")

    def test_kernel_hook(self):
        """kernel hook → section 包含 "kprobe" """
        src = 'tool t {} observe kernel("tcp_v4_connect") { @k[func] = count(); }'
        ast = parse(src)
        ir = build_ir(ast)

        self.assertEqual(len(ir.probes), 1)
        self.assertEqual(ir.probes[0].hook_kind, "KERNEL")
        self.assertIn("kprobe", ir.probes[0].section)

    def test_all_hook_types(self):
        """验证全部 7 种 hook 类型都生成正确的 hook_kind"""
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
        """where 条件被正确序列化到 IRProbe.where_conditions"""
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
        """when 条件被正确序列化到出口 probe 的 IRProbe.when_conditions"""
        src = 'tool t {} observe syscall("r") measure latency when latency > 1000 { @c[pid] = count(); }'
        ast = parse(src)
        ir = build_ir(ast)

        exit_probe = ir.probes[1]
        self.assertEqual(len(exit_probe.when_conditions), 1)
        self.assertIn("latency", exit_probe.when_conditions[0])


# ===================================================================
# TestIRMapGeneration —— BPF Map 生成测试
# ===================================================================

class TestIRMapGeneration(unittest.TestCase):
    """
    测试聚合语句到 IRMap 的转换。
    
    关键规则:
    - count() → HASH map, value_type="u64"
    - sum/avg/min/max → PERCPU_HASH map
    - avg → value_type="struct { u64 sum; u64 count; }"
    - 同名 @agg 自动去重（多个 observe 引用同一个 @agg 只生成一个 map）
    """

    def test_count_map(self):
        """count() → HASH map, key_fields 来自方括号"""
        src = 'tool t {} observe syscall("r") { @mycount[pid, comm] = count(); }'
        ast = parse(src)
        ir = build_ir(ast)

        self.assertEqual(len(ir.maps), 1)
        m = ir.maps[0]
        self.assertEqual(m.name, "mycount")
        self.assertEqual(m.key_fields, ["pid", "comm"])
        self.assertIn("HASH", m.map_type)

    def test_avg_map(self):
        """avg() → value_type 包含 sum 和 count 字段"""
        src = 'tool t {} observe syscall("r") measure latency { @avg_lat[pid] = avg(latency); }'
        ast = parse(src)
        ir = build_ir(ast)

        self.assertEqual(len(ir.maps), 1)
        m = ir.maps[0]
        self.assertEqual(m.name, "avg_lat")
        self.assertIn("sum", m.value_type)
        self.assertIn("count", m.value_type)

    def test_multiple_aggregations(self):
        """多个聚合 → 生成对应数量的 map"""
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
        """同名 @c 出现在两个 observe 中 → 只生成 1 个 map（去重）"""
        src = """tool t {}
observe syscall("a") { @c[pid] = count(); }
observe syscall("b") { @c[pid] = count(); }"""
        ast = parse(src)
        ir = build_ir(ast)

        # 同名 @c 应被去重为 1 个 map
        self.assertEqual(len(ir.maps), 1)


# ===================================================================
# TestIREmitGeneration —— Emit / Event 生成测试
# ===================================================================

class TestIREmitGeneration(unittest.TestCase):
    """
    测试 emit 语句到 IREmit 和 IREventStruct 的转换。
    
    emit 语句声明要输出到 ring buffer 的事件字段。
    多个 emit 语句在同一个 tool 中时，字段会自动合并到一个事件结构体。
    """

    def test_emit_event(self):
        """emit 语句 → IREventStruct，字段名正确传递"""
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
        """两个 observe 中的 emit 字段 → 合并到同一个事件结构体"""
        src = """tool demo {}
observe syscall("a") {
    emit { time = nsecs; };
}
observe syscall("b") {
    emit { pid = pid; latency = latency; };
}"""
        ast = parse(src)
        ir = build_ir(ast)

        # 同一 tool 的事件应合并
        self.assertEqual(len(ir.events), 1)
        field_names = {f["name"] for f in ir.events[0].fields}
        self.assertIn("time", field_names)
        self.assertIn("pid", field_names)
        self.assertIn("latency", field_names)


# ===================================================================
# TestIRLifecycle —— 生命周期 IR 生成测试
# ===================================================================

class TestIRLifecycle(unittest.TestCase):
    """
    测试 every/begin/end 语句到 IR 的转换。
    """

    def test_every_task(self):
        """every interval → IREveryTask，关联的 @agg 被记录到 agg_reads"""
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
        """begin 和 end → IRPrint 列表"""
        src = """tool t {}
begin { print("start"); }
end { print("done"); print(@c); }"""
        ast = parse(src)
        ir = build_ir(ast)

        self.assertEqual(len(ir.begin_stmts), 1)
        self.assertEqual(ir.begin_stmts[0].expr, '"start"')
        self.assertEqual(len(ir.end_stmts), 2)
        self.assertEqual(ir.end_stmts[0].expr, '"done"')


# ===================================================================
# TestIROptions —— Option 序列化测试
# ===================================================================

class TestIROptions(unittest.TestCase):
    """
    测试 tool option 到 IR 的序列化。
    """

    def test_options(self):
        """4 种不同类型的 option → IR 中正确序列化"""
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


# ===================================================================
# TestIRJsonSerialization —— JSON 序列化测试
# ===================================================================

class TestIRJsonSerialization(unittest.TestCase):
    """
    测试 IR 到 JSON 的序列化和反序列化。
    
    JSON 序列化是 Python 前端和 C++ 后端之间的桥梁格式。
    需要确保序列化后的 JSON 可以被正确解析。
    """

    def test_to_json(self):
        """基本程序的 IR → JSON 往返验证"""
        src = 'tool t {} observe syscall("r") { @c[pid] = count(); }'
        ast = parse(src)
        ir = build_ir(ast)

        json_str = ir.to_json()
        data = json.loads(json_str)

        self.assertEqual(data["tool_name"], "t")
        self.assertEqual(len(data["probes"]), 1)
        self.assertEqual(len(data["maps"]), 1)

    def test_full_feature_json(self):
        """full_feature_test.emon 的 IR → JSON 往返验证（综合场景）"""
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


# ===================================================================
# TestIRFullPipeline —— 全管线集成测试
# ===================================================================

class TestIRFullPipeline(unittest.TestCase):
    """
    端到端测试: parse → semantic → IR 全流程。
    
    这是最重要的集成测试——验证编译器前端三个阶段的完整协作。
    使用一个包含几乎所有 DSL 特性的综合程序作为输入。
    """

    def test_pipeline(self):
        """综合 DSL 程序 → 完整的 IR 结构验证"""
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

        # 验证 JSON 往返
        json_str = ir.to_json()
        self.assertIsInstance(json_str, str)
        data = json.loads(json_str)
        self.assertEqual(data["tool_name"], "pipeline_test")


# ===================================================================
# 测试入口
# ===================================================================

if __name__ == '__main__':
    unittest.main()
