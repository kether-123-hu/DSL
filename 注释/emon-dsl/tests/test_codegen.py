# ===================================================================
# test_codegen.py —— Emon DSL 代码生成器测试
# ===================================================================
#
# 【本文件的作用】
# 对三个代码生成后端进行单元测试，验证从 IR 生成的目标代码的正确性。
#
# 【测试覆盖的三个后端】
#   1. bpfc_gen.py      — eBPF C 代码生成（.bpf.c 文件）
#   2. loader_gen.py    — libbpf 加载器 C 代码生成（用户态程序）
#   3. manifest_gen.py  — YAML 清单文件生成（部署配置）
#
# 【测试策略】
# 由于我们无法在每个测试中真正编译并运行 eBPF 程序，
# 测试主要验证生成代码的"结构正确性"：
#   - 关键头文件是否被 include
#   - SEC 宏是否正确标注挂载点
#   - BPF helper 函数调用是否存在
#   - Map 类型是否正确（HASH vs PERCPU_HASH）
#   - Ring buffer 操作是否完整
#   - 条件过滤代码是否生成
#   - 字面量转换是否正确（100us → 100000 ns）
#
# 【五个测试类】
#   TestBpfCGenerator     — eBPF C 代码生成测试（24 个测试）
#   TestLoaderGenerator   — libbpf 加载器生成测试（15 个测试）
#   TestManifestGenerator — YAML 清单生成测试（7 个测试）
#   TestCompilePipeline   — 全管线编译测试（端到端）
#   TestIRPhaseSeparation — IR 阶段分离验证
#   TestIRMapTypes        — Map 类型分配验证
# ===================================================================

import unittest
import os
import tempfile

from emon.parser import parse
from emon.semantic import analyze
from emon.ir import build_ir, build_ir_from_source, compile_source, compile_file
from emon.ir import IRProgram, IRProbe, IRMap, IREveryTask


# ===================================================================
# 辅助函数
# ===================================================================

def _build_ir(src: str) -> IRProgram:
    """
    快捷的 parse → semantic → IR 管线。
    
    参数:
        src: Emon DSL 源代码字符串
    
    返回:
        IRProgram: 构建好的中间表示
    
    注意:
        此函数在语义错误时会抛出异常（由 analyze 触发），
        因此只应在测试合法程序时使用。
    """
    return build_ir_from_source(src)


# ===================================================================
# TestBpfCGenerator —— eBPF C 代码生成测试
# ===================================================================

class TestBpfCGenerator(unittest.TestCase):
    """
    测试 eBPF C 代码生成（bpfc_gen.py）。
    
    生成的目标代码遵循 libbpf / BPF CO-RE 标准，
    使用 clang -target bpf 编译。
    
    验证要点:
    - 头文件: vmlinux.h, bpf_helpers.h 等
    - SEC 宏: 正确的挂载点标注
    - BPF helper: bpf_map_lookup_elem, bpf_ringbuf_reserve 等
    - 条件语句: where/when 生成 if return 模式
    - Map 类型: HASH vs PERCPU_HASH
    - 字面量转换: 时间→纳秒, 大小→字节
    """

    # ------------------------------------------------------------------
    # 基本程序结构
    # ------------------------------------------------------------------

    def test_basic_syscall_count(self):
        """最简 syscall count 程序: 验证头文件、SEC、BPF helper"""
        src = 'tool t {} observe syscall("read") { @c[pid] = count(); }'
        ir = _build_ir(src)
        from emon.bpfc_gen import generate_bpf_c
        code = generate_bpf_c(ir)

        # 结构检查: 生成代码应包含这些关键元素
        self.assertIn('#include "vmlinux.h"', code)
        self.assertIn("char LICENSE[]", code)
        self.assertIn('SEC("license")', code)
        self.assertIn('SEC("tracepoint/syscalls/sys_enter_read")', code)
        self.assertIn("bpf_get_current_pid_tgid", code)
        self.assertIn("bpf_map_lookup_elem", code)
        self.assertIn("bpf_map_update_elem", code)

    # ------------------------------------------------------------------
    # Latency 测量（entry/exit 分离）
    # ------------------------------------------------------------------

    def test_syscall_with_latency(self):
        """测 latency → 生成 entry + exit 两个 SEC，含 __start_time map"""
        src = 'tool t {} observe syscall("read") measure latency { @c[pid] = count(); }'
        ir = _build_ir(src)
        from emon.bpfc_gen import generate_bpf_c
        code = generate_bpf_c(ir)

        # 两个探针: entry + exit
        self.assertIn("sys_enter_read", code)
        self.assertIn("sys_exit_read", code)
        self.assertIn("__start_time_", code)
        self.assertIn("latency", code)
        self.assertIn("bpf_map_delete_elem", code)

    # ------------------------------------------------------------------
    # 不同 Hook 类型
    # ------------------------------------------------------------------

    def test_kernel_hook(self):
        """kernel hook → SEC("kprobe/...")，参数通过 PT_REGS_PARM 获取"""
        src = 'tool t {} observe kernel("tcp_v4_connect") { @k[func] = count(); }'
        ir = _build_ir(src)
        from emon.bpfc_gen import generate_bpf_c
        code = generate_bpf_c(ir)

        self.assertIn("kprobe/tcp_v4_connect", code)
        self.assertIn("PT_REGS_PARM", code)
        self.assertIn("struct pt_regs *ctx", code)

    def test_uprobe_hook(self):
        """uprobe hook → SEC("uprobe/...") """
        src = 'tool t {} observe uprobe("/bin/bash", "readline") { @u[pid] = count(); }'
        ir = _build_ir(src)
        from emon.bpfc_gen import generate_bpf_c
        code = generate_bpf_c(ir)

        self.assertIn("uprobe/readline", code)

    def test_tracepoint_hook(self):
        """tracepoint hook → SEC("tracepoint/...") """
        src = 'tool t {} observe tracepoint("sched:sched_switch") { @s[cpu] = count(); }'
        ir = _build_ir(src)
        from emon.bpfc_gen import generate_bpf_c
        code = generate_bpf_c(ir)

        self.assertIn("tracepoint/sched:sched_switch", code)

    def test_sched_hook(self):
        """sched hook → SEC("tracepoint/sched/...") """
        src = 'tool t {} observe sched("sched_switch") { @s[cpu] = count(); }'
        ir = _build_ir(src)
        from emon.bpfc_gen import generate_bpf_c
        code = generate_bpf_c(ir)

        self.assertIn("tracepoint/sched/sched_switch", code)

    def test_file_hook(self):
        """file hook → SEC("kprobe/...") """
        src = 'tool t {} observe file("open") { @f[pid] = count(); }'
        ir = _build_ir(src)
        from emon.bpfc_gen import generate_bpf_c
        code = generate_bpf_c(ir)

        self.assertIn("kprobe/open", code)

    def test_net_hook(self):
        """net hook → SEC("kprobe/...") """
        src = 'tool t {} observe net("tcp") { @n[pid] = count(); }'
        ir = _build_ir(src)
        from emon.bpfc_gen import generate_bpf_c
        code = generate_bpf_c(ir)

        self.assertIn("kprobe/tcp", code)

    # ------------------------------------------------------------------
    # Ring Buffer / Emit
    # ------------------------------------------------------------------

    def test_emit_ringbuf(self):
        """emit 语句 → BPF_MAP_TYPE_RINGBUF + ringbuf_reserve/submit"""
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

    # ------------------------------------------------------------------
    # 条件过滤（where / when）
    # ------------------------------------------------------------------

    def test_where_and_when_conditions(self):
        """where + when → 生成 if (!(cond)) return; 过滤模式"""
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
        self.assertIn("if (!(", code)  # 过滤条件模式

    # ------------------------------------------------------------------
    # 聚合函数
    # ------------------------------------------------------------------

    def test_aggregation_functions(self):
        """全部 7 种聚合函数: 每种生成对应的 map 更新代码"""
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

        self.assertIn("(*__val_", code)  # count 递增模式
        self.assertIn("// avg:", code)
        self.assertIn("// hist:", code)
        self.assertIn("// lhist:", code)

    # ------------------------------------------------------------------
    # 复合 Key / 结构体
    # ------------------------------------------------------------------

    def test_composite_keys(self):
        """复合 key (pid, comm, syscall) → 生成 packed struct key"""
        src = 'tool t {} observe syscall("read") { @c[pid, comm, syscall] = count(); }'
        ir = _build_ir(src)
        from emon.bpfc_gen import generate_bpf_c
        code = generate_bpf_c(ir)

        # 应生成复合 key 结构体
        self.assertIn("struct key_", code)
        self.assertIn("__attribute__((packed))", code)

    # ------------------------------------------------------------------
    # if / else / let
    # ------------------------------------------------------------------

    def test_if_else_block(self):
        """if-else 分支: 生成对应的 C if-else 结构"""
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

    # ------------------------------------------------------------------
    # 多目标
    # ------------------------------------------------------------------

    def test_multiple_targets(self):
        """多个 syscall 目标 → 各自生成独立的 SEC("sys_enter_...") """
        src = 'tool t {} observe syscall("read", "write", "openat") { @c[pid] = count(); }'
        ir = _build_ir(src)
        from emon.bpfc_gen import generate_bpf_c
        code = generate_bpf_c(ir)

        # 三个入口探针
        self.assertIn("sys_enter_read", code)
        self.assertIn("sys_enter_write", code)
        self.assertIn("sys_enter_openat", code)

    # ------------------------------------------------------------------
    # 上下文变量提取
    # ------------------------------------------------------------------

    def test_context_extraction(self):
        """验证标准上下文变量的 BPF helper 调用"""
        src = 'tool t {} observe syscall("read") { @c[pid] = count(); }'
        ir = _build_ir(src)
        from emon.bpfc_gen import generate_bpf_c
        code = generate_bpf_c(ir)

        self.assertIn("bpf_get_current_pid_tgid", code)
        self.assertIn("bpf_get_current_uid_gid", code)
        self.assertIn("bpf_get_current_comm", code)
        self.assertIn("bpf_ktime_get_ns", code)
        self.assertIn("bpf_get_smp_processor_id", code)

    # ------------------------------------------------------------------
    # Option 解析 & 字面量转换
    # ------------------------------------------------------------------

    def test_option_resolution_in_conditions(self):
        """where 中的 option 引用 → 被解析为实际值"""
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

        # target_pid=0 应在实际 C 代码中被解析（注释中可能保留原始文本）
        self.assertIn("100000", code)  # 100us → 纳秒
        # 验证条件代码中的解析
        cond_line = [l for l in code.split('\n') if 'if (!(' in l and '0 == 0' in l]
        self.assertTrue(len(cond_line) > 0, "where condition should resolve target_pid to 0")

    def test_time_literal_conversion(self):
        """时间字面量转换: 1ms → 1000000 ns"""
        src = '''
        tool t { option threshold = 1ms; }
        observe syscall("read") measure latency
        when latency > threshold
        { @c[pid] = count(); }
        '''
        ir = _build_ir(src)
        from emon.bpfc_gen import generate_bpf_c
        code = generate_bpf_c(ir)

        self.assertIn("1000000", code)  # 1ms = 1,000,000 ns

    def test_size_literal_conversion(self):
        """大小字面量转换: 1MB → 1048576 字节"""
        src = '''
        tool t { option max_sz = 1MB; }
        observe syscall("read") measure size
        when size > max_sz
        { @c[pid] = count(); }
        '''
        ir = _build_ir(src)
        from emon.bpfc_gen import generate_bpf_c
        code = generate_bpf_c(ir)

        self.assertIn("1048576", code)  # 1MB = 1,048,576 字节

    # ------------------------------------------------------------------
    # 出口探针细节
    # ------------------------------------------------------------------

    def test_syscall_name_hardcoded(self):
        """syscall 名在 BPF 代码中被硬编码为字符串字面量"""
        src = 'tool t {} observe syscall("openat") { @c[pid] = count(); }'
        ir = _build_ir(src)
        from emon.bpfc_gen import generate_bpf_c
        code = generate_bpf_c(ir)

        self.assertIn('"openat"', code)

    def test_exit_probe_context(self):
        """出口探针 → 使用 trace_event_raw_sys_exit 上下文类型"""
        src = 'tool t {} observe syscall("read") measure latency { @c[pid] = count(); }'
        ir = _build_ir(src)
        from emon.bpfc_gen import generate_bpf_c
        code = generate_bpf_c(ir)

        self.assertIn("trace_event_raw_sys_exit", code)

    def test_exit_probe_has_retval(self):
        """测量 retval → 出口探针包含 BPF_CORE_READ(ctx, ret) """
        src = 'tool t {} observe syscall("read") measure latency, retval { @c[pid] = count(); }'
        ir = _build_ir(src)
        from emon.bpfc_gen import generate_bpf_c
        code = generate_bpf_c(ir)

        self.assertIn("retval", code)
        self.assertIn("BPF_CORE_READ(ctx, ret)", code)

    def test_entry_probe_no_actions_with_latency(self):
        """测 latency 时，入口探针不应包含聚合动作（聚合在出口执行）"""
        src = 'tool t {} observe syscall("read") measure latency { @c[pid] = avg(latency); }'
        ir = _build_ir(src)
        from emon.bpfc_gen import generate_bpf_c
        code = generate_bpf_c(ir)

        # 入口探针不应包含 @avg 聚合代码
        entry_section = code.find("sys_enter_read")
        exit_section = code.find("sys_exit_read")
        between = code[entry_section:exit_section] if exit_section > entry_section else ""
        self.assertNotIn("@avg", between if between else code[:exit_section])

    # ------------------------------------------------------------------
    # Map 类型
    # ------------------------------------------------------------------

    def test_percpu_map_generation(self):
        """非 count 聚合 → 使用 PERCPU_HASH（避免 CPU 间竞争）"""
        src = 'tool t {} observe syscall("read") measure latency { @avg[pid] = avg(latency); }'
        ir = _build_ir(src)
        from emon.bpfc_gen import generate_bpf_c
        code = generate_bpf_c(ir)

        self.assertIn("PERCPU_HASH", code)

    def test_count_map_is_hash(self):
        """count 聚合 → 使用普通 HASH（无需 per-CPU）"""
        src = 'tool t {} observe syscall("read") { @c[pid] = count(); }'
        ir = _build_ir(src)
        from emon.bpfc_gen import generate_bpf_c
        code = generate_bpf_c(ir)

        self.assertIn("BPF_MAP_TYPE_HASH", code)

    # ------------------------------------------------------------------
    # 代码风格 / 细节
    # ------------------------------------------------------------------

    def test_no_rodata_string_literals(self):
        """字符串初始化应使用 char[] = "..." 而非 __builtin_memcpy（避免 .rodata 问题）"""
        src = 'tool t {} observe syscall("read") { @c[pid] = count(); }'
        ir = _build_ir(src)
        from emon.bpfc_gen import generate_bpf_c
        code = generate_bpf_c(ir)

        # 应使用 = "read" 而非 memcpy("read")
        self.assertIn('char syscall[16] = "read"', code)
        self.assertNotIn('__builtin_memcpy(syscall, "read"', code)

    def test_composite_key_memset(self):
        """复合 key 初始化 → 使用 __builtin_memset 而非 = {0} """
        src = 'tool t {} observe syscall("read") { @c[pid, comm] = count(); }'
        ir = _build_ir(src)
        from emon.bpfc_gen import generate_bpf_c
        code = generate_bpf_c(ir)

        self.assertIn("__builtin_memset", code)

    def test_empty_options(self):
        """无 option 的 tool → 仍应生成合法代码（不崩溃）"""
        src = 'tool t {} observe syscall("read") { @c[pid] = count(); }'
        ir = _build_ir(src)
        from emon.bpfc_gen import generate_bpf_c
        code = generate_bpf_c(ir)
        self.assertGreater(len(code), 100)

    def test_multiple_measure_types(self):
        """多个 measure 声明 (latency, retval, size) → 全部正确处理"""
        src = 'tool t {} observe syscall("read") measure latency, retval, size { @c[pid] = count(); }'
        ir = _build_ir(src)
        from emon.bpfc_gen import generate_bpf_c
        code = generate_bpf_c(ir)

        self.assertIn("latency", code)
        self.assertIn("retval", code)
        self.assertIn("size", code)


# ===================================================================
# TestLoaderGenerator —— libbpf 加载器生成测试
# ===================================================================

class TestLoaderGenerator(unittest.TestCase):
    """
    测试 libbpf 加载器 C 代码生成（loader_gen.py）。
    
    加载器是用户态程序，负责:
    - 打开并加载 eBPF 程序
    - 挂载到内核 hook 点
    - 管理 ring buffer 事件回调
    - 周期性执行 every 任务
    - 处理 begin/end 生命周期
    - 响应 Ctrl+C 信号优雅退出
    """

    def test_basic_loader(self):
        """基本加载器: 验证 open/load/attach/destroy 流程 + 信号处理"""
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
        """有 emit → 加载器包含 ring_buffer__new/poll/free"""
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
        """有 every → 加载器包含时间轮询逻辑 (__last_tick, time(NULL))"""
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
        """有 begin/end → 加载器包含对应的执行块"""
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
        """有 option → 加载器包含 __opt_* 变量声明"""
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
        """时间间隔字符串 → 秒数转换（最小 1 秒）"""
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
        """无显式 end 块 → 加载器应在退出时自动打印 map 汇总"""
        src = 'tool t {} observe syscall("read") { @c[pid] = count(); }'
        ir = _build_ir(src)
        from emon.loader_gen import generate_loader_c
        code = generate_loader_c(ir)

        self.assertIn("Final Report", code)
        self.assertIn("__print_map_", code)

    def test_loader_with_top_query(self):
        """every 块中的 top(@c, n) → 生成 __print_map_ 调用"""
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
        """字符串 option → 正确转义为 C 字符串字面量"""
        src = '''
        tool t { option path = "/var/log/test.log"; }
        observe syscall("read") { @c[pid] = count(); }
        '''
        ir = _build_ir(src)
        from emon.loader_gen import generate_loader_c
        code = generate_loader_c(ir)

        # 应有正确的 C 字符串
        self.assertIn('"/var/log/test.log"', code)
        # 不应有双引号
        self.assertNotIn('""/var/', code)

    def test_loader_event_struct(self):
        """有 emit → 加载器包含 struct event_t 定义"""
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
        """信号处理 → 使用 sigaction 而非 signal（POSIX 推荐）"""
        src = 'tool t {} observe syscall("read") { @c[pid] = count(); }'
        ir = _build_ir(src)
        from emon.loader_gen import generate_loader_c
        code = generate_loader_c(ir)

        self.assertIn("sigaction(SIGINT", code)
        self.assertIn("__setup_signals", code)
        self.assertNotIn("signal(SIGINT", code)

    def test_loader_small_sleep_chunks(self):
        """主循环 → 使用 usleep(50000) 小片段睡眠以响应 Ctrl+C"""
        src = 'tool t {} observe syscall("read") { @c[pid] = count(); }'
        ir = _build_ir(src)
        from emon.loader_gen import generate_loader_c
        code = generate_loader_c(ir)

        self.assertIn("usleep(50000)", code)

    def test_loader_percpu_map_printer(self):
        """PERCPU map → 打印时使用 __percpu_sum 汇总所有 CPU 的值"""
        src = 'tool t {} observe syscall("read") measure latency { @avg[pid] = avg(latency); }'
        ir = _build_ir(src)
        from emon.loader_gen import generate_loader_c
        code = generate_loader_c(ir)

        self.assertIn("__percpu_sum", code)
        self.assertIn("libbpf_num_possible_cpus", code)

    def test_loader_hist_map_printer(self):
        """hist map → 使用桶（bucket）格式打印直方图"""
        src = 'tool t {} observe syscall("read") measure latency { @my_hist[pid] = hist(latency); }'
        ir = _build_ir(src)
        from emon.loader_gen import generate_loader_c
        code = generate_loader_c(ir)

        self.assertIn("bucket", code)
        self.assertIn("fputc('#', stdout)", code)

    def test_loader_no_emit_no_ringbuf(self):
        """无 emit → 加载器不应设置 ring buffer"""
        src = 'tool t {} observe syscall("read") { @c[pid] = count(); }'
        ir = _build_ir(src)
        from emon.loader_gen import generate_loader_c
        code = generate_loader_c(ir)

        self.assertNotIn("ring_buffer__new", code)

    def test_loader_heap_fallback(self):
        """大 percpu value → 使用堆分配（malloc）而非栈分配"""
        src = 'tool t {} observe syscall("read") measure latency { @h[pid] = hist(latency); }'
        ir = _build_ir(src)
        from emon.loader_gen import generate_loader_c
        code = generate_loader_c(ir)

        self.assertIn("malloc", code)
        self.assertIn("use_heap", code)


# ===================================================================
# TestManifestGenerator —— YAML 清单生成测试
# ===================================================================

class TestManifestGenerator(unittest.TestCase):
    """
    测试 YAML 清单文件生成（manifest_gen.py）。
    
    清单文件描述了 DSL 程序的元数据，包括:
    - tool 名称和基本信息
    - options 配置参数
    - maps 定义（类型、key/value 结构）
    - probes 挂载点信息
    - events 事件结构
    - lifecycle 生命周期配置
    """

    def test_basic_manifest(self):
        """基本清单: 验证 tool, maps, probes, events, lifecycle 段落存在"""
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
        """有 option → 清单中包含 threshold 和 top_n"""
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
        """有 emit → 清单中包含 ringbuf 和字段名"""
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
        """map 详情: 包含 map 名和聚合函数名"""
        src = 'tool t {} observe syscall("read") measure latency { @avg_lat[pid, comm] = avg(latency); }'
        ir = _build_ir(src)
        from emon.manifest_gen import generate_manifest
        yaml_str = generate_manifest(ir)

        self.assertIn("name: avg_lat", yaml_str)
        self.assertIn("avg", yaml_str.lower())

    def test_manifest_with_lifecycle(self):
        """有生命周期语句 → 清单中包含 begin, every, end 段落"""
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
        """多种 hook 类型 → 清单中包含对应的类型名"""
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
        """有 where/when + latency → 清单中记录条件信息和 measures_latency"""
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


# ===================================================================
# TestCompilePipeline —— 全管线编译测试
# ===================================================================

class TestCompilePipeline(unittest.TestCase):
    """
    测试从 DSL 源代码到最终产物的完整编译管线。
    
    这是最高级别的集成测试——验证 parse → semantic → IR → codegen 全流程。
    包括 compile_source（内存编译）和 compile_file（文件编译）两种模式。
    """

    def test_compile_source_returns_all_artifacts(self):
        """compile_source → 返回 bpf_c, loader_c, manifest, ir 四种产物"""
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
        """语义错误 → compile_source 应抛出 ValueError"""
        # 缺少 measure 声明就使用 'latency'
        src = 'tool t {} observe syscall("read") { @c[pid] = avg(latency); }'
        with self.assertRaises(ValueError) as ctx:
            compile_source(src)
        self.assertIn("Semantic", str(ctx.exception))

    def test_compile_file_writes_outputs(self):
        """compile_file → 输出目录中生成 .bpf.c / loader.c / manifest.yaml 文件"""
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
        """有 option 的 tool → 编译验证 option 解析"""
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
            # target_pid option 应被解析为 0
            self.assertIn("0", bpf_code)

    def test_compile_file_creates_output_dir(self):
        """compile_file → 自动创建不存在的输出目录"""
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
        """集成测试: 编译完整的 syscall_latency.emon 示例文件"""
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


# ===================================================================
# TestIRPhaseSeparation —— IR 阶段分离验证
# ===================================================================

class TestIRPhaseSeparation(unittest.TestCase):
    """
    验证 IR 正确地将 where/when 条件分配到 entry/exit probe。
    
    这是 IR 构建中最关键的设计决策之一:
    - where 条件 → 始终放在 entry probe（函数入口处执行）
    - when 条件 → 不测 latency 放 entry，测 latency 放 exit
    - 测 latency 时: entry probe 只记录时间戳，不执行聚合动作
    """

    def test_where_on_entry_only(self):
        """不测 latency: where → entry probe"""
        src = 'tool t {} observe syscall("read") where pid > 0 { @c[pid] = count(); }'
        ir = _build_ir(src)
        self.assertEqual(len(ir.probes), 1)
        probe = ir.probes[0]
        self.assertFalse(probe.is_exit)
        self.assertEqual(len(probe.where_conditions), 1)
        self.assertEqual(len(probe.when_conditions), 0)

    def test_when_on_entry_when_no_latency(self):
        """不测 latency: when → entry probe（when 条件仍在入口检查）"""
        src = 'tool t {} observe syscall("read") when pid > 0 { @c[pid] = count(); }'
        ir = _build_ir(src)
        self.assertEqual(len(ir.probes), 1)
        probe = ir.probes[0]
        self.assertEqual(len(probe.when_conditions), 1)

    def test_where_entry_when_exit_with_latency(self):
        """测 latency: where → entry, when → exit（正确分离）"""
        src = 'tool t {} observe syscall("read") where pid > 0 measure latency when latency > 1000 { @c[pid] = count(); }'
        ir = _build_ir(src)
        self.assertEqual(len(ir.probes), 2)

        entry = [p for p in ir.probes if not p.is_exit][0]
        exit_p = [p for p in ir.probes if p.is_exit][0]

        # where 只在 entry
        self.assertGreater(len(entry.where_conditions), 0)
        self.assertEqual(len(entry.when_conditions), 0)
        # when 只在 exit
        self.assertEqual(len(exit_p.where_conditions), 0)
        self.assertGreater(len(exit_p.when_conditions), 0)

    def test_entry_probe_no_actions_with_latency(self):
        """测 latency: entry probe 无聚合动作，exit probe 有全部聚合"""
        src = 'tool t {} observe syscall("read") measure latency { @c[pid] = count(); @avg[pid] = avg(latency); }'
        ir = _build_ir(src)

        entry = [p for p in ir.probes if not p.is_exit][0]
        exit_p = [p for p in ir.probes if p.is_exit][0]

        # 入口探针不应有聚合
        self.assertEqual(len(entry.aggregations), 0)
        self.assertEqual(len(entry.emits), 0)
        # 出口探针应有全部聚合
        self.assertEqual(len(exit_p.aggregations), 2)

    def test_multi_target_probes(self):
        """多目标 + latency: 2 targets × 2 (entry+exit) = 4 probes"""
        src = 'tool t {} observe syscall("read", "write") measure latency { @c[pid] = count(); }'
        ir = _build_ir(src)

        # 2 目标 × 2 探针 (entry+exit) = 4 探针
        self.assertEqual(len(ir.probes), 4)
        entries = [p for p in ir.probes if not p.is_exit]
        exits = [p for p in ir.probes if p.is_exit]
        self.assertEqual(len(entries), 2)
        self.assertEqual(len(exits), 2)


# ===================================================================
# TestIRMapTypes —— Map 类型分配验证
# ===================================================================

class TestIRMapTypes(unittest.TestCase):
    """
    验证 BPF map 类型的正确分配。
    
    Map 类型选择规则:
    - count() → HASH（普通哈希表，不需要 per-CPU）
    - sum/avg/min/max/hist/lhist → PERCPU_HASH（避免多 CPU 竞争）
    - avg → value_type 为 struct { u64 sum; u64 count; }（平均值需要两个字段）
    """

    def test_count_is_hash(self):
        """count() → HASH"""
        ir = _build_ir('tool t {} observe syscall("read") { @c[pid] = count(); }')
        m = ir.maps[0]
        self.assertEqual(m.map_type, "HASH")

    def test_sum_is_percpu_hash(self):
        """sum() → PERCPU_HASH"""
        ir = _build_ir('tool t {} observe syscall("read") measure latency { @s[pid] = sum(latency); }')
        m = ir.maps[0]
        self.assertEqual(m.map_type, "PERCPU_HASH")

    def test_avg_is_percpu_hash(self):
        """avg() → PERCPU_HASH"""
        ir = _build_ir('tool t {} observe syscall("read") measure latency { @a[pid] = avg(latency); }')
        m = ir.maps[0]
        self.assertEqual(m.map_type, "PERCPU_HASH")

    def test_hist_is_percpu_hash(self):
        """hist() → PERCPU_HASH"""
        ir = _build_ir('tool t {} observe syscall("read") measure latency { @h[pid] = hist(latency); }')
        m = ir.maps[0]
        self.assertEqual(m.map_type, "PERCPU_HASH")

    def test_avg_value_type(self):
        """avg() → value_type 包含 sum 和 count 字段"""
        ir = _build_ir('tool t {} observe syscall("read") measure latency { @a[pid] = avg(latency); }')
        m = ir.maps[0]
        self.assertIn("sum", m.value_type)
        self.assertIn("count", m.value_type)

    def test_map_deduplication(self):
        """两个 observe 使用同名 @c → 只生成 1 个 map（去重验证）"""
        src = '''
        tool t {}
        observe syscall("read") { @c[pid] = count(); }
        observe syscall("write") { @c[pid] = count(); }
        '''
        ir = _build_ir(src)
        # 同名 @c map 应被去重
        c_maps = [m for m in ir.maps if m.name == "c"]
        self.assertEqual(len(c_maps), 1)


# ===================================================================
# 测试入口
# ===================================================================

if __name__ == '__main__':
    unittest.main()
