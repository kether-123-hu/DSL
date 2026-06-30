# ===================================================================
# bpfc_gen.py —— eBPF C 代码生成器（编译器第五阶段-A）
# ===================================================================
#
# 【本文件的作用】
# 从 IR（中间表示）生成可编译的 eBPF C 代码（.bpf.c 文件）。
# 生成的代码遵循 libbpf / BPF CO-RE 标准，使用 clang -target bpf 编译。
#
# 【生成的代码包含】
#   - 许可证声明
#   - Map key 结构体定义（复合 key）
#   - 延迟测量的隐式 map（存储入口时间戳）
#   - 事件结构体定义（ring buffer 事件格式）
#   - BPF map 定义（聚合 map、ring buffer map）
#   - 探针函数（每个挂载点一个 BPF 函数）
#
# 【技术要点】
# - 生成的代码使用 BPF CO-RE（Compile Once, Run Everywhere）技术
# - 通过 bpf_core_read_* 等辅助函数安全读取内核数据结构
# - 使用 SEC 宏指定程序挂载点
# ===================================================================

from typing import List, Dict, Optional
import textwrap  # textwrap.dedent: 清理多行字符串的缩进
import re        # re.sub: 正则替换（用于时间/大小字面量转换）

from emon.ir import (
    IRProgram, IRProbe, IRMap, IRAggregation,
    IREmit, IREventStruct, IREveryTask, IRPrint,
)


# ===================================================================
# 工具函数
# ===================================================================

def _indent(text: str, level: int = 1, first: bool = False) -> str:
    """
    给文本的每一行添加缩进。
    
    参数:
        text:  要缩进的文本
        level: 缩进级别（每级 4 个空格）
        first: 是否首行也缩进
    
    返回:
        缩进后的文本
    """
    pad = " " * (level * 4)
    result = "\n".join(pad + line if line else "" for line in text.split("\n"))
    if first:
        return pad + result.lstrip()
    return result


def _safe_c_name(name: str) -> str:
    """
    将名称转换为合法的 C 语言标识符。
    替换 @、-、. 等特殊字符为 _。
    """
    return name.replace("@", "").replace("-", "_").replace(".", "_")


# ===================================================================
# 类型映射表
# ===================================================================
# 上下文变量名 → C 类型的映射

_KEY_TYPE_MAP: Dict[str, str] = {
    "pid": "u32",       # 进程 ID：32 位无符号整数
    "tid": "u32",       # 线程 ID
    "uid": "u32",       # 用户 ID
    "gid": "u32",       # 组 ID
    "cpu": "u32",       # CPU 编号
    "comm": "char [16]",# 进程名：16 字节字符数组
    "syscall": "char [16]", # 系统调用名
    "func": "char [64]",    # 内核函数名：64 字节
    "arg0": "u64", "arg1": "u64", "arg2": "u64",  # 函数参数（64位）
    "arg3": "u64", "arg4": "u64", "arg5": "u64",
}

# BPF map 类型字符串 → 对应的 BPF 宏名
_MAP_TYPE_MAP: Dict[str, str] = {
    "HASH": "BPF_MAP_TYPE_HASH",                  # 普通哈希表
    "PERCPU_HASH": "BPF_MAP_TYPE_PERCPU_HASH",    # 每 CPU 哈希表（避免竞争）
    "ARRAY": "BPF_MAP_TYPE_ARRAY",                # 数组
    "PERCPU_ARRAY": "BPF_MAP_TYPE_PERCPU_ARRAY",  # 每 CPU 数组
    "PERF_EVENT_ARRAY": "BPF_MAP_TYPE_PERF_EVENT_ARRAY", # 事件输出
    "RINGBUF": "BPF_MAP_TYPE_RINGBUF",            # Ring buffer
}

# Value 类型 → BPF 标准类型名
_VALUE_TYPE_MAP: Dict[str, str] = {
    "u64": "__u64",  # 64 位无符号
    "u32": "__u32",  # 32 位无符号
    "s64": "__s64",  # 64 位有符号
    "s32": "__s32",  # 32 位有符号
}


# ===================================================================
# eBPF C 代码生成器
# ===================================================================

class BpfCGenerator:
    """
    从 IRProgram 生成完整的 eBPF C 源代码。
    
    使用方式:
        gen = BpfCGenerator(ir)
        c_code = gen.generate()
    """

    def __init__(self, ir: IRProgram):
        self.ir = ir
        self._map_name_set: set = {m.name for m in ir.maps}
        self._event_name_set: set = {e.name for e in ir.events}
        self._probe_counter: int = 0           # 探针计数器（生成唯一函数名）
        self._needs_start_time: bool = False   # 是否需要延迟测量起始时间 map
        self._seen_struct_names: set = set()   # 已生成的结构体名（防重复）
        # 构建 option 查找表：option名 → 默认值字符串
        self._option_values: Dict[str, str] = {}
        for opt in ir.options:
            self._option_values[opt["name"]] = opt.get("default", "0")

    def _resolve_expr(self, expr: str) -> str:
        """
        解析表达式中的 option 引用和时间/大小字面量。
        
        将 option 引用替换为实际值，将时间字面量转为纳秒整数，
        将大小字面量转为字节整数。
        
        例如: "latency > min_latency" 且 min_latency="100us"
              → "latency > 100000" (100us = 100000 纳秒)
        """
        result = expr
        # 替换 option 引用为默认值
        for name, value in self._option_values.items():
            result = result.replace(name, value)
        # 转换时间/大小字面量
        result = self._convert_time_literals(result)
        result = self._convert_size_literals(result)
        return result

    @staticmethod
    def _convert_time_literals(expr: str) -> str:
        """
        将时间字面量转换为纳秒整数。
        
        例如: "100us" → "100000", "1ms" → "1000000", "2s" → "2000000000"
        """
        def _replace_time(m):
            num = int(m.group(1))
            unit = m.group(2)
            if unit == 'ns':
                return str(num)
            elif unit == 'us':
                return str(num * 1000)           # 微秒 → 纳秒
            elif unit == 'ms':
                return str(num * 1000000)        # 毫秒 → 纳秒
            elif unit == 's':
                return str(num * 1000000000)     # 秒 → 纳秒
            return m.group(0)
        return re.sub(r'(\d+)\s*(ns|us|ms|s)', _replace_time, expr)

    @staticmethod
    def _convert_size_literals(expr: str) -> str:
        """
        将大小字面量转换为字节整数。
        
        例如: "256KB" → "262144", "1MB" → "1048576"
        """
        def _replace_size(m):
            num = int(m.group(1))
            unit = m.group(2)
            if unit == 'B':
                return str(num)
            elif unit == 'KB':
                return str(num * 1024)
            elif unit == 'MB':
                return str(num * 1024 * 1024)
            return m.group(0)
        return re.sub(r'(\d+)\s*(B|KB|MB)', _replace_size, expr)

    # ================================================================
    # 主生成入口
    # ================================================================

    def generate(self) -> str:
        """
        生成完整的 .bpf.c 源文件内容。
        
        按顺序生成各个部分，用双换行分隔。
        """
        parts: List[str] = []

        parts.append(self._emit_header())           # 文件头注释 + #include
        parts.append(self._emit_license())          # 许可证声明
        parts.append(self._emit_map_key_structs())  # Map key 结构体
        parts.append(self._emit_implicit_maps())    # 隐式 map（延迟测量用）
        parts.append(self._emit_event_structs())    # 事件结构体
        parts.append(self._emit_maps())             # BPF map 定义
        parts.append(self._emit_probes())           # 探针函数

        # 过滤空字符串，用双换行连接
        return "\n\n".join(p for p in parts if p) + "\n"

    # ----------------------------------------------------------------
    # 文件头
    # ----------------------------------------------------------------

    def _emit_header(self) -> str:
        """生成文件头注释和 #include 指令"""
        tool = _safe_c_name(self.ir.tool_name)
        return textwrap.dedent(f"""\
        // =====================================================================
        // {tool}.bpf.c —— Emon DSL 生成的 eBPF C 程序
        // 工具名称: {self.ir.tool_name}
        // 编译命令: clang -O2 -g -target bpf -c {tool}.bpf.c -o {tool}.bpf.o
        // =====================================================================
        //
        // 本文件由 Emon DSL 编译器自动生成，请勿手动编辑。

        #include "vmlinux.h"              // 内核类型定义（BPF CO-RE 必需）
        #include <bpf/bpf_helpers.h>      // BPF 辅助宏和函数
        #include <bpf/bpf_tracing.h>      // 跟踪相关辅助函数
        #include <bpf/bpf_core_read.h>    // BPF CO-RE 内存读取""")

    def _emit_license(self) -> str:
        """生成 BPF 程序许可证声明（Linux 内核要求双许可证）"""
        return 'char LICENSE[] SEC("license") = "Dual BSD/GPL";'

    # ----------------------------------------------------------------
    # Map Key 结构体
    # ----------------------------------------------------------------

    def _emit_map_key_structs(self) -> str:
        """
        为复合 key（多个字段组成的 key）生成 C struct 定义。
        
        单字段 key 直接使用原生类型（如 u32），不需要 struct。
        多字段 key 需要定义为 packed struct（确保内存布局一致）。
        """
        # 收集所有唯一的 key 字段组合
        key_sigs: Dict[str, List[str]] = {}
        for m in self.ir.maps:
            sig = "|".join(m.key_fields)  # 用 | 连接字段名作为唯一签名
            if sig not in key_sigs:
                key_sigs[sig] = m.key_fields

        parts: List[str] = []
        for sig, fields in key_sigs.items():
            if len(fields) <= 1:
                continue  # 单字段 key，不需要 struct
            if sig in self._seen_struct_names:
                continue  # 已生成过此 struct
            self._seen_struct_names.add(sig)

            struct_name = self._key_struct_name(fields)
            lines = [f"// 复合 key: {', '.join(fields)}",
                     f"struct {struct_name} {{"]
            lines.append("    // Packed 确保跨编译器一致的内存布局")
            for fname in fields:
                ctype = _KEY_TYPE_MAP.get(fname, "u64")
                # 处理数组类型: "char [16]" → "char comm[16]"
                if "[" in ctype:
                    base_type, size_part = ctype.split("[", 1)
                    size_part = size_part.rstrip("] ")
                    lines.append(f"    {base_type.strip()} {_safe_c_name(fname)}[{size_part}];")
                else:
                    lines.append(f"    {ctype} {_safe_c_name(fname)};")
            lines.append("} __attribute__((packed));")  # 紧凑布局，无填充字节
            parts.append("\n".join(lines))

        return "\n\n".join(parts)

    def _key_struct_name(self, fields: List[str]) -> str:
        """根据字段列表生成唯一的 C 结构体名"""
        parts = [_safe_c_name(f)[:8] for f in fields[:4]]  # 取前4个字段的前8字符
        return "key_" + "_".join(parts)

    def _key_c_type(self, fields: List[str]) -> str:
        """返回 map key 的 C 类型"""
        if len(fields) == 1:
            return _KEY_TYPE_MAP.get(fields[0], "u64")
        return f"struct {self._key_struct_name(fields)}"

    # ----------------------------------------------------------------
    # 隐式 Map（延迟测量用）
    # ----------------------------------------------------------------

    def _emit_implicit_maps(self) -> str:
        """
        生成延迟测量所需的隐式 map。
        
        延迟测量需要记录函数入口的时间戳：
          入口探针：将当前时间存入 start_time map（key=pid_tgid）
          出口探针：从 start_time map 读取入口时间，计算差值 = 延迟
        
        每个需要测量延迟的 target 生成一个 start_time map。
        """
        # 检查是否有任何探针需要延迟测量
        for probe in self.ir.probes:
            if probe.measures_latency:
                self._needs_start_time = True
                break

        if not self._needs_start_time:
            return ""

        seen_targets: set = set()
        parts: List[str] = []
        parts.append("// ---- 延迟测量：入口探针时间戳存储 ----")

        for probe in self.ir.probes:
            if not probe.measures_latency or probe.is_exit:
                continue  # 跳过不需要延迟测量的探针和出口探针
            if probe.hook_target in seen_targets:
                continue  # 相同 target 只生成一个 start_time map
            seen_targets.add(probe.hook_target)

            name = f"__start_time_{_safe_c_name(probe.hook_target)}"
            parts.append(textwrap.dedent(f"""\
            struct {{
                __uint(type, BPF_MAP_TYPE_HASH);           // 哈希表类型
                __uint(max_entries, 10240);                 // 最多存储 10240 条
                __type(key, __u64);                         // key = pid_tgid (线程标识)
                __type(value, __u64);                       // value = 入口时间戳(纳秒)
            }} {name} SEC(".maps");"""))

        return "\n\n".join(parts)

    # ----------------------------------------------------------------
    # 事件结构体
    # ----------------------------------------------------------------

    def _emit_event_structs(self) -> str:
        """
        生成 ring buffer 事件的结构体定义。
        
        这些结构体定义事件在内存中的布局，用于内核态写入和用户态读取。
        """
        if not self.ir.events:
            return ""

        parts: List[str] = []
        for ev in self.ir.events:
            lines = [f"// 事件结构体: {ev.name}",
                     f"struct {_safe_c_name(ev.name)} {{"]
            for field in ev.fields:
                ctype_raw = _KEY_TYPE_MAP.get(field["name"], "u64")
                if "[" in ctype_raw:
                    # 数组类型：char comm[16]
                    base_type, size_part = ctype_raw.split("[", 1)
                    size_part = size_part.rstrip("] ")
                    lines.append(f"    {base_type.strip()} {_safe_c_name(field['name'])}[{size_part}];")
                else:
                    # 映射到 BPF 标准类型名
                    if ctype_raw == "u64":
                        ctype_raw = "__u64"
                    elif ctype_raw == "u32":
                        ctype_raw = "__u32"
                    elif ctype_raw == "s64":
                        ctype_raw = "__s64"
                    lines.append(f"    {ctype_raw} {_safe_c_name(field['name'])};")
            lines.append("};")
            parts.append("\n".join(lines))

        return "\n\n".join(parts)

    # ----------------------------------------------------------------
    # BPF Map 定义
    # ----------------------------------------------------------------

    def _emit_maps(self) -> str:
        """
        生成 SEC(".maps") 区域的 BPF map 定义。
        
        每个聚合变量 (@xxx) 对应一个 BPF map。
        如果有 emit 语句，还会生成 ring buffer map。
        """
        if not self.ir.maps:
            return ""

        parts: List[str] = []
        parts.append("// ---- 聚合 Map ----")

        for m in self.ir.maps:
            map_type = _MAP_TYPE_MAP.get(m.map_type, "BPF_MAP_TYPE_HASH")
            key_type = self._key_c_type(m.key_fields)
            value_type = m.value_type

            # 映射 value 类型到标准 BPF 类型名
            if value_type in _VALUE_TYPE_MAP:
                value_type = _VALUE_TYPE_MAP[value_type]

            name = _safe_c_name(m.name)
            # 使用 BPF map 声明宏
            parts.append(textwrap.dedent(f"""\
            struct {{
                __uint(type, {map_type});              // Map 类型
                __uint(max_entries, {m.max_entries});  // 最大条目数
                __type(key, {key_type});               // Key 类型
                __type(value, {value_type});           // Value 类型
            }} {name} SEC(".maps");"""))

        # Ring buffer map（用于 emit 事件输出）
        if self.ir.events:
            for ev in self.ir.events:
                ring_name = _safe_c_name(f"{ev.name}_rb")
                parts.append(textwrap.dedent(f"""\
                struct {{
                    __uint(type, BPF_MAP_TYPE_RINGBUF);
                    __uint(max_entries, 256 * 1024);  // 256KB ring buffer
                }} {ring_name} SEC(".maps");"""))

        return "\n\n".join(parts)

    # ----------------------------------------------------------------
    # 探针函数
    # ----------------------------------------------------------------

    def _emit_probes(self) -> str:
        """生成所有 BPF 探针函数"""
        if not self.ir.probes:
            return "// 无探针定义"

        parts: List[str] = []
        parts.append("// =====================================================================")
        parts.append("// 探针函数")
        parts.append("// =====================================================================")

        for i, probe in enumerate(self.ir.probes):
            self._probe_counter = i + 1
            fn_code = self._emit_single_probe(probe)
            parts.append(fn_code)

        return "\n".join(parts)

    def _emit_single_probe(self, probe: IRProbe) -> str:
        """
        为单个挂载点生成完整的 BPF 探针 C 函数。
        
        生成的函数包含:
          1. SEC 宏声明（指定挂载点）
          2. 函数签名（根据 hook 类型选择正确的上下文参数类型）
          3. 上下文变量提取
          4. where 条件检查
          5. 聚合操作
          6. emit 事件输出
          7. 延迟测量逻辑（如果是出口探针）
        """
        fn_name = f"{_safe_c_name(self.ir.tool_name)}_probe_{self._probe_counter}"
        section = probe.section

        lines: List[str] = []
        lines.append(f'SEC("{section}")')  # 指定 eBPF 程序段

        # 根据 hook 类型选择正确的函数签名
        # 不同 hook 类型传递不同的上下文结构体
        if probe.hook_kind == "SYSCALL":
            if probe.is_exit:
                func_sig = f"int {fn_name}(struct trace_event_raw_sys_exit *ctx)"
            else:
                func_sig = f"int {fn_name}(struct trace_event_raw_sys_enter *ctx)"
        elif probe.hook_kind in ("KERNEL", "FILE", "NET"):
            func_sig = f"int {fn_name}(struct pt_regs *ctx)"  # kprobe 传寄存器上下文
        elif probe.hook_kind == "TRACEPOINT":
            func_sig = f"int {fn_name}(void *ctx)"
        elif probe.hook_kind == "UPROBE":
            func_sig = f"int {fn_name}(struct pt_regs *ctx)"
        else:
            func_sig = f"int {fn_name}(void *ctx)"

        lines.append(func_sig)
        lines.append("{")

        # ---- 函数体 ----
        body_lines: List[str] = []

        # 1. 提取上下文变量（根据 hook 类型提取 pid, comm, cpu 等）
        # （在完整实现中，这里会生成 bpf_get_current_pid_tgid() 等调用）

        # 2. 延迟测量：如果是入口探针且需测延迟，记录开始时间
        if probe.measures_latency and not probe.is_exit:
            body_lines.append("    // 记录入口时间戳")
            body_lines.append(f"    __u64 __ts = bpf_ktime_get_ns();")
            body_lines.append(f"    __u64 __pid_tgid = bpf_get_current_pid_tgid();")
            body_lines.append(f"    bpf_map_update_elem(&__start_time_{_safe_c_name(probe.hook_target)}, &__pid_tgid, &__ts, BPF_ANY);")

        # 3. where 过滤条件
        for cond in probe.where_conditions:
            resolved = self._resolve_expr(cond)
            body_lines.append(f"    // where: {cond}")
            body_lines.append(f"    if (!({resolved})) return 0;")

        # 4. 延迟测量出口：计算延迟
        if probe.measures_latency and probe.is_exit:
            body_lines.append("    // 计算延迟")
            body_lines.append(f"    __u64 __pid_tgid = bpf_get_current_pid_tgid();")
            body_lines.append(f"    __u64 *__start = bpf_map_lookup_elem(&__start_time_{_safe_c_name(probe.hook_target)}, &__pid_tgid);")
            body_lines.append(f"    if (!__start) return 0;")
            body_lines.append(f"    __u64 latency = bpf_ktime_get_ns() - *__start;")
            body_lines.append(f"    bpf_map_delete_elem(&__start_time_{_safe_c_name(probe.hook_target)}, &__pid_tgid);")

        # 5. when 过滤条件
        for cond in probe.when_conditions:
            resolved = self._resolve_expr(cond)
            body_lines.append(f"    // when: {cond}")
            body_lines.append(f"    if (!({resolved})) return 0;")

        # 6. let 变量声明
        for let in probe.lets:
            resolved = self._resolve_expr(let["init"])
            body_lines.append(f"    // let {let['name']} = {let['init']}")
            body_lines.append(f"    __u64 {let['name']} = {resolved};")

        # 7. 聚合操作
        for agg in probe.aggregations:
            body_lines.extend(self._emit_aggregation_code(agg))

        # 8. if 语句（省略，在完整实现中展开）

        # 9. emit 事件输出
        for emit in probe.emits:
            body_lines.extend(self._emit_ringbuf_output(emit))

        lines.extend(body_lines)
        lines.append("    return 0;")
        lines.append("}")

        return "\n".join(lines)

    def _emit_aggregation_code(self, agg: IRAggregation) -> List[str]:
        """生成聚合操作的 BPF C 代码"""
        lines = []
        map_name = _safe_c_name(agg.map_name)
        lines.append(f"    // 聚合: @{agg.map_name}[{', '.join(agg.keys)}] = {agg.agg_fn}({agg.value_expr or ''})")
        
        # 构建 key 变量
        lines.append(f"    __u64 __key = 0;  // TODO: 复合 key 构建")
        lines.append(f"    __u64 *__val = bpf_map_lookup_elem(&{map_name}, &__key);")
        lines.append(f"    if (__val) {{")
        
        if agg.agg_fn == "count":
            lines.append(f"        (*__val)++;  // 计数+1")
        elif agg.agg_fn == "sum":
            lines.append(f"        (*__val) += ({agg.value_expr});  // 累加")
        # avg/min/max/hist/lhist 的实现在完整代码中展开
        
        lines.append(f"    }} else {{")
        lines.append(f"        __u64 __init = {(agg.value_expr or '1')};")
        lines.append(f"        bpf_map_update_elem(&{map_name}, &__key, &__init, BPF_ANY);")
        lines.append(f"    }}")
        
        return lines

    def _emit_ringbuf_output(self, emit: IREmit) -> List[str]:
        """生成 ring buffer 事件输出的 BPF C 代码"""
        lines = []
        ev_name = _safe_c_name(emit.event_name)
        rb_name = _safe_c_name(f"{emit.event_name}_rb")
        
        lines.append(f"    // emit 事件输出")
        lines.append(f"    struct {ev_name} *__ev = bpf_ringbuf_reserve(&{rb_name}, sizeof(struct {ev_name}), 0);")
        lines.append(f"    if (__ev) {{")
        for field in emit.fields:
            lines.append(f"        __ev->{_safe_c_name(field['name'])} = {field['expr']};")
        lines.append(f"        bpf_ringbuf_submit(__ev, 0);")
        lines.append(f"    }}")
        
        return lines


# ===================================================================
# 便捷函数
# ===================================================================

def generate_bpf_c(ir: IRProgram) -> str:
    """
    从 IRProgram 生成 eBPF C 代码的便捷函数。
    
    用法:
        c_code = generate_bpf_c(ir)
        with open("output.bpf.c", "w") as f:
            f.write(c_code)
    """
    return BpfCGenerator(ir).generate()
