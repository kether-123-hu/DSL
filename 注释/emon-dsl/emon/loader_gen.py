# ===================================================================
# loader_gen.py —— libbpf 加载器代码生成器（编译器第五阶段-B）
# ===================================================================
#
# 【本文件的作用】
# 从 IR（中间表示）生成用户态 libbpf 加载器 C 代码（_loader.c 文件）。
# 加载器负责将编译好的 eBPF 字节码加载到内核中，并处理用户态逻辑。
#
# 【加载器的职责】
#   1. 打开并加载编译好的 BPF 对象文件 (.bpf.o)
#   2. 自动挂载所有 BPF 程序到对应的内核挂载点
#   3. 创建 ring buffer 并轮询接收内核事件
#   4. 执行 every 周期性任务（定时读取并打印 map 数据）
#   5. 执行 begin/end 生命周期钩子
#   6. 处理信号（Ctrl+C 优雅退出）
#   7. 解析命令行选项
#
# 【生成的代码使用 libbpf 骨架（skeleton）模式】
#   骨架由 bpftool gen skeleton 从 .bpf.o 生成，
#   提供了类型安全的 map 和程序访问方式。
# ===================================================================

from typing import List
from emon.ir import IRProgram, IREveryTask, IRPrint


def _safe_c_name(name: str) -> str:
    """
    将名称转换为合法的 C 语言标识符。
    替换 @、-、. 等特殊字符为 _。
    """
    return name.replace("@", "").replace("-", "_").replace(".", "_")


class LoaderGenerator:
    """
    从 IRProgram 生成用户态 libbpf 加载器 C 代码。
    
    使用方式:
        gen = LoaderGenerator(ir)
        loader_code = gen.generate()
    """

    def __init__(self, ir: IRProgram):
        self.ir = ir
        # 构建 option 查找表，并去掉字符串值的引号
        self._opt_map: dict = {}
        for o in ir.options:
            val = o.get("default", "0")
            # 去掉字符串字面量外层引号: "/path/log" → /path/log
            if val.startswith('"') and val.endswith('"'):
                val = val[1:-1]
            self._opt_map[o["name"]] = val

    def _get_option_value(self, name: str) -> str:
        """获取 option 的默认值"""
        return self._opt_map.get(name, "0")

    def generate(self) -> str:
        """
        生成完整的 _loader.c 源文件。
        
        按顺序组装各个代码段：头注释 → include → 全局变量 → 
        事件处理器 → option 变量 → map 打印器 → main 函数。
        """
        parts: List[str] = []
        parts.append(self._emit_header())             # 文件头注释
        parts.append(self._emit_includes())           # #include 指令
        parts.append(self._emit_globals())            # 全局变量和信号处理
        parts.append(self._emit_event_handler())      # ring buffer 回调
        parts.append(self._emit_option_variables())   # option 变量
        parts.append(self._emit_map_printers())       # map 打印函数
        parts.append(self._emit_main())               # main 函数
        return "\n\n".join(parts) + "\n"

    # ----------------------------------------------------------------
    # 文件头注释
    # ----------------------------------------------------------------

    def _emit_header(self) -> str:
        """生成文件头注释（中文，指导编译步骤）"""
        tool = _safe_c_name(self.ir.tool_name)
        return f"""\
// =====================================================================
// {tool}_loader.c -- Emon DSL 生成的用户态 libbpf 加载器
// 工具名称: {self.ir.tool_name}
//
// 编译步骤（三步走）:
//   1. clang -O2 -g -target bpf -c {tool}.bpf.c -o {tool}.bpf.o
//      → 将 BPF C 代码编译为 eBPF 字节码目标文件
//   2. bpftool gen skeleton {tool}.bpf.o > {tool}.skel.h
//      → 从字节码生成 libbpf 骨架头文件（类型安全的 map/程序访问）
//   3. gcc {tool}_loader.c -o {tool}_loader -lbpf -lelf -lz
//      → 将加载器编译为可执行文件，链接 libbpf
//
// 本文件由 Emon DSL 编译器自动生成，请勿手动编辑。
// ====================================================================="""

    # ----------------------------------------------------------------
    # #include 指令
    # ----------------------------------------------------------------

    def _emit_includes(self) -> str:
        """生成头文件包含和事件结构体定义"""
        tool = _safe_c_name(self.ir.tool_name)
        return f"""\
#include <stdio.h>        // 标准输入输出（printf, fprintf）
#include <stdlib.h>       // 标准库（exit, malloc）
#include <unistd.h>       // POSIX API（sleep, usleep）
#include <string.h>       // 字符串操作（memset）
#include <signal.h>       // 信号处理（SIGINT, SIGTERM）
#include <time.h>         // 时间函数
#include <errno.h>        // 错误号
#include <bpf/libbpf.h>   // libbpf 核心库
#include <bpf/bpf.h>      // BPF 系统调用封装

#include "{tool}.skel.h"  // bpftool 生成的骨架头文件

// ---- 事件结构体（与 BPF 侧定义保持一致） ----
{self._emit_loader_event_structs()}"""

    # ----------------------------------------------------------------
    # 全局变量和信号处理
    # ----------------------------------------------------------------

    def _emit_globals(self) -> str:
        """
        生成全局变量和信号处理代码。
        
        使用 sigaction 而非 signal()，避免 SA_RESTART 标志
        导致 Ctrl+C 无法中断 sleep() 的问题。
        """
        tool = _safe_c_name(self.ir.tool_name)
        return f"""\
static volatile sig_atomic_t __stop = 0;  // 原子标志：是否应该停止

// Ctrl+C 信号处理器
static void __sigint_handler(int sig) {{
    (void)sig;
    __stop = 1;  // 设置停止标志
}}

static struct {tool}_bpf *__skel = NULL;        // BPF 骨架对象
static struct ring_buffer *__rb = NULL;          // Ring buffer 对象

// 安装信号处理器（使用 sigaction 避免 SA_RESTART）
static void __setup_signals(void) {{
    struct sigaction sa = {{0}};
    sa.sa_handler = __sigint_handler;
    sa.sa_flags = 0;           // 不设置 SA_RESTART，允许 sleep 被信号中断
    sigaction(SIGINT, &sa, NULL);   // Ctrl+C
    sigaction(SIGTERM, &sa, NULL);  // kill 命令
}}"""

    # ----------------------------------------------------------------
    # 事件结构体（用户态侧）
    # ----------------------------------------------------------------

    def _emit_loader_event_structs(self) -> str:
        """
        生成用户态的事件结构体定义。
        
        这些结构体必须和 BPF 侧的定义完全一致（大小和布局），
        否则 ring buffer 读取会出错。
        """
        if not self.ir.events:
            return ""
        parts = []
        for ev in self.ir.events:
            name = ev.name.replace("-", "_").replace(".", "_")
            lines = [f"struct {name} {{"]
            for field in ev.fields:
                fname = field["name"].replace("-", "_").replace(".", "_")
                ftype = field["type"]
                # 将 BPF 类型映射为 C 标准类型
                if "char" in ftype:
                    # 字符数组: "char [16]" → "char fname[16]"
                    if "[" in ftype:
                        base, size = ftype.split("[", 1)
                        size = size.rstrip("] ")
                        lines.append(f"    char {fname}[{size}];")
                    else:
                        lines.append(f"    char {fname}[64];")
                elif ftype in ("u64", "__u64"):
                    lines.append(f"    unsigned long long {fname};")  # 64位无符号
                elif ftype in ("u32", "__u32"):
                    lines.append(f"    unsigned int {fname};")        # 32位无符号
                elif ftype in ("s64", "__s64"):
                    lines.append(f"    long long {fname};")           # 64位有符号
                else:
                    lines.append(f"    unsigned long long {fname};")
            lines.append("};")
            parts.append("\n".join(lines))
        return "\n".join(parts) + "\n"

    # ----------------------------------------------------------------
    # Ring Buffer 事件处理器
    # ----------------------------------------------------------------

    def _emit_event_handler(self) -> str:
        """
        生成 ring buffer 回调函数。
        
        当内核态通过 bpf_ringbuf_submit 提交事件时，
        这个回调函数被调用，打印事件内容。
        """
        if not self.ir.events:
            return "// 无 emit 事件定义"

        ev = self.ir.events[0]
        ev_name = _safe_c_name(ev.name)

        # 生成每个字段的打印代码
        field_prints: List[str] = []
        for field in ev.fields:
            fname = field["name"]
            ftype = field["type"]
            if "char" in ftype:
                # 字符串类型：用 %s 打印
                field_prints.append(
                    f'    fprintf(stderr, "  {fname}=%s\\n", e->{_safe_c_name(fname)});')
            else:
                # 数值类型：用 %llu 打印
                field_prints.append(
                    f'    fprintf(stderr, "  {fname}=%llu\\n", '
                    f'(unsigned long long)e->{_safe_c_name(fname)});')

        fp = "\n".join(field_prints)

        return f"""\
// ---- Ring Buffer 事件处理器 ----
// 每次内核发送事件时被调用
static int __handle_event(void *ctx, void *data, size_t data_sz) {{
    (void)ctx;
    const struct {ev_name} *e = data;  // 类型转换
    fprintf(stderr, "[{self.ir.tool_name}] event (size=%zu):\\n", data_sz);
{fp}
    return 0;  // 返回 0 表示继续接收事件
}}"""

    # ----------------------------------------------------------------
    # Option 变量
    # ----------------------------------------------------------------

    def _emit_option_variables(self) -> str:
        """生成 option 的 C 变量声明（可在运行时通过命令行修改）"""
        if not self.ir.options:
            return "// 无配置选项"

        lines: List[str] = ["// ---- 配置选项（启动时可修改） ----"]
        for opt in self.ir.options:
            name = opt["name"]
            default = self._opt_map.get(name, "0")
            # 转义反斜杠和双引号
            escaped = default.replace("\\", "\\\\").replace('"', '\\"')
            lines.append(f'static const char *__opt_{name} = "{escaped}";')
        return "\n".join(lines)

    # ----------------------------------------------------------------
    # Map 打印器
    # ----------------------------------------------------------------

    def _emit_map_printers(self) -> str:
        """
        生成 BPF map 读取和打印的辅助函数。
        
        这些函数在 every 任务和 end 块中被调用，
        用于定期输出统计结果。
        """
        parts: List[str] = []
        parts.append("// ---- Map 打印辅助函数 ----")
        
        # 为每个聚合 map 生成一个打印函数
        for m in self.ir.maps:
            name = _safe_c_name(m.name)
            parts.append(f"""\
// 打印 map: {m.name}
static void __print_{name}(struct {_safe_c_name(self.ir.tool_name)}_bpf *skel) {{
    int fd = bpf_map__fd(skel->maps.{name});  // 获取 map 的文件描述符
    if (fd < 0) {{
        fprintf(stderr, "  (map '{name}' not found)\\n");
        return;
    }}
    fprintf(stdout, "--- @{m.name} (key: {', '.join(m.key_fields)}) ---\\n");
    // TODO: 遍历并打印 map 内容（调用 emon_rt_dump_hash_u64_map_fd）
}}""")
        
        return "\n".join(parts)

    # ----------------------------------------------------------------
    # Main 函数
    # ----------------------------------------------------------------

    def _emit_main(self) -> str:
        """
        生成 main 函数 —— 加载器的入口点。
        
        main 函数的执行流程:
          1. 安装信号处理器
          2. 打开并加载 BPF 对象
          3. 设置 ring buffer 并开始轮询
          4. 执行 begin 块
          5. 进入主循环（处理 every 任务和事件）
          6. 收到退出信号后执行 end 块
          7. 清理资源并退出
        """
        tool = _safe_c_name(self.ir.tool_name)
        
        # begin 块代码
        begin_code = ""
        if self.ir.begin_stmts:
            for stmt in self.ir.begin_stmts:
                begin_code += f'    fprintf(stdout, "{stmt.expr}\\n");\n'
        else:
            begin_code = f'    fprintf(stdout, "[{self.ir.tool_name}] 监控已启动\\n");\n'
        
        # end 块代码
        end_code = ""
        if self.ir.end_stmts:
            for stmt in self.ir.end_stmts:
                end_code += f'    fprintf(stdout, "{stmt.expr}\\n");\n'
        else:
            end_code = f'    fprintf(stdout, "[{self.ir.tool_name}] 监控已停止\\n");\n'
        
        # every 任务代码
        every_code = ""
        if self.ir.every_tasks:
            for task in self.ir.every_tasks:
                for p in task.prints:
                    every_code += f'        fprintf(stdout, "{p.expr}\\n");\n'
                for agg_name in task.agg_reads:
                    safe_agg = _safe_c_name(agg_name)
                    every_code += f'        __print_{safe_agg}(__skel);\n'
                every_code += f'        fprintf(stdout, "---\\n");\n'
        
        # 主循环
        main_loop = f"""\
    // 主循环：轮询 ring buffer 并执行周期性任务
    while (!__stop) {{
        // 轮询 ring buffer（最多等待 100ms）
        int err = ring_buffer__poll(__rb, 100);
        if (err < 0 && err != -EINTR) {{
            fprintf(stderr, "ring_buffer__poll 错误: %d\\n", err);
            break;
        }}
        // TODO: 周期性 every 任务
    }}""" if self.ir.events else f"""\
    // 主循环：等待信号
    while (!__stop) {{
        sleep(1);
    }}"""
        
        return f"""\
int main(int argc, char **argv) {{
    (void)argc;
    (void)argv;

    // 1. 安装信号处理器（Ctrl+C 优雅退出）
    __setup_signals();
    fprintf(stderr, "[{self.ir.tool_name}] Emon DSL 加载器启动中...\\n");

    // 2. 打开 BPF 骨架
    __skel = {tool}_bpf__open();
    if (!__skel) {{
        fprintf(stderr, "无法打开 BPF 骨架\\n");
        return 1;
    }}

    // 3. 加载 BPF 程序到内核
    if ({tool}_bpf__load(__skel)) {{
        fprintf(stderr, "无法加载 BPF 程序\\n");
        goto cleanup;
    }}

    // 4. 挂载 BPF 程序到内核挂载点
    if ({tool}_bpf__attach(__skel)) {{
        fprintf(stderr, "无法挂载 BPF 程序\\n");
        goto cleanup;
    }}

    // 5. 设置 ring buffer（如果有 emit 事件）
    {self._emit_rb_setup(tool)}

    // 6. 执行 begin 块（启动初始化）
    fprintf(stderr, "[{self.ir.tool_name}] 开始监控... 按 Ctrl+C 停止\\n");
{begin_code}
    // 7. 主循环
{main_loop}
    // 8. 执行 end 块（退出清理）
    fprintf(stderr, "\\n[{self.ir.tool_name}] 正在停止...\\n");
{end_code}
cleanup:
    // 9. 清理资源
    ring_buffer__free(__rb);
    {tool}_bpf__destroy(__skel);
    fprintf(stderr, "[{self.ir.tool_name}] 已退出\\n");
    return 0;
}}"""

    def _emit_rb_setup(self, tool: str) -> str:
        """生成 ring buffer 设置代码"""
        if not self.ir.events:
            return "    // 无 emit 事件，跳过 ring buffer 设置"
        
        ev = self.ir.events[0]
        rb_name = _safe_c_name(f"{ev.name}_rb")
        return f"""\
    // 创建 ring buffer 并绑定事件处理器
    __rb = ring_buffer__new(
        bpf_map__fd(__skel->maps.{rb_name}),  // ring buffer map 的文件描述符
        __handle_event,                        // 事件回调函数
        NULL,                                  // 回调上下文（不需要）
        NULL                                   // 可选选项
    );
    if (!__rb) {{
        fprintf(stderr, "无法创建 ring buffer\\n");
        goto cleanup;
    }}"""


# ===================================================================
# 便捷函数
# ===================================================================

def generate_loader_c(ir: IRProgram) -> str:
    """
    从 IRProgram 生成加载器 C 代码的便捷函数。
    
    用法:
        loader_code = generate_loader_c(ir)
        with open("output_loader.c", "w") as f:
            f.write(loader_code)
    """
    return LoaderGenerator(ir).generate()
