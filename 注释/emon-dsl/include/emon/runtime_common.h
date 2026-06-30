// =====================================================================
// runtime_common.h —— Emon DSL 用户态运行时公共头文件
// =====================================================================
//
// 【本文件的作用】
// 声明用户态运行时库（emon_rt_*.c）中所有公共函数的接口。
// 其他 C 文件通过 #include 此头文件来使用运行时库的功能。
//
// 【头文件是什么？】
// 在 C 语言中，头文件（.h）相当于"目录"或"说明书"。
// 它告诉编译器有哪些函数可用、函数需要什么参数、返回什么值，
// 但具体的实现代码写在 .c 文件中。
//
// 【本文件声明的功能分组】
//   信号与生命周期:
//     emon_rt_install_signal_handler()  → 安装 Ctrl+C 信号处理器
//     emon_rt_should_stop()             → 查询是否收到停止信号
//     emon_rt_open_load_attach()        → 打开/加载/挂载 BPF 程序
//     emon_rt_sleep_loop()              → 主循环（周期性任务 + ring buffer 轮询）
//
//   Map 读取:
//     emon_rt_dump_hash_u64_map_fd()    → 通过 fd 遍历 map 并输出 top-N
//     emon_rt_dump_hash_u64_map()       → 通过名称遍历 map
//
//   格式化输出:
//     emon_rt_print_hist()              → 打印直方图
//     emon_rt_print_table_header()      → 打印表格
//     emon_rt_print_bar()               → 打印条形图
//     emon_rt_ringbuffer_poll()         → 轮询 ring buffer
//
// 【#pragma once 是什么？】
// 这是一个"头文件保护"指令，确保同一个头文件不会被重复包含。
// 如果多个 .c 文件都 #include 了这个头文件，编译器只会处理一次。
// =====================================================================
#pragma once

// ---- 标准库头文件 ----
#include <bpf/libbpf.h>    // libbpf 核心库（提供 struct bpf_object, ring_buffer 等）
#include <stdint.h>         // 固定宽度整数类型（uint64_t, uint32_t 等）
#include <stdio.h>          // 标准 I/O（FILE* 类型）
#include <time.h>           // 时间相关

// ---- C++ 兼容性 ----
// 如果这段代码被 C++ 编译器编译，需要用 extern "C" 包裹
// 以禁止 C++ 的名称修饰（name mangling），保持 C 语言的符号名
#ifdef __cplusplus
extern "C" {
#endif

// =====================================================================
// 信号与生命周期
// =====================================================================

// 安装信号处理器（SIGINT=Ctrl+C, SIGTERM=kill）
// 调用后，用户可以按 Ctrl+C 优雅退出程序
void emon_rt_install_signal_handler(void);

// 查询是否收到了停止信号
// 返回: 0=继续运行, 1=应该停止
int  emon_rt_should_stop(void);

// 通用 BPF 对象打开→加载→挂载流程
// 参数:
//   out_obj:  [输出] 成功加载的 BPF 对象指针
//   obj_path: BPF 对象文件路径（.bpf.o 文件）
// 返回: 0=成功, -1=失败
int  emon_rt_open_load_attach(struct bpf_object** out_obj,
                               const char* obj_path);

// 主休眠循环（用于 every 周期性任务）
// 参数:
//   interval_sec: 每次周期的间隔（秒）
//   tick_cb:      周期回调函数（每个周期执行一次，用于读 map 和打印）
//   ctx:          传给 tick_cb 的用户上下文指针
//   rb:           ring buffer 对象（用于在休眠期间接收内核事件）
// 返回: 执行了多少次周期回调
int  emon_rt_sleep_loop(int interval_sec,
                         int (*tick_cb)(void*), void* ctx,
                         struct ring_buffer* rb);

// =====================================================================
// Map 读取
// =====================================================================

// 通过 map 文件描述符遍历 hash map（key 为任意大小，value 为 u64）
// 打印前 top_n 条记录（按 value 降序排列）
// 参数:
//   map_fd: map 的文件描述符（通过 bpf_map__fd 获取）
//   top_n:  输出前 N 条，0 表示输出全部
// 返回: 0=成功, -1=失败
int  emon_rt_dump_hash_u64_map_fd(int map_fd, int top_n);

// 通过 map 名称 dump（需要 bpf_object 上下文）
// 注意：在骨架模式下，推荐直接使用 emon_rt_dump_hash_u64_map_fd
int  emon_rt_dump_hash_u64_map(const char* map_name, int top_n);

// =====================================================================
// 格式化输出
// =====================================================================

// 打印直方图（支持 log2 对数分桶和线性分桶）
// 参数:
//   title:   直方图标题
//   buckets: 每个桶的计数值数组
//   n:       桶的数量
void emon_rt_print_hist(const char* title, const uint64_t* buckets, int n);

// 打印对齐的多列表格
// 参数:
//   out:     输出流（stdout 或 stderr）
//   headers: 列标题数组
//   ncols:   列数
//   rows:    数据行（每个单元格最多 64 字符）
//   nrows:   行数
void emon_rt_print_table_header(FILE* out, const char* const headers[], int ncols,
                                const char* const rows[][64], int nrows);

// 打印单条 ASCII 条形图
// 参数:
//   label:   标签
//   value:   当前值
//   max_val: 最大值（用于计算比例）
void emon_rt_print_bar(const char* label, uint64_t value, uint64_t max_val);

// Ring buffer 轮询
// 参数:
//   rb:         ring buffer 对象
//   timeout_ms: 超时时间（毫秒）
// 返回: 接收到的事件数，负数表示错误
int  emon_rt_ringbuffer_poll(struct ring_buffer* rb, int timeout_ms);

#ifdef __cplusplus
}
#endif
