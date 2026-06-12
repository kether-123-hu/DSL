// =====================================================================
// Emon DSL —— 用户态运行时公共头
// 提供 BPF map 读取、事件解析、直方图、打印工具
// 与 emon_rt_*.c 静态库一起链接到生成的 loader 中。
// =====================================================================
#pragma once
#include <bpf/libbpf.h>
#include <stdint.h>
#include <stdio.h>
#include <time.h>

#ifdef __cplusplus
extern "C" {
#endif

// ---- 信号与生命周期 ----
void emon_rt_install_signal_handler(void);
int  emon_rt_should_stop(void);
int  emon_rt_open_load_attach(struct bpf_object** out_obj,
                               const char* obj_path);
int  emon_rt_sleep_loop(int interval_sec,
                         int (*tick_cb)(void*), void* ctx,
                         struct ring_buffer* rb);

// ---- Map 读取 ----
// 通过 map fd 遍历并打印 top-N（hex key → u64 value）
int  emon_rt_dump_hash_u64_map_fd(int map_fd, int top_n);
// 通过 map 名称 dump（需要 bpf_object 上下文）
int  emon_rt_dump_hash_u64_map(const char* map_name, int top_n);

// ---- 格式化输出 ----
// 打印直方图（log2 桶或线性桶）
void emon_rt_print_hist(const char* title, const uint64_t* buckets, int n);
// 打印简单表格
void emon_rt_print_table_header(FILE* out, const char* const headers[], int ncols,
                                const char* const rows[][64], int nrows);
// 打印单条 bar 图
void emon_rt_print_bar(const char* label, uint64_t value, uint64_t max_val);
// ring buffer 轮询
int  emon_rt_ringbuffer_poll(struct ring_buffer* rb, int timeout_ms);

#ifdef __cplusplus
}
#endif
