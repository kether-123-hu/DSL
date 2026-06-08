// =====================================================================
// Emon DSL —— 用户态运行时公共头
// 提供 BPF map 读取、事件解析、直方图、打印工具
// =====================================================================
#pragma once
#include <bpf/libbpf.h>
#include <stdint.h>
#include <stdio.h>
#include <time.h>

#ifdef __cplusplus
extern "C" {
#endif

// 打印一个 u64 map 的聚合值；用于 @count/@hist 的用户态 dump
int emon_rt_dump_hash_u64_map(const char* map_name, int top_n);

// 输出直方图（log2 桶）
void emon_rt_print_hist(const char* title, const uint64_t* buckets, int n);

// 周期任务的周期性地读取 ringbuf 轮询；返回已处理事件数
int emon_rt_ringbuffer_poll(struct ring_buffer* rb, int timeout_ms);

// 简单表格打印
void emon_rt_print_table_header(FILE* out, const char* const headers[], int ncols,
                        const char* const rows[][64], int nrows);

#ifdef __cplusplus
}
#endif
