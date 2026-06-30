# ===================================================================
# emon_rt_map.c —— BPF Map 读取与打印（用户态）
# ===================================================================
#
# 【本文件的作用】
# 提供遍历 BPF hash map 并输出 top-N 统计数据的工具函数。
# 用于实现 every 块中的 print(@agg) 功能。
#
# 【BPF Map 简介】
# BPF map 是内核态 eBPF 程序和用户态程序之间共享数据的核心机制。
# 可以理解为"内核中的键值存储数据库"：
#   - 内核态程序通过 bpf_map_update_elem 写入数据
#   - 用户态程序通过 bpf_map_lookup_elem / bpf_map_get_next_key 读取数据
#
# 【本文件的函数】
#   emon_rt_dump_hash_u64_map_fd(map_fd, top_n)
#     → 通过 map 文件描述符遍历 hash map 并输出前 top_n 条数据
#   
#   emon_rt_dump_hash_u64_map(map_name, top_n)
#     → 通过 map 名称遍历（需要 bpf_object 上下文，仅存根函数）
# ===================================================================
#include <bpf/libbpf.h>         // libbpf API
#include <bpf/bpf.h>            // BPF 系统调用封装（bpf_map_get_next_key 等）
#include <stdio.h>              // 标准 I/O
#include <stdint.h>             // 固定宽度整数类型
#include <stdlib.h>             // malloc, free, qsort
#include <string.h>             // memcpy
#include <errno.h>              // 错误号（ENOENT 等）
#include "emon/runtime_common.h"

// ---- 内部数据结构 ----
// 用于存储 map 中的一个 key-value 对
typedef struct {
    void *key;          // 指向 key 数据的指针（动态分配）
    size_t key_size;    // key 的字节大小
    uint64_t value;     // value（必须是 u64 类型）
} emon_map_entry;

// ---- 排序比较函数（降序） ----
// qsort 使用的比较函数，按 value 从大到小排列
// 返回负数 = a 排在 b 前面（a 的 value 更大）
static int _compare_entries_desc(const void *a, const void *b) {
    const emon_map_entry *ea = (const emon_map_entry *)a;
    const emon_map_entry *eb = (const emon_map_entry *)b;
    if (ea->value > eb->value) return -1;  // a 更大 → a 排在前面
    if (ea->value < eb->value) return 1;   // b 更大 → b 排在前面
    return 0;  // 相等
}

// ---- 主函数：遍历 hash map 并输出 top-N ----
int emon_rt_dump_hash_u64_map_fd(int map_fd, int top_n) {
    // 参数校验
    if (map_fd < 0) {
        fprintf(stderr, "[emon_rt] 无效的 map 文件描述符\n");
        return -1;
    }

    // ---- 第一步：探测 key 大小 ----
    // BPF map 的 key 可以是任意大小，我们需要先探测
    void *key = NULL;
    void *next_key = NULL;
    size_t key_size = 0;

    // 用一个足够大的缓冲区尝试获取第一个 key
    unsigned char dummy_key[256] = {0};
    unsigned char dummy_next[256] = {0};
    int err = bpf_map_get_next_key(map_fd, NULL, dummy_next);
    if (err) {
        if (errno == ENOENT) {
            // map 是空的
            fprintf(stdout, "  (空 map)\n");
            return 0;
        }
        // 无法探测 → 假设 key 是 4 字节（常见情况）
        key_size = 4;
    }

    if (key_size == 0) key_size = 4;
    
    // 分配 key 缓冲区
    key = calloc(1, key_size);
    next_key = calloc(1, key_size);
    if (!key || !next_key) {
        free(key);
        free(next_key);
        return -1;
    }

    // ---- 第二步：第一遍遍历，统计条目数 ----
    int count = 0;
    err = bpf_map_get_next_key(map_fd, NULL, next_key);
    while (err == 0) {
        count++;
        memcpy(key, next_key, key_size);  // 保存当前 key
        err = bpf_map_get_next_key(map_fd, key, next_key);  // 获取下一个 key
    }

    if (count == 0) {
        fprintf(stdout, "  (空 map)\n");
        free(key);
        free(next_key);
        return 0;
    }

    // ---- 第三步：第二遍遍历，收集所有条目 ----
    emon_map_entry *entries = calloc(count, sizeof(emon_map_entry));
    if (!entries) {
        free(key);
        free(next_key);
        return -1;
    }

    int idx = 0;
    err = bpf_map_get_next_key(map_fd, NULL, next_key);
    while (err == 0 && idx < count) {
        // 复制 key
        entries[idx].key = malloc(key_size);
        memcpy(entries[idx].key, next_key, key_size);
        entries[idx].key_size = key_size;

        // 读取 value
        uint64_t val = 0;
        if (bpf_map_lookup_elem(map_fd, entries[idx].key, &val) == 0) {
            entries[idx].value = val;
        }
        
        idx++;
        memcpy(key, next_key, key_size);
        err = bpf_map_get_next_key(map_fd, key, next_key);
    }

    // ---- 第四步：排序（按 value 降序） ----
    qsort(entries, count, sizeof(emon_map_entry), _compare_entries_desc);

    // ---- 第五步：输出 top-N ----
    int limit = top_n > 0 && top_n < count ? top_n : count;
    for (int i = 0; i < limit; i++) {
        fprintf(stdout, "  [%3d] ", i + 1);
        
        // 打印 key（按十六进制字节输出，简化版）
        unsigned char *kb = (unsigned char *)entries[i].key;
        fprintf(stdout, "key=");
        for (size_t j = 0; j < entries[i].key_size && j < 16; j++) {
            fprintf(stdout, "%02x", kb[j]);  // 每字节两个十六进制字符
        }
        fprintf(stdout, "  =>  %llu\n", (unsigned long long)entries[i].value);
    }

    // ---- 清理资源 ----
    for (int i = 0; i < count; i++) {
        free(entries[i].key);
    }
    free(entries);
    free(key);
    free(next_key);

    return 0;
}

// ---- 通过 map 名读取（存根函数） ----
// 在骨架模式下，由生成的 loader 直接调用 emon_rt_dump_hash_u64_map_fd，
// 因为骨架已经提供了类型安全的 map 文件描述符访问。
int emon_rt_dump_hash_u64_map(const char* map_name, int top_n) {
    (void)map_name;  // 未使用
    (void)top_n;     // 未使用
    fprintf(stderr, "[emon_rt] 请使用 emon_rt_dump_hash_u64_map_fd 并传入 map fd\n");
    return 0;
}
