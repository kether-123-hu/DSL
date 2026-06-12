// Emon DSL —— BPF map 读取（用户态）
// 提供遍历 hash map 并输出 top-N（文档 5.4.7 every 块）
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include "emon/runtime_common.h"

// 单个 map entry 的 key-value 对
typedef struct {
    void *key;
    size_t key_size;
    uint64_t value;
} emon_map_entry;

static int _compare_entries_desc(const void *a, const void *b) {
    const emon_map_entry *ea = (const emon_map_entry *)a;
    const emon_map_entry *eb = (const emon_map_entry *)b;
    if (ea->value > eb->value) return -1;
    if (ea->value < eb->value) return 1;
    return 0;
}

int emon_rt_dump_hash_u64_map_fd(int map_fd, int top_n) {
    if (map_fd < 0) {
        fprintf(stderr, "[emon_rt] invalid map fd\n");
        return -1;
    }

    // 获取第一个 key（空 key 探测 key size）
    void *key = NULL;
    void *next_key = NULL;
    size_t key_size = 0;

    // 探测 key size：尝试一个足够大的 buffer
    unsigned char dummy_key[256] = {0};
    unsigned char dummy_next[256] = {0};
    int err = bpf_map_get_next_key(map_fd, NULL, dummy_next);
    if (err) {
        if (errno == ENOENT) {
            fprintf(stdout, "  (empty map)\n");
            return 0;
        }
        // 没有 key，尝试用 4 字节 key
        key_size = 4;
    }

    // Allocate initial key buffer
    if (key_size == 0) key_size = 4;
    key = calloc(1, key_size);
    next_key = calloc(1, key_size);
    if (!key || !next_key) {
        free(key);
        free(next_key);
        return -1;
    }

    // 第一遍：统计数量
    int count = 0;
    err = bpf_map_get_next_key(map_fd, NULL, next_key);
    while (err == 0) {
        count++;
        memcpy(key, next_key, key_size);
        err = bpf_map_get_next_key(map_fd, key, next_key);
    }

    if (count == 0) {
        fprintf(stdout, "  (empty map)\n");
        free(key);
        free(next_key);
        return 0;
    }

    // 第二遍：收集所有 entries
    emon_map_entry *entries = calloc(count, sizeof(emon_map_entry));
    if (!entries) {
        free(key);
        free(next_key);
        return -1;
    }

    int idx = 0;
    err = bpf_map_get_next_key(map_fd, NULL, next_key);
    while (err == 0 && idx < count) {
        entries[idx].key = malloc(key_size);
        memcpy(entries[idx].key, next_key, key_size);
        entries[idx].key_size = key_size;

        uint64_t val = 0;
        if (bpf_map_lookup_elem(map_fd, entries[idx].key, &val) == 0) {
            entries[idx].value = val;
        }
        idx++;
        memcpy(key, next_key, key_size);
        err = bpf_map_get_next_key(map_fd, key, next_key);
    }

    // 排序（降序）
    qsort(entries, count, sizeof(emon_map_entry), _compare_entries_desc);

    // 输出 top-N
    int limit = top_n > 0 && top_n < count ? top_n : count;
    for (int i = 0; i < limit; i++) {
        fprintf(stdout, "  [%3d] ", i + 1);
        // 打印 key (简化：按字节打印)
        unsigned char *kb = (unsigned char *)entries[i].key;
        fprintf(stdout, "key=");
        for (size_t j = 0; j < entries[i].key_size && j < 16; j++) {
            fprintf(stdout, "%02x", kb[j]);
        }
        fprintf(stdout, "  =>  %llu\n", (unsigned long long)entries[i].value);
    }

    // Cleanup
    for (int i = 0; i < count; i++) {
        free(entries[i].key);
    }
    free(entries);
    free(key);
    free(next_key);

    return 0;
}

int emon_rt_dump_hash_u64_map(const char* map_name, int top_n) {
    // 此函数需要 bpf_object 上下文，由 loader 在加载后调用
    // 骨架模式下，由生成的 loader 直接调用 emon_rt_dump_hash_u64_map_fd
    (void)map_name;
    (void)top_n;
    fprintf(stderr, "[emon_rt] emon_rt_dump_hash_u64_map: use emon_rt_dump_hash_u64_map_fd with fd\n");
    return 0;
}
