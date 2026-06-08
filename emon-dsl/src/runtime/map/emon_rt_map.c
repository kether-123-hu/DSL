// Emon DSL —— BPF map 读取（用户态）
// 提供遍历 hash map 并输出 top-N（文档 5.4.7 every 块）
#include <bpf/libbpf.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include "emon/runtime_common.h"

int emon_rt_dump_hash_u64_map(const char* map_name, int top_n) {
    // 示意代码：通过 bpf_object__find_map_by_name 然后 bpf_map__get_next_key 遍历
    (void)map_name; (void)top_n;
    fprintf(stderr, "[emon_rt_dump_hash_u64_map] 骨架实现请在示例工具中调用\n");
    return 0;
}
