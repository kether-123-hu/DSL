// Emon DSL —— 用户态事件输出（表格、直方图、ring buffer poll）
// 提供格式化输出工具，供生成的 loader 调用。
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <bpf/libbpf.h>
#include "emon/runtime_common.h"

void emon_rt_print_hist(const char* title, const uint64_t* buckets, int n) {
    fprintf(stdout, "-- %s (histogram, %d buckets) --\n", title, n);

    // 找到最大值以计算比例
    uint64_t max_val = 0;
    for (int i = 0; i < n; ++i) {
        if (buckets[i] > max_val) max_val = buckets[i];
    }
    if (max_val == 0) {
        fprintf(stdout, "  (no data)\n");
        return;
    }

    const int max_bar_width = 40;
    for (int i = 0; i < n; ++i) {
        if (!buckets[i]) continue;
        int bar_width = (int)((double)buckets[i] / (double)max_val * max_bar_width);
        if (bar_width < 1) bar_width = 1;
        fprintf(stdout, "  [%2d] %10llu |", i, (unsigned long long)buckets[i]);
        for (int j = 0; j < bar_width; ++j) fputc('#', stdout);
        fputc('\n', stdout);
    }
}

void emon_rt_print_table_header(FILE* out,
                                const char* const headers[], int ncols,
                                const char* const rows[][64], int nrows) {
    if (!out || !headers || ncols <= 0) return;
    for (int i = 0; i < ncols; ++i) fprintf(out, "%-12s", headers[i] ? headers[i] : "");
    fprintf(out, "\n");
    for (int i = 0; i < ncols; ++i) fprintf(out, "------------");
    fprintf(out, "\n");
    for (int r = 0; r < nrows; ++r) {
        if (!rows[r]) continue;
        for (int c = 0; c < ncols; ++c) {
            fprintf(out, "%-12s", rows[r][c] ? rows[r][c] : "");
        }
        fprintf(out, "\n");
    }
}

int emon_rt_ringbuffer_poll(struct ring_buffer* rb, int timeout_ms) {
    if (!rb) return 0;
    return ring_buffer__poll(rb, timeout_ms);
}

void emon_rt_print_bar(const char* label, uint64_t value, uint64_t max_val) {
    const int max_width = 50;
    int width = max_val > 0 ? (int)((double)value / (double)max_val * max_width) : 0;
    if (width < 1 && value > 0) width = 1;
    fprintf(stdout, "  %-24s %10llu |", label, (unsigned long long)value);
    for (int i = 0; i < width; ++i) fputc('#', stdout);
    fputc('\n', stdout);
}
