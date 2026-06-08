// Emon DSL —— 用户态事件输出（表格、直方图）
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include "emon/runtime_common.h"

void emon_rt_print_hist(const char* title, const uint64_t* buckets, int n) {
    fprintf(stdout, "-- %s (histogram, %d buckets) --\n", title, n);
    for (int i = 0; i < n; ++i) {
        if (!buckets[i]) continue;
        fprintf(stdout, "  [%2d] %10llu ", i, (unsigned long long)buckets[i]);
        const int bar = (int)(buckets[i] > 200 ? 40 : (int)buckets[i] / 5);
        for (int j = 0; j < bar; ++j) fputc('#', stdout);
        fputc('\n', stdout);
    }
}

void emon_rt_print_table_header(FILE* out,
                                const char* const headers[], int ncols,
                                const char* const rows[][64], int nrows) {
    for (int i = 0; i < ncols; ++i) fprintf(out, "%-12s", headers[i]);
    fprintf(out, "\n");
    for (int i = 0; i < ncols; ++i) fprintf(out, "------------");
    fprintf(out, "\n");
    for (int r = 0; r < nrows; ++r) {
        for (int c = 0; c < ncols; ++c) fprintf(out, "%-12s", rows[r][c]);
        fprintf(out, "\n");
    }
}

int emon_rt_ringbuffer_poll(struct ring_buffer* rb, int timeout_ms) {
    if (!rb) return 0;
    return ring_buffer__poll(rb, timeout_ms);
}
