// =====================================================================
// syscall_latency_monitor_loader.c -- Emon DSL 生成的用户态 libbpf 加载器
// 工具名称: syscall_latency_monitor
//
// 编译步骤:
//   1. clang -O2 -g -target bpf -c syscall_latency_monitor.bpf.c -o syscall_latency_monitor.bpf.o
//   2. bpftool gen skeleton syscall_latency_monitor.bpf.o > syscall_latency_monitor.skel.h
//   3. gcc syscall_latency_monitor_loader.c -o syscall_latency_monitor_loader -lbpf -lelf -lz
//
// 本文件由 Emon DSL 编译器自动生成，请勿手动编辑。
// =====================================================================

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <signal.h>
#include <time.h>
#include <errno.h>
#include <sys/resource.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>

#include "syscall_latency_monitor.skel.h"

// ---- Event struct (mirrors BPF side definition) ----
struct event_syscall_latency_monitor {
    unsigned long long time;
    char syscall[16];
    unsigned int pid;
    char comm[16];
    unsigned long long latency;
};


static volatile sig_atomic_t __stop = 0;
static void __sigint_handler(int sig) {
    (void)sig;
    __stop = 1;
}

static struct syscall_latency_monitor_bpf *__skel = NULL;
static struct ring_buffer *__rb = NULL;

static int __bump_memlock_rlimit(void) {
    struct rlimit rlim = {
        .rlim_cur = RLIM_INFINITY,
        .rlim_max = RLIM_INFINITY,
    };
    return setrlimit(RLIMIT_MEMLOCK, &rlim);
}

// Use sigaction instead of signal() to avoid SA_RESTART,
// which prevents Ctrl+C from interrupting sleep().
static void __setup_signals(void) {
    struct sigaction sa = {0};
    sa.sa_handler = __sigint_handler;
    sa.sa_flags = 0;  // no SA_RESTART
    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);
}

// ---- Ring Buffer Event Handler ----
static int __handle_event(void *ctx, void *data, size_t data_sz) {
    (void)ctx;
    const struct event_syscall_latency_monitor *e = data;
    fprintf(stderr, "[syscall_latency_monitor] event (size=%zu):\n", data_sz);
    fprintf(stderr, "  time=%llu\n", (unsigned long long)e->time);
    fprintf(stderr, "  syscall=%s\n", e->syscall);
    fprintf(stderr, "  pid=%llu\n", (unsigned long long)e->pid);
    fprintf(stderr, "  comm=%s\n", e->comm);
    fprintf(stderr, "  latency=%llu\n", (unsigned long long)e->latency);
    return 0;
}

// ---- Options (configurable at startup) ----
static const char *__opt_min_latency = "100us";

// ---- Map dump helpers ----

// Helper: print a key - shows comm-like prefix + hex for binary parts
static void __print_key(const unsigned char *key, int key_size) {
    // Print first 16 bytes as string if they look like a comm name
    int i, str_end = 0;
    for (i = 0; i < key_size && i < 16; i++) {
        if (key[i] == 0) { str_end = i; break; }
        if (key[i] < 32 || key[i] > 126) { str_end = -1; break; }
    }
    if (str_end > 0) {
        fprintf(stdout, "%.*s ", str_end, (const char *)key);
    }
    // Print remaining bytes as hex
    for (i = (str_end > 0 ? 16 : 0); i < key_size && i < 36; i++)
        fprintf(stdout, "%02x", key[i]);
}

// Sum a PERCPU value across all CPUs
static __u64 __percpu_sum(const void *value_ptr, int val_size, int nr_cpus, int offset) {
    __u64 total = 0;
    int cpu;
    const unsigned char *base = (const unsigned char *)value_ptr;
    for (cpu = 0; cpu < nr_cpus; cpu++)
        total += *(__u64 *)(base + cpu * val_size + offset);
    return total;
}


static void __print_map_count(int top_n) {
    if (!__skel) return;
    struct bpf_map *map = __skel->maps.count;
    if (!map) { fprintf(stderr, "map 'count' not found\n"); return; }

    int fd = bpf_map__fd(map);
    if (fd < 0) return;

    int key_size = (int)bpf_map__key_size(map);
    if (key_size <= 0 || key_size > 64) key_size = 64;
    int nr_cpus = libbpf_num_possible_cpus();
    if (nr_cpus <= 0) nr_cpus = 1;
    int val_size = (int)bpf_map__value_size(map);
    if (val_size <= 0) val_size = 8;

    unsigned char key[64];
    unsigned char next_key[64];
    // PERCPU maps need val_size * nr_cpus bytes for lookup_elem.
    // Use stack buffer for small values, heap for large (nr_cpus can be 128+).
    int total_val = val_size * nr_cpus;
    unsigned char stack_buf[4096];
    unsigned char *value_buf = stack_buf;
    int use_heap = 0;
    if (total_val > (int)sizeof(stack_buf)) {
        value_buf = (unsigned char *)malloc(total_val);
        if (!value_buf) {
            fprintf(stderr, "map 'count': malloc(%d) failed\n", total_val);
            return;
        }
        use_heap = 1;
    }
    int buf_size = use_heap ? total_val : (int)sizeof(stack_buf);
    memset(key, 0, sizeof(key));
    memset(next_key, 0, sizeof(next_key));
    memset(value_buf, 0, buf_size);
    int count = 0;

    fprintf(stdout, "\n-- @count --\n");

    int err = bpf_map_get_next_key(fd, NULL, next_key);
    while (err == 0) {
        memcpy(key, next_key, key_size);
        memset(value_buf, 0, buf_size);
        if (bpf_map_lookup_elem(fd, key, value_buf) == 0) {
            count++;
            if (top_n <= 0 || count <= top_n) {
                fprintf(stdout, "  [%4d] key=", count);
                __print_key(key, key_size);
                __u64 val = *(__u64*)value_buf;
                fprintf(stdout, "  val=%llu\n", (unsigned long long)val);
            }
        }
        err = bpf_map_get_next_key(fd, key, next_key);
    }

    if (count == 0)
        fprintf(stdout, "  (empty)\n");
    else
        fprintf(stdout, "  total: %d entries\n", count);

    if (use_heap) free(value_buf);
}


// =====================================================================
// main
// =====================================================================

int main(int argc, char **argv) {
    int err;
    int ret = 0;

    (void)argc; (void)argv;
    const char *min_latency = "100us";

    fprintf(stderr, "[syscall_latency_monitor] Emon DSL monitor starting...\n");

    // ---- Signal handlers ----
    __setup_signals();

    // ---- BPF memory lock limit ----
    if (__bump_memlock_rlimit()) {
        fprintf(stderr, "Warning: failed to increase RLIMIT_MEMLOCK: %s\n", strerror(errno));
    }

    // ---- Load BPF skeleton ----
    __skel = syscall_latency_monitor_bpf__open();
    if (!__skel) {
        fprintf(stderr, "Failed to open BPF skeleton\n");
        return 1;
    }

    // ---- Apply options to BPF program (if needed) ----
    fprintf(stderr, "  option min_latency = %s\n", min_latency);

    // ---- Load BPF programs ----
    err = syscall_latency_monitor_bpf__load(__skel);
    if (err) {
        fprintf(stderr, "Failed to load BPF skeleton: %d\n", err);
        ret = 1;
        goto cleanup;
    }

    // ---- Attach BPF programs ----
    err = syscall_latency_monitor_bpf__attach(__skel);
    if (err) {
        fprintf(stderr, "Failed to attach BPF skeleton: %d\n", err);
        ret = 1;
        goto cleanup;
    }
    fprintf(stderr, "[syscall_latency_monitor] BPF programs loaded and attached.\n");

    // ---- Ring buffer for emit events ----
    __rb = ring_buffer__new(bpf_map__fd(__skel->maps.event_syscall_latency_monitor_rb),
                            __handle_event, NULL, NULL);
    if (!__rb) {
        fprintf(stderr, "Failed to create ring buffer\n");
        ret = 1;
        goto cleanup;
    }

    // ---- begin block ----
    // No begin block

    // ---- Main event loop (every tasks) ----
    fprintf(stderr, "[syscall_latency_monitor] Running (Ctrl+C to stop)...\n");
    while (!__stop) {
        // ---- every task ----
        static time_t __last_tick = 0;
        time_t __now = time(NULL);
        if (__now - __last_tick >= 1) {
            __last_tick = __now;
            fprintf(stdout, "=== 系统调用延迟统计 ===\n");
            __print_map_count(10);
        }
        // Small sleep chunks for Ctrl+C responsiveness
        int __j;
        for (__j = 0; __j < 20 && !__stop; __j++)
            usleep(50000);  // 50ms
        // Poll ring buffer for events
        ring_buffer__poll(__rb, 100);
    }

    // ---- end block ----
    // ---- end block ----
    fprintf(stdout, "=== 最终统计报告 ===\n");
    fprintf(stdout, "  @count\n");


    fprintf(stderr, "[syscall_latency_monitor] Shutting down.\n");

cleanup:
    ring_buffer__free(__rb);
    if (__skel) {
        syscall_latency_monitor_bpf__destroy(__skel);
        __skel = NULL;
    }
    return ret;
}
