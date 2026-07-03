// =====================================================================
// syscall_latency_native.c —— 原生eBPF C用户态加载器
// =====================================================================
//
// 功能说明：
// 1. 加载并挂载BPF程序
// 2. 处理ring buffer事件（延迟超过100us的系统调用）
// 3. 每秒打印聚合统计
// 4. Ctrl+C退出时打印最终报告
//
// 用于对比Emon DSL的开发效率
// =====================================================================

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <time.h>
#include <errno.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "syscall_latency_native.skel.h"  // 由bpftool gen skeleton生成

// =====================================================================
// 全局变量
// =====================================================================

static volatile bool exiting = false;
static struct ring_buffer *rb = NULL;
static int count_map_fd = -1;

// =====================================================================
// 数据结构定义（与内核态保持一致）
// =====================================================================

#define COMM_LEN 16

struct agg_key {
    char comm[COMM_LEN];
    int pid;
};

struct latency_event {
    unsigned long long time;
    char syscall[COMM_LEN];
    int pid;
    char comm[COMM_LEN];
    unsigned long long latency;
};

// =====================================================================
// 信号处理：Ctrl+C退出
// =====================================================================

static void sig_handler(int sig)
{
    exiting = true;
}

// =====================================================================
// Ring Buffer事件回调函数
// =====================================================================

static int handle_event(void *ctx, void *data, size_t len)
{
    struct latency_event *e = (struct latency_event *)data;
    
    // 转换延迟为微秒（us）
    double latency_us = e->latency / 1000.0;
    
    // 格式化时间
    time_t t = time(NULL);
    struct tm *tm_info = localtime(&t);
    char time_buf[32];
    strftime(time_buf, sizeof(time_buf), "%H:%M:%S", tm_info);
    
    // 打印事件信息
    printf("[%s] PID=%d COMM=%s SYSCALL=%s LATENCY=%.2f us\n",
           time_buf, e->pid, e->comm, e->syscall, latency_us);
    
    return 0;
}

// =====================================================================
// 打印聚合统计Map
// =====================================================================

static void print_count_map(void)
{
    struct agg_key key = {};
    struct agg_key next_key = {};
    unsigned long long value;
    
    printf("\n=== 系统调用延迟统计 ===\n");
    printf("%-16s %-8s %s\n", "COMM", "PID", "COUNT");
    printf("----------------------------------------\n");
    
    // 遍历所有键值对
    while (bpf_map_get_next_key(count_map_fd, &key, &next_key) == 0) {
        if (bpf_map_lookup_elem(count_map_fd, &next_key, &value) == 0) {
            printf("%-16s %-8d %llu\n", next_key.comm, next_key.pid, value);
        }
        key = next_key;
    }
    
    printf("\n");
}

// =====================================================================
// 定时打印线程（每1秒）
// =====================================================================

static void periodic_print(void)
{
    print_count_map();
}

// =====================================================================
// 主函数
// =====================================================================

int main(int argc, char **argv)
{
    struct syscall_latency_native_bpf *skel;
    int err;
    
    // -----------------------------------------------------------------
    // 1. 设置信号处理
    // -----------------------------------------------------------------
    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);
    
    // -----------------------------------------------------------------
    // 2. 打开并加载BPF skeleton
    // -----------------------------------------------------------------
    skel = syscall_latency_native_bpf__open();
    if (!skel) {
        fprintf(stderr, "Failed to open BPF skeleton\n");
        return 1;
    }
    
    err = syscall_latency_native_bpf__load(skel);
    if (err) {
        fprintf(stderr, "Failed to load BPF skeleton: %d\n", err);
        goto cleanup;
    }
    
    // -----------------------------------------------------------------
    // 3. 挂载BPF程序
    // -----------------------------------------------------------------
    err = syscall_latency_native_bpf__attach(skel);
    if (err) {
        fprintf(stderr, "Failed to attach BPF skeleton: %d\n", err);
        goto cleanup;
    }
    
    // -----------------------------------------------------------------
    // 4. 获取count_map的fd
    // -----------------------------------------------------------------
    count_map_fd = bpf_map__fd(skel->maps.count_map);
    if (count_map_fd < 0) {
        fprintf(stderr, "Failed to get count_map fd\n");
        err = 1;
        goto cleanup;
    }
    
    // -----------------------------------------------------------------
    // 5. 设置ring buffer回调
    // -----------------------------------------------------------------
    rb = ring_buffer__new(bpf_map__fd(skel->maps.events), handle_event, NULL, NULL);
    if (!rb) {
        fprintf(stderr, "Failed to create ring buffer\n");
        err = 1;
        goto cleanup;
    }
    
    // -----------------------------------------------------------------
    // 6. 主循环：轮询事件 + 定时打印
    // -----------------------------------------------------------------
    printf("系统调用延迟监控已启动...\n");
    printf("监控目标: read, write, openat\n");
    printf("过滤条件: PID > 0\n");
    printf("延迟阈值: 100 us\n");
    printf("按 Ctrl+C 退出并查看最终报告\n\n");
    
    time_t last_print = time(NULL);
    
    while (!exiting) {
        // 轮询ring buffer事件（超时100ms）
        err = ring_buffer__poll(rb, 100);
        if (err < 0 && err != -EINTR) {
            fprintf(stderr, "Error polling ring buffer: %d\n", err);
            break;
        }
        
        // 每秒打印一次统计
        time_t now = time(NULL);
        if (now - last_print >= 1) {
            periodic_print();
            last_print = now;
        }
    }
    
    // -----------------------------------------------------------------
    // 7. 退出时打印最终报告
    // -----------------------------------------------------------------
    printf("\n=== 最终统计报告 ===\n");
    print_count_map();
    
cleanup:
    // -----------------------------------------------------------------
    // 8. 清理资源
    // -----------------------------------------------------------------
    ring_buffer__free(rb);
    syscall_latency_native_bpf__destroy(skel);
    
    return err != 0 ? 1 : 0;
}