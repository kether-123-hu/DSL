// Emon DSL —— 用户态 libbpf 加载器骨架（文档 5.4.7）
// 本文件提供可复用的加载/卸载/attach 工具函数
// 与生成的 *_loader.c 静态链接，提供公共信号处理和加载工具。
#include <bpf/libbpf.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include "emon/runtime_common.h"

static volatile sig_atomic_t emon_stop = 0;
static void emon_sigint(int sig) {
    (void)sig;
    emon_stop = 1;
}

void emon_rt_install_signal_handler(void) {
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = emon_sigint;
    sa.sa_flags = 0;
    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);
}

int emon_rt_should_stop(void) { return emon_stop; }

// 通用 skeleton 加载 + attach 流程
int emon_rt_open_load_attach(struct bpf_object** out_obj,
                              const char* obj_path) {
    if (!out_obj || !obj_path) return -1;

    struct bpf_object *obj = bpf_object__open(obj_path);
    if (!obj) {
        fprintf(stderr, "[emon_rt] failed to open BPF object: %s\n", obj_path);
        return -1;
    }

    int err = bpf_object__load(obj);
    if (err) {
        fprintf(stderr, "[emon_rt] failed to load BPF object: %d\n", err);
        bpf_object__close(obj);
        return -1;
    }

    // Attach all auto-attachable programs
    struct bpf_program *prog;
    bpf_object__for_each_program(prog, obj) {
        struct bpf_link *link = bpf_program__attach(prog);
        if (!link) {
            fprintf(stderr, "[emon_rt] warning: failed to attach program '%s'\n",
                    bpf_program__name(prog));
        }
    }

    *out_obj = obj;
    fprintf(stderr, "[emon_rt] BPF object loaded and attached: %s\n", obj_path);
    return 0;
}

// 简单 sleep 循环（every 任务的主循环）
int emon_rt_sleep_loop(int interval_sec,
                        int (*tick_cb)(void*), void* ctx,
                        struct ring_buffer* rb) {
    struct timespec ts;
    ts.tv_sec = interval_sec > 0 ? interval_sec : 1;
    ts.tv_nsec = 0;

    int tick_count = 0;
    while (!emon_stop) {
        // 执行周期回调
        if (tick_cb) {
            int ret = tick_cb(ctx);
            if (ret < 0) break;
        }
        tick_count++;

        // Poll ring buffer
        if (rb) {
            ring_buffer__poll(rb, 100);
        }

        // Sleep 方式：使用更细粒度的 sleep 以响应信号
        for (int i = 0; i < interval_sec * 10 && !emon_stop; i++) {
            usleep(100000);  // 100ms
        }
    }

    return tick_count;
}
