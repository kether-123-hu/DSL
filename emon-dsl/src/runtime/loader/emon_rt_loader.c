// Emon DSL —— 用户态 libbpf 加载器骨架（文档 5.4.7）
// 本文件提供可复用的加载/卸载/attach 工具函数
#include <bpf/libbpf.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include "emon/runtime_common.h"

static volatile sig_atomic_t emon_stop = 0;
static void emon_sigint(int) { emon_stop = 1; }

void emon_rt_install_signal_handler(void) {
    struct sigaction sa = {};
    sa.sa_handler = emon_sigint;
    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);
}

int emon_rt_should_stop(void) { return emon_stop; }

// 通用 skeleton 加载器（示例工具用）
int emon_rt_open_load_attach(struct bpf_object** out_obj) {
    (void)out_obj;
    fprintf(stderr, "[emon_rt] skeleton loader: linking with libbpf\n");
    return 0;
}
