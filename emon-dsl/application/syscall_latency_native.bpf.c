// =====================================================================
// syscall_latency_native.bpf.c —— 原生eBPF C内核态程序
// =====================================================================
//
// 功能说明：
// 1. 监控 read/write/openat 三个系统调用
// 2. 过滤 PID > 0 的进程（排除内核进程）
// 3. 按进程名和PID聚合计数
// 4. 输出延迟超过100us的事件
//
// 用于对比Emon DSL的开发效率
// =====================================================================

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

// =====================================================================
// 常量定义
// =====================================================================

#define MIN_LATENCY_NS 100000   // 100us = 100000ns
#define COMM_LEN 16
#define MAX_ENTRIES 10240

// =====================================================================
// 数据结构定义
// =====================================================================

// 聚合Map的键：进程名 + PID
struct agg_key {
    char comm[COMM_LEN];
    u32 pid;
};

// 延迟事件结构（用于ring buffer输出）
struct latency_event {
    u64 time;           // 事件时间戳（纳秒）
    char syscall[COMM_LEN];  // 系统调用名称
    u32 pid;            // 进程ID
    char comm[COMM_LEN];     // 进程名
    u64 latency;        // 延迟（纳秒）
};

// =====================================================================
// BPF Map定义
// =====================================================================

// 聚合统计Map：按进程名+PID统计调用次数
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_ENTRIES);
    __type(key, struct agg_key);
    __type(value, u64);
} count_map SEC(".maps");

// 时间戳Map：记录系统调用开始时间
// 键：PID + TID（u64），值：开始时间戳
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_ENTRIES);
    __type(key, u64);
    __type(value, u64);
} start_time_map SEC(".maps");

// Ring Buffer：用于输出延迟事件到用户态
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);  // 256KB
} events SEC(".maps");

// =====================================================================
// 辅助函数
// =====================================================================

// 获取进程ID（PID）
static inline u32 get_pid(void)
{
    u64 pid_tgid = bpf_get_current_pid_tgid();
    return pid_tgid >> 32;
}

// 获取线程ID（TID）
static inline u32 get_tid(void)
{
    u64 pid_tgid = bpf_get_current_pid_tgid();
    return (u32)pid_tgid;
}

// 获取唯一键（PID + TID）
static inline u64 get_pid_tid_key(void)
{
    return bpf_get_current_pid_tgid();
}

// 更新聚合计数
static inline void update_count(u32 pid, const char *syscall_name)
{
    struct agg_key key = {};
    
    // 填充键
    key.pid = pid;
    bpf_get_current_comm(&key.comm, sizeof(key.comm));
    
    // 查找并更新计数
    u64 *count = bpf_map_lookup_elem(&count_map, &key);
    if (count) {
        (*count)++;
    } else {
        u64 init = 1;
        bpf_map_update_elem(&count_map, &key, &init, BPF_ANY);
    }
}

// 输出延迟事件
static inline void emit_latency_event(u32 pid, const char *syscall_name, u64 latency)
{
    // 过滤：延迟必须超过阈值
    if (latency < MIN_LATENCY_NS) {
        return;
    }
    
    // 从ring buffer申请空间
    struct latency_event *e;
    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) {
        return;
    }
    
    // 填充事件数据
    e->time = bpf_ktime_get_ns();
    e->pid = pid;
    e->latency = latency;
    
    // 设置系统调用名称
    __builtin_memcpy(e->syscall, syscall_name, COMM_LEN);
    
    // 获取进程名
    bpf_get_current_comm(&e->comm, sizeof(e->comm));
    
    // 提交事件
    bpf_ringbuf_submit(e, 0);
}

// =====================================================================
// 系统调用入口探针：记录开始时间
// =====================================================================

SEC("tracepoint/syscalls/sys_enter_read")
int tp_sys_enter_read(struct trace_event_raw_sys_enter *ctx)
{
    u32 pid = get_pid();
    
    // 过滤：PID > 0
    if (pid == 0) {
        return 0;
    }
    
    // 记录开始时间
    u64 start_time = bpf_ktime_get_ns();
    u64 key = get_pid_tid_key();
    bpf_map_update_elem(&start_time_map, &key, &start_time, BPF_ANY);
    
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_write")
int tp_sys_enter_write(struct trace_event_raw_sys_enter *ctx)
{
    u32 pid = get_pid();
    
    // 过滤：PID > 0
    if (pid == 0) {
        return 0;
    }
    
    // 记录开始时间
    u64 start_time = bpf_ktime_get_ns();
    u64 key = get_pid_tid_key();
    bpf_map_update_elem(&start_time_map, &key, &start_time, BPF_ANY);
    
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_openat")
int tp_sys_enter_openat(struct trace_event_raw_sys_enter *ctx)
{
    u32 pid = get_pid();
    
    // 过滤：PID > 0
    if (pid == 0) {
        return 0;
    }
    
    // 记录开始时间
    u64 start_time = bpf_ktime_get_ns();
    u64 key = get_pid_tid_key();
    bpf_map_update_elem(&start_time_map, &key, &start_time, BPF_ANY);
    
    return 0;
}

// =====================================================================
// 系统调用出口探针：计算延迟、更新统计、输出事件
// =====================================================================

SEC("tracepoint/syscalls/sys_exit_read")
int tp_sys_exit_read(struct trace_event_raw_sys_exit *ctx)
{
    u32 pid = get_pid();
    
    // 过滤：PID > 0
    if (pid == 0) {
        return 0;
    }
    
    // 获取开始时间
    u64 key = get_pid_tid_key();
    u64 *start_time = bpf_map_lookup_elem(&start_time_map, &key);
    if (!start_time) {
        return 0;
    }
    
    // 计算延迟
    u64 end_time = bpf_ktime_get_ns();
    u64 latency = end_time - *start_time;
    
    // 删除开始时间记录
    bpf_map_delete_elem(&start_time_map, &key);
    
    // 更新聚合计数
    update_count(pid, "read");
    
    // 输出延迟事件（如果超过阈值）
    emit_latency_event(pid, "read", latency);
    
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_write")
int tp_sys_exit_write(struct trace_event_raw_sys_exit *ctx)
{
    u32 pid = get_pid();
    
    // 过滤：PID > 0
    if (pid == 0) {
        return 0;
    }
    
    // 获取开始时间
    u64 key = get_pid_tid_key();
    u64 *start_time = bpf_map_lookup_elem(&start_time_map, &key);
    if (!start_time) {
        return 0;
    }
    
    // 计算延迟
    u64 end_time = bpf_ktime_get_ns();
    u64 latency = end_time - *start_time;
    
    // 删除开始时间记录
    bpf_map_delete_elem(&start_time_map, &key);
    
    // 更新聚合计数
    update_count(pid, "write");
    
    // 输出延迟事件（如果超过阈值）
    emit_latency_event(pid, "write", latency);
    
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_openat")
int tp_sys_exit_openat(struct trace_event_raw_sys_exit *ctx)
{
    u32 pid = get_pid();
    
    // 过滤：PID > 0
    if (pid == 0) {
        return 0;
    }
    
    // 获取开始时间
    u64 key = get_pid_tid_key();
    u64 *start_time = bpf_map_lookup_elem(&start_time_map, &key);
    if (!start_time) {
        return 0;
    }
    
    // 计算延迟
    u64 end_time = bpf_ktime_get_ns();
    u64 latency = end_time - *start_time;
    
    // 删除开始时间记录
    bpf_map_delete_elem(&start_time_map, &key);
    
    // 更新聚合计数
    update_count(pid, "openat");
    
    // 输出延迟事件（如果超过阈值）
    emit_latency_event(pid, "openat", latency);
    
    return 0;
}