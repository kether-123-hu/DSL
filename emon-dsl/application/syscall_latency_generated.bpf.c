// =====================================================================
// syscall_latency_monitor.bpf.c —— Emon DSL 生成的 eBPF C 程序
// 工具名称: syscall_latency_monitor
// 编译命令: clang -O2 -g -target bpf -c syscall_latency_monitor.bpf.c -o syscall_latency_monitor.bpf.o
// =====================================================================
//
// 本文件由 Emon DSL 编译器自动生成，请勿手动编辑。
// 源 DSL 语义见项目文档 sections 5.1–5.7。

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

// Composite key: comm, pid
struct key_comm_pid {
    // Packed to ensure consistent key layout
    char comm[16];
    u32 pid;
} __attribute__((packed));

// ---- Latency measurement: entry probe timestamp storage ----

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, __u64);   // pid_tgid
    __type(value, __u64); // timestamp in ns
} __start_time_read SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, __u64);   // pid_tgid
    __type(value, __u64); // timestamp in ns
} __start_time_write SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, __u64);   // pid_tgid
    __type(value, __u64); // timestamp in ns
} __start_time_openat SEC(".maps");

// Event struct: event_syscall_latency_monitor
struct event_syscall_latency_monitor {
    __u64 time;
    char syscall[16];
    __u32 pid;
    char comm[16];
    __u64 latency;
};

// ---- Aggregation Maps ----

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, struct key_comm_pid);
    __type(value, __u64);
} count SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} event_syscall_latency_monitor_rb SEC(".maps");

// =====================================================================
// Probe Functions
// =====================================================================
SEC("tracepoint/syscalls/sys_enter_read")
int syscall_latency_monitor_probe_1(struct trace_event_raw_sys_enter *ctx)
{
    // --- Context extraction ---
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;
    __u32 tid = (__u32)pid_tgid;
    __u64 uid_gid = bpf_get_current_uid_gid();
    __u32 uid = uid_gid;
    __u32 gid = uid_gid >> 32;
    char comm[16];
    bpf_get_current_comm(&comm, sizeof(comm));
    __u64 nsecs = bpf_ktime_get_ns();
    __u32 cpu = bpf_get_smp_processor_id();
    // syscall target: read
    unsigned long syscall_id = BPF_CORE_READ(ctx, id);
    char syscall[16] = "read";
    // Default measure variables (overridden if hook provides them)
    __u64 size = 0;
    __u64 stack = 0;
    // where: (pid > 0)
    if (!((pid > 0))) return 0;
// --- Latency measurement: store entry timestamp ---
__u64 __entry_ts = bpf_ktime_get_ns();
bpf_map_update_elem(&__start_time_read, &pid_tgid, &__entry_ts, BPF_ANY);
    return 0;
}
SEC("tracepoint/syscalls/sys_exit_read")
int syscall_latency_monitor_probe_2(struct trace_event_raw_sys_exit *ctx)
{
    // --- Context extraction ---
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;
    __u32 tid = (__u32)pid_tgid;
    __u64 uid_gid = bpf_get_current_uid_gid();
    __u32 uid = uid_gid;
    __u32 gid = uid_gid >> 32;
    char comm[16];
    bpf_get_current_comm(&comm, sizeof(comm));
    __u64 nsecs = bpf_ktime_get_ns();
    __u32 cpu = bpf_get_smp_processor_id();
    // syscall exit probe: read
    unsigned long syscall_id = BPF_CORE_READ(ctx, id);
    long retval = BPF_CORE_READ(ctx, ret);
    char syscall[16] = "read";
    // Default measure variables (overridden if hook provides them)
    __u64 size = 0;
    __u64 stack = 0;
// --- Latency measurement: compute delta from entry ---
__u64 *__start_ptr = bpf_map_lookup_elem(&__start_time_read, &pid_tgid);
if (!__start_ptr) return 0;
__u64 latency = bpf_ktime_get_ns() - *__start_ptr;
bpf_map_delete_elem(&__start_time_read, &pid_tgid);
    // when: (latency > min_latency)
    if (!((latency > 100000))) return 0;
    // @count = count() keys=[comm, pid]
    static struct key_comm_pid __key_count;
    __builtin_memset(&__key_count, 0, sizeof(__key_count));
    __builtin_memcpy(&__key_count.comm, comm, sizeof(comm));
    __key_count.pid = pid;
    __u64 *__val_count = bpf_map_lookup_elem(&count, &__key_count);
    if (__val_count) {
        (*__val_count)++;
    } else {
        __u64 __one = 1;
        bpf_map_update_elem(&count, &__key_count, &__one, BPF_ANY);
    }
    // emit -> ring buffer
    struct event_syscall_latency_monitor *__ev = bpf_ringbuf_reserve(&event_syscall_latency_monitor_rb, sizeof(struct event_syscall_latency_monitor), 0);
    if (__ev) {
        __ev->time = (nsecs);
        __builtin_memcpy(&__ev->syscall, &(syscall), sizeof(__ev->syscall));
        __ev->pid = (pid);
        __builtin_memcpy(&__ev->comm, &(comm), sizeof(__ev->comm));
        __ev->latency = (latency);
        bpf_ringbuf_submit(__ev, 0);
    }
    return 0;
}
SEC("tracepoint/syscalls/sys_enter_write")
int syscall_latency_monitor_probe_3(struct trace_event_raw_sys_enter *ctx)
{
    // --- Context extraction ---
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;
    __u32 tid = (__u32)pid_tgid;
    __u64 uid_gid = bpf_get_current_uid_gid();
    __u32 uid = uid_gid;
    __u32 gid = uid_gid >> 32;
    char comm[16];
    bpf_get_current_comm(&comm, sizeof(comm));
    __u64 nsecs = bpf_ktime_get_ns();
    __u32 cpu = bpf_get_smp_processor_id();
    // syscall target: write
    unsigned long syscall_id = BPF_CORE_READ(ctx, id);
    char syscall[16] = "write";
    // Default measure variables (overridden if hook provides them)
    __u64 size = 0;
    __u64 stack = 0;
    // where: (pid > 0)
    if (!((pid > 0))) return 0;
// --- Latency measurement: store entry timestamp ---
__u64 __entry_ts = bpf_ktime_get_ns();
bpf_map_update_elem(&__start_time_write, &pid_tgid, &__entry_ts, BPF_ANY);
    return 0;
}
SEC("tracepoint/syscalls/sys_exit_write")
int syscall_latency_monitor_probe_4(struct trace_event_raw_sys_exit *ctx)
{
    // --- Context extraction ---
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;
    __u32 tid = (__u32)pid_tgid;
    __u64 uid_gid = bpf_get_current_uid_gid();
    __u32 uid = uid_gid;
    __u32 gid = uid_gid >> 32;
    char comm[16];
    bpf_get_current_comm(&comm, sizeof(comm));
    __u64 nsecs = bpf_ktime_get_ns();
    __u32 cpu = bpf_get_smp_processor_id();
    // syscall exit probe: write
    unsigned long syscall_id = BPF_CORE_READ(ctx, id);
    long retval = BPF_CORE_READ(ctx, ret);
    char syscall[16] = "write";
    // Default measure variables (overridden if hook provides them)
    __u64 size = 0;
    __u64 stack = 0;
// --- Latency measurement: compute delta from entry ---
__u64 *__start_ptr = bpf_map_lookup_elem(&__start_time_write, &pid_tgid);
if (!__start_ptr) return 0;
__u64 latency = bpf_ktime_get_ns() - *__start_ptr;
bpf_map_delete_elem(&__start_time_write, &pid_tgid);
    // when: (latency > min_latency)
    if (!((latency > 100000))) return 0;
    // @count = count() keys=[comm, pid]
    static struct key_comm_pid __key_count;
    __builtin_memset(&__key_count, 0, sizeof(__key_count));
    __builtin_memcpy(&__key_count.comm, comm, sizeof(comm));
    __key_count.pid = pid;
    __u64 *__val_count = bpf_map_lookup_elem(&count, &__key_count);
    if (__val_count) {
        (*__val_count)++;
    } else {
        __u64 __one = 1;
        bpf_map_update_elem(&count, &__key_count, &__one, BPF_ANY);
    }
    // emit -> ring buffer
    struct event_syscall_latency_monitor *__ev = bpf_ringbuf_reserve(&event_syscall_latency_monitor_rb, sizeof(struct event_syscall_latency_monitor), 0);
    if (__ev) {
        __ev->time = (nsecs);
        __builtin_memcpy(&__ev->syscall, &(syscall), sizeof(__ev->syscall));
        __ev->pid = (pid);
        __builtin_memcpy(&__ev->comm, &(comm), sizeof(__ev->comm));
        __ev->latency = (latency);
        bpf_ringbuf_submit(__ev, 0);
    }
    return 0;
}
SEC("tracepoint/syscalls/sys_enter_openat")
int syscall_latency_monitor_probe_5(struct trace_event_raw_sys_enter *ctx)
{
    // --- Context extraction ---
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;
    __u32 tid = (__u32)pid_tgid;
    __u64 uid_gid = bpf_get_current_uid_gid();
    __u32 uid = uid_gid;
    __u32 gid = uid_gid >> 32;
    char comm[16];
    bpf_get_current_comm(&comm, sizeof(comm));
    __u64 nsecs = bpf_ktime_get_ns();
    __u32 cpu = bpf_get_smp_processor_id();
    // syscall target: openat
    unsigned long syscall_id = BPF_CORE_READ(ctx, id);
    char syscall[16] = "openat";
    // Default measure variables (overridden if hook provides them)
    __u64 size = 0;
    __u64 stack = 0;
    // where: (pid > 0)
    if (!((pid > 0))) return 0;
// --- Latency measurement: store entry timestamp ---
__u64 __entry_ts = bpf_ktime_get_ns();
bpf_map_update_elem(&__start_time_openat, &pid_tgid, &__entry_ts, BPF_ANY);
    return 0;
}
SEC("tracepoint/syscalls/sys_exit_openat")
int syscall_latency_monitor_probe_6(struct trace_event_raw_sys_exit *ctx)
{
    // --- Context extraction ---
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;
    __u32 tid = (__u32)pid_tgid;
    __u64 uid_gid = bpf_get_current_uid_gid();
    __u32 uid = uid_gid;
    __u32 gid = uid_gid >> 32;
    char comm[16];
    bpf_get_current_comm(&comm, sizeof(comm));
    __u64 nsecs = bpf_ktime_get_ns();
    __u32 cpu = bpf_get_smp_processor_id();
    // syscall exit probe: openat
    unsigned long syscall_id = BPF_CORE_READ(ctx, id);
    long retval = BPF_CORE_READ(ctx, ret);
    char syscall[16] = "openat";
    // Default measure variables (overridden if hook provides them)
    __u64 size = 0;
    __u64 stack = 0;
// --- Latency measurement: compute delta from entry ---
__u64 *__start_ptr = bpf_map_lookup_elem(&__start_time_openat, &pid_tgid);
if (!__start_ptr) return 0;
__u64 latency = bpf_ktime_get_ns() - *__start_ptr;
bpf_map_delete_elem(&__start_time_openat, &pid_tgid);
    // when: (latency > min_latency)
    if (!((latency > 100000))) return 0;
    // @count = count() keys=[comm, pid]
    static struct key_comm_pid __key_count;
    __builtin_memset(&__key_count, 0, sizeof(__key_count));
    __builtin_memcpy(&__key_count.comm, comm, sizeof(comm));
    __key_count.pid = pid;
    __u64 *__val_count = bpf_map_lookup_elem(&count, &__key_count);
    if (__val_count) {
        (*__val_count)++;
    } else {
        __u64 __one = 1;
        bpf_map_update_elem(&count, &__key_count, &__one, BPF_ANY);
    }
    // emit -> ring buffer
    struct event_syscall_latency_monitor *__ev = bpf_ringbuf_reserve(&event_syscall_latency_monitor_rb, sizeof(struct event_syscall_latency_monitor), 0);
    if (__ev) {
        __ev->time = (nsecs);
        __builtin_memcpy(&__ev->syscall, &(syscall), sizeof(__ev->syscall));
        __ev->pid = (pid);
        __builtin_memcpy(&__ev->comm, &(comm), sizeof(__ev->comm));
        __ev->latency = (latency);
        bpf_ringbuf_submit(__ev, 0);
    }
    return 0;
}
