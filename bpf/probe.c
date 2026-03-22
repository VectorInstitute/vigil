//go:build ignore
// This file is compiled by the Makefile (clang + bpftool), not by `go build`.

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>
#include "headers/common.h"

char __license[] SEC("license") = "GPL";

// ── Maps ─────────────────────────────────────────────────────────────────────

// Ring buffer: kernel → userspace event stream
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24); // 16 MB
} events SEC(".maps");

// Deny-list: path prefixes to block (populated by Go daemon from profile)
// Key: null-terminated path prefix (up to MAX_PATH_LEN), Value: 1
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 256);
    __type(key,   char[MAX_PATH_LEN]);
    __type(value, __u8);
} denied_path_prefixes SEC(".maps");

// Deny-list: IPv4 addresses to block (populated by Go daemon)
// Key: __u32 in network byte order, Value: 1
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 256);
    __type(key,   __u32);
    __type(value, __u8);
} denied_ipv4 SEC(".maps");

// ── Process lineage maps ──────────────────────────────────────────────────────

// entry_comm[0] holds the agent's root process comm string (e.g. "gemini").
// Written by the Go daemon from profile.entry_comm at startup.
// If entry[0] == '\0', lineage filtering is disabled (watch all PIDs).
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key,   __u32);
    __type(value, char[MAX_COMM_LEN]);
} entry_comm SEC(".maps");

// watched_pids tracks PIDs that belong to the agent's process tree.
// Populated by trace_exec_lineage (entry process) and trace_fork_lineage
// (descendant processes). Cleaned up by trace_exit_lineage.
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key,   __u32); // PID
    __type(value, __u8);  // always 1
} watched_pids SEC(".maps");

// ── Helpers ───────────────────────────────────────────────────────────────────

// pid_is_watched returns 1 if the PID should generate events.
// When entry_comm is unconfigured (first byte '\0'), all PIDs are watched.
// When entry_comm is set, only PIDs in the watched_pids map pass.
static __always_inline int pid_is_watched(__u32 pid) {
    __u32 z = 0;
    char *entry = bpf_map_lookup_elem(&entry_comm, &z);
    if (!entry || entry[0] == '\0')
        return 1; // no lineage filtering — watch all
    return bpf_map_lookup_elem(&watched_pids, &pid) != NULL;
}

static __always_inline void emit_event(struct event *e) {
    struct event *ring_e = bpf_ringbuf_reserve(&events, sizeof(*ring_e), 0);
    if (!ring_e)
        return;
    __builtin_memcpy(ring_e, e, sizeof(*ring_e));
    ring_e->timestamp_ns = bpf_ktime_get_ns();
    bpf_ringbuf_submit(ring_e, 0);
}

// ── Process lineage tracepoints ───────────────────────────────────────────────

// trace_exec_lineage: fires after a successful exec.
// If the new comm matches entry_comm, add this PID to watched_pids.
SEC("tracepoint/sched/sched_process_exec")
int trace_exec_lineage(void *ctx) {
    __u32 z = 0;
    char *entry = bpf_map_lookup_elem(&entry_comm, &z);
    if (!entry || entry[0] == '\0')
        return 0; // lineage filtering disabled

    char comm[MAX_COMM_LEN];
    bpf_get_current_comm(comm, sizeof(comm));

    // Compare comm with entry_comm byte by byte.
    for (int i = 0; i < MAX_COMM_LEN; i++) {
        if (entry[i] != comm[i])
            return 0; // mismatch
        if (entry[i] == '\0')
            break; // matched up to null terminator
    }

    // This process is the entry point — add to watched_pids.
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    __u8 one = 1;
    bpf_map_update_elem(&watched_pids, &pid, &one, BPF_ANY);
    return 0;
}

// trace_fork_lineage: fires when a process forks.
// If the parent is in watched_pids, add the child too (inherit membership).
SEC("tracepoint/sched/sched_process_fork")
int trace_fork_lineage(struct trace_event_raw_sched_process_fork *ctx) {
    __u32 parent_pid = ctx->parent_pid;
    __u8 *watched = bpf_map_lookup_elem(&watched_pids, &parent_pid);
    if (!watched)
        return 0; // parent not watched — child inherits nothing

    __u32 child_pid = ctx->child_pid;
    __u8 one = 1;
    bpf_map_update_elem(&watched_pids, &child_pid, &one, BPF_ANY);
    return 0;
}

// trace_exit_lineage: fires when a process exits.
// Remove the PID from watched_pids to prevent PID reuse false positives.
SEC("tracepoint/sched/sched_process_exit")
int trace_exit_lineage(void *ctx) {
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    bpf_map_delete_elem(&watched_pids, &pid);
    return 0;
}

// ── Observation tracepoints ───────────────────────────────────────────────────

// Trace openat(2) — file open
SEC("tracepoint/syscalls/sys_enter_openat")
int trace_openat(struct trace_event_raw_sys_enter *ctx) {
    __u64 id  = bpf_get_current_pid_tgid();
    __u32 pid = id >> 32;
    if (!pid_is_watched(pid))
        return 0;

    struct event e = {};
    e.event_type = EVENT_FILE_OPEN;
    e.action     = ACTION_ALLOW; // LSM hook will override to BLOCK if needed
    e.pid        = pid;
    e.tgid       = (__u32)id;
    bpf_get_current_comm(&e.comm, sizeof(e.comm));

    // ctx->args[1] is the filename pointer for openat
    bpf_probe_read_user_str(e.path, sizeof(e.path), (const void *)ctx->args[1]);

    emit_event(&e);
    return 0;
}

// Trace execve(2) — process spawn
SEC("tracepoint/syscalls/sys_enter_execve")
int trace_execve(struct trace_event_raw_sys_enter *ctx) {
    __u64 id  = bpf_get_current_pid_tgid();
    __u32 pid = id >> 32;
    if (!pid_is_watched(pid))
        return 0;

    struct event e = {};
    e.event_type = EVENT_EXEC;
    e.action     = ACTION_ALLOW;
    e.pid        = pid;
    e.tgid       = (__u32)id;
    bpf_get_current_comm(&e.comm, sizeof(e.comm));
    bpf_probe_read_user_str(e.path, sizeof(e.path), (const void *)ctx->args[0]);

    emit_event(&e);
    return 0;
}

// Trace connect(2) — outbound network connection
SEC("tracepoint/syscalls/sys_enter_connect")
int trace_connect(struct trace_event_raw_sys_enter *ctx) {
    __u64 id  = bpf_get_current_pid_tgid();
    __u32 pid = id >> 32;
    if (!pid_is_watched(pid))
        return 0;

    struct event e = {};
    e.event_type = EVENT_NET_CONNECT;
    e.action     = ACTION_ALLOW;
    e.pid        = pid;
    e.tgid       = (__u32)id;
    bpf_get_current_comm(&e.comm, sizeof(e.comm));

    // ctx->args[1] is struct sockaddr * (user pointer)
    struct sockaddr sa = {};
    bpf_probe_read_user(&sa, sizeof(sa), (const void *)ctx->args[1]);

    if (sa.sa_family == AF_INET) {
        struct sockaddr_in sin = {};
        bpf_probe_read_user(&sin, sizeof(sin), (const void *)ctx->args[1]);
        e.dest_ip4  = sin.sin_addr.s_addr;
        e.dest_port = bpf_ntohs(sin.sin_port);
        e.is_ipv6   = 0;

        // Check deny list
        __u8 *blocked = bpf_map_lookup_elem(&denied_ipv4, &e.dest_ip4);
        if (blocked)
            e.action = ACTION_BLOCK;

    } else if (sa.sa_family == AF_INET6) {
        struct sockaddr_in6 sin6 = {};
        bpf_probe_read_user(&sin6, sizeof(sin6), (const void *)ctx->args[1]);
        __builtin_memcpy(e.dest_ip6, &sin6.sin6_addr, 16);
        e.dest_port = bpf_ntohs(sin6.sin6_port);
        e.is_ipv6   = 1;
    }

    emit_event(&e);
    return 0;
}
