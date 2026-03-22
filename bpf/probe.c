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

// SSL events ring buffer: kernel → userspace SSL payload stream
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24); // 16 MB
} ssl_events SEC(".maps");

// ssl_read_args: saves SSL_read buf pointer at entry, keyed by TID
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key,   __u32);  // TID
    __type(value, __u64);  // buf pointer
} ssl_read_args SEC(".maps");

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

// trace_exec_lineage: fires at sys_enter_execve, BEFORE the exec completes.
// We check if the filename's basename (last path component) matches entry_comm.
//
// Using sys_enter_execve instead of sched_process_exec is essential for
// shebang scripts: when the user runs `gemini` (a Node.js script), the kernel
// ultimately execs `/usr/bin/node`, so sched_process_exec fires with comm="node".
// But sys_enter_execve fires with the original filename="/usr/bin/gemini"
// (basename="gemini"), which correctly matches entry_comm.
//
// We add the PID before exec completes, so there is zero window between process
// start and tracking. If the exec fails (rare), the stale entry is cleaned up
// when the process exits via trace_exit_lineage.
SEC("tracepoint/syscalls/sys_enter_execve")
int trace_exec_lineage(struct trace_event_raw_sys_enter *ctx) {
    __u32 z = 0;
    char *entry = bpf_map_lookup_elem(&entry_comm, &z);
    if (!entry || entry[0] == '\0')
        return 0; // lineage filtering disabled

    // Read the filename being exec'd from userspace (ctx->args[0]).
    char path[MAX_PATH_LEN] = {};
    bpf_probe_read_user_str(path, sizeof(path), (const void *)ctx->args[0]);

    // Scan path comparing the last component (basename) against entry_comm.
    // On each '/' we reset; mismatches in a component set e to a sentinel.
    int e = 0;
    for (int i = 0; i < MAX_PATH_LEN; i++) {
        char c = path[i];
        if (c == '\0')
            break;
        if (c == '/') {
            e = 0; // start of new path component — reset
            continue;
        }
        if (e < MAX_COMM_LEN && entry[e] == c)
            e++;
        else
            e = MAX_COMM_LEN; // mismatch in this component
    }
    // Exact basename match: we consumed all of entry_comm and hit end/slash.
    if (e <= 0 || e >= MAX_COMM_LEN || entry[e] != '\0')
        return 0;

    // Filename basename matches entry_comm — add this PID to watched_pids.
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    __u8 one = 1;
    bpf_map_update_elem(&watched_pids, &pid, &one, BPF_ANY);
    return 0;
}

// trace_fork_lineage: fires when a process forks.
// If the parent is in watched_pids, add the child too (inherit membership).
//
// Important: ctx->parent_pid is the TID of the thread that called fork/clone,
// which differs from the TGID for multi-threaded processes (e.g. Node.js worker
// threads). watched_pids stores TGIDs, so we use bpf_get_current_pid_tgid()>>32
// to get the parent TGID regardless of which thread triggered the fork.
SEC("tracepoint/sched/sched_process_fork")
int trace_fork_lineage(struct trace_event_raw_sched_process_fork *ctx) {
    __u32 parent_tgid = bpf_get_current_pid_tgid() >> 32;
    __u8 *watched = bpf_map_lookup_elem(&watched_pids, &parent_tgid);
    if (!watched)
        return 0; // parent not watched — child inherits nothing

    __u32 child_pid = ctx->child_pid;
    __u8 one = 1;
    bpf_map_update_elem(&watched_pids, &child_pid, &one, BPF_ANY);
    return 0;
}

// trace_exit_lineage: fires when a thread or process exits.
// Remove the TGID from watched_pids only when the MAIN thread exits (TID==TGID).
// Worker threads (TID != TGID) exiting must NOT evict the main process — doing
// so would create a security hole where the remaining process is no longer tracked.
SEC("tracepoint/sched/sched_process_exit")
int trace_exit_lineage(void *ctx) {
    __u64 id   = bpf_get_current_pid_tgid();
    __u32 tgid = id >> 32;
    __u32 tid  = (__u32)id;
    if (tgid == tid) // only the main thread's exit means the process is gone
        bpf_map_delete_elem(&watched_pids, &tgid);
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

    struct task_struct *task = (struct task_struct *)bpf_get_current_task();

    struct event e = {};
    e.event_type = EVENT_FILE_OPEN;
    e.action     = ACTION_ALLOW; // LSM hook will override to BLOCK if needed
    e.pid        = pid;
    e.tgid       = (__u32)id;
    e.ppid       = BPF_CORE_READ(task, real_parent, tgid);
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

    struct task_struct *task = (struct task_struct *)bpf_get_current_task();

    struct event e = {};
    e.event_type = EVENT_EXEC;
    e.action     = ACTION_ALLOW;
    e.pid        = pid;
    e.tgid       = (__u32)id;
    e.ppid       = BPF_CORE_READ(task, real_parent, tgid);
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

    struct task_struct *task = (struct task_struct *)bpf_get_current_task();

    struct event e = {};
    e.event_type = EVENT_NET_CONNECT;
    e.action     = ACTION_ALLOW;
    e.pid        = pid;
    e.tgid       = (__u32)id;
    e.ppid       = BPF_CORE_READ(task, real_parent, tgid);
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

// ── SSL/TLS uprobes ───────────────────────────────────────────────────────────

// uprobe_ssl_write: fires at SSL_write entry.
// Captures the plaintext buffer being written (sent to LLM API).
SEC("uprobe")
int uprobe_ssl_write(struct pt_regs *ctx) {
    __u64 id  = bpf_get_current_pid_tgid();
    __u32 pid = id >> 32;
    if (!pid_is_watched(pid))
        return 0;

    void *buf = (void *)PT_REGS_PARM2(ctx);
    int   num = (int)PT_REGS_PARM3(ctx);
    if (num <= 0 || !buf)
        return 0;

    struct task_struct *task = (struct task_struct *)bpf_get_current_task();

    struct ssl_event *e = bpf_ringbuf_reserve(&ssl_events, sizeof(*e), 0);
    if (!e)
        return 0;
    __builtin_memset(e, 0, sizeof(*e));
    e->timestamp_ns = bpf_ktime_get_ns();
    e->pid       = pid;
    e->tgid      = (__u32)id;
    e->ppid      = BPF_CORE_READ(task, real_parent, tgid);
    e->direction = SSL_DIRECTION_SEND;
    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    __u32 to_copy = num < MAX_SSL_BUF ? (__u32)num : MAX_SSL_BUF;
    e->data_len = to_copy;
    bpf_probe_read_user(e->data, to_copy, buf);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

// uprobe_ssl_read_entry: fires at SSL_read entry.
// Saves the user-supplied buffer pointer for use in the return probe.
SEC("uprobe")
int uprobe_ssl_read_entry(struct pt_regs *ctx) {
    __u64 id  = bpf_get_current_pid_tgid();
    __u32 pid = id >> 32;
    if (!pid_is_watched(pid))
        return 0;

    __u32 tid  = (__u32)id;
    __u64 buf  = PT_REGS_PARM2(ctx);
    bpf_map_update_elem(&ssl_read_args, &tid, &buf, BPF_ANY);
    return 0;
}

// uretprobe_ssl_read: fires at SSL_read return.
// Reads the plaintext data that was received (response from LLM API).
SEC("uretprobe")
int uretprobe_ssl_read(struct pt_regs *ctx) {
    __u64 id  = bpf_get_current_pid_tgid();
    __u32 pid = id >> 32;
    __u32 tid  = (__u32)id;

    __u64 *buf_ptr = bpf_map_lookup_elem(&ssl_read_args, &tid);
    if (!buf_ptr)
        return 0;
    __u64 buf = *buf_ptr;
    bpf_map_delete_elem(&ssl_read_args, &tid);

    int retval = (int)PT_REGS_RC(ctx);
    if (retval <= 0 || !buf)
        return 0;

    if (!pid_is_watched(pid))
        return 0;

    struct task_struct *task = (struct task_struct *)bpf_get_current_task();

    struct ssl_event *e = bpf_ringbuf_reserve(&ssl_events, sizeof(*e), 0);
    if (!e)
        return 0;
    __builtin_memset(e, 0, sizeof(*e));
    e->timestamp_ns = bpf_ktime_get_ns();
    e->pid       = pid;
    e->tgid      = (__u32)id;
    e->ppid      = BPF_CORE_READ(task, real_parent, tgid);
    e->direction = SSL_DIRECTION_RECV;
    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    __u32 to_copy = retval < MAX_SSL_BUF ? (__u32)retval : MAX_SSL_BUF;
    e->data_len = to_copy;
    bpf_probe_read_user(e->data, to_copy, (void *)buf);

    bpf_ringbuf_submit(e, 0);
    return 0;
}
