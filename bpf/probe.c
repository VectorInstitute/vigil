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

// ── Helpers ───────────────────────────────────────────────────────────────────

static __always_inline int path_has_prefix(const char *path, const char *prefix, int prefix_len) {
    for (int i = 0; i < prefix_len && i < MAX_PATH_LEN - 1; i++) {
        if (prefix[i] == '\0') return 1; // reached end of prefix — matched
        if (path[i] != prefix[i]) return 0;
    }
    return 1;
}

static __always_inline __u8 check_path_denied(const char path[MAX_PATH_LEN]) {
    // Iterate over denied_path_prefixes map entries.
    // BPF hash iteration isn't available, so the Go side populates a small
    // parallel array map indexed 0..N for linear scan.
    return 0; // stub — real check done via LSM hook in lsm.c
}

static __always_inline void emit_event(struct event *e) {
    struct event *ring_e = bpf_ringbuf_reserve(&events, sizeof(*ring_e), 0);
    if (!ring_e)
        return;
    __builtin_memcpy(ring_e, e, sizeof(*ring_e));
    ring_e->timestamp_ns = bpf_ktime_get_ns();
    bpf_ringbuf_submit(ring_e, 0);
}

// ── Tracepoints ───────────────────────────────────────────────────────────────

// Trace openat(2) — file open
SEC("tracepoint/syscalls/sys_enter_openat")
int trace_openat(struct trace_event_raw_sys_enter *ctx) {
    struct event e = {};
    e.event_type = EVENT_FILE_OPEN;
    e.action     = ACTION_ALLOW; // LSM hook will override to BLOCK if needed

    e.pid  = bpf_get_current_pid_tgid() >> 32;
    e.tgid = (__u32)bpf_get_current_pid_tgid();
    bpf_get_current_comm(&e.comm, sizeof(e.comm));

    // ctx->args[1] is the filename pointer for openat
    bpf_probe_read_user_str(e.path, sizeof(e.path), (const void *)ctx->args[1]);

    emit_event(&e);
    return 0;
}

// Trace execve(2) — process spawn
SEC("tracepoint/syscalls/sys_enter_execve")
int trace_execve(struct trace_event_raw_sys_enter *ctx) {
    struct event e = {};
    e.event_type = EVENT_EXEC;
    e.action     = ACTION_ALLOW;

    e.pid  = bpf_get_current_pid_tgid() >> 32;
    e.tgid = (__u32)bpf_get_current_pid_tgid();
    bpf_get_current_comm(&e.comm, sizeof(e.comm));
    bpf_probe_read_user_str(e.path, sizeof(e.path), (const void *)ctx->args[0]);

    emit_event(&e);
    return 0;
}

// Trace connect(2) — outbound network connection
SEC("tracepoint/syscalls/sys_enter_connect")
int trace_connect(struct trace_event_raw_sys_enter *ctx) {
    struct event e = {};
    e.event_type = EVENT_NET_CONNECT;
    e.action     = ACTION_ALLOW;

    e.pid  = bpf_get_current_pid_tgid() >> 32;
    e.tgid = (__u32)bpf_get_current_pid_tgid();
    bpf_get_current_comm(&e.comm, sizeof(e.comm));

    // ctx->args[1] is struct sockaddr * (user pointer, no __user annotation needed for BPF)
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
