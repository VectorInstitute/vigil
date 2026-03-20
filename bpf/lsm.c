//go:build ignore
// LSM BPF hooks — compiled separately, requires CONFIG_BPF_LSM=y and lsm=bpf boot param.
// These hooks run synchronously BEFORE the syscall completes, enabling true inline blocking.

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "headers/common.h"

char __license[] SEC("license") = "GPL";

// ── Shared maps (must match probe.c definitions) ─────────────────────────────

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);
} events SEC(".maps");

// Block-list for file paths: key = exact path string, value = 1
// Populated by the Go daemon from the profile's denied_paths list.
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 512);
    __type(key,   char[MAX_PATH_LEN]);
    __type(value, __u8);
} blocked_paths SEC(".maps");

// Block-list for IPv4 addresses: key = __u32 network byte order, value = 1
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 256);
    __type(key,   __u32);
    __type(value, __u8);
} blocked_ipv4 SEC(".maps");

// ── Helpers ───────────────────────────────────────────────────────────────────

static __always_inline void emit_block(struct event *e) {
    struct event *r = bpf_ringbuf_reserve(&events, sizeof(*r), 0);
    if (!r) return;
    __builtin_memcpy(r, e, sizeof(*r));
    r->timestamp_ns = bpf_ktime_get_ns();
    r->action = ACTION_BLOCK;
    bpf_ringbuf_submit(r, 0);
}

// ── LSM: file_open ────────────────────────────────────────────────────────────

// Runs before every file open. Returns -EPERM to deny.
SEC("lsm/file_open")
int BPF_PROG(vigil_file_open, struct file *file) {
    char path[MAX_PATH_LEN] = {};
    struct path f_path = BPF_CORE_READ(file, f_path);
    bpf_d_path(&f_path, path, sizeof(path));

    __u8 *blocked = bpf_map_lookup_elem(&blocked_paths, path);
    if (!blocked)
        return 0; // allow

    struct event e = {};
    e.event_type = EVENT_FILE_OPEN;
    e.pid  = bpf_get_current_pid_tgid() >> 32;
    e.tgid = (__u32)bpf_get_current_pid_tgid();
    bpf_get_current_comm(&e.comm, sizeof(e.comm));
    __builtin_memcpy(e.path, path, sizeof(path));
    emit_block(&e);

    return -1; // kernel maps -1 → -EPERM for LSM deny
}

// ── LSM: socket_connect ───────────────────────────────────────────────────────

// Runs before every connect(). Returns -EPERM to deny.
SEC("lsm/socket_connect")
int BPF_PROG(vigil_socket_connect, struct socket *sock, struct sockaddr *address, int addrlen) {
    if (address->sa_family != AF_INET)
        return 0; // only IPv4 blocking in MVP

    struct sockaddr_in *sin = (struct sockaddr_in *)address;
    __u32 dest_ip = BPF_CORE_READ(sin, sin_addr.s_addr);

    __u8 *blocked = bpf_map_lookup_elem(&blocked_ipv4, &dest_ip);
    if (!blocked)
        return 0;

    struct event e = {};
    e.event_type = EVENT_NET_CONNECT;
    e.pid      = bpf_get_current_pid_tgid() >> 32;
    e.tgid     = (__u32)bpf_get_current_pid_tgid();
    e.dest_ip4 = dest_ip;
    e.dest_port = bpf_ntohs(BPF_CORE_READ(sin, sin_port));
    bpf_get_current_comm(&e.comm, sizeof(e.comm));
    emit_block(&e);

    return -1; // -EPERM
}

// ── LSM: bprm_check_security ─────────────────────────────────────────────────

// Runs before every exec. Returns -EPERM to deny.
SEC("lsm/bprm_check_security")
int BPF_PROG(vigil_bprm_check, struct linux_binprm *bprm) {
    char path[MAX_PATH_LEN] = {};
    struct path f_path = BPF_CORE_READ(bprm, file, f_path);
    bpf_d_path(&f_path, path, sizeof(path));

    __u8 *blocked = bpf_map_lookup_elem(&blocked_paths, path);
    if (!blocked)
        return 0;

    struct event e = {};
    e.event_type = EVENT_EXEC;
    e.pid  = bpf_get_current_pid_tgid() >> 32;
    e.tgid = (__u32)bpf_get_current_pid_tgid();
    bpf_get_current_comm(&e.comm, sizeof(e.comm));
    __builtin_memcpy(e.path, path, sizeof(path));
    emit_block(&e);

    return -1; // -EPERM
}
