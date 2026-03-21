//go:build ignore
// LSM BPF hooks — compiled separately, requires CONFIG_BPF_LSM=y and lsm=bpf boot param.
// These hooks run synchronously BEFORE the syscall completes, enabling true inline blocking.

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>
#include "headers/common.h"

char __license[] SEC("license") = "GPL";

// ── Shared maps (must match probe.c definitions) ─────────────────────────────

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);
} events __weak SEC(".maps");

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

// Per-cpu scratch buffer for normalising the bpf_d_path result.
// bpf_d_path writes the string at the END of the on-stack buffer then
// memmoves it to the front, leaving a copy of the string in the tail.
// Using a second on-stack 256-byte buffer would exceed the 512-byte BPF
// stack limit, so we keep the scratch buffer in a per-cpu map instead.
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key,   __u32);
    __type(value, char[MAX_PATH_LEN]);
} path_scratch SEC(".maps");

// ── LSM: file_open ────────────────────────────────────────────────────────────

// Runs before every file open. Returns -EPERM to deny.
// bpf_d_path requires a pointer into kernel memory (not a stack copy),
// so pass &file->f_path directly rather than a BPF_CORE_READ copy.
SEC("lsm/file_open")
int BPF_PROG(vigil_file_open, struct file *file) {
    char path[MAX_PATH_LEN] = {};
    if (bpf_d_path(&file->f_path, path, sizeof(path)) <= 0)
        return 0;

    // bpf_d_path leaves d_path leftovers in the tail of path[].
    // Copy the null-terminated result into a per-cpu scratch buffer so the
    // 256-byte hash key has zeros after the null, matching stored keys.
    __u32 z = 0;
    char *key = bpf_map_lookup_elem(&path_scratch, &z);
    if (!key)
        return 0;
    bpf_probe_read_kernel_str(key, MAX_PATH_LEN, path);

    __u8 *blocked = bpf_map_lookup_elem(&blocked_paths, key);
    if (!blocked)
        return 0;

    struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return -1;
    __builtin_memset(e, 0, sizeof(*e));
    e->timestamp_ns = bpf_ktime_get_ns();
    e->event_type   = EVENT_FILE_OPEN;
    e->action       = ACTION_BLOCK;
    e->pid          = bpf_get_current_pid_tgid() >> 32;
    e->tgid         = (__u32)bpf_get_current_pid_tgid();
    bpf_get_current_comm(&e->comm, sizeof(e->comm));
    __builtin_memcpy(e->path, key, MAX_PATH_LEN);
    bpf_ringbuf_submit(e, 0);

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

    struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return -1;
    __builtin_memset(e, 0, sizeof(*e));
    e->timestamp_ns = bpf_ktime_get_ns();
    e->event_type   = EVENT_NET_CONNECT;
    e->action       = ACTION_BLOCK;
    e->pid          = bpf_get_current_pid_tgid() >> 32;
    e->tgid         = (__u32)bpf_get_current_pid_tgid();
    e->dest_ip4     = dest_ip;
    e->dest_port    = bpf_ntohs(BPF_CORE_READ(sin, sin_port));
    bpf_get_current_comm(&e->comm, sizeof(e->comm));
    bpf_ringbuf_submit(e, 0);

    return -1; // -EPERM
}

// ── LSM: bprm_check_security ─────────────────────────────────────────────────

// Runs before every exec. Returns -EPERM to deny.
// Chain trusted pointer dereferences directly (bprm → file → f_path) so the
// BPF verifier tracks the full chain as trusted_ptr_.  BPF_CORE_READ would
// materialise the pointer via bpf_probe_read_kernel, producing a scalar and
// failing the bpf_d_path type check.
SEC("lsm/bprm_check_security")
int BPF_PROG(vigil_bprm_check, struct linux_binprm *bprm) {
    char path[MAX_PATH_LEN] = {};
    if (bpf_d_path(&bprm->file->f_path, path, sizeof(path)) <= 0)
        return 0;

    // Same tail-cleanup as vigil_file_open: use per-cpu scratch buffer.
    __u32 z = 0;
    char *key = bpf_map_lookup_elem(&path_scratch, &z);
    if (!key)
        return 0;
    bpf_probe_read_kernel_str(key, MAX_PATH_LEN, path);

    __u8 *blocked = bpf_map_lookup_elem(&blocked_paths, key);
    if (!blocked)
        return 0;

    struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return -1;
    __builtin_memset(e, 0, sizeof(*e));
    e->timestamp_ns = bpf_ktime_get_ns();
    e->event_type   = EVENT_EXEC;
    e->action       = ACTION_BLOCK;
    e->pid          = bpf_get_current_pid_tgid() >> 32;
    e->tgid         = (__u32)bpf_get_current_pid_tgid();
    bpf_get_current_comm(&e->comm, sizeof(e->comm));
    __builtin_memcpy(e->path, key, MAX_PATH_LEN);
    bpf_ringbuf_submit(e, 0);

    return -1; // -EPERM
}
