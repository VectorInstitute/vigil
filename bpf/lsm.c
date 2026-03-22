// go:build ignore
//  LSM BPF hooks — compiled separately, requires CONFIG_BPF_LSM=y and lsm=bpf boot param.
//  These hooks run synchronously BEFORE the syscall completes, enabling true inline blocking.

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
	__type(key, char[MAX_PATH_LEN]);
	__type(value, __u8);
} blocked_paths SEC(".maps");

// Block-list for IPv4 addresses: key = __u32 network byte order, value = 1
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 256);
	__type(key, __u32);
	__type(value, __u8);
} blocked_ipv4 SEC(".maps");

// Per-cpu scratch buffer for normalising the bpf_d_path result.
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, char[MAX_PATH_LEN]);
} path_scratch SEC(".maps");

// watched_pids: shared with probe.c — only enforce against agent process tree.
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 4096);
	__type(key, __u32);
	__type(value, __u8);
} watched_pids __weak SEC(".maps");

// entry_comm: shared with probe.c — detect when lineage filtering is active.
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, char[MAX_COMM_LEN]);
} entry_comm __weak SEC(".maps");

// ── Helpers ───────────────────────────────────────────────────────────────────

// pid_is_watched mirrors the same helper in probe.c.
// When entry_comm is unconfigured (first byte '\0'), all PIDs pass — meaning
// enforcement applies to every process (safe default when no lineage data).
// When entry_comm is set, only PIDs in watched_pids are enforced — so vigil
// only blocks the agent's own process tree, leaving sudo, sshd, etc. alone.
static __always_inline int pid_is_watched(__u32 pid)
{
	__u32 z = 0;
	char *entry = bpf_map_lookup_elem(&entry_comm, &z);
	if (!entry || entry[0] == '\0')
		return 1; // no lineage configured — enforce all (safe default)
	return bpf_map_lookup_elem(&watched_pids, &pid) != NULL;
}

// ── LSM: file_open ────────────────────────────────────────────────────────────

SEC("lsm/file_open")
int BPF_PROG(vigil_file_open, struct file *file)
{
	__u32 pid = bpf_get_current_pid_tgid() >> 32;
	if (!pid_is_watched(pid))
		return 0;

	char path[MAX_PATH_LEN] = {};
	if (bpf_d_path(&file->f_path, path, sizeof(path)) <= 0)
		return 0;

	__u32 z = 0;
	char *key = bpf_map_lookup_elem(&path_scratch, &z);
	if (!key)
		return 0;
	__builtin_memset(key, 0, MAX_PATH_LEN);
	for (int i = 0; i < MAX_PATH_LEN; i++) {
		char c = path[i];
		key[i] = c;
		if (!c)
			break;
	}

	__u8 *blocked = bpf_map_lookup_elem(&blocked_paths, key);
	if (!blocked)
		return 0;

	struct task_struct *task = (struct task_struct *)bpf_get_current_task();

	struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e)
		return -1;
	__builtin_memset(e, 0, sizeof(*e));
	e->timestamp_ns = bpf_ktime_get_ns();
	e->event_type = EVENT_FILE_OPEN;
	e->action = ACTION_BLOCK;
	e->pid = pid;
	e->tgid = (__u32)bpf_get_current_pid_tgid();
	e->ppid = BPF_CORE_READ(task, real_parent, tgid);
	bpf_get_current_comm(&e->comm, sizeof(e->comm));
	__builtin_memcpy(e->path, key, MAX_PATH_LEN);
	bpf_ringbuf_submit(e, 0);

	return -1; // kernel maps -1 → -EPERM for LSM deny
}

// ── LSM: socket_connect ───────────────────────────────────────────────────────

SEC("lsm/socket_connect")
int BPF_PROG(vigil_socket_connect, struct socket *sock, struct sockaddr *address, int addrlen)
{
	__u32 pid = bpf_get_current_pid_tgid() >> 32;
	if (!pid_is_watched(pid))
		return 0;

	if (address->sa_family != AF_INET)
		return 0;

	struct sockaddr_in *sin = (struct sockaddr_in *)address;
	__u32 dest_ip = BPF_CORE_READ(sin, sin_addr.s_addr);

	__u8 *blocked = bpf_map_lookup_elem(&blocked_ipv4, &dest_ip);
	if (!blocked)
		return 0;

	struct task_struct *task = (struct task_struct *)bpf_get_current_task();

	struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e)
		return -1;
	__builtin_memset(e, 0, sizeof(*e));
	e->timestamp_ns = bpf_ktime_get_ns();
	e->event_type = EVENT_NET_CONNECT;
	e->action = ACTION_BLOCK;
	e->pid = pid;
	e->tgid = (__u32)bpf_get_current_pid_tgid();
	e->ppid = BPF_CORE_READ(task, real_parent, tgid);
	e->dest_ip4 = dest_ip;
	e->dest_port = bpf_ntohs(BPF_CORE_READ(sin, sin_port));
	bpf_get_current_comm(&e->comm, sizeof(e->comm));
	bpf_ringbuf_submit(e, 0);

	return -1; // -EPERM
}

// ── LSM: bprm_check_security ─────────────────────────────────────────────────

SEC("lsm/bprm_check_security")
int BPF_PROG(vigil_bprm_check, struct linux_binprm *bprm)
{
	__u32 pid = bpf_get_current_pid_tgid() >> 32;
	if (!pid_is_watched(pid))
		return 0;

	char path[MAX_PATH_LEN] = {};
	if (bpf_d_path(&bprm->file->f_path, path, sizeof(path)) <= 0)
		return 0;

	__u32 z = 0;
	char *key = bpf_map_lookup_elem(&path_scratch, &z);
	if (!key)
		return 0;
	__builtin_memset(key, 0, MAX_PATH_LEN);
	for (int i = 0; i < MAX_PATH_LEN; i++) {
		char c = path[i];
		key[i] = c;
		if (!c)
			break;
	}

	__u8 *blocked = bpf_map_lookup_elem(&blocked_paths, key);
	if (!blocked)
		return 0;

	struct task_struct *task = (struct task_struct *)bpf_get_current_task();

	struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e)
		return -1;
	__builtin_memset(e, 0, sizeof(*e));
	e->timestamp_ns = bpf_ktime_get_ns();
	e->event_type = EVENT_EXEC;
	e->action = ACTION_BLOCK;
	e->pid = pid;
	e->tgid = (__u32)bpf_get_current_pid_tgid();
	e->ppid = BPF_CORE_READ(task, real_parent, tgid);
	bpf_get_current_comm(&e->comm, sizeof(e->comm));
	__builtin_memcpy(e->path, key, MAX_PATH_LEN);
	bpf_ringbuf_submit(e, 0);

	return -1; // -EPERM
}
