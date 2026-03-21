#pragma once

// Kernel sparse annotations — vmlinux.h may define __user as an address-space
// attribute that clang's BPF target rejects. Force it to empty unconditionally.
#undef  __user
#define __user

// Socket family constants — defined as #defines in <linux/socket.h>,
// not captured by BTF. Force-define unconditionally.
#undef  AF_INET
#undef  AF_INET6
#define AF_INET  2
#define AF_INET6 10

#define MAX_PATH_LEN  256
#define MAX_COMM_LEN  16
#define MAX_ARGV_LEN  128

// Event types must match events.Type in Go
#define EVENT_FILE_OPEN   0
#define EVENT_NET_CONNECT 1
#define EVENT_EXEC        2

// Actions — written into the ring buffer so userspace can log them
#define ACTION_ALLOW 0
#define ACTION_BLOCK 1

struct event {
    __u64 timestamp_ns;
    __u32 pid;
    __u32 tgid;
    __u8  event_type;     // EVENT_*
    __u8  action;         // ACTION_*
    __u8  _pad[2];

    char  comm[MAX_COMM_LEN];

    // FileOpen / Exec
    char  path[MAX_PATH_LEN];

    // NetConnect
    __u32 dest_ip4;       // network byte order
    __u8  dest_ip6[16];
    __u16 dest_port;      // host byte order
    __u8  is_ipv6;
    __u8  _pad2;
};
