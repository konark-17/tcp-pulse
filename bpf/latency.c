//go:build ignore

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

char __license[] SEC("license") = "Dual MIT/GPL";

// Event struct transferred from kernel space to user space
struct event {
    __u32 pid;
    __u32 saddr;
    __u32 daddr;
    __u16 sport;
    __u16 dport;
    __u32 oldstate;
    __u32 newstate;
};

const struct event *unused __attribute__((unused));

// Ring buffer map for zero-copy event streaming
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024); // 256 KB buffer
} events SEC(".maps");

// Trace TCP state changes across the kernel
SEC("tracepoint/sock/inet_sock_set_state")
int trace_inet_sock_set_state(struct trace_event_raw_inet_sock_set_state *ctx) {
    // Filter for IPv4 TCP traffic (protocol 6)
    if (ctx->protocol != 6) {
        return 0;
    }

    // Reserve memory chunk in the ring buffer
    struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) {
        return 0; // Ring buffer saturated, drop event
    }

    e->pid = bpf_get_current_pid_tgid() >> 32;
    e->oldstate = ctx->oldstate;
    e->newstate = ctx->newstate;
    e->sport = ctx->sport;
    e->dport = ctx->dport;

    // Commit event to userspace ring buffer
    bpf_ringbuf_submit(e, 0);
    return 0;
}
