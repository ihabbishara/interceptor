// uprobe on SSL_write / SSL_read. On entry we see the plaintext buffer and
// length (args to the libssl call). Copy a bounded slice into a ring buffer
// event tagged with pid, a synthetic fd placeholder, direction, and ktime.
// SPIKE SCOPE: fd is not resolved here (it needs the SSL* -> fd map); the
// spike only needs to prove plaintext capture. fd resolution is a v1 task.
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#define MAX_DATA 1024  // bounded copy; spike only needs to see the marker

struct event {
    __u64 time_ns;
    __u32 pid;
    __u32 len;
    __u8  direction; // 0 = out (write), 1 = in (read)
    __u8  data[MAX_DATA];
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);
} events SEC(".maps");

static __always_inline int emit(void *buf, int num, __u8 dir) {
    if (num <= 0) return 0;
    struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) return 0;
    e->pid = bpf_get_current_pid_tgid() >> 32;
    e->direction = dir;
    e->time_ns = bpf_ktime_get_ns();
    __u32 n = num;
    if (n > MAX_DATA) n = MAX_DATA;
    e->len = n;
    bpf_probe_read_user(&e->data, n, buf);
    bpf_ringbuf_submit(e, 0);
    return 0;
}

// int SSL_write(SSL *ssl, const void *buf, int num);
SEC("uprobe/SSL_write")
int BPF_UPROBE(probe_ssl_write, void *ssl, void *buf, int num) {
    return emit(buf, num, 0);
}

// int SSL_read(SSL *ssl, void *buf, int num);
// NOTE: at uprobe entry of SSL_read, buf is not yet filled. For the spike we
// capture writes (request body) as the primary proof; reads require a uretprobe.
// A uretprobe variant is added only if write-capture succeeds (see findings).
SEC("uprobe/SSL_read")
int BPF_UPROBE(probe_ssl_read, void *ssl, void *buf, int num) {
    return 0; // placeholder; request-body capture is the spike's bar
}

char LICENSE[] SEC("license") = "GPL";
