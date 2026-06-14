// uprobe on SSL_write / SSL_read. On entry we see the plaintext buffer and
// length (args to the libssl call). Copy a bounded slice into a ring buffer
// event tagged with pid, a synthetic fd placeholder, direction, and ktime.
// SPIKE SCOPE: fd is not resolved here (it needs the SSL* -> fd map); the
// spike only needs to prove plaintext capture. fd resolution is a v1 task.
// BTF-less include style: this program touches no kernel structs (only
// function args + basic helpers), so it needs neither vmlinux.h nor a
// kernel /sys/kernel/btf/vmlinux. Works on minimal kernels (e.g. Docker
// Desktop linuxkit) as well as BTF-enabled ones.
#include <linux/types.h>
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
// asm/ptrace.h defines `struct user_pt_regs` (arm64) / `struct pt_regs`,
// which bpf_tracing.h's PT_REGS_PARM macros need. With vmlinux.h these come
// from kernel BTF; BTF-less we supply them from the uapi header. Must precede
// bpf_tracing.h.
#include <asm/ptrace.h>
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
    /* Mask only (no prior clamp): a clamp lets clang prove the mask
       redundant and elide it, leaving a size the old verifier can't bound.
       num>0 here (guarded above); &(MAX_DATA-1) gives a provable [0,1023]. */
    __u32 n = num & (MAX_DATA - 1);
    e->len = n;
    bpf_probe_read_user(&e->data, n, buf);
    bpf_ringbuf_submit(e, 0);
    return 0;
}

// int SSL_write(SSL *ssl, const void *buf, int num);
SEC("uprobe/SSL_write")
int BPF_KPROBE(probe_ssl_write, void *ssl, void *buf, int num) {
    return emit(buf, num, 0);
}

// int SSL_write_ex(SSL *ssl, const void *buf, size_t num, size_t *written);
// OpenSSL 3.x clients (incl. CPython 3.10) use this instead of SSL_write.
// buf=PARM2, num=PARM3 (size_t); emit masks the length so the int param is fine.
SEC("uprobe/SSL_write_ex")
int BPF_KPROBE(probe_ssl_write_ex, void *ssl, void *buf, __u64 num) {
    return emit(buf, num, 0);
}

// int SSL_read(SSL *ssl, void *buf, int num);
// NOTE: at uprobe entry of SSL_read, buf is not yet filled. For the spike we
// capture writes (request body) as the primary proof; reads require a uretprobe.
// A uretprobe variant is added only if write-capture succeeds (see findings).
SEC("uprobe/SSL_read")
int BPF_KPROBE(probe_ssl_read, void *ssl, void *buf, int num) {
    return 0; // placeholder; request-body capture is the spike's bar
}

char LICENSE[] SEC("license") = "GPL";
