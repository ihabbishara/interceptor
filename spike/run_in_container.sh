#!/bin/sh
# Drives the eBPF capture spike inside a privileged ubuntu container.
# NOT committed product code — a harness helper for running Task 6.
# /src = repo mounted READ-ONLY; we build in a writable copy at /work so the
# container (root) can never mutate the host repo. Kernel may lack BTF; the
# BPF program is BTF-less so that's fine.
set -e

echo "=== env ==="
uname -r -m
[ -f /sys/kernel/btf/vmlinux ] && echo "BTF: present" || echo "BTF: missing (BTF-less program, OK)"

echo "=== install toolchain ==="
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq clang llvm libbpf-dev linux-libc-dev \
    python3 python3-requests curl ca-certificates xz-utils >/dev/null
echo "clang $(clang --version | head -1)"
echo "openssl $(python3 -c 'import ssl; print(ssl.OPENSSL_VERSION)')"

echo "=== install Go 1.23 (apt's 1.18 is too old for cilium/ebpf) ==="
GOARCH_DL=$(uname -m | sed 's/aarch64/arm64/;s/x86_64/amd64/')
curl -sSL "https://go.dev/dl/go1.23.4.linux-${GOARCH_DL}.tar.gz" | tar -C /usr/local -xz
export PATH=/usr/local/go/bin:$PATH
export GOFLAGS=-mod=mod
go version

ARCH_TRIPLET=$(dpkg-architecture -qDEB_HOST_MULTIARCH 2>/dev/null || echo aarch64-linux-gnu)
ls -l /usr/lib/$ARCH_TRIPLET/libssl.so.3 2>/dev/null || echo "libssl.so.3: NOT at expected path"

echo "=== copy repo to writable /work (host stays untouched) ==="
mkdir -p /work && cp -a /src/. /work/
cd /work
go mod edit -go=1.23   # only in the copy; lets the ebpf dep resolve

echo "=== build loader (bpf2go BTF-less + go) ==="
go get github.com/cilium/ebpf@latest
BPFARCH=$(uname -m | sed 's/aarch64/arm64/;s/x86_64/x86/')
cd /work/spike/loader
export GOPACKAGE=main   # bpf2go needs this when not run via `go generate`
go run github.com/cilium/ebpf/cmd/bpf2go -cc clang \
  -cflags "-O2 -g -Wall -target bpf -D__TARGET_ARCH_${BPFARCH} -I/usr/include/${ARCH_TRIPLET}" \
  ssl ../bpf/ssl.c
cd /work
go build -tags spike -o /tmp/loader ./spike/loader
echo "loader built"

echo "=== run capture ==="
# cilium/ebpf link.OpenExecutable requires the +x bit; Ubuntu ships libssl 0644.
chmod +x /usr/lib/${ARCH_TRIPLET}/libssl.so.3 2>/dev/null || true
/tmp/loader > /tmp/loader.out 2>&1 &
LPID=$!
sleep 3
python3 /work/spike/target/llm_call.py || echo "target exited non-zero (network?)"
sleep 2
kill $LPID 2>/dev/null || true

echo "=== loader output ==="
cat /tmp/loader.out
echo "=== RESULT ==="
if grep -q "marker=true" /tmp/loader.out; then
  echo "SPIKE_RESULT=CAPTURED"
elif grep -q "RawEvent" /tmp/loader.out; then
  echo "SPIKE_RESULT=PARTIAL (events fired, marker not matched)"
else
  echo "SPIKE_RESULT=NOT_CAPTURED"
fi
