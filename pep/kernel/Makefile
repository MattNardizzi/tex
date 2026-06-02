# Build the kernel-floor PEP: eBPF object + Go agent.
#
# Requires (at deploy/build host, NOT in the app repo): clang/llvm >= 14,
# libbpf headers, bpftool (for vmlinux.h), and Go >= 1.22.

BPF_CLANG ?= clang
BPF_CFLAGS ?= -O2 -g -Wall -target bpf -D__TARGET_ARCH_x86

.PHONY: all vmlinux bpf generate build clean

all: build

# Generate vmlinux.h from the running kernel's BTF (CO-RE).
vmlinux:
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > bpf/vmlinux.h

# Compile the eBPF program to a CO-RE object.
bpf: bpf/tex_redirect.bpf.c bpf/vmlinux.h
	$(BPF_CLANG) $(BPF_CFLAGS) -c bpf/tex_redirect.bpf.c -o bpf/tex_redirect.o

# Generate Go bindings (texRedirectObjects, loadTexRedirectObjects) via bpf2go.
generate:
	cd agent && go generate ./...

build: generate
	cd agent && CGO_ENABLED=0 go build -o ../tex-kernel-pep .

clean:
	rm -f bpf/tex_redirect.o bpf/vmlinux.h agent/texredirect_*.go tex-kernel-pep
