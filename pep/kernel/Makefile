# Build the kernel-floor PEP: eBPF object + Go agent.
#
# Requires (at deploy/build host, NOT in the app repo): clang/llvm >= 14,
# libbpf headers, bpftool (for vmlinux.h), and Go >= 1.22.

BPF_CLANG ?= clang

# Select the BPF target arch from the build host's machine type so the same
# Makefile compiles correctly on an x86_64 build node and inside an arm64 VM.
# clang -target bpf still needs -D__TARGET_ARCH_<arch> for the CO-RE asm/ptrace
# field accessors (libbpf bpf_tracing.h) to pick the right register layout.
# Override BPF_TARGET_ARCH directly to cross-compile (e.g. BPF_TARGET_ARCH=arm64).
UNAME_M := $(shell uname -m)
ifeq ($(UNAME_M),x86_64)
  BPF_TARGET_ARCH ?= x86
else ifeq ($(UNAME_M),aarch64)
  BPF_TARGET_ARCH ?= arm64
else ifeq ($(UNAME_M),arm64)
  BPF_TARGET_ARCH ?= arm64
else
  # Fall back to x86 (the historical default) for unknown hosts; override
  # BPF_TARGET_ARCH if this is wrong for your build node.
  BPF_TARGET_ARCH ?= x86
endif

BPF_CFLAGS ?= -O2 -g -Wall -target bpf -D__TARGET_ARCH_$(BPF_TARGET_ARCH)

.PHONY: all vmlinux bpf generate build clean vm-test

# Surface the resolved arch so build logs/CI show what was actually compiled.
arch-info:
	@echo "BPF target arch: $(BPF_TARGET_ARCH) (uname -m: $(UNAME_M))"

all: build

# Generate vmlinux.h from the running kernel's BTF (CO-RE).
vmlinux:
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > bpf/vmlinux.h

# Compile the eBPF program to a CO-RE object.
bpf: bpf/tex_redirect.bpf.c bpf/vmlinux.h
	$(BPF_CLANG) $(BPF_CFLAGS) -c bpf/tex_redirect.bpf.c -o bpf/tex_redirect.o

# Generate Go bindings (texRedirectObjects, loadTexRedirectObjects) via bpf2go.
# bpf2go drives its own clang, so pass the resolved arch define through to it
# (BPF2GO_FLAGS, consumed by the //go:generate directive in agent/main.go) so the
# embedded object matches the host arch — mirroring the standalone `bpf` target.
generate:
	cd agent && BPF2GO_FLAGS="-D__TARGET_ARCH_$(BPF_TARGET_ARCH)" go generate ./...

build: generate
	cd agent && CGO_ENABLED=0 go build -o ../tex-kernel-pep .

clean:
	rm -f bpf/tex_redirect.o bpf/vmlinux.h agent/texredirect_*.go tex-kernel-pep

# Build + load + verifier + behavior tests inside the Lima VM (see hack/).
# Runs the kernel-half Go tests as root against the running kernel's BTF.
vm-test:
	hack/build-and-test.sh
