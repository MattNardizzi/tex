# Multi-stage: compile the eBPF object + Go agent, ship a minimal runtime.
# The agent runs privileged in a DaemonSet alongside the enforcement proxy.

FROM golang:1.22-bookworm AS build
RUN apt-get update && apt-get install -y --no-install-recommends \
      clang llvm libbpf-dev linux-headers-generic bpftool make ca-certificates \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /src
COPY . .
# vmlinux.h is generated on the build host from its own BTF; for portability
# CO-RE objects relocate at load time against the target kernel's BTF.
RUN make vmlinux bpf generate \
    && cd agent && CGO_ENABLED=0 go build -o /out/tex-kernel-pep .
RUN cp /src/bpf/tex_redirect.o /out/tex_redirect.o

FROM gcr.io/distroless/static-debian12
COPY --from=build /out/tex-kernel-pep /usr/local/bin/tex-kernel-pep
COPY --from=build /out/tex_redirect.o /etc/tex/tex_redirect.o
ENTRYPOINT ["/usr/local/bin/tex-kernel-pep"]
