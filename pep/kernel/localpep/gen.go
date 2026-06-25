// SPDX-License-Identifier: Apache-2.0
//
// localpep — userspace loader for the GPL BPF-LSM local-action enforcement leg
// (../bpf/tex_lsm_local.bpf.c). Kept in its own package + binary so it is fully
// isolated from the Apache-2.0 egress floor (agent/): a build or load failure
// here can never regress the working 5-program cgroup egress floor.
//
// The embedded GPL object is licensed per-.o (the LICENSE[] = "GPL" section in
// the .c); this Go code is Apache-2.0 — the two licenses do not mix in one .o,
// which is exactly why this object is separate.
package localpep

// $BPF2GO_FLAGS (set by ../Makefile from the host arch) is appended after "--".
//go:generate sh -c "go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -target bpf texlocal ../bpf/tex_lsm_local.bpf.c -- $BPF2GO_FLAGS"
