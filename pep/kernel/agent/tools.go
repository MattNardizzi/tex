//go:build tools
// +build tools

// This file exists only to pin the bpf2go code generator as a module
// dependency, so `go mod tidy` records it and its transitive deps in go.sum and
// `go generate` (../Makefile: generate -> go run .../cmd/bpf2go) is
// reproducible. The `tools` build tag is never set for normal builds, so none
// of this is compiled into tex-kernel-pep.
package main

import _ "github.com/cilium/ebpf/cmd/bpf2go"
