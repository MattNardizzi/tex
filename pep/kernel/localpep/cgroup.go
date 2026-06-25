// SPDX-License-Identifier: Apache-2.0
package localpep

import (
	"encoding/binary"
	"fmt"
	"os"

	"golang.org/x/sys/unix"
)

// CgroupID resolves a cgroup v2 directory path to the 64-bit id that the kernel
// helper bpf_get_current_cgroup_id() returns for a task in that cgroup.
//
// The id is the kernfs node id of the cgroup directory. name_to_handle_at(2) on
// the cgroup directory returns a file handle whose first 8 bytes (little-endian)
// are that kernfs id — the same value the BPF helper reports. This is the
// battle-tested resolution used across the eBPF ecosystem (Cilium, Parca,
// Pixie). The loader's enforcement is self-validating: if this id did not match
// what the kernel reports, the deny would never fire and the behavior test would
// fail — so a wrong id is a loud failure, not a silent one.
func CgroupID(path string) (uint64, error) {
	handle, _, err := unix.NameToHandleAt(unix.AT_FDCWD, path, 0)
	if err != nil {
		return 0, fmt.Errorf("name_to_handle_at(%q): %w", path, err)
	}
	b := handle.Bytes()
	if len(b) < 8 {
		return 0, fmt.Errorf("cgroup handle too short (%d bytes) for %q", len(b), path)
	}
	return binary.LittleEndian.Uint64(b[:8]), nil
}

// InodeOf returns the inode number of a path — the subject key the LSM hooks
// match against (the kernel resolves the dentry->inode before the hook, so this
// is the exact object the in-kernel deny compares).
func InodeOf(path string) (uint64, error) {
	var st unix.Stat_t
	if err := unix.Stat(path, &st); err != nil {
		return 0, fmt.Errorf("stat(%q): %w", path, err)
	}
	return uint64(st.Ino), nil
}

// SelfCgroupPath returns the unified (cgroup v2) path for a pid, resolved under
// the cgroup2 mount root. Used by tests/tools to enroll a process's own cgroup.
func SelfCgroupPath(pid int, cgroup2Root string) (string, error) {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/cgroup", pid))
	if err != nil {
		return "", err
	}
	// cgroup v2 line is "0::<path>".
	for _, line := range splitLines(string(data)) {
		if len(line) >= 3 && line[0] == '0' && line[1] == ':' && line[2] == ':' {
			rel := line[3:]
			if rel == "/" {
				return cgroup2Root, nil
			}
			return cgroup2Root + rel, nil
		}
	}
	return "", fmt.Errorf("no cgroup v2 (0::) entry for pid %d", pid)
}

func splitLines(s string) []string {
	var out []string
	start := 0
	for i := 0; i < len(s); i++ {
		if s[i] == '\n' {
			out = append(out, s[start:i])
			start = i + 1
		}
	}
	if start < len(s) {
		out = append(out, s[start:])
	}
	return out
}
