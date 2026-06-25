// SPDX-License-Identifier: Apache-2.0
package localpep

import (
	"errors"
	"fmt"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

// localKey mirrors `struct tex_local_key` in ../bpf/tex_lsm_local.bpf.c
// byte-for-byte (two u64, no padding). cilium/ebpf marshals it in native byte
// order, matching the in-kernel layout on the same host.
type localKey struct {
	CgroupID uint64
	Ino      uint64
}

// Loader owns the loaded GPL LSM object, the attached LSM links, and the two
// control maps. It is the privilege-separated enforcement component: only this
// process (running with CAP_BPF / CAP_MAC_ADMIN on the agent-fleet host, NOT the
// agent) can write the verdict maps. A compromised agent in an enrolled cgroup
// cannot reach these maps, so it cannot grant itself an exemption.
type Loader struct {
	objs  texlocalObjects
	links []link.Link
}

// Open loads the GPL LSM object and attaches every local-action hook. After Open
// the maps are EMPTY, so nothing is governed yet — bit-for-bit inert until a
// cgroup is enrolled and a forbid is added. That is the default-OFF posture.
func Open() (*Loader, error) {
	if err := rlimit.RemoveMemlock(); err != nil {
		return nil, fmt.Errorf("remove memlock: %w", err)
	}
	l := &Loader{}
	if err := loadTexlocalObjects(&l.objs, nil); err != nil {
		return nil, fmt.Errorf("load lsm object: %w", err)
	}
	// Attach every local-action LSM program. AttachLSM installs the program at
	// the kernel MAC boundary; the returned link must be held for the hook to
	// stay active (closing it detaches — see Close / the kill-switch story).
	for name, prog := range map[string]*ebpf.Program{
		"inode_unlink": l.objs.TexInodeUnlink,
		"path_unlink":  l.objs.TexPathUnlink,
	} {
		if prog == nil {
			l.closeLinks()
			l.objs.Close()
			return nil, fmt.Errorf("program %q missing from object", name)
		}
		lnk, err := link.AttachLSM(link.LSMOptions{Program: prog})
		if err != nil {
			l.closeLinks()
			l.objs.Close()
			return nil, fmt.Errorf("attach lsm/%s: %w", name, err)
		}
		l.links = append(l.links, lnk)
	}
	return l, nil
}

// Enroll marks a cgroup as governed by the local PEP. Returns the resolved
// cgroup id (the value the in-kernel hooks match against).
func (l *Loader) Enroll(cgroupPath string) (uint64, error) {
	id, err := CgroupID(cgroupPath)
	if err != nil {
		return 0, err
	}
	if err := l.objs.TexEnrolledCgroups.Put(id, uint8(1)); err != nil {
		return 0, fmt.Errorf("enroll cgroup %d: %w", id, err)
	}
	return id, nil
}

// Forbid adds (cgroup_id, inode) to the in-kernel forbid-set: the enrolled agent
// in that cgroup will be denied the irreversible op on that inode with -EPERM.
func (l *Loader) Forbid(cgroupID, ino uint64) error {
	return l.objs.TexLocalDeny.Put(localKey{CgroupID: cgroupID, Ino: ino}, uint8(1))
}

// Unforbid removes a forbid entry (lifts the deny).
func (l *Loader) Unforbid(cgroupID, ino uint64) error {
	err := l.objs.TexLocalDeny.Delete(localKey{CgroupID: cgroupID, Ino: ino})
	if errors.Is(err, ebpf.ErrKeyNotExist) {
		return nil
	}
	return err
}

// EnrolledCount reports how many cgroups are currently governed (0 == inert).
func (l *Loader) EnrolledCount() (int, error) {
	n := 0
	var key uint64
	var val uint8
	it := l.objs.TexEnrolledCgroups.Iterate()
	for it.Next(&key, &val) {
		n++
	}
	return n, it.Err()
}

// Disarm is the KILL-SWITCH: it un-enrolls every cgroup, so the LSM hooks fire
// for no one and the host is instantly, totally back to ungoverned — without
// detaching the programs (so re-arming is immediate). Returns the count cleared.
// The hooks remain attached but tex_local_verdict() returns 0 for every task
// whose cgroup is no longer enrolled, i.e. everyone.
func (l *Loader) Disarm() (int, error) {
	var key uint64
	var val uint8
	var keys []uint64
	it := l.objs.TexEnrolledCgroups.Iterate()
	for it.Next(&key, &val) {
		keys = append(keys, key)
	}
	if err := it.Err(); err != nil {
		return 0, err
	}
	for i := range keys {
		k := keys[i]
		if err := l.objs.TexEnrolledCgroups.Delete(k); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
			return i, err
		}
	}
	return len(keys), nil
}

func (l *Loader) closeLinks() {
	for _, lnk := range l.links {
		_ = lnk.Close()
	}
	l.links = nil
}

// Close detaches every LSM hook and releases the object. After Close nothing is
// governed (full teardown — the heavier kill-switch). Disarm is the fast path.
func (l *Loader) Close() error {
	l.closeLinks()
	return l.objs.Close()
}
