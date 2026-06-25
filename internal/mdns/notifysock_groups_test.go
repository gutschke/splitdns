package mdns

import (
	"context"
	"encoding/binary"
	"errors"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// TestAuthorizedGroupSeam unit-tests the authorization decision with an injected
// uid->gids resolver, so it does not depend on the host's group database.
func TestAuthorizedGroupSeam(t *testing.T) {
	mk := func(allowUID func(uint32) bool, groups map[uint32]string, gidsOf func(uint32) ([]uint32, error)) *NotifySocket {
		return &NotifySocket{allowUID: allowUID, groups: groups, groupsOf: gidsOf, log: func(string) {}}
	}
	deny := func(uint32) bool { return false }
	allow1000 := func(u uint32) bool { return u == 1000 }

	// allowUID short-circuits regardless of groups.
	if !mk(allow1000, nil, nil).authorized(1000) {
		t.Error("allowUID match should authorize")
	}
	// Member of an allowed group => authorized.
	in5 := func(uint32) ([]uint32, error) { return []uint32{42, 5, 7}, nil }
	if !mk(deny, map[uint32]string{5: "ops"}, in5).authorized(33) {
		t.Error("member of allowed group should authorize")
	}
	// Not a member of any allowed group => rejected.
	if mk(deny, map[uint32]string{9: "other"}, in5).authorized(33) {
		t.Error("non-member must be rejected")
	}
	// No groups configured and allowUID denies => rejected.
	if mk(deny, nil, in5).authorized(33) {
		t.Error("no groups + deny must reject")
	}
	// A lookup error is fail-closed.
	boom := func(uint32) ([]uint32, error) { return nil, errors.New("nss down") }
	if mk(deny, map[uint32]string{5: "ops"}, boom).authorized(33) {
		t.Error("group lookup error must fail closed")
	}
}

// TestNotifySocketGroupDelivery is a real end-to-end check: allowUID rejects every uid,
// but one of THIS process's actual groups is in notify_groups, so the connection is
// authorized via the (real) lookupPeerGroups path and the announcement fires the trigger.
func TestNotifySocketGroupDelivery(t *testing.T) {
	gids, err := os.Getgroups()
	if err != nil || len(gids) == 0 {
		t.Skip("no supplementary groups to test with")
	}
	mine := uint32(gids[0])

	rec := &changeRec{}
	src := NewSource(rec.fn, nil)
	path := filepath.Join(t.TempDir(), "notify.sock")

	ns, err := ListenNotify(path, src, func(uint32) bool { return false }, nil) // deny all uids
	if err != nil {
		t.Fatalf("ListenNotify: %v", err)
	}
	ns.WithGroups(map[uint32]string{mine: "self"}, 0) // ...but authorize my group
	defer ns.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go ns.Run(ctx, nil)

	c, err := net.Dial("unix", path)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	if _, err := c.Write(announce(t, "edge.local.", "9.9.9.9")); err != nil {
		t.Fatalf("write: %v", err)
	}
	c.Close()

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if rec.count() == 1 && rec.last() == "edge:9.9.9.9" {
			return // authorized via group, delivered as trusted
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("group-authorized announcement did not converge; events=%d", rec.count())
}

// TestNotifySocketGroupRejectsNonMember: a notify_groups entry the caller is NOT in
// does not authorize (and allowUID denies), so nothing is delivered.
func TestNotifySocketGroupRejectsNonMember(t *testing.T) {
	rec := &changeRec{}
	src := NewSource(rec.fn, nil)
	path := filepath.Join(t.TempDir(), "notify.sock")

	ns, err := ListenNotify(path, src, func(uint32) bool { return false }, nil)
	if err != nil {
		t.Fatalf("ListenNotify: %v", err)
	}
	ns.WithGroups(map[uint32]string{65530: "stranger"}, 0) // a gid we are not in
	defer ns.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go ns.Run(ctx, nil)

	c, err := net.Dial("unix", path)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	c.Write(announce(t, "edge.local.", "9.9.9.9"))
	c.Close()

	time.Sleep(200 * time.Millisecond)
	if rec.count() != 0 {
		t.Errorf("non-member must not deliver; got %d events", rec.count())
	}
}

// aclEntry mirrors the packed {tag, perm, id} for decoding in the round-trip test.
type aclEntry struct {
	tag, perm uint16
	id        uint32
}

func decodeACL(b []byte) (uint32, []aclEntry) {
	ver := binary.LittleEndian.Uint32(b[0:])
	var es []aclEntry
	for off := 4; off+8 <= len(b); off += 8 {
		es = append(es, aclEntry{
			tag:  binary.LittleEndian.Uint16(b[off:]),
			perm: binary.LittleEndian.Uint16(b[off+2:]),
			id:   binary.LittleEndian.Uint32(b[off+4:]),
		})
	}
	return ver, es
}

// TestSocketGroupACLRoundTrip proves the kernel accepts our packed ACL (it validates
// and rejects malformed blobs) and that reading it back yields the granted groups.
func TestSocketGroupACLRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "acl.sock")
	l, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer l.Close()
	os.Chmod(path, 0o660)

	want := []uint32{100, 65530}
	if err := setSocketGroupACL(path, want, 0o660); err != nil {
		if errors.Is(err, errNoACL) {
			t.Skip("filesystem has no POSIX ACL support")
		}
		t.Fatalf("setSocketGroupACL: %v", err)
	}

	buf := make([]byte, 512)
	n, err := unix.Getxattr(path, "system.posix_acl_access", buf)
	if err != nil {
		t.Fatalf("getxattr: %v", err)
	}
	ver, entries := decodeACL(buf[:n])
	if ver != aclEAVersion {
		t.Errorf("ACL version = %d, want %d", ver, aclEAVersion)
	}
	gotGroups := map[uint32]uint16{}
	var haveUserObj, haveMask, haveOther bool
	for _, e := range entries {
		switch e.tag {
		case aclTagUser:
			haveUserObj = true
		case aclTagMask:
			haveMask = true
		case aclTagOther:
			haveOther = true
		case aclTagGroup:
			gotGroups[e.id] = e.perm
		}
	}
	if !haveUserObj || !haveMask || !haveOther {
		t.Errorf("ACL missing required entries: userObj=%v mask=%v other=%v", haveUserObj, haveMask, haveOther)
	}
	for _, g := range want {
		if p, ok := gotGroups[g]; !ok || p&aclPermRW != aclPermRW {
			t.Errorf("gid %d: granted=%v perm=%#x, want rw", g, ok, p)
		}
	}
}
