package mdns

import (
	"encoding/binary"
	"errors"
	"os"
	"sort"

	"golang.org/x/sys/unix"
)

// POSIX access-ACL on-disk format (system.posix_acl_access xattr). This lets the
// unprivileged daemon grant rw on the notify socket to MULTIPLE groups — including
// groups it is not itself a member of — which plain chgrp cannot do (chgrp without
// CAP_CHOWN is restricted to a group the caller is a member of). Setting an ACL on a
// file is an owner operation and needs no privilege. Layout: a uint32 version (2)
// followed by fixed 8-byte entries {tag uint16, perm uint16, id uint32}, all
// little-endian. See acl(5) / <linux/posix_acl_xattr.h>.
const (
	aclEAVersion = 2
	aclTagUser   = 0x01 // ACL_USER_OBJ (id = undefined)
	aclTagGroup  = 0x08 // ACL_GROUP (named group, id = gid)
	aclTagGrpObj = 0x04 // ACL_GROUP_OBJ (owning group, id = undefined)
	aclTagMask   = 0x10 // ACL_MASK (caps the named/group perms)
	aclTagOther  = 0x20 // ACL_OTHER (id = undefined)
	aclUndefined = 0xFFFFFFFF
	aclPermRW    = 0x06 // read|write
)

// errNoACL reports that the filesystem cannot store POSIX ACLs (e.g. ENOTSUP). The
// caller degrades gracefully: the socket stays restricted to its owner/group + the
// allowUID set, and group-based triggering is simply unavailable (DNS is unaffected).
var errNoACL = errors.New("filesystem does not support POSIX ACLs")

// buildAccessACL packs an access ACL granting the owner and owning-group the mode's
// own/group bits, every gid in groups rw, OTHER the mode's other bits, and a MASK of
// the mode's group bits (so the granted groups get at most what the group bits allow —
// keep group rw in the mode, e.g. 0660). gids are sorted for a deterministic blob.
func buildAccessACL(groups []uint32, mode os.FileMode) []byte {
	gids := append([]uint32(nil), groups...)
	sort.Slice(gids, func(i, j int) bool { return gids[i] < gids[j] })

	ownerP := uint16(mode>>6) & 7
	groupP := uint16(mode>>3) & 7
	otherP := uint16(mode) & 7

	type ent struct {
		tag, perm uint16
		id        uint32
	}
	entries := []ent{
		{aclTagUser, ownerP, aclUndefined},
		{aclTagGrpObj, groupP, aclUndefined},
	}
	for _, g := range gids {
		entries = append(entries, ent{aclTagGroup, aclPermRW, g})
	}
	// A MASK entry is required whenever named entries are present; set it to the mode's
	// group bits so the file mode and ACL stay consistent.
	entries = append(entries,
		ent{aclTagMask, groupP, aclUndefined},
		ent{aclTagOther, otherP, aclUndefined},
	)

	buf := make([]byte, 4+8*len(entries))
	binary.LittleEndian.PutUint32(buf[0:], aclEAVersion)
	off := 4
	for _, e := range entries {
		binary.LittleEndian.PutUint16(buf[off:], e.tag)
		binary.LittleEndian.PutUint16(buf[off+2:], e.perm)
		binary.LittleEndian.PutUint32(buf[off+4:], e.id)
		off += 8
	}
	return buf
}

// setSocketGroupACL grants each gid rw on the socket at path via a POSIX access ACL, in
// addition to the owner. It returns errNoACL when the filesystem lacks ACL support so
// the caller can warn and carry on. The daemon owns the socket, so this needs no
// privilege and no group membership.
func setSocketGroupACL(path string, gids []uint32, mode os.FileMode) error {
	if mode == 0 {
		mode = 0o660
	}
	err := unix.Setxattr(path, "system.posix_acl_access", buildAccessACL(gids, mode), 0)
	if errors.Is(err, unix.ENOTSUP) || errors.Is(err, unix.EOPNOTSUPP) {
		return errNoACL
	}
	return err
}
