package mdns

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/user"
	"strconv"
	"time"

	"golang.org/x/sys/unix"
)

// maxNotifyMsg bounds a single notify message so a peer cannot stream unbounded
// bytes into the parser. A real announcement is a few hundred bytes.
const maxNotifyMsg = 64 * 1024

// readDeadline bounds how long a connected peer may take to deliver its message.
const notifyReadDeadline = 2 * time.Second

// acceptHeartbeat bounds each Accept so an otherwise-idle worker ticks progress for the
// supervisor's stall detector well within its minutes-long ceiling. A var so tests can
// shrink it.
var acceptHeartbeat = 30 * time.Second

// NotifySocket is the authenticated local DDNS-trigger channel (D7): a unix-domain
// socket that splitdns-notify(8) connects to. Every accepted connection is
// SO_PEERCRED-checked, and only a packet from an allowed peer uid is fed to the
// Source as a TRUSTED announcement (so it may move a Cloudflare record). The socket
// file is created mode 0660 and removed on Close, so filesystem ownership is the
// first gate and the peer-cred check is defense-in-depth.
type NotifySocket struct {
	src      *Source
	ln       *net.UnixListener
	path     string
	allowUID func(uint32) bool
	log      func(string)

	// Group-based authorization (optional; see WithGroups). groups maps an allowed gid
	// to its name (for the audit log). A peer whose uid is a member of any of these
	// groups may trigger DDNS, in addition to the allowUID set — no shared key needed.
	// mode is the socket permission; groupsOf resolves a uid to its gids (a test seam,
	// nil => lookupPeerGroups).
	groups   map[uint32]string
	mode     os.FileMode
	groupsOf func(uint32) ([]uint32, error)
}

// ListenNotify creates the socket at path feeding accepted announcements into src.
// allowUID reports whether a peer uid may inject announcements (callers always allow
// root + the daemon uid). log may be nil. A stale socket file at path is removed
// first.
func ListenNotify(path string, src *Source, allowUID func(uint32) bool, log func(string)) (*NotifySocket, error) {
	if log == nil {
		log = func(string) {}
	}
	if allowUID == nil {
		allowUID = func(uint32) bool { return false }
	}
	// Remove a stale socket from a previous run; ignore "not exist".
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return nil, fmt.Errorf("notify: stale socket %q: %w", path, err)
	}
	ln, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		return nil, fmt.Errorf("notify: listen %q: %w", path, err)
	}
	// 0660: owner + group (splitdns) read/write; the peer-cred check narrows further.
	if err := os.Chmod(path, 0o660); err != nil {
		ln.Close()
		return nil, fmt.Errorf("notify: chmod %q: %w", path, err)
	}
	return &NotifySocket{src: src, ln: ln, path: path, allowUID: allowUID, log: log, mode: 0o660}, nil
}

// WithGroups authorizes members of the given groups (gid -> name) to trigger DDNS via
// the socket, in addition to the always-allowed allowUID set — no shared key, no daemon
// group membership. It stamps a POSIX ACL granting those groups rw so the KERNEL permits
// their connect(), and (when mode != 0) sets the socket permission. A filesystem without
// ACL support is logged and tolerated: the socket then stays restricted to its
// owner/group + allowUID (DNS is unaffected). Returns n for chaining; call before Run.
func (n *NotifySocket) WithGroups(groups map[uint32]string, mode os.FileMode) *NotifySocket {
	n.groups = groups
	if mode != 0 {
		if err := os.Chmod(n.path, mode); err != nil {
			n.log(fmt.Sprintf("notify: chmod %q to %o: %v", n.path, mode, err))
		} else {
			n.mode = mode
		}
	}
	if len(groups) > 0 {
		gids := make([]uint32, 0, len(groups))
		for g := range groups {
			gids = append(gids, g)
		}
		if err := setSocketGroupACL(n.path, gids, n.mode); err != nil {
			if errors.Is(err, errNoACL) {
				n.log(fmt.Sprintf("notify: %q filesystem lacks POSIX ACL support; notify_groups NOT applied "+
					"(socket stays owner/group + notify_uids only)", n.path))
			} else {
				n.log(fmt.Sprintf("notify: set group ACL on %q: %v", n.path, err))
			}
		}
	}
	return n
}

// authorized reports whether a connecting peer uid may inject a trusted announcement:
// it is in the allowUID set (root / daemon / notify_uids), or it is a member of one of
// the configured notify groups. The ACL is the kernel's connect gate; this membership
// re-check is the authorization (and would still reject a non-member even if the ACL
// were somehow loosened). Group membership is resolved from the local group database.
func (n *NotifySocket) authorized(uid uint32) bool {
	if n.allowUID(uid) {
		return true
	}
	if len(n.groups) == 0 {
		return false
	}
	resolve := n.groupsOf
	if resolve == nil {
		resolve = lookupPeerGroups
	}
	gids, err := resolve(uid)
	if err != nil {
		n.log(fmt.Sprintf("notify: group lookup for uid %d: %v", uid, err))
		return false
	}
	for _, g := range gids {
		if name, ok := n.groups[g]; ok {
			n.log(fmt.Sprintf("notify: accepted uid %d via group %s", uid, name))
			return true
		}
	}
	return false
}

// lookupPeerGroups returns the gids a uid belongs to, read from the local group
// database. With CGO disabled (this project's build) os/user uses the pure-Go reader of
// /etc/passwd + /etc/group, so it sees local groups (the service accounts notify_groups
// targets); it does not resolve LDAP/SSS-backed groups.
func lookupPeerGroups(uid uint32) ([]uint32, error) {
	u, err := user.LookupId(strconv.FormatUint(uint64(uid), 10))
	if err != nil {
		return nil, err
	}
	ids, err := u.GroupIds()
	if err != nil {
		return nil, err
	}
	out := make([]uint32, 0, len(ids))
	for _, s := range ids {
		if g, err := strconv.ParseUint(s, 10, 32); err == nil {
			out = append(out, uint32(g))
		}
	}
	return out, nil
}

// Run accepts connections until ctx is cancelled. It implements the supervisor's
// Worker.Run shape: progress (nil-safe) ticks on each accept and on idle.
func (n *NotifySocket) Run(ctx context.Context, progress func()) {
	if progress == nil {
		progress = func() {}
	}
	done := make(chan struct{})
	defer close(done)
	go func() {
		select {
		case <-ctx.Done():
			n.ln.Close() // unblock Accept on shutdown
		case <-done:
			// Run already returned (e.g. listener closed via Close()); don't leak
			// this goroutine waiting on a ctx that may never be cancelled.
		}
	}()
	for {
		// Bound each Accept so an idle socket still wakes periodically to heartbeat. The
		// supervisor restarts a worker that makes no progress for minutes; without this,
		// a notify socket that simply has no traffic looks wedged and gets needlessly
		// restarted (and restarting it is unsafe — main owns the listener).
		_ = n.ln.SetDeadline(time.Now().Add(acceptHeartbeat))
		conn, err := n.ln.AcceptUnix()
		if err != nil {
			// A closed listener / cancelled ctx is TERMINAL — Accept on it fails immediately
			// and forever, so we must return rather than loop back in (the old `continue`
			// here tight-spun, flooding the log). This fires on either shutdown closer: the
			// ctx.Done() goroutine above or NotifySocket.Close(). Checked first so shutdown
			// always wins a race with the idle deadline. Expected, so not logged.
			if errors.Is(err, net.ErrClosed) || ctx.Err() != nil {
				return
			}
			// Idle heartbeat: the per-Accept deadline fired with no connection. Tick progress
			// so the supervisor sees a live worker, then keep accepting.
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				progress()
				continue
			}
			// Unexpected, possibly-transient accept error: log once and pace the retry so a
			// persistent error can never become a hot, log-flooding spin.
			n.log(fmt.Sprintf("notify: accept: %v", err))
			progress()
			select {
			case <-ctx.Done():
				return
			case <-time.After(50 * time.Millisecond):
			}
			continue
		}
		n.handle(conn)
		progress()
	}
}

// handle authenticates one peer and feeds its message to the Source as trusted.
func (n *NotifySocket) handle(conn *net.UnixConn) {
	defer conn.Close()
	uid, err := peerUID(conn)
	if err != nil {
		n.log(fmt.Sprintf("notify: peer-cred: %v", err))
		return
	}
	if !n.authorized(uid) {
		n.log(fmt.Sprintf("notify: REJECTED connection from uid %d (not permitted)", uid))
		return
	}
	conn.SetReadDeadline(time.Now().Add(notifyReadDeadline))
	b, err := io.ReadAll(io.LimitReader(conn, maxNotifyMsg))
	if err != nil {
		n.log(fmt.Sprintf("notify: read from uid %d: %v", uid, err))
		return
	}
	if len(b) == 0 {
		return
	}
	n.src.HandlePacket(b, true) // authenticated peer ⇒ trusted DDNS trigger
}

// Close stops the listener and removes the socket file.
func (n *NotifySocket) Close() error {
	err := n.ln.Close()
	os.Remove(n.path)
	return err
}

// Path returns the socket path (useful for tests with an ephemeral path).
func (n *NotifySocket) Path() string { return n.path }

// peerUID reads the connected peer's uid via SO_PEERCRED on the unix socket fd.
func peerUID(conn *net.UnixConn) (uint32, error) {
	raw, err := conn.SyscallConn()
	if err != nil {
		return 0, err
	}
	var ucred *unix.Ucred
	var cerr error
	if err := raw.Control(func(fd uintptr) {
		ucred, cerr = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
	}); err != nil {
		return 0, err
	}
	if cerr != nil {
		return 0, cerr
	}
	return ucred.Uid, nil
}

// AllowUIDFunc builds the peer-uid predicate: root (0) and the daemon's own uid are
// always allowed, plus any uid in extra.
func AllowUIDFunc(selfUID uint32, extra []int) func(uint32) bool {
	set := map[uint32]bool{0: true, selfUID: true}
	for _, u := range extra {
		if u >= 0 {
			set[uint32(u)] = true
		}
	}
	return func(uid uint32) bool { return set[uid] }
}
