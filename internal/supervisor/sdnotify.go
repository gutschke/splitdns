package supervisor

import (
	"net"
	"os"
	"strconv"
	"time"
)

// Notify sends a single sd_notify(3) datagram (e.g. "READY=1", "WATCHDOG=1") to the
// systemd notify socket named by $NOTIFY_SOCKET. When the daemon is not running
// under systemd (the socket is unset) it is a no-op returning nil, so callers need
// no environment check. Abstract sockets ("@…") are supported.
func Notify(state string) error {
	sock := os.Getenv("NOTIFY_SOCKET")
	if sock == "" {
		return nil // not under systemd
	}
	name := sock
	if name[0] == '@' {
		name = "\x00" + name[1:] // Linux abstract namespace
	}
	conn, err := net.DialUnix("unixgram", nil, &net.UnixAddr{Name: name, Net: "unixgram"})
	if err != nil {
		return err
	}
	defer conn.Close()
	_, err = conn.Write([]byte(state))
	return err
}

// NotifyReady tells systemd startup is complete (Type=notify).
func NotifyReady() error { return Notify("READY=1") }

// NotifyWatchdog sends one watchdog keepalive (WatchdogSec).
func NotifyWatchdog() error { return Notify("WATCHDOG=1") }

// WatchdogInterval returns the cadence at which to send keepalives: half of systemd's
// $WATCHDOG_USEC (so a missed cycle still leaves margin). It returns 0 when the
// watchdog is not configured (no $WATCHDOG_USEC, or it is not for this PID).
func WatchdogInterval() time.Duration {
	if pid := os.Getenv("WATCHDOG_PID"); pid != "" && pid != strconv.Itoa(os.Getpid()) {
		return 0 // watchdog env is for a different process
	}
	usec := os.Getenv("WATCHDOG_USEC")
	if usec == "" {
		return 0
	}
	n, err := strconv.ParseInt(usec, 10, 64)
	if err != nil || n <= 0 {
		return 0
	}
	return time.Duration(n) * time.Microsecond / 2
}
