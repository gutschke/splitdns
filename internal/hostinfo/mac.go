package hostinfo

import (
	"bufio"
	"net"
	"net/netip"
	"os"
	"strings"
)

// procNetARP is the kernel IPv4 ARP table; overridable in tests.
var procNetARP = "/proc/net/arp"

// EUI64MAC extracts the hardware address embedded in a SLAAC EUI-64 IPv6 address (the
// interface id has ff:fe in the middle and the U/L bit flipped). This is PASSIVE — the MAC
// falls straight out of an address we already hold, and it works across routed subnets where
// ARP would not. Returns false for IPv4, privacy/temporary addresses, and manually-set iids.
func EUI64MAC(ip netip.Addr) (net.HardwareAddr, bool) {
	if !ip.Is6() || ip.Is4In6() {
		return nil, false
	}
	b := ip.As16()
	if b[11] != 0xff || b[12] != 0xfe {
		return nil, false // not an EUI-64 interface id
	}
	mac := net.HardwareAddr{b[8] ^ 0x02, b[9], b[10], b[13], b[14], b[15]}
	if isZeroMAC(mac) {
		return nil, false
	}
	return mac, true
}

// ARPMAC looks up an IPv4 address's MAC in the kernel ARP table (same-L2-segment hosts
// only). Returns false if absent/incomplete. Populate a missing entry first with a caller's
// ping if desired (see the diag layer's gating).
func ARPMAC(ip netip.Addr) (net.HardwareAddr, bool) {
	if !ip.Is4() {
		return nil, false
	}
	f, err := os.Open(procNetARP)
	if err != nil {
		return nil, false
	}
	defer f.Close()
	target := ip.String()
	sc := bufio.NewScanner(f)
	sc.Scan() // header
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		// IP  HWtype  Flags  HWaddr  Mask  Device
		if len(fields) < 4 || fields[0] != target {
			continue
		}
		if fields[2] == "0x0" { // incomplete entry
			return nil, false
		}
		if mac, err := net.ParseMAC(fields[3]); err == nil && !isZeroMAC(mac) {
			return mac, true
		}
		return nil, false
	}
	return nil, false
}

func isZeroMAC(mac net.HardwareAddr) bool {
	for _, b := range mac {
		if b != 0 {
			return false
		}
	}
	return true
}
