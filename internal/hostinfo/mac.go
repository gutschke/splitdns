package hostinfo

import (
	"encoding/binary"
	"net"
	"net/netip"
	"sync"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

// EUI64MAC extracts the hardware address embedded in a SLAAC EUI-64 IPv6 address (the
// interface id has ff:fe in the middle and the U/L bit flipped). This is PASSIVE — the MAC
// falls straight out of an address we already hold, and it works across routed subnets where
// the neighbor table would not. Returns false for IPv4, privacy/temporary addresses, and
// manually-set interface ids.
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

// neighborTableFn is the neighbor-table source (overridable in tests); neighborNow is the
// clock. The table (ARP for IPv4, ND for IPv6) is cached briefly so a burst of lookups reads
// it once, not once per address.
var (
	neighborTableFn = netlinkNeighbors
	neighborNow     = time.Now

	neighMu      sync.Mutex
	neighCache   map[netip.Addr]net.HardwareAddr
	neighFetched time.Time
)

const neighborTTL = 5 * time.Second

// NeighborMAC returns the MAC the kernel has cached for ip — ARP for IPv4, ND for IPv6 (so a
// privacy IPv6 address resolves once the neighbor entry exists). ok=false if the entry is
// absent or in an unusable state. Same-L2-segment only, by ARP/ND's nature.
func NeighborMAC(ip netip.Addr) (net.HardwareAddr, bool) {
	ip = ip.Unmap()
	neighMu.Lock()
	defer neighMu.Unlock()
	if neighCache == nil || neighborNow().Sub(neighFetched) > neighborTTL {
		neighCache = neighborTableFn()
		neighFetched = neighborNow()
	}
	mac, ok := neighCache[ip]
	return mac, ok
}

// netlinkNeighbors dumps the kernel neighbor cache as ip->MAC, keeping only entries in a
// usable state (reachable/stale/delay/probe/permanent). Empty map on any error.
func netlinkNeighbors() map[netip.Addr]net.HardwareAddr {
	out := map[netip.Addr]net.HardwareAddr{}
	data, err := syscall.NetlinkRIB(unix.RTM_GETNEIGH, unix.AF_UNSPEC)
	if err != nil {
		return out
	}
	msgs, err := syscall.ParseNetlinkMessage(data)
	if err != nil {
		return out
	}
	const usable = unix.NUD_REACHABLE | unix.NUD_STALE | unix.NUD_DELAY | unix.NUD_PROBE | unix.NUD_PERMANENT
	for i := range msgs {
		m := &msgs[i]
		if m.Header.Type != unix.RTM_NEWNEIGH || len(m.Data) < unix.SizeofNdMsg {
			continue
		}
		state := binary.LittleEndian.Uint16(m.Data[8:10]) // ndmsg.ndm_state
		if state&usable == 0 {
			continue
		}
		var ip netip.Addr
		var mac net.HardwareAddr
		for _, a := range parseRtAttrs(m.Data[unix.SizeofNdMsg:]) {
			switch a.typ {
			case unix.NDA_DST:
				if x, ok := netip.AddrFromSlice(a.val); ok {
					ip = x.Unmap()
				}
			case unix.NDA_LLADDR:
				if len(a.val) == 6 && !isZeroMAC(net.HardwareAddr(a.val)) {
					mac = net.HardwareAddr(append([]byte(nil), a.val...))
				}
			}
		}
		if ip.IsValid() && mac != nil {
			out[ip] = mac
		}
	}
	return out
}

type rtAttr struct {
	typ uint16
	val []byte
}

// parseRtAttrs walks a run of netlink rtattr TLVs (u16 len, u16 type, value; 4-byte aligned).
func parseRtAttrs(b []byte) []rtAttr {
	var out []rtAttr
	for len(b) >= 4 {
		alen := binary.LittleEndian.Uint16(b[0:2])
		atyp := binary.LittleEndian.Uint16(b[2:4])
		if alen < 4 || int(alen) > len(b) {
			break
		}
		out = append(out, rtAttr{typ: atyp, val: b[4:alen]})
		adv := (int(alen) + 3) &^ 3
		if adv <= 0 || adv > len(b) {
			break
		}
		b = b[adv:]
	}
	return out
}

func isZeroMAC(mac net.HardwareAddr) bool {
	for _, b := range mac {
		if b != 0 {
			return false
		}
	}
	return true
}
