//go:build linux

package hop

import (
	"net"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

// NetlinkConntrack flushes matching UDP entries from the Linux conntrack table.
type NetlinkConntrack struct{}

func (NetlinkConntrack) FlushUDPOrigDst(ip net.IP, port int) (int, error) {
	filter, err := udpOrigDstFilter(ip, port)
	if err != nil {
		return 0, err
	}
	n, err := netlink.ConntrackDeleteFilters(netlink.ConntrackTable, unix.AF_INET, filter)
	return int(n), err
}

func udpOrigDstFilter(ip net.IP, port int) (*netlink.ConntrackFilter, error) {
	var filter netlink.ConntrackFilter
	if err := filter.AddProtocol(17); err != nil {
		return nil, err
	}
	if err := filter.AddIP(netlink.ConntrackOrigDstIP, ip); err != nil {
		return nil, err
	}
	if err := filter.AddPort(netlink.ConntrackOrigDstPort, uint16(port)); err != nil {
		return nil, err
	}
	return &filter, nil
}
