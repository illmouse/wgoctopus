//go:build linux

package netsetup

import (
	"fmt"
	"net"
	"net/netip"

	"github.com/vishvananda/netlink"
)

// Netlink implements Link using Linux netlink.
type Netlink struct{}

// EnsureUp adds the address if absent, sets a requested MTU, and brings the link up.
func (Netlink) EnsureUp(name, addressCIDR string, mtu int) error {
	l, err := netlink.LinkByName(name)
	if err != nil {
		return err
	}
	p, err := netip.ParsePrefix(addressCIDR)
	if err != nil {
		return err
	}
	addrs, err := netlink.AddrList(l, netlink.FAMILY_ALL)
	if err != nil {
		return err
	}
	found := false
	for _, a := range addrs {
		if a.IPNet.String() == prefixIPNet(p).String() {
			found = true
			break
		}
	}
	if !found {
		if err = netlink.AddrAdd(l, &netlink.Addr{IPNet: prefixIPNet(p)}); err != nil {
			return err
		}
	}
	if mtu > 0 && l.Attrs().MTU != mtu {
		if err = netlink.LinkSetMTU(l, mtu); err != nil {
			return err
		}
	}
	if l.Attrs().Flags&net.FlagUp == 0 {
		return netlink.LinkSetUp(l)
	}
	return nil
}

func prefixIPNet(p netip.Prefix) *net.IPNet {
	return &net.IPNet{IP: net.IP(p.Addr().AsSlice()), Mask: net.CIDRMask(p.Bits(), p.Addr().BitLen())}
}

// Delete removes a link; an absent link is already in the desired state.
func (Netlink) Delete(name string) error {
	l, err := netlink.LinkByName(name)
	if isLinkMissing(err) {
		return nil
	}
	if err != nil {
		return err
	}
	return netlink.LinkDel(l)
}

// Exists reports whether the named link exists.
func (Netlink) Exists(name string) (bool, error) {
	_, err := netlink.LinkByName(name)
	if isLinkMissing(err) {
		return false, nil
	}
	return err == nil, err
}

// DefaultRouteInterface returns the interface selected for an external IPv4 destination.
func (Netlink) DefaultRouteInterface() (string, error) {
	routes, err := netlink.RouteGet(net.ParseIP("1.1.1.1"))
	if err != nil {
		return "", err
	}
	if len(routes) == 0 {
		return "", fmt.Errorf("no default route")
	}
	l, err := netlink.LinkByIndex(routes[0].LinkIndex)
	if err != nil {
		return "", err
	}
	return l.Attrs().Name, nil
}

func isLinkMissing(err error) bool {
	if err == nil {
		return false
	}
	if _, ok := err.(netlink.LinkNotFoundError); ok {
		return true
	}
	return false
}
