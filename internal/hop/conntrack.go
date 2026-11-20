package hop

import "net"

// Conntrack removes UDP flows for an original destination.
type Conntrack interface {
	FlushUDPOrigDst(ip net.IP, port int) (deleted int, err error)
}
