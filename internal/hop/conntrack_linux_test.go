//go:build linux

package hop

import (
	"net"
	"testing"
)

func TestUDPOrigDstFilter(t *testing.T) {
	if _, err := udpOrigDstFilter(net.ParseIP("192.0.2.1"), 1234); err != nil {
		t.Fatal(err)
	}
	if _, err := udpOrigDstFilter(nil, 1234); err == nil {
		t.Fatal("expected invalid IP error")
	}
}
