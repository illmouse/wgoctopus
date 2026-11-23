package hop

import (
	"context"
	"errors"
	"net"
	"reflect"
	"strconv"
	"testing"

	"github.com/illmouse/wgoctopus/internal/state"
)

type conntrackFake struct {
	deleted     int
	err         error
	calls       []string
	mutations   *int
	runnerCalls *int
	callAtFlush []int
}

func (c *conntrackFake) FlushUDPOrigDst(ip net.IP, port int) (int, error) {
	if *c.mutations == 0 {
		panic("conntrack flushed before rules were applied")
	}
	c.calls = append(c.calls, ip.String()+":"+strconv.Itoa(port))
	if c.runnerCalls != nil {
		c.callAtFlush = append(c.callAtFlush, *c.runnerCalls)
	}
	return c.deleted, c.err
}

func TestForwarderConntrackFlush(t *testing.T) {
	x := &fake{rules: map[string][][]string{}}
	c := &conntrackFake{deleted: 3, mutations: &x.mutations, runnerCalls: &x.calls}
	deps := Deps{Runner: x, Conntrack: c, IPForwardReader: func() (bool, error) { return true, nil }, AddrChecker: func(string, string) (bool, error) { return true, nil }}
	f := New(deps)
	h := hop()
	// Initial routes may have stale non-NAT entries from traffic before their rules existed.
	initial, err := f.Apply(context.Background(), h)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(initial.AddedRoutes, []int{1000, 1001}) || !reflect.DeepEqual(c.calls, []string{"192.0.2.1:1000", "192.0.2.1:1001"}) || c.callAtFlush[0] != c.callAtFlush[1] {
		t.Fatalf("initial=%+v calls=%v", initial, c.calls)
	}
	next := hop()
	next.Routes[0].BackendIP = "198.51.100.9"
	next.Routes = append(next.Routes, state.HopRoute{ListenPort: 1002, BackendIP: "198.51.100.3", BackendPort: 2002})
	r, err := f.Apply(context.Background(), next)
	if err != nil || r.Flushed != 6 || !reflect.DeepEqual(r.AddedRoutes, []int{1002}) || !reflect.DeepEqual(r.ChangedRoutes, []int{1000}) || !reflect.DeepEqual(c.calls[2:], []string{"192.0.2.1:1000", "192.0.2.1:1002"}) {
		t.Fatalf("result=%+v calls=%v err=%v", r, c.calls, err)
	}
	if c.callAtFlush[2] != x.calls || c.callAtFlush[3] != x.calls {
		t.Fatal("expected route add calls before conntrack flush")
	}
	before := len(c.calls)
	if _, err = f.Apply(context.Background(), next); err != nil || len(c.calls) != before {
		t.Fatalf("identical apply flushed: %v", err)
	}
	r, err = f.Apply(context.Background(), nil)
	if err != nil || len(r.RemovedRoutes) != 3 || len(c.calls) != before+3 {
		t.Fatalf("cleanup=%+v calls=%v err=%v", r, c.calls, err)
	}
	stats := f.Stats()
	if stats.FlushedTotal != 21 || stats.Routes != 0 {
		t.Fatalf("stats=%+v", stats)
	}
}

func TestForwarderConntrackFlushErrorIsNonFatal(t *testing.T) {
	x := &fake{rules: map[string][][]string{}}
	c := &conntrackFake{err: errors.New("denied"), mutations: &x.mutations}
	f := New(Deps{Runner: x, Conntrack: c, IPForwardReader: func() (bool, error) { return true, nil }, AddrChecker: func(string, string) (bool, error) { return true, nil }})
	h := hop()
	r, err := f.Apply(context.Background(), h)
	if err != nil || len(r.Warnings) != 2 || f.Stats().FlushErrorsTotal != 2 {
		t.Fatalf("result=%+v err=%v stats=%+v", r, err, f.Stats())
	}
	added := hop()
	added.Routes = added.Routes[:0]
	added.Routes = append(added.Routes, state.HopRoute{ListenPort: 1010, BackendIP: "198.51.100.10", BackendPort: 2010})
	x2 := &fake{rules: map[string][][]string{}}
	c2 := &conntrackFake{err: errors.New("denied"), mutations: &x2.mutations}
	f2 := New(Deps{Runner: x2, Conntrack: c2, IPForwardReader: func() (bool, error) { return true, nil }, AddrChecker: func(string, string) (bool, error) { return true, nil }})
	if _, err := f2.Apply(context.Background(), &state.Hop{WANInterface: "eth0", HopIP: "192.0.2.1"}); err != nil {
		t.Fatal(err)
	}
	addedResult, err := f2.Apply(context.Background(), added)
	if err != nil || len(addedResult.Warnings) != 1 || !reflect.DeepEqual(addedResult.AddedRoutes, []int{1010}) {
		t.Fatalf("added=%+v err=%v", addedResult, err)
	}
}

func TestForwarderWithoutConntrack(t *testing.T) {
	x := &fake{rules: map[string][][]string{}}
	f := New(Deps{Runner: x, IPForwardReader: func() (bool, error) { return true, nil }, AddrChecker: func(string, string) (bool, error) { return true, nil }})
	if _, err := f.Apply(context.Background(), hop()); err != nil {
		t.Fatal(err)
	}
	h := hop()
	h.Routes[0].BackendIP = "198.51.100.9"
	if r, err := f.Apply(context.Background(), h); err != nil || r.Flushed != 0 || len(r.Warnings) != 0 {
		t.Fatalf("result=%+v err=%v", r, err)
	}
}

func TestForwarderApplyErrorStats(t *testing.T) {
	x := &fake{rules: map[string][][]string{}, failAt: 1}
	f := New(Deps{Runner: x})
	if _, err := f.Apply(context.Background(), nil); err == nil || f.Stats().ApplyErrorsTotal != 1 {
		t.Fatalf("expected apply error, stats=%+v", f.Stats())
	}
	if jumpRules(nil) != nil {
		t.Fatal("nil hop has jump rules")
	}
}
