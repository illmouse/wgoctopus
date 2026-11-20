package hop

import (
	"context"
	"errors"
	"net"
	"strconv"
	"testing"
)

type conntrackFake struct {
	deleted   int
	err       error
	calls     []string
	mutations *int
}

func (c *conntrackFake) FlushUDPOrigDst(ip net.IP, port int) (int, error) {
	if *c.mutations == 0 {
		panic("conntrack flushed before rules were applied")
	}
	c.calls = append(c.calls, ip.String()+":"+strconv.Itoa(port))
	return c.deleted, c.err
}

func TestForwarderConntrackFlush(t *testing.T) {
	x := &fake{rules: map[string][][]string{}}
	c := &conntrackFake{deleted: 3, mutations: &x.mutations}
	deps := Deps{Runner: x, Conntrack: c, IPForwardReader: func() (bool, error) { return true, nil }, AddrChecker: func(string, string) (bool, error) { return true, nil }}
	f := New(deps)
	h := hop()
	if _, err := f.Apply(context.Background(), h); err != nil {
		t.Fatal(err)
	}
	next := hop()
	next.Routes[0].BackendIP = "198.51.100.9"
	r, err := f.Apply(context.Background(), next)
	if err != nil || r.Flushed != 3 || len(c.calls) != 1 || c.calls[0] != "192.0.2.1:1000" {
		t.Fatalf("result=%+v calls=%v err=%v", r, c.calls, err)
	}
	before := len(c.calls)
	if _, err = f.Apply(context.Background(), next); err != nil || len(c.calls) != before {
		t.Fatalf("identical apply flushed: %v", err)
	}
	r, err = f.Apply(context.Background(), nil)
	if err != nil || len(r.RemovedRoutes) != 2 || len(c.calls) != before+2 {
		t.Fatalf("cleanup=%+v calls=%v err=%v", r, c.calls, err)
	}
	stats := f.Stats()
	if stats.FlushedTotal != 9 || stats.Routes != 0 {
		t.Fatalf("stats=%+v", stats)
	}
}

func TestForwarderConntrackFlushErrorIsNonFatal(t *testing.T) {
	x := &fake{rules: map[string][][]string{}}
	c := &conntrackFake{err: errors.New("denied"), mutations: &x.mutations}
	f := New(Deps{Runner: x, Conntrack: c, IPForwardReader: func() (bool, error) { return true, nil }, AddrChecker: func(string, string) (bool, error) { return true, nil }})
	h := hop()
	if _, err := f.Apply(context.Background(), h); err != nil {
		t.Fatal(err)
	}
	h.Routes[0].BackendIP = "198.51.100.9"
	r, err := f.Apply(context.Background(), h)
	if err != nil || len(r.Warnings) != 1 || f.Stats().FlushErrorsTotal != 1 {
		t.Fatalf("result=%+v err=%v stats=%+v", r, err, f.Stats())
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
