package hop

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/illmouse/wgoctopus/internal/state"
)

type fake struct {
	rules     map[string][][]string
	chains    map[string]bool
	calls     int
	mutations int
	failAt    int
	callLog   [][]string
}

func (x *fake) Run(a []string) (string, int, error) {
	x.calls++
	x.callLog = append(x.callLog, append([]string(nil), a...))
	if x.chains == nil {
		x.chains = map[string]bool{}
	}
	if x.rules == nil {
		x.rules = map[string][][]string{}
	}
	if x.failAt == x.calls {
		return "", 0, errors.New("injected failure")
	}
	table, at := "filter", 0
	if len(a) > 2 && a[1] == "-t" {
		table, at = a[2], 3
	}
	if at < len(a) && a[at] == "-w" {
		at++
	}
	if at >= len(a) {
		return "", 1, nil
	}
	cmd := a[at]
	if cmd == "-A" || cmd == "-I" || cmd == "-D" || cmd == "-F" || cmd == "-X" {
		x.mutations++
	}
	if cmd == "-S" {
		chain := a[at+1]
		if strings.HasPrefix(chain, "WGOCT_HOP_") && !x.chains[table+":"+chain] {
			return "", 1, nil
		}
		var b strings.Builder
		for _, r := range x.rules[table+":"+chain] {
			b.WriteString("-A " + chain + " " + quote(r) + "\n")
		}
		return b.String(), 0, nil
	}
	if cmd == "-N" {
		key := table + ":" + a[at+1]
		if x.chains[key] {
			return "", 1, nil
		}
		x.chains[key] = true
		return "", 0, nil
	}
	if cmd == "-A" || cmd == "-I" {
		chain := a[at+1]
		spec := append([]string{}, a[at+2:]...)
		if cmd == "-I" {
			spec = spec[1:]
		}
		x.rules[table+":"+chain] = append(x.rules[table+":"+chain], spec)
		return "", 0, nil
	}
	if cmd == "-D" {
		chain := a[at+1]
		spec := strings.Join(a[at+2:], " ")
		rs := x.rules[table+":"+chain]
		for i, r := range rs {
			if strings.Join(r, " ") == spec {
				x.rules[table+":"+chain] = append(rs[:i], rs[i+1:]...)
				break
			}
		}
		return "", 0, nil
	}
	if cmd == "-F" {
		x.rules[table+":"+a[at+1]] = nil
		return "", 0, nil
	}
	if cmd == "-X" {
		delete(x.rules, table+":"+a[at+1])
		delete(x.chains, table+":"+a[at+1])
		return "", 0, nil
	}
	if cmd == "-C" {
		chain := a[at+1]
		spec := strings.Join(a[at+2:], " ")
		for _, r := range x.rules[table+":"+chain] {
			if strings.Join(r, " ") == spec {
				return "", 0, nil
			}
		}
		return "", 1, nil
	}
	return "", 0, nil
}
func quote(r []string) string {
	var b strings.Builder
	for i, s := range r {
		if i > 0 {
			b.WriteByte(' ')
		}
		if strings.ContainsAny(s, ": ") {
			b.WriteString("\"" + s + "\"")
		} else {
			b.WriteString(s)
		}
	}
	return b.String()
}
func newTestForwarder(x *fake) *Forwarder {
	if x.chains == nil {
		x.chains = map[string]bool{}
	}
	return New(Deps{Runner: x, IPForwardReader: func() (bool, error) { return true, nil }, AddrChecker: func(string, string) (bool, error) { return true, nil }})
}
func hop() *state.Hop {
	return &state.Hop{WANInterface: "eth0", HopIP: "192.0.2.1", Routes: []state.HopRoute{{ListenPort: 1000, BackendIP: "198.51.100.1", BackendPort: 2000}, {ListenPort: 1001, BackendIP: "198.51.100.2", BackendPort: 2001}}}
}

func TestApplyIdempotentAndRoutes(t *testing.T) {
	tests := []struct {
		name                    string
		mutate                  func(*state.Hop)
		wantChanged, wantRoutes int
	}{
		{"add", func(h *state.Hop) {
			h.Routes = append(h.Routes, state.HopRoute{ListenPort: 1002, BackendIP: "198.51.100.3", BackendPort: 2002})
		}, 1, 0},
		{"backend change", func(h *state.Hop) { h.Routes[0].BackendIP = "198.51.100.9" }, 1, 1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			x := &fake{rules: map[string][][]string{}}
			f := newTestForwarder(x)
			if _, err := f.Apply(context.Background(), hop()); err != nil {
				t.Fatal(err)
			}
			before := x.calls
			res, err := f.Apply(context.Background(), func() *state.Hop { h := hop(); tt.mutate(h); return h }())
			if err != nil {
				t.Fatal(err)
			}
			if !res.Changed || len(res.ChangedRoutes) != tt.wantRoutes {
				t.Fatalf("result %+v", res)
			}
			_ = before
		})
	}
	t.Run("identical no mutation", func(t *testing.T) {
		x := &fake{rules: map[string][][]string{}}
		f := newTestForwarder(x)
		_, _ = f.Apply(context.Background(), hop())
		before := x.mutations
		r, e := f.Apply(context.Background(), hop())
		if e != nil || r.Changed || x.mutations != before {
			t.Fatalf("%+v %v mutations %d/%d", r, e, before, x.mutations)
		}
	})
	t.Run("nil cleanup", func(t *testing.T) {
		x := &fake{rules: map[string][][]string{}}
		f := newTestForwarder(x)
		_, _ = f.Apply(context.Background(), hop())
		r, e := f.Apply(context.Background(), nil)
		if e != nil || len(r.RemovedRoutes) != 2 {
			t.Fatalf("%+v %v", r, e)
		}
	})
}

func TestApplyPreconditionsAndFailure(t *testing.T) {
	for _, tc := range []struct {
		name   string
		deps   Deps
		h      *state.Hop
		failAt int
	}{
		{"forward disabled", Deps{IPForwardReader: func() (bool, error) { return false, nil }}, hop(), 0},
		{"missing address", Deps{IPForwardReader: func() (bool, error) { return true, nil }, AddrChecker: func(string, string) (bool, error) { return false, nil }}, hop(), 0},
		{"runner failure", Deps{IPForwardReader: func() (bool, error) { return true, nil }, AddrChecker: func(string, string) (bool, error) { return true, nil }}, hop(), 5},
	} {
		t.Run(tc.name, func(t *testing.T) {
			x := &fake{rules: map[string][][]string{}, failAt: tc.failAt}
			tc.deps.Runner = x
			f := New(tc.deps)
			_, err := f.Apply(context.Background(), tc.h)
			if err == nil {
				t.Fatal("expected error")
			}
			if tc.failAt == 0 && x.calls != 0 {
				t.Fatalf("mutated/queried before precondition: %d", x.calls)
			}
		})
	}
}

func TestExactRouteRuleArguments(t *testing.T) {
	rs := routeRules(hop(), hop().Routes[0])
	got := rs[0].add()
	want := []string{"-t", "nat", "-A", dnatChain, "-p", "udp", "--dport", "1000", "-m", "comment", "--comment", "wgoct:hop:1000", "-j", "DNAT", "--to-destination", "198.51.100.1:2000"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("%v", got)
	}
}
