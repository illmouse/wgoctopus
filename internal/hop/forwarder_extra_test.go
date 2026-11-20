package hop

import (
	"context"
	"os"
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/illmouse/wgoctopus/internal/state"
)

func TestApplyNilCleansEverything(t *testing.T) {
	x := &fake{rules: map[string][][]string{}}
	f := newTestForwarder(x)
	if _, err := f.Apply(context.Background(), hop()); err != nil {
		t.Fatal(err)
	}
	r, err := f.Apply(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if got := r.RemovedRoutes; !reflect.DeepEqual(sorted(got), []int{1000, 1001}) {
		t.Fatalf("removed routes %v", got)
	}
	for _, c := range []string{"nat:" + dnatChain, "nat:" + snatChain, "filter:" + fwdChain} {
		if x.chains[c] {
			t.Errorf("chain still exists: %s", c)
		}
	}
	for _, c := range []struct{ table, chain, target string }{{"nat", "PREROUTING", dnatChain}, {"nat", "POSTROUTING", snatChain}, {"filter", "FORWARD", fwdChain}} {
		for _, rule := range x.rules[c.table+":"+c.chain] {
			if rule[len(rule)-1] == c.target {
				t.Errorf("jump remains: %s %v", c.chain, rule)
			}
		}
	}
}

func TestApplyNilOnCleanHostNoop(t *testing.T) {
	x := &fake{rules: map[string][][]string{}}
	r, err := newTestForwarder(x).Apply(context.Background(), nil)
	if err != nil || r.Changed || x.mutations != 0 {
		t.Fatalf("result=%+v err=%v mutations=%d", r, err, x.mutations)
	}
}

func TestWANChangeMovesJumps(t *testing.T) {
	assertJumpMove(t, func(h *state.Hop) { h.WANInterface = "eth1" })
}

func TestHopIPChangeMovesPreroutingJump(t *testing.T) {
	assertJumpMove(t, func(h *state.Hop) { h.HopIP = "192.0.2.2" })
}

func assertJumpMove(t *testing.T, change func(*state.Hop)) {
	t.Helper()
	x := &fake{rules: map[string][][]string{}}
	f := newTestForwarder(x)
	old := hop()
	if _, err := f.Apply(context.Background(), old); err != nil {
		t.Fatal(err)
	}
	next := hop()
	change(next)
	if _, err := f.Apply(context.Background(), next); err != nil {
		t.Fatal(err)
	}
	for _, j := range jumpRules(old) {
		if j.chain == "PREROUTING" && old.HopIP == next.HopIP || j.chain != "PREROUTING" && old.WANInterface == next.WANInterface {
			continue
		}
		count := 0
		for _, spec := range x.rules[j.table+":"+j.chain] {
			if reflect.DeepEqual(spec, j.spec) {
				count++
			}
		}
		if count != 0 {
			t.Errorf("old jump remains in %s: %v", j.chain, x.rules[j.table+":"+j.chain])
		}
	}
	for _, j := range jumpRules(next) {
		count := 0
		for _, spec := range x.rules[j.table+":"+j.chain] {
			if reflect.DeepEqual(spec, j.spec) {
				count++
			}
		}
		if count != 1 {
			t.Errorf("jump %s count %d", j.chain, count)
		}
	}
}

func TestNewDefaultsAndRealReaders(t *testing.T) {
	if New(Deps{}) == nil {
		t.Fatal("New returned nil")
	}
	_, err := readIPForward()
	if _, statErr := os.Stat("/proc/sys/net/ipv4/ip_forward"); statErr == nil && err != nil {
		t.Fatal(err)
	}
	if ok, err := hasAddress("lo", "127.0.0.1"); err != nil || !ok {
		t.Fatalf("loopback: %v %v", ok, err)
	}
	if ok, err := hasAddress("lo", "203.0.113.9"); err != nil || ok {
		t.Fatalf("unexpected loopback address: %v %v", ok, err)
	}
	if ok, err := hasAddress("no-such-if0", "10.0.0.1"); err == nil && ok {
		t.Fatal("nonexistent interface unexpectedly has address")
	}
}

func TestAddBeforeDeleteOrdering(t *testing.T) {
	x := &fake{rules: map[string][][]string{}}
	f := newTestForwarder(x)
	base := hop()
	if _, err := f.Apply(context.Background(), base); err != nil {
		t.Fatal(err)
	}
	start := len(x.callLog)
	next := hop()
	next.Routes[0].BackendIP = "198.51.100.9"
	if _, err := f.Apply(context.Background(), next); err != nil {
		t.Fatal(err)
	}
	firstDelete, lastAdd := len(x.callLog), -1
	for i, call := range x.callLog[start:] {
		joined := strings.Join(call, " ")
		if strings.Contains(joined, "wgoct:hop:1000") && strings.Contains(joined, " -A ") {
			lastAdd = start + i
		}
		if strings.Contains(joined, "wgoct:hop:1000") && strings.Contains(joined, " -D ") && start+i < firstDelete {
			firstDelete = start + i
		}
		if strings.Contains(joined, "wgoct:hop:1001") && (strings.Contains(joined, " -A ") || strings.Contains(joined, " -D ")) {
			t.Errorf("unmodified route touched: %v", call)
		}
	}
	if lastAdd < 0 || firstDelete == len(x.callLog) || lastAdd >= firstDelete {
		t.Fatalf("add index %d, delete index %d", lastAdd, firstDelete)
	}
}

func TestDuplicateJumpDeduplicated(t *testing.T) {
	x := &fake{rules: map[string][][]string{}}
	f := newTestForwarder(x)
	if _, err := f.Apply(context.Background(), hop()); err != nil {
		t.Fatal(err)
	}
	j := jumpRules(hop())[0]
	x.rules[j.table+":"+j.chain] = append(x.rules[j.table+":"+j.chain], append([]string(nil), j.spec...))
	if _, err := f.Apply(context.Background(), hop()); err != nil {
		t.Fatal(err)
	}
	count := 0
	for _, spec := range x.rules[j.table+":"+j.chain] {
		if reflect.DeepEqual(spec, j.spec) {
			count++
		}
	}
	if count != 1 {
		t.Fatalf("PREROUTING jump count %d", count)
	}
}

func sorted(a []int) []int { out := append([]int(nil), a...); sort.Ints(out); return out }
