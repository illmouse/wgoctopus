package keeper

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/illmouse/wgoctopus/internal/state"
	"github.com/illmouse/wgoctopus/internal/uapi"
)

type source struct{ s state.State }

func (s source) Applied() state.State  { return s.s }
func (s source) TryKeep(f func()) bool { f(); return true }

type device struct {
	live uapi.Live
	ops  []uapi.Ops
	fail bool
}

type blockedSource struct{ source }

func (blockedSource) TryKeep(func()) bool { return false }

func (d *device) Get() (uapi.Live, error) { return d.live, nil }
func (d *device) Set(o uapi.Ops) error {
	d.ops = append(d.ops, o)
	if d.fail {
		d.fail = false
		return errors.New("failed")
	}
	return nil
}

func TestKeeper(t *testing.T) {
	base := time.Unix(1000, 0)
	for _, tc := range []struct {
		name, mode string
		keep       uint16
		handshake  uint64
		advance    time.Duration
		want       int
	}{
		{"never early", "client", 25, 0, 19 * time.Second, 0}, {"never ready", "client", 25, 0, 20 * time.Second, 2}, {"stale", "client", 25, uint64(base.Add(-151 * time.Second).Unix()), 0, 2}, {"recent", "client", 25, uint64(base.Add(-100 * time.Second).Unix()), 0, 0}, {"server", "server", 25, 0, 20 * time.Second, 0}, {"disabled keepalive", "client", 0, 0, 20 * time.Second, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d := &device{live: uapi.Live{Peers: map[string]uapi.Peer{"key": {PublicKey: "key", Endpoint: "1.2.3.4:5", LastHandshakeSec: tc.handshake}}}}
			k := Keeper{Source: source{state.State{Interfaces: []state.Interface{{Name: "wg0", Mode: tc.mode, Peers: []state.Peer{{PublicKey: "key", Endpoint: "1.2.3.4:5", PersistentKeepalive: tc.keep}}}}}}, Device: func(string) Device { return d }}
			k.Tick(base)
			k.Tick(base.Add(tc.advance))
			if len(d.ops) != tc.want {
				t.Fatalf("ops=%d want %d", len(d.ops), tc.want)
			}
			if tc.want == 2 {
				for i, o := range d.ops {
					p := o.Peers[0]
					expected := uint16(0)
					if i == 1 {
						expected = tc.keep
					}
					if len(o.Fields) != 0 || len(o.Peers) != 1 || p.PublicKey != "key" || !p.UpdateOnly || p.PersistentKeepalive == nil || *p.PersistentKeepalive != expected {
						t.Fatalf("unexpected operation: %#v", o)
					}
				}
			}
		})
	}
}

func TestRateLimitAndRetry(t *testing.T) {
	base := time.Unix(1000, 0)
	d := &device{fail: true, live: uapi.Live{Peers: map[string]uapi.Peer{"key": {LastHandshakeSec: uint64(base.Unix() - 151)}}}}
	k := Keeper{Source: source{state.State{Interfaces: []state.Interface{{Name: "wg", Mode: "client", Peers: []state.Peer{{PublicKey: "key", Endpoint: "x", PersistentKeepalive: 10}}}}}}, Device: func(string) Device { return d }}
	k.Tick(base)
	if len(d.ops) != 1 {
		t.Fatal(len(d.ops))
	}
	k.Tick(base.Add(30 * time.Second))
	if len(d.ops) != 3 {
		t.Fatal(len(d.ops))
	}
	k.Tick(base.Add(59 * time.Second))
	if len(d.ops) != 3 {
		t.Fatal(len(d.ops))
	}
	k.Tick(base.Add(60 * time.Second))
	if len(d.ops) != 5 {
		t.Fatal(len(d.ops))
	}
}

func TestNoopPathsAndCallback(t *testing.T) {
	var k Keeper
	k.Tick(time.Now())
	base := time.Unix(1000, 0)
	d := &device{live: uapi.Live{Peers: map[string]uapi.Peer{"k": {LastHandshakeSec: uint64(base.Unix() - 151)}}}}
	s := source{state.State{Interfaces: []state.Interface{{Name: "wg", Mode: "client", Peers: []state.Peer{{PublicKey: "k", Endpoint: "x", PersistentKeepalive: 1}}}}}}
	called := 0
	k = Keeper{Source: blockedSource{s}, Device: func(string) Device { return d }}
	k.Tick(base)
	if len(d.ops) != 0 {
		t.Fatal(len(d.ops))
	}
	k.Source = s
	k.OnKick = func(name string) {
		if name != "wg" {
			t.Fatal(name)
		}
		called++
	}
	k.Tick(base)
	if called != 1 {
		t.Fatal(called)
	}
	k.Device = func(string) Device { return failingDevice{} }
	k.Tick(base.Add(time.Minute))
}

func TestRunCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	(&Keeper{Interval: time.Millisecond}).Run(ctx)
}

type failingDevice struct{}

func (failingDevice) Get() (uapi.Live, error) { return uapi.Live{}, errors.New("get failed") }
func (failingDevice) Set(uapi.Ops) error      { return nil }
