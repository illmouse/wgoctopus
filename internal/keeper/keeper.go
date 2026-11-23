// Package keeper periodically re-arms client peers whose handshakes have stalled.
package keeper

import (
	"context"
	"log/slog"
	"sync"
	"time"

	"github.com/illmouse/wgoctopus/internal/state"
	"github.com/illmouse/wgoctopus/internal/uapi"
)

type Source interface {
	Applied() state.State
	TryKeep(func()) bool
}
type Device interface {
	Get() (uapi.Live, error)
	Set(uapi.Ops) error
}
type Factory func(string) Device
type Keeper struct {
	Source   Source
	Device   Factory
	Interval time.Duration
	Now      func() time.Time
	OnKick   func(string)
	mu       sync.Mutex
	seen     map[string]time.Time
	kicks    map[string]time.Time
}

func (k *Keeper) Run(ctx context.Context) {
	interval := k.Interval
	if interval <= 0 {
		interval = 10 * time.Second
	}
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-t.C:
			k.Tick(now)
		}
	}
}

func (k *Keeper) Tick(now time.Time) {
	if k.Now != nil {
		now = k.Now()
	}
	if k.Source == nil || k.Device == nil {
		return
	}
	k.Source.TryKeep(func() {
		for _, in := range k.Source.Applied().Interfaces {
			if in.Mode != "client" {
				continue
			}
			dev := k.Device(in.Name)
			live, err := dev.Get()
			if err != nil {
				continue
			}
			for _, p := range in.Peers {
				if p.PersistentKeepalive == 0 || p.Endpoint == "" {
					continue
				}
				lp, ok := live.Peers[p.PublicKey]
				if !ok {
					continue
				}
				key := in.Name + "\x00" + p.PublicKey
				k.mu.Lock()
				if k.seen == nil {
					k.seen = map[string]time.Time{}
					k.kicks = map[string]time.Time{}
				}
				first, exists := k.seen[key]
				if !exists {
					first = now
					k.seen[key] = now
				}
				age := time.Duration(0)
				if lp.LastHandshakeSec > 0 {
					age = now.Sub(time.Unix(int64(lp.LastHandshakeSec), int64(lp.LastHandshakeNSec)))
				}
				needs := false
				if lp.LastHandshakeSec == 0 {
					needs = now.Sub(first) >= 20*time.Second
				} else {
					needs = age > 150*time.Second
				}
				last := k.kicks[key]
				allow := needs && (last.IsZero() || now.Sub(last) >= 30*time.Second)
				if allow {
					k.kicks[key] = now
				}
				k.mu.Unlock()
				if !allow {
					continue
				}
				zero, want := uint16(0), p.PersistentKeepalive
				if err = dev.Set(uapi.Ops{Peers: []uapi.PeerOp{{PublicKey: p.PublicKey, UpdateOnly: true, PersistentKeepalive: &zero}}}); err == nil {
					err = dev.Set(uapi.Ops{Peers: []uapi.PeerOp{{PublicKey: p.PublicKey, UpdateOnly: true, PersistentKeepalive: &want}}})
				}
				if err != nil {
					k.mu.Lock()
					delete(k.kicks, key)
					k.mu.Unlock()
					continue
				}
				slog.Info("client peer keepalive re-armed", "interface", in.Name)
				if k.OnKick != nil {
					k.OnKick(in.Name)
				}
			}
		}
	})
}
