package metrics

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/illmouse/wgoctopus/internal/uapi"
)

type fakeDevice struct {
	live uapi.Live
	err  error
}

func (d fakeDevice) Get() (uapi.Live, error) { return d.live, d.err }
func (fakeDevice) Set(uapi.Ops) error        { return nil }

func TestRender(t *testing.T) {
	now := time.Unix(200, 0)
	live := uapi.Live{Peers: map[string]uapi.Peer{
		"never": {PublicKey: "never", RxBytes: 4, TxBytes: 5},
		"done":  {PublicKey: "done", LastHandshakeSec: 190, LastHandshakeNSec: 500000000, RxBytes: 6, TxBytes: 7},
	}}
	c := &Collector{
		Interfaces:      func() []string { return []string{"z", "a"} },
		Device:          func(name string) (uapi.Device, error) { return fakeDevice{live: live}, nil },
		AppliedRevision: func() int64 { return 8 },
		Restarts:        func(string) uint64 { return 2 },
		Now:             func() time.Time { return now },
		Version:         "v1",
		GoVersion:       "go1.24.4",
	}
	first := string(c.Render(context.Background()))
	if first != string(c.Render(context.Background())) {
		t.Fatal("render is not deterministic")
	}
	for _, expected := range []string{
		"# HELP wg_interface_up", "wgoctopus_agent_applied_revision 8\n",
		`wg_interface_up{interface="a"} 1`, `wg_interface_up{interface="z"} 1`,
		`wg_peer_handshake_age_seconds{interface="a",public_key="done"} 9.5`,
		`wg_peer_last_handshake_timestamp_seconds{interface="a",public_key="never"} 0`,
		`wg_peer_rx_bytes_total{interface="a",public_key="never"} 4`,
	} {
		if !strings.Contains(first, expected) {
			t.Errorf("missing %q", expected)
		}
	}
	if strings.Contains(first, `wg_peer_handshake_age_seconds{interface="a",public_key="never"}`) {
		t.Error("age emitted for peer that never handshaked")
	}
	if strings.Index(first, `public_key="done"`) > strings.Index(first, `public_key="never"`) {
		t.Error("peers are not sorted")
	}
}

func TestRenderFailureEscapingAndContext(t *testing.T) {
	c := &Collector{
		Interfaces: func() []string { return []string{"bad\nname", "good"} },
		Device: func(name string) (uapi.Device, error) {
			if name == "bad\nname" {
				return nil, errors.New("unavailable")
			}
			return fakeDevice{live: uapi.Live{Peers: map[string]uapi.Peer{`k"\\\n`: {PublicKey: `k"\\\n`}}}}, nil
		},
	}
	out := string(c.Render(context.Background()))
	for _, expected := range []string{`wg_interface_up{interface="bad\nname"} 0`, `wg_interface_up{interface="good"} 1`, `interface="good",public_key="k\"\\\\\\n"`} {
		if !strings.Contains(out, expected) {
			t.Errorf("missing escaped/failure output %q", expected)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if !strings.Contains(string(c.Render(ctx)), `wg_interface_up{interface="good"} 0`) {
		t.Error("canceled context should mark lookup down")
	}
}
