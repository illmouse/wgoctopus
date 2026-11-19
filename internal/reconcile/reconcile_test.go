package reconcile

import (
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/illmouse/wgoctopus/internal/state"
	"github.com/illmouse/wgoctopus/internal/uapi"
)

const testKey = "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE="

type fakeDevice struct {
	live   uapi.Live
	writes int
}

func (f *fakeDevice) Get() (uapi.Live, error) { return f.live, nil }
func (f *fakeDevice) Set(o uapi.Ops) error {
	f.writes++
	for k, v := range o.Fields {
		if k == "private_key" {
			v = normalizePrivateKey(v)
		}
		f.live.Fields[k] = v
		if k == "private_key" {
			f.live.PrivateKey = v
		}
	}
	for _, p := range o.Peers {
		if p.Remove {
			delete(f.live.Peers, p.PublicKey)
			continue
		}
		old := f.live.Peers[p.PublicKey]
		old.PublicKey = p.PublicKey
		if p.PresharedKey != nil {
			old.PresharedKey = *p.PresharedKey
		}
		if p.ReplaceAllowedIPs {
			old.AllowedIPs = p.AllowedIPs
		}
		f.live.Peers[p.PublicKey] = old
	}
	return nil
}

func desired(peers ...state.Peer) state.Interface {
	return state.Interface{PrivateKey: testKey, ListenPort: 51820, Obfuscation: state.Obfuscation{H1: "1", H2: "2", H3: "3", H4: "4"}, Peers: peers}
}
func liveKey() string { return normalizePrivateKey(testKey) }
func TestApplyNoopAndIdempotent(t *testing.T) {
	w := desired(state.Peer{PublicKey: testKey, AllowedIPs: []string{"10.0.0.2/24"}})
	f := &fakeDevice{live: uapi.Live{PrivateKey: liveKey(), Fields: map[string]string{"private_key": liveKey(), "listen_port": "51820", "h1": "1", "h2": "2", "h3": "3", "h4": "4"}, Peers: map[string]uapi.Peer{testKey: {PublicKey: testKey, AllowedIPs: []string{"10.0.0.0/24"}}}}}
	if err := Apply(f, w, false); err != nil {
		t.Fatal(err)
	}
	if f.writes != 0 {
		t.Fatalf("noop wrote %d times", f.writes)
	}
	w.Peers = nil
	if err := Apply(f, w, false); err != nil {
		t.Fatal(err)
	}
	if f.writes != 1 || len(f.live.Peers) != 0 {
		t.Fatal("peer removal did not apply")
	}
	if err := Apply(f, w, false); err != nil {
		t.Fatal(err)
	}
	if f.writes != 1 {
		t.Fatal("second apply was not idempotent")
	}
}
func TestDangerousRefusalDoesNotWrite(t *testing.T) {
	f := &fakeDevice{live: uapi.Live{PrivateKey: liveKey(), Fields: map[string]string{"private_key": liveKey(), "listen_port": "51820", "h1": "1", "h2": "2", "h3": "3", "h4": "4"}, Peers: map[string]uapi.Peer{}}}
	w := desired()
	w.ListenPort = 51821
	err := Apply(f, w, false)
	if !errors.Is(err, ErrDangerous) || f.writes != 0 {
		t.Fatalf("err=%v writes=%d", err, f.writes)
	}
	if err := Apply(f, w, true); err != nil || f.writes != 1 {
		t.Fatalf("err=%v writes=%d", err, f.writes)
	}
}
func TestFirstInterfaceIsNotDangerousAndNewPeerIsNotUpdate(t *testing.T) {
	w := desired(state.Peer{PublicKey: testKey, AllowedIPs: []string{"10.0.0.0/24"}})
	p := Plan(w, uapi.Live{Fields: map[string]string{}, Peers: map[string]uapi.Peer{}})
	if len(p.Dangerous) != 0 {
		t.Fatal(p.Dangerous)
	}
	if len(p.Ops.Peers) != 1 || p.Ops.Peers[0].UpdateOnly {
		t.Fatal("new peer must not use update_only")
	}
}

func TestDaemonClampedPrivateKeyIsNoop(t *testing.T) {
	w := desired()
	live := uapi.Live{PrivateKey: liveKey(), Fields: map[string]string{"private_key": liveKey(), "listen_port": "51820", "h1": "1", "h2": "2", "h3": "3", "h4": "4"}, Peers: map[string]uapi.Peer{}}
	p := Plan(w, live)
	if len(p.Ops.Fields) != 0 || len(p.Dangerous) != 0 {
		t.Fatalf("daemon-normalized key caused changes: %#v", p)
	}
}

func TestPeerUpdateAndDangerousFields(t *testing.T) {
	otherKey := "AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI="
	w := desired(state.Peer{PublicKey: testKey, PresharedKey: otherKey, AllowedIPs: []string{"10.0.0.0/24"}})
	live := uapi.Live{PrivateKey: liveKey(), Fields: map[string]string{"private_key": liveKey(), "listen_port": "51820", "h1": "1", "h2": "2", "h3": "3", "h4": "4", "jc": "4"}, Peers: map[string]uapi.Peer{testKey: {PublicKey: testKey, PresharedKey: testKey, AllowedIPs: []string{"10.0.0.0/24"}}}}
	p := Plan(w, live)
	if len(p.Ops.Peers) != 1 || !p.Ops.Peers[0].UpdateOnly || p.Ops.Peers[0].PresharedKey == nil {
		t.Fatal(p.Ops.Peers)
	}
	if len(p.Dangerous) != 1 || p.Dangerous[0] != "jc" {
		t.Fatal(p.Dangerous)
	}
	// Clearing an optional field sends the default rather than preserving a live value.
	w.Peers[0].PresharedKey = ""
	w.Obfuscation.I1 = ""
	live.Fields["i1"] = "live-value"
	p = Plan(w, live)
	if p.Ops.Fields["i1"] != "" || p.Ops.Peers[0].PresharedKey == nil || *p.Ops.Peers[0].PresharedKey != "" {
		t.Fatal(p)
	}
}

func TestAllowedIPChangesAndPeerOrderAreDeterministic(t *testing.T) {
	keyA, keyB := testKey, "AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI="
	w := desired(state.Peer{PublicKey: keyB, AllowedIPs: []string{"192.0.3.5/24"}}, state.Peer{PublicKey: keyA, AllowedIPs: []string{"10.0.0.0/24"}})
	live := uapi.Live{PrivateKey: liveKey(), Fields: map[string]string{"private_key": liveKey(), "listen_port": "51820", "h1": "1", "h2": "2", "h3": "3", "h4": "4"}, Peers: map[string]uapi.Peer{keyA: {PublicKey: keyA, AllowedIPs: []string{"10.0.0.0/24"}}, keyB: {PublicKey: keyB, AllowedIPs: []string{"192.0.2.0/24"}}}}
	first := Plan(w, live)
	w.Peers[0], w.Peers[1] = w.Peers[1], w.Peers[0]
	second := Plan(w, live)
	if !reflect.DeepEqual(first, second) {
		t.Fatalf("peer order changed plan: %#v != %#v", first, second)
	}
	if len(first.Ops.Peers) != 1 || first.Ops.Peers[0].AllowedIPs[0] != "192.0.3.0/24" {
		t.Fatalf("masked allowed IP was not applied: %#v", first.Ops.Peers)
	}
	serialized, err := uapi.Serialize(first.Ops)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(serialized, "replace_peers") {
		t.Fatal(serialized)
	}
}
