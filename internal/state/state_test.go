package state

import (
	"encoding/json"
	"os"
	"testing"
)

func TestExampleAndInvalid(t *testing.T) {
	b, e := os.ReadFile("../../schema/examples/state.example.json")
	if e != nil {
		t.Fatal(e)
	}
	var s State
	if e = json.Unmarshal(b, &s); e != nil {
		t.Fatal(e)
	}
	if e = s.Validate(); e != nil {
		t.Fatal(e)
	}
	s.Interfaces[0].ListenPort = 0
	if s.Validate() == nil {
		t.Fatal("accepted zero port")
	}
}

func TestOptionalInterfaceNetworkFields(t *testing.T) {
	b, err := os.ReadFile("../../schema/examples/state.example.json")
	if err != nil {
		t.Fatal(err)
	}
	var s State
	if err := json.Unmarshal(b, &s); err != nil {
		t.Fatal(err)
	}
	base := s.Checksum()
	s.Interfaces[0].MTU = 1400
	s.Interfaces[0].EgressInterface = "eth0"
	s.Interfaces[0].SNATIP = "2001:db8::1"
	if err := s.Validate(); err != nil {
		t.Fatal(err)
	}
	if s.Checksum() == base {
		t.Fatal("optional fields missing from checksum")
	}
	s.Interfaces[0].MTU = 100
	if s.Validate() == nil {
		t.Fatal("accepted mtu 100")
	}
	s.Interfaces[0].MTU = 10000
	if s.Validate() == nil {
		t.Fatal("accepted mtu 10000")
	}
	s.Interfaces[0].MTU = 1400
	s.Interfaces[0].EgressInterface = "bad iface"
	if s.Validate() == nil {
		t.Fatal("accepted egress interface with space")
	}
	s.Interfaces[0].EgressInterface = "interface-name-too-long"
	if s.Validate() == nil {
		t.Fatal("accepted overlong egress interface")
	}
	s.Interfaces[0].EgressInterface = "eth0"
	s.Interfaces[0].SNATIP = "not-an-ip"
	if s.Validate() == nil {
		t.Fatal("accepted invalid snat_ip")
	}
}

func TestOmittedNetworkFieldsPreserveChecksum(t *testing.T) {
	b, err := os.ReadFile("../../schema/examples/state.example.json")
	if err != nil {
		t.Fatal(err)
	}
	var s State
	if err := json.Unmarshal(b, &s); err != nil {
		t.Fatal(err)
	}
	before := s.Checksum()
	s.Interfaces[0].MTU = 0
	s.Interfaces[0].EgressInterface = ""
	s.Interfaces[0].SNATIP = ""
	if got := s.Checksum(); got != before {
		t.Fatalf("omitted fields changed checksum: %s != %s", got, before)
	}
}

func TestClientModeContract(t *testing.T) {
	b, err := os.ReadFile("../../schema/examples/state.probe.example.json")
	if err != nil {
		t.Fatal(err)
	}
	var valid State
	if err := json.Unmarshal(b, &valid); err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name    string
		edit    func(*State)
		wantErr bool
	}{
		{"client zero port endpoint and keepalive", func(*State) {}, false},
		{"server zero port", func(s *State) { s.Interfaces[0].Mode = "" }, true},
		{"bogus mode", func(s *State) { s.Interfaces[0].Mode = "bogus" }, true},
		{"hostname endpoint", func(s *State) { s.Interfaces[0].Peers[0].Endpoint = "example.com:1234" }, true},
		{"zero endpoint port", func(s *State) { s.Interfaces[0].Peers[0].Endpoint = "192.0.2.10:0" }, true},
		{"IPv6 endpoint", func(s *State) { s.Interfaces[0].Peers[0].Endpoint = "[2001:db8::1]:13440" }, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := valid
			s.Interfaces = append([]Interface(nil), valid.Interfaces...)
			s.Interfaces[0].Peers = append([]Peer(nil), valid.Interfaces[0].Peers...)
			tc.edit(&s)
			err := s.Validate()
			if (err != nil) != tc.wantErr {
				t.Fatalf("Validate() error = %v, wantErr %v", err, tc.wantErr)
			}
		})
	}
}

func TestZeroValueClientFieldsPreserveChecksum(t *testing.T) {
	b, err := os.ReadFile("../../schema/examples/state.example.json")
	if err != nil {
		t.Fatal(err)
	}
	var s State
	if err := json.Unmarshal(b, &s); err != nil {
		t.Fatal(err)
	}
	before := s.Checksum()
	s.Interfaces[0].Mode = ""
	s.Interfaces[0].Peers[0].Endpoint = ""
	s.Interfaces[0].Peers[0].PersistentKeepalive = 0
	if got := s.Checksum(); got != before {
		t.Fatalf("zero-value client fields changed checksum: got %s want %s", got, before)
	}
}

func TestRejectsInvalidHeaderRanges(t *testing.T) {
	b, err := os.ReadFile("../../schema/examples/state.example.json")
	if err != nil {
		t.Fatal(err)
	}
	var s State
	if err := json.Unmarshal(b, &s); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct{ h1, h2 string }{{"20-10", "30"}, {"10-20", "20-30"}, {"4294967296", "30"}} {
		s.Interfaces[0].Obfuscation.H1, s.Interfaces[0].Obfuscation.H2 = tc.h1, tc.h2
		if err := s.Validate(); err == nil {
			t.Errorf("accepted h1=%q h2=%q", tc.h1, tc.h2)
		}
	}
}

func TestHopContract(t *testing.T) {
	if (State{}).String() != "[redacted]" || (State{}).LogValue().String() != "[redacted]" || (Interface{}).String() != "[redacted]" || (Interface{}).LogValue().String() != "[redacted]" || (Peer{}).String() != "[redacted]" || (Peer{}).LogValue().String() != "[redacted]" || (Hop{}).String() != "[redacted]" || (Hop{}).LogValue().String() != "[redacted]" || (HopRoute{}).String() != "[redacted]" || (HopRoute{}).LogValue().String() != "[redacted]" {
		t.Fatal("redaction methods")
	}
	base := State{Revision: 1, Interfaces: []Interface{}, Hop: &Hop{WANInterface: "eth0", HopIP: "192.0.2.10", Routes: []HopRoute{{ListenPort: 51820, BackendIP: "10.0.0.2", BackendPort: 51820}}}}
	if err := base.Validate(); err != nil {
		t.Fatal(err)
	}
	fixture, err := os.ReadFile("../../schema/examples/state.example.json")
	if err != nil {
		t.Fatal(err)
	}
	var collision State
	if err := json.Unmarshal(fixture, &collision); err != nil {
		t.Fatal(err)
	}
	collision.Hop = &Hop{WANInterface: "eth0", HopIP: "192.0.2.10", Routes: []HopRoute{{ListenPort: int(collision.Interfaces[0].ListenPort), BackendIP: "10.0.0.2", BackendPort: 51820}}}
	if collision.Validate() == nil {
		t.Fatal("accepted hop/interface port collision")
	}
	empty := base
	empty.Hop = &Hop{WANInterface: "eth0", HopIP: "192.0.2.10"}
	if err := empty.Validate(); err != nil {
		t.Fatalf("empty routes: %v", err)
	}
	for _, tc := range []struct {
		name   string
		mutate func(*State)
	}{
		{"duplicate listen_port", func(s *State) { s.Hop.Routes = append(s.Hop.Routes, s.Hop.Routes[0]) }},
		{"bad hop ip", func(s *State) { s.Hop.HopIP = "127.0.0.1" }},
		{"bad backend ip", func(s *State) { s.Hop.Routes[0].BackendIP = "0.0.0.0" }},
		{"backend equals hop", func(s *State) { s.Hop.Routes[0].BackendIP = s.Hop.HopIP }},
		{"bad port", func(s *State) { s.Hop.Routes[0].ListenPort = 65536 }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := base
			s.Hop = &Hop{WANInterface: base.Hop.WANInterface, HopIP: base.Hop.HopIP, Routes: append([]HopRoute(nil), base.Hop.Routes...)}
			tc.mutate(&s)
			if s.Validate() == nil {
				t.Fatal("accepted invalid hop")
			}
		})
	}
	invalidBackend := base
	invalidBackend.Hop = &Hop{WANInterface: "eth0", HopIP: "192.0.2.10", Routes: []HopRoute{{ListenPort: 51820, BackendIP: "2001:db8::1", BackendPort: 51820}}}
	if invalidBackend.Validate() == nil {
		t.Fatal("accepted IPv6 backend")
	}
	tooMany := base
	tooMany.Hop = &Hop{WANInterface: "eth0", HopIP: "192.0.2.10", Routes: make([]HopRoute, 257)}
	if tooMany.Validate() == nil {
		t.Fatal("accepted more than 256 routes")
	}
	for _, tc := range []struct {
		name   string
		mutate func(*Hop)
	}{
		{"wan", func(h *Hop) { h.WANInterface = "bad iface" }},
		{"long wan", func(h *Hop) { h.WANInterface = "interface-name-too-long" }},
		{"non-ipv4", func(h *Hop) { h.HopIP = "2001:db8::1" }},
		{"multicast", func(h *Hop) { h.HopIP = "224.0.0.1" }},
		{"route name", func(h *Hop) { h.Routes[0].Name = "bad name" }},
		{"backend port", func(h *Hop) { h.Routes[0].BackendPort = 0 }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := base
			s.Hop = &Hop{WANInterface: base.Hop.WANInterface, HopIP: base.Hop.HopIP, Routes: append([]HopRoute(nil), base.Hop.Routes...)}
			tc.mutate(s.Hop)
			if s.Validate() == nil {
				t.Fatal("accepted invalid hop")
			}
		})
	}
	old := fixture
	var oldState State
	if err = json.Unmarshal(old, &oldState); err != nil {
		t.Fatal(err)
	}
	if oldState.Hop != nil {
		t.Fatal("old example unexpectedly has hop")
	}
	oldChecksum := oldState.Checksum()
	if got := oldState.Checksum(); got != oldChecksum {
		t.Fatal("hop omission changed existing checksum")
	}
	oldState.Hop = nil
	if oldState.Checksum() != oldChecksum {
		t.Fatal("nil hop changed existing checksum")
	}
	changed := base
	changed.Hop = &Hop{WANInterface: base.Hop.WANInterface, HopIP: base.Hop.HopIP, Routes: append([]HopRoute(nil), base.Hop.Routes...)}
	changed.Hop.Routes[0].BackendIP = "10.0.0.3"
	if base.Checksum() == changed.Checksum() {
		t.Fatal("backend change missing from checksum")
	}
	reordered := base
	reordered.Hop = &Hop{WANInterface: "eth0", HopIP: "192.0.2.10", Routes: []HopRoute{{ListenPort: 51821, BackendIP: "10.0.0.3", BackendPort: 80}, {ListenPort: 51820, BackendIP: "10.0.0.2", BackendPort: 51820}}}
	ordered := reordered
	ordered.Hop = &Hop{WANInterface: "eth0", HopIP: "192.0.2.10", Routes: []HopRoute{reordered.Hop.Routes[1], reordered.Hop.Routes[0]}}
	if reordered.Checksum() != ordered.Checksum() {
		t.Fatal("route input ordering changed checksum")
	}
}
