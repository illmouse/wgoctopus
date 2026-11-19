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
