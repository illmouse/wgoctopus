package uapi

import (
	"bufio"
	"encoding/base64"
	"errors"
	"net"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestParseKeyEncodingAndPeerFields(t *testing.T) {
	key := strings.Repeat("01", 32)
	live, err := Parse(strings.NewReader("private_key=" + key + "\npublic_key=" + key + "\npreshared_key=" + key + "\nallowed_ip=10.0.0.0/24\nunknown=value\nerrno=0\n"))
	if err != nil {
		t.Fatal(err)
	}
	peerKey := "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE="
	peer, ok := live.Peers[peerKey]
	if live.PrivateKey != peerKey || live.Fields["private_key"] != peerKey || !ok || peer.PresharedKey != peerKey || len(peer.AllowedIPs) != 1 {
		t.Fatal("UAPI keys were not decoded to canonical base64")
	}
}

func TestParseAWGGetWithOmittedDefaults(t *testing.T) {
	key := "00" + strings.Repeat("01", 30) + "41"
	privateKey := make([]byte, 32)
	for i := range privateKey {
		privateKey[i] = 1
	}
	privateKey[0] = 0
	privateKey[31] = 0x41
	wantKey := base64.StdEncoding.EncodeToString(privateKey)
	live, err := Parse(strings.NewReader("private_key=" + key + "\nh1=100-200\nh2=300-400\nh3=500-600\nh4=700-800\nerrno=0\n"))
	if err != nil {
		t.Fatal(err)
	}
	if live.PrivateKey != wantKey || live.Fields["jc"] != "" || live.Fields["h1"] != "100-200" {
		t.Fatalf("unexpected AWG get state: key matches=%v, fields=%v", live.PrivateKey == wantKey, live.Fields)
	}
}

func TestSerializeKeyAndPeerRemoval(t *testing.T) {
	key := "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE="
	got, err := Serialize(Ops{Peers: []PeerOp{{PublicKey: key, PresharedKey: ptr(""), ReplaceAllowedIPs: true, AllowedIPs: []string{"10.0.0.0/24"}}}})
	if err != nil {
		t.Fatal(err)
	}
	want := "public_key=" + strings.Repeat("01", 32) + "\npreshared_key=" + strings.Repeat("0", 64) + "\nreplace_allowed_ips=true\nallowed_ip=10.0.0.0/24\n\n"
	if got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}

func TestSerializePeerEndpointAndKeepalive(t *testing.T) {
	key := "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE="
	endpoint, keepalive := "192.0.2.1:51820", uint16(25)
	got, err := Serialize(Ops{Peers: []PeerOp{{PublicKey: key, Endpoint: &endpoint, PersistentKeepalive: &keepalive}}})
	if err != nil {
		t.Fatal(err)
	}
	want := "public_key=" + strings.Repeat("01", 32) + "\nendpoint=192.0.2.1:51820\npersistent_keepalive_interval=25\n\n"
	if got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
	keepalive = 0
	got, err = Serialize(Ops{Peers: []PeerOp{{PublicKey: key, Endpoint: ptr(""), PersistentKeepalive: &keepalive}}})
	if err != nil || strings.Contains(got, "endpoint=\n") || !strings.Contains(got, "persistent_keepalive_interval=0\n") {
		t.Fatalf("zero keepalive/empty endpoint serialization: %q, %v", got, err)
	}
}

func ptr(s string) *string { return &s }

func TestParseErrorsAndInvalidLines(t *testing.T) {
	for _, input := range []string{"badline\n", "errno=nope\n", "errno=5\n"} {
		if _, err := Parse(strings.NewReader(input)); err == nil {
			t.Fatalf("Parse(%q) succeeded", input)
		}
	}
	if _, err := Parse(strings.NewReader("private_key=not-hex\n")); err != nil {
		t.Fatal(err)
	}
}

func TestParseZeroPresharedKeyAsUnset(t *testing.T) {
	key := strings.Repeat("01", 32)
	live, err := Parse(strings.NewReader("public_key=" + key + "\npreshared_key=" + strings.Repeat("0", 64) + "\nerrno=0\n"))
	if err != nil {
		t.Fatal(err)
	}
	if live.Peers["AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE="].PresharedKey != "" {
		t.Fatal("zero psk was not normalized to unset")
	}
}

func TestSerializeFieldsAndRemove(t *testing.T) {
	key := "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE="
	got, err := Serialize(Ops{Fields: map[string]string{"private_key": key, "listen_port": "12", "jc": "1", "jmin": "2", "jmax": "3", "s1": "4", "s2": "5", "s3": "6", "s4": "7", "h1": "8", "h2": "9", "h3": "10", "h4": "11", "i1": "a", "i2": "b", "i3": "c", "i4": "d", "i5": "e"}, Peers: []PeerOp{{PublicKey: key, Remove: true}}})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(got, "private_key="+strings.Repeat("01", 32)+"\n") || !strings.Contains(got, "remove=true\n") {
		t.Fatal(got)
	}
	if _, err := Serialize(Ops{Fields: map[string]string{"private_key": "bad"}}); err == nil {
		t.Fatal("invalid key accepted")
	}
	if _, err := Serialize(Ops{Peers: []PeerOp{{PublicKey: "bad"}}}); err == nil {
		t.Fatal("invalid peer key accepted")
	}
	if _, err := Serialize(Ops{Peers: []PeerOp{{PublicKey: key, PresharedKey: ptr("bad")}}}); err == nil {
		t.Fatal("invalid psk accepted")
	}
	if _, err := Serialize(Ops{Peers: []PeerOp{{PublicKey: key, ReplaceAllowedIPs: true, AllowedIPs: []string{"bad"}}}}); err == nil {
		t.Fatal("invalid prefix accepted")
	}
}

func TestClientSocketRoundTripAndErrno(t *testing.T) {
	dir := t.TempDir()
	socket := filepath.Join(dir, "uapi.sock")
	serve := func(response string) net.Listener {
		l, err := net.Listen("unix", socket)
		if err != nil {
			t.Fatal(err)
		}
		go func() {
			defer l.Close()
			c, e := l.Accept()
			if e == nil {
				defer c.Close()
				scanner := bufio.NewScanner(c)
				for scanner.Scan() && scanner.Text() != "" {
				}
				if scanner.Err() != nil {
					t.Error(scanner.Err())
					return
				}
				_, _ = c.Write([]byte(response))
			}
		}()
		return l
	}
	listener := serve("errno=0\n")
	if _, err := (Client{Socket: socket, Timeout: time.Second}).Get(); err != nil {
		t.Fatal(err)
	}
	listener.Close()
	listener = serve("errno=7\n")
	if err := (Client{Socket: socket, Timeout: time.Second}).Set(Ops{}); err == nil {
		t.Fatal("nonzero errno accepted")
	}
	listener.Close()
}

func TestSetSendsAWGFieldsInDaemonFormat(t *testing.T) {
	socket := filepath.Join(t.TempDir(), "uapi.sock")
	l, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	got := make(chan string, 1)
	go func() {
		c, err := l.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		var b strings.Builder
		r := bufio.NewReader(c)
		for {
			line, err := r.ReadString('\n')
			b.WriteString(line)
			if err != nil || line == "\n" {
				break
			}
		}
		got <- b.String()
		_, _ = c.Write([]byte("errno=0\n\n"))
	}()
	key := "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE="
	err = (Client{Socket: socket, Timeout: time.Second}).Set(Ops{Fields: map[string]string{
		"private_key": key, "listen_port": "51820", "jc": "5", "jmin": "100", "jmax": "200",
		"s1": "15", "s2": "18", "s3": "20", "s4": "25", "h1": "100-200", "h2": "300-400", "h3": "500-600", "h4": "700-800",
	}})
	if err != nil {
		t.Fatal(err)
	}
	want := "set=1\nprivate_key=" + strings.Repeat("01", 32) + "\nlisten_port=51820\njc=5\njmin=100\njmax=200\ns1=15\ns2=18\ns3=20\ns4=25\nh1=100-200\nh2=300-400\nh3=500-600\nh4=700-800\n\n"
	if wire := <-got; wire != want {
		t.Fatalf("set payload mismatch\n got: %q\nwant: %q", wire, want)
	}
}

func TestClientTimeout(t *testing.T) {
	socket := filepath.Join(t.TempDir(), "uapi.sock")
	l, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	go func() {
		c, e := l.Accept()
		if e == nil {
			defer c.Close()
			_, _ = bufio.NewReader(c).ReadString('\n')
			time.Sleep(200 * time.Millisecond)
		}
	}()
	start := time.Now()
	_, err = (Client{Socket: socket, Timeout: 30 * time.Millisecond}).Get()
	if err == nil || time.Since(start) > time.Second {
		t.Fatalf("timeout err=%v duration=%v", err, time.Since(start))
	}
}

type brokenReader struct{}

func (brokenReader) Read([]byte) (int, error) { return 0, errors.New("read failed") }

func TestReadAndDialFailures(t *testing.T) {
	if _, err := Parse(brokenReader{}); err == nil {
		t.Fatal("reader error was ignored")
	}
	if _, err := (Client{Socket: "/missing/uapi.sock"}).Get(); err == nil {
		t.Fatal("dial error was ignored")
	}
}
