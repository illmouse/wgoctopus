package uapi

import (
	"bufio"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"time"
)

// Peer contains UAPI-visible configuration and counters for one peer.
type Peer struct {
	PublicKey, PresharedKey             string
	AllowedIPs                          []string
	Endpoint                            string
	LastHandshakeSec, LastHandshakeNSec uint64
	RxBytes, TxBytes                    uint64
	PersistentKeepalive                 string
}

// Live is a device snapshot. Keys are base64-encoded, matching state.State.
type Live struct {
	PrivateKey, ListenPort string
	Fields                 map[string]string
	Peers                  map[string]Peer
}

// PeerOp describes one peer mutation.
type PeerOp struct {
	PublicKey           string
	Remove, UpdateOnly  bool
	PresharedKey        *string
	Endpoint            *string
	PersistentKeepalive *uint16
	ReplaceAllowedIPs   bool
	AllowedIPs          []string
}

// Ops describes a batch of interface and peer mutations.
type Ops struct {
	Fields map[string]string
	Peers  []PeerOp
}

// Device is the minimum device API needed by reconciliation.
type Device interface {
	Get() (Live, error)
	Set(Ops) error
}

// Client communicates with a device over its Unix UAPI socket.
type Client struct {
	Socket  string
	Timeout time.Duration
}

// Parse decodes a WireGuard UAPI response into canonical live state.
func Parse(r io.Reader) (Live, error) {
	d := Live{Fields: map[string]string{}, Peers: map[string]Peer{}}
	s := bufio.NewScanner(r)
	var current *Peer
	for s.Scan() {
		line := s.Text()
		if line == "" {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			return Live{}, fmt.Errorf("invalid UAPI line %q", line)
		}
		if k == "errno" {
			n, e := strconv.Atoi(v)
			if e != nil {
				return Live{}, e
			}
			if n != 0 {
				return Live{}, fmt.Errorf("UAPI errno=%d", n)
			}
			return d, nil
		}
		if k == "public_key" {
			key := hexToBase64(v)
			p := Peer{PublicKey: key}
			d.Peers[key] = p
			current = &p
			continue
		}
		if current != nil {
			switch k {
			case "preshared_key":
				current.PresharedKey = hexToBase64(v)
				if strings.Trim(v, "0") == "" {
					current.PresharedKey = ""
				}
			case "allowed_ip":
				current.AllowedIPs = append(current.AllowedIPs, v)
			case "endpoint":
				current.Endpoint = v
			case "last_handshake_time_sec":
				current.LastHandshakeSec, _ = strconv.ParseUint(v, 10, 64)
			case "last_handshake_time_nsec":
				current.LastHandshakeNSec, _ = strconv.ParseUint(v, 10, 64)
			case "rx_bytes":
				current.RxBytes, _ = strconv.ParseUint(v, 10, 64)
			case "tx_bytes":
				current.TxBytes, _ = strconv.ParseUint(v, 10, 64)
			case "persistent_keepalive_interval":
				current.PersistentKeepalive = v
			}
			d.Peers[current.PublicKey] = *current
		} else {
			if k == "header_protection_key" {
				if strings.Trim(v, "0") == "" {
					v = ""
				} else {
					v = hexToBase64(v)
				}
			}
			if isRangeField(k) {
				v = canonicalRange(v)
			}
			if k == "private_key" {
				d.PrivateKey = hexToBase64(v)
				d.Fields[k] = d.PrivateKey
			} else {
				d.Fields[k] = v
			}
			if k == "listen_port" {
				d.ListenPort = v
			}
		}
	}
	if e := s.Err(); e != nil {
		return Live{}, e
	}
	return d, nil
}
func hexToBase64(s string) string {
	b, e := hex.DecodeString(s)
	if e != nil || len(b) != 32 {
		return s
	}
	return base64.StdEncoding.EncodeToString(b)
}
func keyHex(s string) (string, error) {
	b, e := decode64(s)
	if e != nil || len(b) != 32 {
		return "", fmt.Errorf("key must be base64 of 32 bytes")
	}
	return hex.EncodeToString(b), nil
}
func decode64(s string) ([]byte, error) { return base64.StdEncoding.DecodeString(s) }
func Serialize(o Ops) (string, error) {
	var b strings.Builder
	keys := []string{"private_key", "listen_port", "jc", "jmin", "jmax", "s1", "s2", "s3", "s4", "h1", "h2", "h3", "h4", "i1", "i2", "i3", "i4", "i5", "header_protection_key", "content_padding_addition", "rekey_after_time", "rekey_timeout", "reject_after_time", "keepalive_timeout", "max_handshake_attempts", "random_trailers", "disable_cookies"}
	for _, k := range keys {
		if v, ok := o.Fields[k]; ok {
			if k == "private_key" || k == "header_protection_key" {
				if k == "header_protection_key" && (v == "" || strings.Trim(v, "0") == "") {
					v = strings.Repeat("0", 64)
					fmt.Fprintf(&b, "%s=%s\n", k, v)
					continue
				}
				x, e := keyHex(v)
				if e != nil {
					return "", e
				}
				v = x
			}
			fmt.Fprintf(&b, "%s=%s\n", k, v)
		}
	}
	for _, p := range o.Peers {
		k, e := keyHex(p.PublicKey)
		if e != nil {
			return "", e
		}
		fmt.Fprintf(&b, "public_key=%s\n", k)
		if p.Remove {
			b.WriteString("remove=true\n")
			continue
		}
		if p.UpdateOnly {
			b.WriteString("update_only=true\n")
		}
		if p.Endpoint != nil && *p.Endpoint != "" {
			fmt.Fprintf(&b, "endpoint=%s\n", *p.Endpoint)
		}
		if p.PersistentKeepalive != nil {
			fmt.Fprintf(&b, "persistent_keepalive_interval=%d\n", *p.PersistentKeepalive)
		}
		if p.PresharedKey != nil {
			v := ""
			if *p.PresharedKey != "" {
				v, e = keyHex(*p.PresharedKey)
				if e != nil {
					return "", e
				}
			} else {
				v = strings.Repeat("0", 64)
			}
			fmt.Fprintf(&b, "preshared_key=%s\n", v)
		}
		if p.ReplaceAllowedIPs {
			b.WriteString("replace_allowed_ips=true\n")
			for _, ip := range p.AllowedIPs {
				if _, e := netip.ParsePrefix(ip); e != nil {
					return "", e
				}
				fmt.Fprintf(&b, "allowed_ip=%s\n", ip)
			}
		}
	}
	b.WriteByte('\n')
	return b.String(), nil
}
func isRangeField(k string) bool {
	switch k {
	case "content_padding_addition", "rekey_after_time", "rekey_timeout", "reject_after_time", "keepalive_timeout", "max_handshake_attempts":
		return true
	}
	return false
}
func canonicalRange(v string) string {
	p := strings.Split(v, "-")
	if len(p) == 2 && p[0] == p[1] {
		return p[0]
	}
	return v
}

// Get retrieves the current device state.
func (c Client) Get() (Live, error) { return c.request("get=1\n\n", true) }

// Set applies an operation batch to the device.
func (c Client) Set(o Ops) error {
	s, e := Serialize(o)
	if e != nil {
		return e
	}
	_, e = c.request("set=1\n"+s, false)
	return e
}
func (c Client) request(req string, get bool) (Live, error) {
	conn, e := net.Dial("unix", c.Socket)
	if e != nil {
		return Live{}, e
	}
	defer conn.Close()
	timeout := c.Timeout
	if timeout == 0 {
		timeout = 5 * time.Second
	}
	if e = conn.SetDeadline(time.Now().Add(timeout)); e != nil {
		return Live{}, e
	}
	if _, e = io.WriteString(conn, req); e != nil {
		return Live{}, e
	}
	if get {
		return Parse(conn)
	}
	return Parse(conn)
}
