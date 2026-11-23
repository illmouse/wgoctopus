package state

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/netip"
	"sort"
	"strconv"
	"strings"
)

type State struct {
	Revision   uint64      `json:"revision"`
	Interfaces []Interface `json:"interfaces"`
	Hop        *Hop        `json:"hop,omitempty"`
}

func (State) String() string       { return "[redacted]" }
func (State) LogValue() slog.Value { return slog.StringValue("[redacted]") }

type Interface struct {
	Name            string      `json:"name"`
	Mode            string      `json:"mode,omitempty"`
	ListenPort      uint16      `json:"listen_port"`
	PrivateKey      string      `json:"private_key"`
	Address         string      `json:"address"`
	MTU             int         `json:"mtu,omitempty"`
	EgressInterface string      `json:"egress_interface,omitempty"`
	SNATIP          string      `json:"snat_ip,omitempty"`
	Obfuscation     Obfuscation `json:"obfuscation"`
	Peers           []Peer      `json:"peers"`
}

func (Interface) String() string       { return "[redacted]" }
func (Interface) LogValue() slog.Value { return slog.StringValue("[redacted]") }

type Obfuscation struct {
	JC   uint32 `json:"jc"`
	JMin uint32 `json:"jmin"`
	JMax uint32 `json:"jmax"`
	S1   uint16 `json:"s1"`
	S2   uint16 `json:"s2"`
	S3   uint16 `json:"s3"`
	S4   uint16 `json:"s4"`
	H1   string `json:"h1"`
	H2   string `json:"h2"`
	H3   string `json:"h3"`
	H4   string `json:"h4"`
	I1   string `json:"i1,omitempty"`
	I2   string `json:"i2,omitempty"`
	I3   string `json:"i3,omitempty"`
	I4   string `json:"i4,omitempty"`
	I5   string `json:"i5,omitempty"`
}
type Peer struct {
	PublicKey           string   `json:"public_key"`
	PresharedKey        string   `json:"preshared_key,omitempty"`
	AllowedIPs          []string `json:"allowed_ips"`
	Endpoint            string   `json:"endpoint,omitempty"`
	PersistentKeepalive uint16   `json:"persistent_keepalive,omitempty"`
}

type Hop struct {
	WANInterface string     `json:"wan_interface"`
	HopIP        string     `json:"hop_ip"`
	Routes       []HopRoute `json:"routes"`
}

type HopRoute struct {
	ListenPort  int    `json:"listen_port"`
	BackendIP   string `json:"backend_ip"`
	BackendPort int    `json:"backend_port"`
	Name        string `json:"name,omitempty"`
}

func (Hop) String() string            { return "[redacted]" }
func (Hop) LogValue() slog.Value      { return slog.StringValue("[redacted]") }
func (HopRoute) String() string       { return "[redacted]" }
func (HopRoute) LogValue() slog.Value { return slog.StringValue("[redacted]") }

func (Peer) String() string       { return "[redacted]" }
func (Peer) LogValue() slog.Value { return slog.StringValue("[redacted]") }

func (s State) Validate() error {
	names := map[string]bool{}
	ports := map[uint16]bool{}
	for _, in := range s.Interfaces {
		if in.Name == "" || len(in.Name) > 15 || names[in.Name] {
			return fmt.Errorf("invalid or duplicate interface name %q", in.Name)
		}
		names[in.Name] = true
		if in.Mode != "" && in.Mode != "client" {
			return fmt.Errorf("interface %s: mode must be empty or client", in.Name)
		}
		if in.ListenPort == 0 && in.Mode != "client" {
			return fmt.Errorf("interface %s: listen_port must be 1..65535", in.Name)
		}
		ports[in.ListenPort] = true
		if err := key(in.PrivateKey); err != nil {
			return fmt.Errorf("interface %s private_key: %w", in.Name, err)
		}
		if _, err := netip.ParsePrefix(in.Address); err != nil {
			return fmt.Errorf("interface %s address: invalid CIDR", in.Name)
		}
		if in.MTU != 0 && (in.MTU < 576 || in.MTU > 9000) {
			return fmt.Errorf("interface %s: mtu must be 576..9000", in.Name)
		}
		if in.EgressInterface != "" {
			if len(in.EgressInterface) > 15 {
				return fmt.Errorf("interface %s: invalid egress_interface", in.Name)
			}
			for _, r := range in.EgressInterface {
				if !(r >= 'A' && r <= 'Z' || r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || strings.ContainsRune("_=+.-", r)) {
					return fmt.Errorf("interface %s: invalid egress_interface", in.Name)
				}
			}
		}
		if in.SNATIP != "" {
			if _, err := netip.ParseAddr(in.SNATIP); err != nil {
				return fmt.Errorf("interface %s: invalid snat_ip", in.Name)
			}
		}
		o := in.Obfuscation
		if o.JMin > o.JMax {
			return fmt.Errorf("interface %s: jmin exceeds jmax", in.Name)
		}
		headerRanges := [][2]uint64{}
		for i, h := range []string{o.H1, o.H2, o.H3, o.H4} {
			if h == "" {
				return fmt.Errorf("interface %s: H values required", in.Name)
			}
			parts := strings.Split(h, "-")
			if len(parts) > 2 {
				return fmt.Errorf("interface %s: h%d must be an integer or integer range", in.Name, i+1)
			}
			lo, err := strconv.ParseUint(parts[0], 10, 32)
			if err != nil {
				return fmt.Errorf("interface %s: invalid h%d range: %w", in.Name, i+1, err)
			}
			hi := lo
			if len(parts) == 2 {
				hi, err = strconv.ParseUint(parts[1], 10, 32)
				if err != nil || hi < lo {
					return fmt.Errorf("interface %s: invalid h%d range; upper bound must be >= lower bound and fit uint32", in.Name, i+1)
				}
			}
			for _, r := range headerRanges {
				if lo <= r[1] && r[0] <= hi {
					return fmt.Errorf("interface %s: h%d range overlaps another header range", in.Name, i+1)
				}
			}
			headerRanges = append(headerRanges, [2]uint64{lo, hi})
		}
		peers := map[string]bool{}
		for _, p := range in.Peers {
			if err := key(p.PublicKey); err != nil {
				return fmt.Errorf("peer public_key: %w", err)
			}
			if peers[p.PublicKey] {
				return fmt.Errorf("duplicate peer public_key")
			}
			peers[p.PublicKey] = true
			if p.PresharedKey != "" {
				if err := key(p.PresharedKey); err != nil {
					return fmt.Errorf("peer preshared_key: %w", err)
				}
			}
			if p.Endpoint != "" {
				endpoint, err := netip.ParseAddrPort(p.Endpoint)
				if err != nil || endpoint.Port() == 0 {
					return fmt.Errorf("peer endpoint must be an IP literal host:port with port 1..65535")
				}
			}
			if len(p.AllowedIPs) == 0 {
				return fmt.Errorf("peer allowed_ips must not be empty")
			}
			for _, ip := range p.AllowedIPs {
				if _, err := netip.ParsePrefix(ip); err != nil {
					return fmt.Errorf("invalid allowed_ips CIDR %q", ip)
				}
			}
		}
	}
	if s.Hop != nil {
		h := s.Hop
		if !validIface(h.WANInterface) {
			return fmt.Errorf("invalid hop wan_interface")
		}
		hopIP, err := netip.ParseAddr(h.HopIP)
		if err != nil || !hopIP.Is4() || hopIP.IsUnspecified() || hopIP.IsLoopback() || hopIP.IsMulticast() {
			return fmt.Errorf("invalid hop hop_ip")
		}
		if len(h.Routes) > 256 {
			return fmt.Errorf("hop routes exceeds 256")
		}
		seen := map[int]bool{}
		for _, r := range h.Routes {
			if r.ListenPort < 1 || r.ListenPort > 65535 || seen[r.ListenPort] {
				return fmt.Errorf("invalid or duplicate hop listen_port")
			}
			seen[r.ListenPort] = true
			if ports[uint16(r.ListenPort)] {
				return fmt.Errorf("hop listen_port collides with interface")
			}
			ip, err := netip.ParseAddr(r.BackendIP)
			if err != nil || !ip.Is4() || ip.IsUnspecified() || ip.IsLoopback() || ip.IsMulticast() || ip == hopIP {
				return fmt.Errorf("invalid hop backend_ip")
			}
			if r.BackendPort < 1 || r.BackendPort > 65535 {
				return fmt.Errorf("invalid hop backend_port")
			}
			if r.Name != "" && !validIface(r.Name) {
				return fmt.Errorf("invalid hop route name")
			}
		}
	}
	return nil
}

func validIface(name string) bool {
	if name == "" || len(name) > 15 {
		return false
	}
	for _, r := range name {
		if !(r >= 'A' && r <= 'Z' || r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || strings.ContainsRune("_=+.-", r)) {
			return false
		}
	}
	return true
}
func key(s string) error {
	b, e := base64.StdEncoding.DecodeString(s)
	if e != nil || len(b) != 32 {
		return fmt.Errorf("must be base64 encoding of 32 bytes")
	}
	return nil
}
func (s State) Canonical() ([]byte, error) {
	if s.Hop != nil {
		sort.Slice(s.Hop.Routes, func(i, j int) bool { return s.Hop.Routes[i].ListenPort < s.Hop.Routes[j].ListenPort })
	}
	for i := range s.Interfaces {
		sort.Slice(s.Interfaces[i].Peers, func(a, b int) bool { return s.Interfaces[i].Peers[a].PublicKey < s.Interfaces[i].Peers[b].PublicKey })
		for j := range s.Interfaces[i].Peers {
			sort.Strings(s.Interfaces[i].Peers[j].AllowedIPs)
		}
	}
	sort.Slice(s.Interfaces, func(i, j int) bool { return s.Interfaces[i].Name < s.Interfaces[j].Name })
	return json.Marshal(s)
}
func (s State) Checksum() string {
	b, _ := s.Canonical()
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}
