package reconcile

import (
	"encoding/base64"
	"errors"
	"net/netip"
	"sort"
	"strconv"
	"strings"

	"github.com/illmouse/wgoctopus/internal/state"
	"github.com/illmouse/wgoctopus/internal/uapi"
)

type Device = uapi.Device

// PlanResult contains the device operations and fields requiring acknowledgement.
type PlanResult struct {
	Ops       uapi.Ops
	Dangerous []string
}

// DangerousError reports fields changed without explicit operator acknowledgement.
type DangerousError struct{ Reasons []string }

func (e *DangerousError) Error() string {
	return "dangerous changes require allow_dangerous: " + strings.Join(e.Reasons, ", ")
}

// Is lets callers classify dangerous changes with errors.Is.
func (e *DangerousError) Is(target error) bool { return target == ErrDangerous }

// GetReasons returns the dangerous fields that changed.
func (e *DangerousError) GetReasons() []string { return append([]string(nil), e.Reasons...) }

var ErrDangerous = errors.New("dangerous changes require allow_dangerous")

// Plan computes deterministic device changes for one desired interface.
func Plan(w state.Interface, l uapi.Live) PlanResult {
	r := PlanResult{Ops: uapi.Ops{Fields: map[string]string{}}}
	newInterface := l.PrivateKey == ""
	fields := map[string]string{
		"private_key": normalizePrivateKey(w.PrivateKey),
		"jc":          strconv.FormatUint(uint64(w.Obfuscation.JC), 10), "jmin": strconv.FormatUint(uint64(w.Obfuscation.JMin), 10), "jmax": strconv.FormatUint(uint64(w.Obfuscation.JMax), 10),
		"s1": strconv.Itoa(int(w.Obfuscation.S1)), "s2": strconv.Itoa(int(w.Obfuscation.S2)), "s3": strconv.Itoa(int(w.Obfuscation.S3)), "s4": strconv.Itoa(int(w.Obfuscation.S4)),
		"h1": w.Obfuscation.H1, "h2": w.Obfuscation.H2, "h3": w.Obfuscation.H3, "h4": w.Obfuscation.H4,
		"i1": w.Obfuscation.I1, "i2": w.Obfuscation.I2, "i3": w.Obfuscation.I3, "i4": w.Obfuscation.I4, "i5": w.Obfuscation.I5,
	}
	if w.ListenPort != 0 || w.Mode != "client" {
		fields["listen_port"] = strconv.Itoa(int(w.ListenPort))
	}
	defaults := map[string]string{"jc": "0", "jmin": "0", "jmax": "0", "s1": "0", "s2": "0", "s3": "0", "s4": "0", "h1": "0", "h2": "0", "h3": "0", "h4": "0", "i1": "", "i2": "", "i3": "", "i4": "", "i5": ""}
	for k, v := range fields {
		old := l.Fields[k]
		if old == "" {
			old = defaults[k]
		}
		if normalize(old) != normalize(v) {
			r.Ops.Fields[k] = v
			if !newInterface && (k == "private_key" || k == "listen_port" || strings.HasPrefix(k, "s") || strings.HasPrefix(k, "h") || strings.HasPrefix(k, "i") || k == "jc" || k == "jmin" || k == "jmax") {
				reason := k
				if !contains(r.Dangerous, reason) {
					r.Dangerous = append(r.Dangerous, reason)
				}
			}
		}
	}
	want := map[string]state.Peer{}
	for _, p := range w.Peers {
		want[p.PublicKey] = p
	}
	liveKeys := make([]string, 0, len(l.Peers))
	for k := range l.Peers {
		liveKeys = append(liveKeys, k)
	}
	sort.Strings(liveKeys)
	for _, k := range liveKeys {
		if _, ok := want[k]; !ok {
			r.Ops.Peers = append(r.Ops.Peers, uapi.PeerOp{PublicKey: k, Remove: true})
		}
	}
	keys := make([]string, 0, len(want))
	for k := range want {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		p := want[k]
		old, ok := l.Peers[k]
		op := uapi.PeerOp{PublicKey: k}
		if !ok {
			op.ReplaceAllowedIPs = true
			op.AllowedIPs = canonical(p.AllowedIPs)
			if p.Endpoint != "" {
				v := p.Endpoint
				op.Endpoint = &v
			}
			if p.PersistentKeepalive > 0 {
				v := p.PersistentKeepalive
				op.PersistentKeepalive = &v
			}
			r.Ops.Peers = append(r.Ops.Peers, op)
			continue
		}
		op.UpdateOnly = true
		if normalizeKey(old.PresharedKey) != normalizeKey(p.PresharedKey) {
			v := p.PresharedKey
			op.PresharedKey = &v
		}
		if !sameIPs(old.AllowedIPs, p.AllowedIPs) {
			op.ReplaceAllowedIPs = true
			op.AllowedIPs = canonical(p.AllowedIPs)
		}
		if p.Endpoint != "" && !sameEndpoint(old.Endpoint, p.Endpoint) {
			v := p.Endpoint
			op.Endpoint = &v
		}
		if (p.PersistentKeepalive != 0 || w.Mode == "client") && parseKeepalive(old.PersistentKeepalive) != p.PersistentKeepalive {
			v := p.PersistentKeepalive
			op.PersistentKeepalive = &v
		}
		if op.PresharedKey != nil || op.ReplaceAllowedIPs || op.Endpoint != nil || op.PersistentKeepalive != nil {
			r.Ops.Peers = append(r.Ops.Peers, op)
		}
	}
	sort.Strings(r.Dangerous)
	return r
}

func sameEndpoint(a, b string) bool {
	x, errX := netip.ParseAddrPort(a)
	y, errY := netip.ParseAddrPort(b)
	return errX == nil && errY == nil && x == y
}

func parseKeepalive(s string) uint16 {
	if s == "" || s == "off" {
		return 0
	}
	n, err := strconv.ParseUint(s, 10, 16)
	if err != nil {
		return 0
	}
	return uint16(n)
}

// Apply plans and applies changes, refusing dangerous changes unless acknowledged.
func Apply(d Device, w state.Interface, allowDangerous bool) error {
	live, e := d.Get()
	if e != nil {
		return e
	}
	p := Plan(w, live)
	if len(p.Dangerous) > 0 && !allowDangerous {
		return &DangerousError{Reasons: p.Dangerous}
	}
	if len(p.Ops.Fields) == 0 && len(p.Ops.Peers) == 0 {
		return nil
	}
	return d.Set(p.Ops)
}
func normalize(s string) string { return strings.TrimSpace(s) }
func normalizePrivateKey(s string) string {
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil || len(b) != 32 {
		return s
	}
	b[0] &= 248
	b[31] &= 127
	b[31] |= 64
	return base64.StdEncoding.EncodeToString(b)
}
func normalizeKey(s string) string {
	if s == "" || strings.Trim(s, "0") == "" {
		return ""
	}
	return s
}
func canonical(a []string) []string {
	r := make([]string, 0, len(a))
	for _, s := range a {
		if p, e := netip.ParsePrefix(s); e == nil {
			r = append(r, p.Masked().String())
		} else {
			r = append(r, s)
		}
	}
	sort.Strings(r)
	return r
}
func sameIPs(a, b []string) bool {
	x, y := canonical(a), canonical(b)
	if len(x) != len(y) {
		return false
	}
	for i := range x {
		if x[i] != y[i] {
			return false
		}
	}
	return true
}
func contains(s []string, v string) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}
