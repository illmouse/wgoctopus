package hop

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/illmouse/wgoctopus/internal/netsetup"
	"github.com/illmouse/wgoctopus/internal/state"
)

const (
	dnatChain = "WGOCT_HOP_DNAT"
	snatChain = "WGOCT_HOP_SNAT"
	fwdChain  = "WGOCT_HOP_FWD"
)

type Deps struct {
	Runner          netsetup.Executor
	Path            string
	IPForwardReader func() (bool, error)
	AddrChecker     func(iface, ip string) (bool, error)
	Conntrack       Conntrack
}

type Forwarder struct {
	deps                                                     Deps
	mu                                                       sync.Mutex
	lastHopIP                                                string
	lastRoutes                                               map[int]bool
	flushedTotal, flushErrorsTotal, applyErrorsTotal, routes atomic.Int64
}
type Result struct {
	Changed                      bool
	RemovedRoutes, ChangedRoutes []int
	Warnings                     []string
	Flushed                      int
}

type Stats struct{ FlushedTotal, FlushErrorsTotal, ApplyErrorsTotal, Routes int64 }

func New(deps Deps) *Forwarder {
	if deps.Runner == nil {
		deps.Runner = netsetup.NewCommandExecutor(deps.Path)
	}
	if deps.IPForwardReader == nil {
		deps.IPForwardReader = readIPForward
	}
	if deps.AddrChecker == nil {
		deps.AddrChecker = hasAddress
	}
	return &Forwarder{deps: deps}
}

func readIPForward() (bool, error) {
	b, err := os.ReadFile("/proc/sys/net/ipv4/ip_forward")
	if err != nil {
		return false, err
	}
	v, err := strconv.Atoi(strings.TrimSpace(string(b)))
	return v == 1, err
}

func hasAddress(iface, ip string) (bool, error) {
	i, err := net.InterfaceByName(iface)
	if err != nil {
		return false, err
	}
	addrs, err := i.Addrs()
	if err != nil {
		return false, err
	}
	want, err := netip.ParseAddr(ip)
	if err != nil {
		return false, err
	}
	for _, a := range addrs {
		p, e := netip.ParsePrefix(a.String())
		if e == nil && p.Addr() == want {
			return true, nil
		}
	}
	return false, nil
}

func (f *Forwarder) run(args ...string) (string, int, error) {
	return f.deps.Runner.Run(append([]string{"-w"}, args...))
}

type rule struct {
	table, chain string
	spec         []string
}

func (r rule) add() []string {
	a := []string{}
	if r.table != "" {
		a = append(a, "-t", r.table)
	}
	return append(append(a, "-A", r.chain), r.spec...)
}
func (r rule) del() []string {
	a := []string{}
	if r.table != "" {
		a = append(a, "-t", r.table)
	}
	return append(append(a, "-D", r.chain), r.spec...)
}

func routeRules(h *state.Hop, r state.HopRoute) []rule {
	tag := []string{"-m", "comment", "--comment", fmt.Sprintf("wgoct:hop:%d", r.ListenPort)}
	return []rule{
		{"nat", dnatChain, append(append([]string{"-p", "udp", "--dport", strconv.Itoa(r.ListenPort)}, tag...), "-j", "DNAT", "--to-destination", net.JoinHostPort(r.BackendIP, strconv.Itoa(r.BackendPort)))},
		{"nat", snatChain, append(append([]string{"-p", "udp", "-d", r.BackendIP, "--dport", strconv.Itoa(r.BackendPort), "-m", "conntrack", "--ctstate", "DNAT", "--ctorigdst", h.HopIP, "--ctorigdstport", strconv.Itoa(r.ListenPort)}, tag...), "-j", "MASQUERADE")},
		{"filter", fwdChain, append(append([]string{"-i", h.WANInterface, "-o", h.WANInterface, "-p", "udp", "-d", r.BackendIP, "--dport", strconv.Itoa(r.BackendPort), "-m", "conntrack", "--ctstate", "DNAT", "--ctorigdst", h.HopIP, "--ctorigdstport", strconv.Itoa(r.ListenPort)}, tag...), "-j", "ACCEPT")},
		{"filter", fwdChain, append(append([]string{"-i", h.WANInterface, "-o", h.WANInterface, "-p", "udp", "-s", r.BackendIP, "--sport", strconv.Itoa(r.BackendPort), "-m", "conntrack", "--ctstate", "ESTABLISHED"}, tag...), "-j", "ACCEPT")},
	}
}

func (f *Forwarder) Apply(ctx context.Context, h *state.Hop) (result Result, retErr error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	defer func() {
		if retErr != nil {
			f.applyErrorsTotal.Add(1)
		}
	}()
	select {
	case <-ctx.Done():
		return Result{}, ctx.Err()
	default:
	}
	if h != nil {
		on, err := f.deps.IPForwardReader()
		if err != nil {
			return Result{}, err
		}
		if !on {
			return Result{}, fmt.Errorf("ipv4 forwarding disabled")
		}
		ok, err := f.deps.AddrChecker(h.WANInterface, h.HopIP)
		if err != nil {
			return Result{}, err
		}
		if !ok {
			return Result{}, fmt.Errorf("hop ip %s is not assigned to interface %s", h.HopIP, h.WANInterface)
		}
	}
	chains := []struct{ table, name string }{{"nat", dnatChain}, {"nat", snatChain}, {"filter", fwdChain}}
	have := map[string][]string{}
	exists := map[string]bool{}
	for _, c := range chains {
		a := []string{}
		if c.table != "" {
			a = append(a, "-t", c.table)
		}
		out, code, err := f.run(append(a, "-S", c.name)...)
		if err != nil {
			return Result{}, err
		}
		if h == nil && code != 0 {
			continue
		}
		exists[c.name] = true
		have[c.name] = nil
		for _, line := range strings.Split(out, "\n") {
			fields := strings.Fields(line)
			if len(fields) > 1 && fields[0] == "-A" && fields[1] == c.name {
				have[c.name] = append(have[c.name], line)
			}
		}
	}
	result, err := f.applyRules(h, chains, have, exists)
	if err != nil {
		return result, err
	}
	if h != nil {
		f.lastHopIP = h.HopIP
	}
	ports := map[int]bool{}
	for _, p := range append(result.ChangedRoutes, result.RemovedRoutes...) {
		ports[p] = true
	}
	for p := range ports {
		if f.deps.Conntrack == nil {
			continue
		}
		ip := f.lastHopIP
		if ip == "" {
			result.Warnings = append(result.Warnings, fmt.Sprintf("cannot flush conntrack for port %d: hop IP unknown", p))
			continue
		}
		deleted, flushErr := f.deps.Conntrack.FlushUDPOrigDst(net.ParseIP(ip), p)
		if flushErr != nil {
			result.Warnings = append(result.Warnings, fmt.Sprintf("flush conntrack for %s:%d: %v", ip, p, flushErr))
			f.flushErrorsTotal.Add(1)
			continue
		}
		result.Flushed += deleted
		f.flushedTotal.Add(int64(deleted))
	}
	if h == nil {
		f.lastHopIP = ""
	}
	routes := int64(0)
	if h != nil {
		routes = int64(len(h.Routes))
	}
	f.routes.Store(routes)
	return result, nil
}

func (f *Forwarder) Stats() Stats {
	return Stats{f.flushedTotal.Load(), f.flushErrorsTotal.Load(), f.applyErrorsTotal.Load(), f.routes.Load()}
}

func (f *Forwarder) applyRules(h *state.Hop, chains []struct{ table, name string }, have map[string][]string, exists map[string]bool) (Result, error) {
	result := Result{}
	if h == nil {
		for _, p := range []struct{ table, chain, target string }{{"nat", "PREROUTING", dnatChain}, {"nat", "POSTROUTING", snatChain}, {"filter", "FORWARD", fwdChain}} {
			a := []string{}
			if p.table != "" {
				a = append(a, "-t", p.table)
			}
			out, _, err := f.run(append(a, "-S", p.chain)...)
			if err != nil {
				return result, err
			}
			for _, line := range strings.Split(out, "\n") {
				fields, e := netsetup.SplitRule(line)
				if e != nil {
					return result, e
				}
				if len(fields) > 2 && fields[0] == "-A" && fields[1] == p.chain && fields[len(fields)-1] == p.target {
					del := append(append([]string{}, a...), "-D", p.chain)
					if _, _, e = f.run(append(del, fields[2:]...)...); e != nil {
						return result, e
					}
					result.Changed = true
				}
			}
		}
		for _, c := range chains {
			if !exists[c.name] {
				continue
			}
			for _, line := range have[c.name] {
				fields, err := netsetup.SplitRule(line)
				if err != nil {
					return result, err
				}
				if len(fields) > 0 && strings.Contains(line, "wgoct:hop:") {
					if n, err := strconv.Atoi(strings.TrimPrefix(comment(fields), "wgoct:hop:")); err == nil {
						result.RemovedRoutes = appendUnique(result.RemovedRoutes, n)
					}
				}
			}
			a := []string{}
			if c.table != "" {
				a = append(a, "-t", c.table)
			}
			if _, code, err := f.run(append(a, "-F", c.name)...); err != nil {
				return result, err
			} else if code == 0 {
				result.Changed = true
			}
			if _, code, err := f.run(append(a, "-X", c.name)...); err != nil {
				return result, err
			} else if code == 0 {
				result.Changed = true
			}
		}
		return result, nil
	}
	for _, c := range chains {
		a := []string{}
		if c.table != "" {
			a = append(a, "-t", c.table)
		}
		if _, code, err := f.run(append(a, "-N", c.name)...); err != nil {
			return result, err
		} else if code == 0 {
			result.Changed = true
		}
	}
	// Ensure one exact owned jump, removing obsolete WAN/HopIP variants.
	for _, c := range []struct{ table, chain, target string }{{"nat", "PREROUTING", dnatChain}, {"nat", "POSTROUTING", snatChain}, {"filter", "FORWARD", fwdChain}} {
		args := []string{}
		if c.table != "" {
			args = append(args, "-t", c.table)
		}
		out, _, err := f.run(append(args, "-S", c.chain)...)
		if err != nil {
			return result, err
		}
		seen := false
		for _, line := range strings.Split(out, "\n") {
			fields, e := netsetup.SplitRule(line)
			if e != nil {
				return result, e
			}
			if len(fields) > 2 && fields[0] == "-A" && fields[1] == c.chain && fields[len(fields)-1] == c.target {
				keep := false
				for _, j := range jumpRules(h) {
					if j.table == c.table && j.chain == c.chain && strings.Join(j.spec, " ") == strings.Join(fields[2:], " ") {
						keep = true
					}
				}
				if keep && seen {
					keep = false
				}
				if !keep {
					del := append(append([]string{}, args...), "-D", c.chain)
					del = append(del, fields[2:]...)
					if _, _, e = f.run(del...); e != nil {
						return result, e
					}
					result.Changed = true
				} else {
					seen = true
				}
			}
		}
	}
	want := []rule{}
	for _, r := range h.Routes {
		want = append(want, routeRules(h, r)...)
	}
	// Replace only route tags whose live rule sequence differs.
	wantedByPort := map[int][]rule{}
	for _, r := range h.Routes {
		wantedByPort[r.ListenPort] = routeRules(h, r)
	}
	ports := map[int]bool{}
	for _, line := range append(append(append([]string{}, have[dnatChain]...), have[snatChain]...), have[fwdChain]...) {
		fields, _ := netsetup.SplitRule(line)
		if n, err := strconv.Atoi(strings.TrimPrefix(comment(fields), "wgoct:hop:")); err == nil {
			ports[n] = true
		}
	}
	for p := range wantedByPort {
		ports[p] = true
	}
	for p := range ports {
		old := taggedRules(have, p)
		nw := wantedByPort[p]
		if equalRules(old, nw) {
			continue
		}
		if len(nw) > 0 {
			for _, r := range nw {
				if _, _, err := f.run(r.add()...); err != nil {
					return result, err
				}
			}
			if len(old) > 0 {
				result.ChangedRoutes = append(result.ChangedRoutes, p)
			}
		} else {
			result.RemovedRoutes = append(result.RemovedRoutes, p)
		}
		for _, r := range old {
			if _, _, err := f.run(r.del()...); err != nil {
				return result, err
			}
		}
		result.Changed = true
	}
	for _, j := range jumpRules(h) {
		if err := f.ensureJump(j); err != nil {
			return result, err
		}
	}
	return result, nil
}

func comment(fields []string) string {
	for i := 0; i+1 < len(fields); i++ {
		if fields[i] == "--comment" {
			return fields[i+1]
		}
	}
	return ""
}
func appendUnique(a []int, n int) []int {
	for _, v := range a {
		if v == n {
			return a
		}
	}
	return append(a, n)
}
func taggedRules(have map[string][]string, p int) []rule {
	out := []rule{}
	tag := fmt.Sprintf("wgoct:hop:%d", p)
	for _, c := range []struct{ table, name string }{{"nat", dnatChain}, {"nat", snatChain}, {"filter", fwdChain}} {
		for _, line := range have[c.name] {
			f, _ := netsetup.SplitRule(line)
			if comment(f) == tag {
				out = append(out, rule{c.table, c.name, f[2:]})
			}
		}
	}
	return out
}
func equalRules(a, b []rule) bool {
	if len(a) != len(b) {
		return false
	}
	key := func(r rule) string { return r.table + ":" + r.chain + ":" + strings.Join(r.spec, " ") }
	left, right := make([]string, len(a)), make([]string, len(b))
	for i := range a {
		left[i] = key(a[i])
		right[i] = key(b[i])
	}
	sort.Strings(left)
	sort.Strings(right)
	return strings.Join(left, "\n") == strings.Join(right, "\n")
}
func jumpRules(h *state.Hop) []rule {
	if h == nil {
		return nil
	}
	return []rule{{"nat", "PREROUTING", []string{"-i", h.WANInterface, "-d", h.HopIP, "-p", "udp", "-j", dnatChain}}, {"nat", "POSTROUTING", []string{"-o", h.WANInterface, "-p", "udp", "-j", snatChain}}, {"filter", "FORWARD", []string{"-i", h.WANInterface, "-o", h.WANInterface, "-p", "udp", "-j", fwdChain}}}
}
func (f *Forwarder) ensureJump(w rule) error {
	a := []string{}
	if w.table != "" {
		a = append(a, "-t", w.table)
	}
	check := append(append([]string{}, a...), "-C", w.chain)
	check = append(check, w.spec...)
	if _, code, err := f.run(check...); err != nil {
		return err
	} else if code == 0 {
		return nil
	}
	ins := append(append([]string{}, a...), "-I", w.chain, "1")
	_, _, err := f.run(append(ins, w.spec...)...)
	return err
}
func (f *Forwarder) deleteAll(w rule) error {
	a := []string{}
	if w.table != "" {
		a = append(a, "-t", w.table)
	}
	del := append(append([]string{}, a...), "-D", w.chain)
	del = append(del, w.spec...)
	for {
		_, code, err := f.run(del...)
		if err != nil {
			return err
		}
		if code != 0 {
			return nil
		}
	}
}
