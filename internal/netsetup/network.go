package netsetup

import (
	"fmt"
	"net/netip"
	"os/exec"
	"strconv"
	"strings"
)

// Link manages a network interface.
type Link interface {
	EnsureUp(name, addressCIDR string, mtu int) error
	Delete(name string) error
	Exists(name string) (bool, error)
	DefaultRouteInterface() (string, error)
}

// FirewallSpec describes the forwarding and NAT rules owned for one interface.
type FirewallSpec struct {
	Name, ClientSubnet, EgressIface, SNATIP string
}

// Firewall manages only rules tagged as belonging to its interface.
type Firewall interface {
	Ensure(FirewallSpec) error
	Remove(name string) error
}

// Executor executes an argv vector without a shell.
type Executor interface {
	Run(argv []string) (stdout string, exitCode int, err error)
}

// NewCommandExecutor returns an executor for a command found on PATH by default.
func NewCommandExecutor(path string) Executor {
	if path == "" {
		path = "iptables"
	}
	return commandExecutor{path}
}

type commandExecutor struct{ path string }

func (e commandExecutor) Run(argv []string) (string, int, error) {
	out, err := exec.Command(e.path, argv...).CombinedOutput()
	code := 0
	if err != nil {
		if x, ok := err.(*exec.ExitError); ok {
			code = x.ExitCode()
		} else {
			return string(out), -1, err
		}
	}
	return string(out), code, nil
}

// IPTables manages the WGOCT_FWD and WGOCT_NAT chains.
type IPTables struct {
	Exec          Executor
	Path          string
	DefaultEgress func() (string, error)
}

func (f IPTables) run(args ...string) (string, int, error) {
	e := f.Exec
	if e == nil {
		path := f.Path
		if path == "" {
			path = "iptables"
		}
		e = commandExecutor{path}
	}
	return e.Run(append([]string{"-w"}, args...))
}

// Ensure installs exactly the desired tagged rules without disturbing other interfaces.
func (f IPTables) Ensure(s FirewallSpec) error {
	if err := validateSpec(s); err != nil {
		return err
	}
	if s.EgressIface == "" {
		if f.DefaultEgress == nil {
			return fmt.Errorf("default egress interface is unavailable")
		}
		var err error
		s.EgressIface, err = f.DefaultEgress()
		if err != nil {
			return err
		}
		if err = validateIface(s.EgressIface); err != nil {
			return err
		}
	}
	for _, chain := range []struct{ table, name string }{{"filter", "WGOCT_FWD"}, {"nat", "WGOCT_NAT"}} {
		args := []string{}
		if chain.table == "nat" {
			args = append(args, "-t", "nat")
		}
		_, code, err := f.run(append(args, "-N", chain.name)...)
		if err != nil {
			return err
		}
		if code != 0 { /* Existing chain is expected; rule listing below verifies use. */
		}
	}
	for _, jump := range []struct{ args []string }{{[]string{"-C", "FORWARD", "-j", "WGOCT_FWD"}}, {[]string{"-t", "nat", "-C", "POSTROUTING", "-j", "WGOCT_NAT"}}} {
		_, code, err := f.run(jump.args...)
		if err != nil {
			return err
		}
		if code != 0 {
			a := append([]string(nil), jump.args...)
			command := 0
			if len(a) > 1 && a[0] == "-t" {
				command = 2
			}
			a[command] = "-I"
			a = append(a[:command+2], append([]string{"1"}, a[command+2:]...)...)
			if _, _, err = f.run(a...); err != nil {
				return err
			}
		}
	}
	tag := "wgoct:" + s.Name
	want := [][]string{
		{"-A", "WGOCT_FWD", "-i", s.Name, "-m", "comment", "--comment", tag, "-j", "ACCEPT"},
		{"-A", "WGOCT_FWD", "-o", s.Name, "-m", "conntrack", "--ctstate", "RELATED,ESTABLISHED", "-m", "comment", "--comment", tag, "-j", "ACCEPT"},
		{"-A", "WGOCT_FWD", "-s", s.ClientSubnet, "-o", s.EgressIface, "-m", "comment", "--comment", tag, "-j", "ACCEPT"},
	}
	nat := []string{"-A", "WGOCT_NAT", "-s", s.ClientSubnet, "-o", s.EgressIface, "-m", "comment", "--comment", tag}
	if s.SNATIP != "" {
		nat = append(nat, "-j", "SNAT", "--to-source", s.SNATIP)
	} else {
		nat = append(nat, "-j", "MASQUERADE")
	}

	// Leave live rules untouched when they already match, so a periodic
	// re-apply never opens a window without forwarding rules.
	haveFilter, haveNAT, err := f.listTagged(tag)
	if err != nil {
		return err
	}
	if sameRuleLists(haveFilter, want) && sameRuleLists(haveNAT, [][]string{nat}) {
		return nil
	}
	if err := f.removeTagged(s.Name); err != nil {
		return err
	}
	for _, args := range want {
		if _, _, err := f.run(args...); err != nil {
			return err
		}
	}
	_, _, err = f.run(append([]string{"-t", "nat"}, nat...)...)
	return err
}

// listTagged returns the rules in the owned chains carrying the given tag,
// each as "-A <chain> <spec...>" fields.
func (f IPTables) listTagged(tag string) (filter, nat [][]string, err error) {
	for _, table := range []struct {
		args  []string
		chain string
		dst   *[][]string
	}{{nil, "WGOCT_FWD", &filter}, {[]string{"-t", "nat"}, "WGOCT_NAT", &nat}} {
		out, _, runErr := f.run(append(append([]string(nil), table.args...), "-S", table.chain)...)
		if runErr != nil {
			return nil, nil, runErr
		}
		for _, line := range strings.Split(out, "\n") {
			fields, splitErr := splitRule(line)
			if splitErr != nil {
				return nil, nil, splitErr
			}
			if len(fields) > 0 && fields[0] == "-A" && hasComment(fields, tag) {
				*table.dst = append(*table.dst, fields)
			}
		}
	}
	return filter, nat, nil
}

func sameRuleLists(a, b [][]string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if strings.Join(a[i], " ") != strings.Join(b[i], " ") {
			return false
		}
	}
	return true
}

// Remove deletes only rules tagged for name.
func (f IPTables) Remove(name string) error {
	if err := validateIface(name); err != nil {
		return err
	}
	return f.removeTagged(name)
}

func (f IPTables) removeTagged(name string) error {
	tag := "wgoct:" + name
	for _, table := range []struct {
		args  []string
		chain string
	}{{nil, "WGOCT_FWD"}, {[]string{"-t", "nat"}, "WGOCT_NAT"}} {
		base := append(append([]string(nil), table.args...), "-S", table.chain)
		out, _, err := f.run(base...)
		if err != nil {
			return err
		}
		for _, line := range strings.Split(out, "\n") {
			fields, err := splitRule(line)
			if err != nil {
				return err
			}
			if len(fields) == 0 || fields[0] != "-A" || !(hasComment(fields, tag) || strings.Contains(line, tag)) {
				continue
			}
			del := append([]string(nil), table.args...)
			del = append(del, "-D")
			del = append(del, fields[1:]...)
			if _, _, err := f.run(del...); err != nil {
				return err
			}
		}
	}
	return nil
}

// iptables -S quotes comment values containing punctuation; decode its argv-like output.
func splitRule(line string) ([]string, error) {
	var fields []string
	for i := 0; i < len(line); {
		for i < len(line) && line[i] == ' ' {
			i++
		}
		if i == len(line) {
			break
		}
		if line[i] == '"' {
			start := i
			i++
			for i < len(line) {
				if line[i] == '\\' {
					i += 2
					continue
				}
				if line[i] == '"' {
					i++
					break
				}
				i++
			}
			if i > len(line) || line[i-1] != '"' {
				return nil, fmt.Errorf("invalid iptables rule: %q", line)
			}
			value, err := strconv.Unquote(line[start:i])
			if err != nil {
				return nil, err
			}
			fields = append(fields, value)
			continue
		}
		start := i
		for i < len(line) && line[i] != ' ' {
			i++
		}
		fields = append(fields, line[start:i])
	}
	return fields, nil
}

// SplitRule parses one rule from iptables -S output.
func SplitRule(line string) ([]string, error) { return splitRule(line) }

func hasComment(rule []string, tag string) bool {
	for i := 0; i+1 < len(rule); i++ {
		if rule[i] == "--comment" && rule[i+1] == tag {
			return true
		}
	}
	return false
}

func validateIface(s string) error {
	if len(s) == 0 || len(s) > 15 {
		return fmt.Errorf("invalid interface name %q", s)
	}
	for _, r := range s {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || strings.ContainsRune("_=+.-", r)) {
			return fmt.Errorf("invalid interface name %q", s)
		}
	}
	return nil
}
func validateSpec(s FirewallSpec) error {
	if err := validateIface(s.Name); err != nil {
		return err
	}
	if _, err := netip.ParsePrefix(s.ClientSubnet); err != nil {
		return fmt.Errorf("invalid client subnet: %w", err)
	}
	if s.EgressIface != "" {
		if err := validateIface(s.EgressIface); err != nil {
			return err
		}
	}
	if s.SNATIP != "" {
		if _, err := netip.ParseAddr(s.SNATIP); err != nil {
			return fmt.Errorf("invalid SNAT IP: %w", err)
		}
	}
	return nil
}
