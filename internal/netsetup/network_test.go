package netsetup

import (
	"reflect"
	"strconv"
	"strings"
	"testing"
)

type fakeExecutor struct {
	calls [][]string
	rules map[string][][]string
}

func (e *fakeExecutor) Run(a []string) (string, int, error) {
	e.calls = append(e.calls, append([]string(nil), a...))
	a = a[1:] // The implementation always prefixes argv with iptables' -w.
	table, chain := "filter", ""
	i := 0
	if len(a) > 2 && a[0] == "-t" {
		table, i = a[1], 2
	}
	if len(a) > i+1 {
		chain = a[i+1]
	}
	key := table + "/" + chain
	switch a[i] {
	case "-N":
		if e.rules[key] != nil {
			return "", 1, nil
		}
		e.rules[key] = [][]string{}
	case "-C":
		for _, r := range e.rules[key] {
			if strings.Join(r, " ") == strings.Join(a[i+2:], " ") {
				return "", 0, nil
			}
		}
		return "", 1, nil
	case "-I", "-A":
		ruleStart := i + 2
		if a[i] == "-I" && len(a) > ruleStart && a[ruleStart] == "1" {
			ruleStart++
		}
		r := append([]string(nil), a[ruleStart:]...)
		e.rules[key] = append(e.rules[key], r)
	case "-S":
		var out []string
		for _, r := range e.rules[key] {
			fields := make([]string, len(r))
			for n, field := range r {
				if strings.ContainsAny(field, ": \"\\") {
					fields[n] = strconv.Quote(field)
				} else {
					fields[n] = field
				}
			}
			out = append(out, "-A "+chain+" "+strings.Join(fields, " "))
		}
		return strings.Join(out, "\n"), 0, nil
	case "-D":
		target := strings.Join(a[i+2:], " ")
		for n, r := range e.rules[key] {
			if strings.Join(r, " ") == target {
				e.rules[key] = append(e.rules[key][:n], e.rules[key][n+1:]...)
				break
			}
		}
	}
	return "", 0, nil
}

func TestEnsureAndRemoveTaggedRules(t *testing.T) {
	e := &fakeExecutor{rules: make(map[string][][]string)}
	f := IPTables{Exec: e}
	s := FirewallSpec{Name: "wg0", ClientSubnet: "10.0.0.0/24", EgressIface: "eth0"}
	if err := f.Ensure(s); err != nil {
		t.Fatal(err)
	}
	firstCalls := len(e.calls)
	if got := strings.Join(e.calls[0], " "); got != "-w -N WGOCT_FWD" {
		t.Fatalf("first argv = %q", got)
	}
	first := map[string][][]string{}
	for k, v := range e.rules {
		first[k] = append([][]string(nil), v...)
	}
	if len(first["filter/WGOCT_FWD"]) != 3 || len(first["nat/WGOCT_NAT"]) != 1 {
		t.Fatalf("unexpected installed rules: %#v", first)
	}
	if err := f.Ensure(s); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(first, e.rules) {
		t.Fatalf("ensure duplicated rules: %#v", e.rules)
	}
	for _, call := range e.calls[firstCalls:] {
		joined := strings.Join(call, " ")
		if strings.Contains(joined, " -I ") || strings.Contains(joined, " -A ") {
			t.Fatalf("second Ensure mutated rules: %v", call)
		}
	}
	s.ClientSubnet = "10.1.0.0/24"
	if err := f.Ensure(s); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(strings.Join(e.rules["filter/WGOCT_FWD"][0], " "), "10.0.0.0") {
		t.Fatal("old subnet remained")
	}
	if err := f.Remove("wg0"); err != nil {
		t.Fatal(err)
	}
	if len(e.rules["filter/WGOCT_FWD"]) != 0 || len(e.rules["nat/WGOCT_NAT"]) != 0 {
		t.Fatal("tagged rules remained")
	}
}

func TestInterfacesCoexistAndRemoveIsScoped(t *testing.T) {
	e := &fakeExecutor{rules: map[string][][]string{}}
	f := IPTables{Exec: e}
	for _, name := range []string{"wg0", "wg1"} {
		if err := f.Ensure(FirewallSpec{Name: name, ClientSubnet: "10.0.0.0/24", EgressIface: "eth0"}); err != nil {
			t.Fatal(err)
		}
	}
	if err := f.Remove("wg0"); err != nil {
		t.Fatal(err)
	}
	for _, rules := range e.rules {
		for _, rule := range rules {
			if hasComment(rule, "wgoct:wg0") {
				t.Fatalf("wg0 rule remains: %v", rule)
			}
		}
	}
	if len(e.rules["filter/WGOCT_FWD"]) != 3 || len(e.rules["nat/WGOCT_NAT"]) != 1 {
		t.Fatalf("wg1 rules/chains lost: %#v", e.rules)
	}
}

func TestEnsureValidationBeforeExecutionAndSNATDefaultEgress(t *testing.T) {
	e := &fakeExecutor{rules: make(map[string][][]string)}
	f := IPTables{Exec: e, DefaultEgress: func() (string, error) { return "eth0", nil }}
	for _, spec := range []FirewallSpec{
		{Name: "wg0; rm -rf /", ClientSubnet: "10.0.0.0/24"},
		{Name: "long-interface-name", ClientSubnet: "10.0.0.0/24"},
		{Name: "wg0", ClientSubnet: "bad-cidr"},
		{Name: "wg0", ClientSubnet: "10.0.0.0/24", SNATIP: "bad-ip"},
	} {
		if err := f.Ensure(spec); err == nil {
			t.Fatalf("accepted %#v", spec)
		}
	}
	if len(e.calls) != 0 {
		t.Fatal("invalid input executed commands")
	}
	if err := f.Ensure(FirewallSpec{Name: "wg0", ClientSubnet: "10.0.0.0/24", SNATIP: "192.0.2.2"}); err != nil {
		t.Fatal(err)
	}
	last := strings.Join(e.calls[len(e.calls)-1], " ")
	if !strings.Contains(last, "--to-source 192.0.2.2") || !strings.Contains(last, "eth0") {
		t.Fatalf("unexpected SNAT command: %s", last)
	}
	if !strings.Contains(last, "SNAT") {
		t.Fatalf("missing SNAT target: %s", last)
	}
}
