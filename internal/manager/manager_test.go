package manager

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/illmouse/wgoctopus/internal/hop"
	"github.com/illmouse/wgoctopus/internal/netsetup"
	"github.com/illmouse/wgoctopus/internal/reconcile"
	"github.com/illmouse/wgoctopus/internal/state"
	"github.com/illmouse/wgoctopus/internal/store"
	"github.com/illmouse/wgoctopus/internal/uapi"
)

type testSupervisor struct {
	log      *[]string
	names    []string
	startErr map[string]error
	restarts map[string]uint64
	callback func(string)
	mu       sync.Mutex
}

func (s *testSupervisor) Start(_ context.Context, n string) error {
	*s.log = append(*s.log, "start:"+n)
	return s.startErr[n]
}
func (s *testSupervisor) Stop(n string) error          { *s.log = append(*s.log, "stop:"+n); return nil }
func (s *testSupervisor) StopAll() error               { *s.log = append(*s.log, "stopall"); return nil }
func (s *testSupervisor) Names() []string              { return append([]string(nil), s.names...) }
func (s *testSupervisor) Restarts(n string) uint64     { return s.restarts[n] }
func (s *testSupervisor) SetOnRestart(fn func(string)) { s.callback = fn }

type testLink struct {
	log       *[]string
	ensureErr map[string]error
}

func (l testLink) EnsureUp(n, addr string, mtu int) error {
	if l.log != nil {
		*l.log = append(*l.log, fmt.Sprintf("link:%s:%s:%d", n, addr, mtu))
	}
	return l.ensureErr[n]
}
func (l testLink) Delete(n string) error                { *l.log = append(*l.log, "delete:"+n); return nil }
func (testLink) Exists(string) (bool, error)            { return false, nil }
func (testLink) DefaultRouteInterface() (string, error) { return "eth0", nil }

type testFirewall struct {
	log         *[]string
	err         error
	ensureCalls int
	removeCalls []string
}

func (f *testFirewall) Ensure(s netsetup.FirewallSpec) error {
	f.ensureCalls++
	*f.log = append(*f.log, "firewall:"+s.Name+":"+s.ClientSubnet+":"+s.EgressIface+":"+s.SNATIP)
	return f.err
}
func (f *testFirewall) Remove(n string) error {
	*f.log = append(*f.log, "fwremove:"+n)
	f.removeCalls = append(f.removeCalls, n)
	return nil
}

type testDevice struct {
	log    *[]string
	live   uapi.Live
	getErr error
	setErr error
}

func (d *testDevice) Get() (uapi.Live, error) {
	*d.log = append(*d.log, "get")
	return d.live, d.getErr
}
func (d *testDevice) Set(o uapi.Ops) error {
	*d.log = append(*d.log, "set")
	if d.live.Fields == nil {
		d.live.Fields = make(map[string]string)
	}
	for key, value := range o.Fields {
		d.live.Fields[key] = value
	}
	if value, ok := o.Fields["private_key"]; ok {
		d.live.PrivateKey = value
	}
	return d.setErr
}

type testStore struct {
	log              *[]string
	value            state.State
	found            bool
	loadErr, saveErr error
	saves            int
}

func (s *testStore) Load() (state.State, bool, error) {
	*s.log = append(*s.log, "load")
	return s.value, s.found, s.loadErr
}
func (s *testStore) Save(v state.State) error {
	*s.log = append(*s.log, "save")
	s.saves++
	return s.saveErr
}

func makeState(names ...string) state.State {
	key := base64.StdEncoding.EncodeToString(make([]byte, 32))
	v := state.State{Revision: 7}
	for _, n := range names {
		v.Interfaces = append(v.Interfaces, state.Interface{Name: n, ListenPort: 51820, PrivateKey: key, Address: "10.0.0.1/24", MTU: 1400, EgressInterface: "eth0", SNATIP: "10.1.2.3", Obfuscation: state.Obfuscation{H1: "1", H2: "2", H3: "3", H4: "4"}})
	}
	return v
}
func setup() (*Manager, *[]string, *testStore, map[string]*testDevice) {
	log := new([]string)
	devices := map[string]*testDevice{}
	m := &Manager{Store: &testStore{log: log}, Daemons: &testSupervisor{log: log, restarts: map[string]uint64{}}, Links: testLink{log: log}, Firewall: &testFirewall{log: log}, Device: func(n string) uapi.Device {
		if devices[n] == nil {
			devices[n] = &testDevice{log: log, live: uapi.Live{Fields: map[string]string{}, Peers: map[string]uapi.Peer{}}}
		}
		return devices[n]
	}}
	return m, log, m.Store.(*testStore), devices
}
func expectLog(t *testing.T, got *[]string, want ...string) {
	t.Helper()
	if !reflect.DeepEqual(*got, want) {
		t.Fatalf("log mismatch\n got: %v\nwant: %v", *got, want)
	}
}

func TestApplyOrderIdempotenceAndFirewall(t *testing.T) {
	m, log, s, _ := setup()
	v := makeState("wg0")
	if err := m.Apply(v, true); err != nil {
		t.Fatal(err)
	}
	expectLog(t, log, "start:wg0", "link:wg0:10.0.0.1/24:1400", "get", "set", "firewall:wg0:10.0.0.0/24:eth0:10.1.2.3", "save")
	*log = nil
	if err := m.Apply(v, true); err != nil {
		t.Fatal(err)
	}
	expectLog(t, log, "start:wg0", "link:wg0:10.0.0.1/24:1400", "get", "firewall:wg0:10.0.0.0/24:eth0:10.1.2.3", "save")
	if s.saves != 2 || m.AppliedRevision() != 7 || m.Checksum() != v.Checksum() {
		t.Fatalf("not recorded: saves=%d revision=%d", s.saves, m.AppliedRevision())
	}
}

func TestClientModeSkipsFirewallAndReappliesWithoutUAPISet(t *testing.T) {
	m, log, _, devices := setup()
	v := makeState("wg0")
	v.Interfaces[0].Mode = "client"
	v.Interfaces[0].ListenPort = 0
	fw := &testFirewall{log: log}
	m.Firewall = fw
	if err := m.Apply(v, true); err != nil {
		t.Fatal(err)
	}
	if fw.ensureCalls != 0 || !reflect.DeepEqual(fw.removeCalls, []string{"wg0"}) {
		t.Fatalf("firewall calls: ensure=%d remove=%v", fw.ensureCalls, fw.removeCalls)
	}
	if _, ok := devices["wg0"].live.Fields["listen_port"]; ok {
		t.Fatal("client mode emitted listen_port")
	}
	*log = nil
	if err := m.Apply(v, true); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(strings.Join(*log, ","), ",set,") {
		t.Fatalf("idempotent reapply sent UAPI set: %v", *log)
	}
}

func TestSwitchServerToClientRemovesFirewall(t *testing.T) {
	m, log, _, _ := setup()
	if err := m.Apply(makeState("wg0"), true); err != nil {
		t.Fatal(err)
	}
	*log = nil
	v := makeState("wg0")
	v.Interfaces[0].Mode = "client"
	v.Interfaces[0].ListenPort = 0
	if err := m.Apply(v, true); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(strings.Join(*log, ","), "fwremove:wg0") || strings.Contains(strings.Join(*log, ","), "firewall:wg0") {
		t.Fatalf("stale firewall rules not removed: %v", *log)
	}
}

func TestRemovalOrder(t *testing.T) {
	m, log, _, _ := setup()
	m.Daemons.(*testSupervisor).names = []string{"old"}
	if err := m.Apply(makeState(), true); err != nil {
		t.Fatal(err)
	}
	expectLog(t, log, "fwremove:old", "delete:old", "stop:old", "save")
}

func TestDangerousRefusalContinuesAndDoesNotSave(t *testing.T) {
	m, log, s, devices := setup()
	old := makeState("a", "b")
	for _, in := range old.Interfaces {
		devices[in.Name] = &testDevice{log: log, live: uapi.Live{PrivateKey: base64.StdEncoding.EncodeToString(make([]byte, 32)), Fields: map[string]string{"private_key": "different"}, Peers: map[string]uapi.Peer{}}}
	}
	// The first reconciliation refuses; the second gets a fresh empty device and applies.
	devices["a"].live.Fields["listen_port"] = "1"
	devices["b"].live = uapi.Live{Fields: map[string]string{}, Peers: map[string]uapi.Peer{}}
	err := m.Apply(old, false)
	var de *reconcile.DangerousError
	if !errors.As(err, &de) || !errors.Is(err, reconcile.ErrDangerous) || !strings.Contains(err.Error(), "a") {
		t.Fatalf("dangerous error classification: %v", err)
	}
	if s.saves != 0 || !strings.Contains(strings.Join(*log, ","), "firewall:b:") {
		t.Fatalf("did not continue / unexpectedly saved: %v", *log)
	}
}

func TestPartialFailureContinuesAndDoesNotSave(t *testing.T) {
	m, log, s, _ := setup()
	m.Links = testLink{log: log, ensureErr: map[string]error{"a": errors.New("link failed")}}
	if err := m.Apply(makeState("a", "b"), true); err == nil || !strings.Contains(err.Error(), "a") {
		t.Fatalf("expected named error, got %v", err)
	}
	if s.saves != 0 || !strings.Contains(strings.Join(*log, ","), "firewall:b:") {
		t.Fatalf("b not applied or state saved: %v", *log)
	}
}

func TestRestartOnlyTargetAndNoPriorState(t *testing.T) {
	m, log, _, _ := setup()
	m.OnRestart("wg0")
	if len(*log) != 0 {
		t.Fatal(*log)
	}
	if err := m.Apply(makeState("wg0", "wg1"), true); err != nil {
		t.Fatal(err)
	}
	*log = nil
	m.OnRestart("wg0")
	if strings.Contains(strings.Join(*log, ","), "wg1") || !strings.Contains(strings.Join(*log, ","), "start:wg0") {
		t.Fatalf("wrong restart replay: %v", *log)
	}
}

func TestBootAndRetry(t *testing.T) {
	t.Run("saved", func(t *testing.T) {
		m, log, s, _ := setup()
		s.value = makeState("wg0")
		s.found = true
		if err := m.Boot(context.Background(), time.Millisecond); err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(strings.Join(*log, ","), "save") {
			t.Fatal(*log)
		}
	})
	t.Run("retry", func(t *testing.T) {
		m, log, s, _ := setup()
		s.value = makeState("wg0")
		s.found = true
		calls := 0
		m.Links = testLinkRetry{log: log, fail: &calls}
		m.After = func(time.Duration) <-chan time.Time { ch := make(chan time.Time, 1); ch <- time.Now(); return ch }
		if err := m.Boot(context.Background(), time.Second); err != nil {
			t.Fatal(err)
		}
		if calls != 2 {
			t.Fatalf("calls=%d", calls)
		}
	})
	t.Run("none", func(t *testing.T) {
		m, log, _, _ := setup()
		if err := m.Boot(context.Background(), time.Second); err != nil {
			t.Fatal(err)
		}
		if len(*log) != 1 || (*log)[0] != "load" {
			t.Fatal(*log)
		}
	})
	t.Run("cancel", func(t *testing.T) {
		m, _, s, _ := setup()
		s.value = makeState("wg0")
		s.found = true
		m.Links = testLink{ensureErr: map[string]error{"wg0": errors.New("fail")}}
		m.After = func(time.Duration) <-chan time.Time { return make(chan time.Time) }
		ctx, cancel := context.WithCancel(context.Background())
		done := make(chan error, 1)
		go func() { done <- m.Boot(ctx, time.Second) }()
		time.Sleep(10 * time.Millisecond)
		cancel()
		select {
		case err := <-done:
			if !errors.Is(err, context.Canceled) {
				t.Fatal(err)
			}
		case <-time.After(time.Second):
			t.Fatal("Boot did not cancel")
		}
	})
}

func TestBootRestoresRevisionAndChecksumBeforeRetry(t *testing.T) {
	dir := t.TempDir()
	want := makeState("wg0")
	want.Revision = 4
	fileStore := FileStore{Store: store.Store{Dir: dir}}
	first, _, _, _ := setup()
	first.Store = fileStore
	if err := first.Apply(want, true); err != nil {
		t.Fatal(err)
	}

	second, _, _, _ := setup()
	second.Store = fileStore
	failed := make(chan struct{}, 1)
	second.Links = testLinkFailOnce{failed: failed}
	second.After = func(time.Duration) <-chan time.Time { return make(chan time.Time) }
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- second.Boot(ctx, time.Second) }()
	deadline := time.Now().Add(time.Second)
	select {
	case <-failed:
	case <-time.After(time.Second):
		t.Fatal("boot did not reach failed apply")
	}
	for second.AppliedRevision() != int64(want.Revision) && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if second.AppliedRevision() != int64(want.Revision) || second.Checksum() != want.Checksum() {
		t.Fatalf("restored desired state: revision=%d checksum=%q", second.AppliedRevision(), second.Checksum())
	}
	cancel()
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
}

type testLinkFailOnce struct{ failed chan struct{} }

func (l testLinkFailOnce) EnsureUp(string, string, int) error {
	l.failed <- struct{}{}
	return errors.New("initial failure")
}
func (testLinkFailOnce) Delete(string) error                    { return nil }
func (testLinkFailOnce) Exists(string) (bool, error)            { return false, nil }
func (testLinkFailOnce) DefaultRouteInterface() (string, error) { return "eth0", nil }

type testLinkRetry struct {
	log  *[]string
	fail *int
}

func (l testLinkRetry) EnsureUp(n, a string, mtu int) error {
	*l.log = append(*l.log, "link:"+n)
	*l.fail++
	if *l.fail == 1 {
		return errors.New("once")
	}
	return nil
}
func (testLinkRetry) Delete(string) error                    { return nil }
func (testLinkRetry) Exists(string) (bool, error)            { return false, nil }
func (testLinkRetry) DefaultRouteInterface() (string, error) { return "eth0", nil }

func TestShutdownOnlyStopsDaemons(t *testing.T) {
	m, log, _, _ := setup()
	if err := m.Shutdown(); err != nil {
		t.Fatal(err)
	}
	expectLog(t, log, "stopall")
}

func TestAdaptersAndAccessors(t *testing.T) {
	dir := t.TempDir()
	file := FileStore{Store: store.Store{Dir: dir}}
	if _, found, err := file.Load(); err != nil || found {
		t.Fatalf("empty store: found=%v err=%v", found, err)
	}
	want := makeState("wg0")
	if err := file.Save(want); err != nil {
		t.Fatal(err)
	}
	got, found, err := file.Load()
	if err != nil || !found || got.Revision != want.Revision {
		t.Fatalf("load: %#v %v %v", got, found, err)
	}
	if _, found, err := (FileStore{Store: store.Store{Dir: filepath.Join(dir, "missing")}}).Load(); err != nil || found {
		t.Fatalf("missing load: found=%v err=%v", found, err)
	}
	m, _, _, devices := setup()
	if m.Applied().Revision != 0 || m.Checksum() != "" {
		t.Fatal("nonzero initial accessors")
	}
	if err := m.Apply(want, true); err != nil {
		t.Fatal(err)
	}
	if m.Applied().Revision != want.Revision {
		t.Fatal(m.Applied())
	}
	if _, err := (LiveSource{Device: m.Device}).Live("wg0"); err != nil {
		t.Fatal(err)
	}
	if _, err := (LiveSource{}).Live("wg0"); err == nil {
		t.Fatal("expected missing device factory")
	}
	_ = devices
	if err := (&Manager{}).Shutdown(); err != nil {
		t.Fatal(err)
	}
}

func TestRestartRegistrationAndCollector(t *testing.T) {
	m, _, _, _ := setup()
	m.RegisterRestartHandler()
	s := m.Daemons.(*testSupervisor)
	if s.callback == nil {
		t.Fatal("restart callback not registered")
	}
	s.callback("unused")
	collector := m.Collector()
	if len(collector.Interfaces()) != 0 || collector.Restarts("wg0") != 0 {
		t.Fatal("unexpected empty collector adapters")
	}
	if _, err := collector.Device("wg0"); err != nil {
		t.Fatal(err)
	}
	m.Daemons = nil
	collector = m.Collector()
	if collector.Interfaces() != nil || collector.Restarts("wg0") != 0 {
		t.Fatal("nil supervisor adapters")
	}
}

func TestCollectorIncludesClientInterfaceAndPeerHandshake(t *testing.T) {
	m, log, _, devices := setup()
	m.Daemons.(*testSupervisor).names = []string{"probe0"}
	devices["probe0"] = &testDevice{log: log, live: uapi.Live{Peers: map[string]uapi.Peer{
		"peer-key": {PublicKey: "peer-key", LastHandshakeSec: 123},
	}}}
	out := string(m.Collector().Render(context.Background()))
	for _, want := range []string{`wg_interface_up{interface="probe0"} 1`, `wg_peer_last_handshake_timestamp_seconds{interface="probe0",public_key="peer-key"} 123`} {
		if !strings.Contains(out, want) {
			t.Errorf("missing metric %q", want)
		}
	}
}

func TestValidationAndSaveFailures(t *testing.T) {
	m, _, s, _ := setup()
	if err := m.Apply(state.State{Interfaces: []state.Interface{{Name: "bad"}}}, true); err == nil {
		t.Fatal("expected validation error")
	}
	s.saveErr = errors.New("save failed")
	if err := m.Apply(makeState("wg0"), true); !errors.Is(err, s.saveErr) {
		t.Fatalf("save error: %v", err)
	}
	if m.AppliedRevision() != 0 {
		t.Fatal("failed save recorded applied state")
	}
}

type fakeHop struct {
	calls  int
	values []*state.Hop
	err    error
	log    *[]string
}

func (f *fakeHop) Apply(_ context.Context, h *state.Hop) (hop.Result, error) {
	f.calls++
	f.values = append(f.values, h)
	if f.log != nil {
		*f.log = append(*f.log, "hop")
	}
	return hop.Result{Warnings: []string{"warn"}}, f.err
}

func (f *fakeHop) Stats() hop.Stats { return hop.Stats{Routes: int64(len(f.values))} }

func TestHopApplyFlow(t *testing.T) {
	t.Run("after interfaces and no dangerous approval", func(t *testing.T) {
		m, log, _, _ := setup()
		h := &fakeHop{log: log}
		m.Hop = h
		v := makeState("wg0")
		v.Hop = &state.Hop{WANInterface: "eth0", HopIP: "192.0.2.1"}
		if err := m.Apply(v, false); err != nil {
			t.Fatal(err)
		}
		if (*log)[len(*log)-2] != "hop" || h.calls != 1 {
			t.Fatalf("order/calls: %v %d", *log, h.calls)
		}
		if got := m.Warnings(); len(got) != 1 || got[0] != "warn" || m.HopStats().Routes != 1 {
			t.Fatalf("warnings=%v stats=%+v", got, m.HopStats())
		}
	})
	t.Run("nil never and after use", func(t *testing.T) {
		m, _, _, _ := setup()
		h := &fakeHop{}
		m.Hop = h
		if err := m.Apply(makeState(), true); err != nil || h.calls != 0 {
			t.Fatalf("calls=%d err=%v", h.calls, err)
		}
		v := makeState()
		v.Hop = &state.Hop{WANInterface: "eth0", HopIP: "192.0.2.1"}
		if err := m.Apply(v, true); err != nil {
			t.Fatal(err)
		}
		if err := m.Apply(makeState(), true); err != nil || h.calls != 2 || h.values[1] != nil {
			t.Fatalf("calls=%d err=%v", h.calls, err)
		}
	})
	t.Run("error joined and unsaved", func(t *testing.T) {
		m, _, s, _ := setup()
		failure := errors.New("hop failed")
		m.Hop = &fakeHop{err: failure}
		interfaceFailure := errors.New("interface failed")
		m.Links = testLink{ensureErr: map[string]error{"wg0": interfaceFailure}}
		v := makeState("wg0")
		v.Hop = &state.Hop{WANInterface: "eth0", HopIP: "192.0.2.1"}
		err := m.Apply(v, false)
		if !errors.Is(err, failure) || !errors.Is(err, interfaceFailure) || s.saves != 0 {
			t.Fatalf("err=%v saves=%d", err, s.saves)
		}
	})
	t.Run("backend change reaches applier", func(t *testing.T) {
		m, _, _, _ := setup()
		h := &fakeHop{}
		m.Hop = h
		v := makeState()
		v.Hop = &state.Hop{WANInterface: "eth0", HopIP: "192.0.2.1", Routes: []state.HopRoute{{ListenPort: 1000, BackendIP: "198.51.100.1", BackendPort: 1001}}}
		if err := m.Apply(v, false); err != nil {
			t.Fatal(err)
		}
		v.Revision++
		v.Hop.Routes[0].BackendIP = "198.51.100.2"
		if err := m.Apply(v, false); err != nil {
			t.Fatal(err)
		}
		if h.calls != 2 || h.values[1].Routes[0].BackendIP != "198.51.100.2" {
			t.Fatalf("applied %#v", h.values)
		}
	})
	t.Run("boot reapplies", func(t *testing.T) {
		m, _, s, _ := setup()
		v := makeState()
		v.Hop = &state.Hop{WANInterface: "eth0", HopIP: "192.0.2.1"}
		s.value, s.found = v, true
		h := &fakeHop{}
		m.Hop = h
		if err := m.Boot(context.Background(), time.Millisecond); err != nil || h.calls != 1 {
			t.Fatalf("calls=%d err=%v", h.calls, err)
		}
	})
}

func TestBootLoadErrorAndCanceledContext(t *testing.T) {
	m, _, s, _ := setup()
	s.loadErr = errors.New("load failed")
	if err := m.Boot(context.Background(), time.Second); !errors.Is(err, s.loadErr) {
		t.Fatal(err)
	}
	s.loadErr = nil
	s.found = true
	s.value = makeState("wg0")
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	m.Links = testLink{ensureErr: map[string]error{"wg0": errors.New("retry")}}
	m.After = func(time.Duration) <-chan time.Time { return make(chan time.Time) }
	if err := m.Boot(ctx, time.Second); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
}

func TestConcurrentApplySerialized(t *testing.T) {
	m, _, _, _ := setup()
	entered := make(chan struct{}, 2)
	release := make(chan struct{})
	original := m.Device
	m.Device = func(n string) uapi.Device {
		return &blockingDevice{Device: original(n), entered: entered, release: release}
	}
	done := make(chan error, 2)
	go func() { done <- m.Apply(makeState("wg0"), true) }()
	<-entered
	go func() { done <- m.Apply(makeState("wg0"), true) }()
	select {
	case <-entered:
		t.Fatal("second apply entered while first held lock")
	case <-time.After(20 * time.Millisecond):
	}
	release <- struct{}{}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	<-entered
	release <- struct{}{}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

type blockingDevice struct {
	uapi.Device
	entered chan struct{}
	release chan struct{}
	once    sync.Once
}

func (d *blockingDevice) Get() (uapi.Live, error) {
	d.once.Do(func() { d.entered <- struct{}{}; <-d.release })
	return d.Device.Get()
}
