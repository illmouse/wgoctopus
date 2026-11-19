package daemon

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"sync"
	"syscall"
	"testing"
	"time"
)

type fakeProcess struct {
	done       chan struct{}
	once       sync.Once
	ignoreTerm bool
}

func (p *fakeProcess) Wait() error { <-p.done; return nil }
func (p *fakeProcess) Signal(s os.Signal) error {
	if s == syscall.SIGTERM && !p.ignoreTerm {
		p.exit()
	}
	return nil
}
func (p *fakeProcess) Kill() error { p.exit(); return nil }
func (p *fakeProcess) exit()       { p.once.Do(func() { close(p.done) }) }

type fakeRunner struct {
	mu        sync.Mutex
	processes []*fakeProcess
	ignore    bool
	start     func()
	err       error
	errAfter  int
}

func (r *fakeRunner) Start(_ string, _, _ []string) (Process, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.err != nil || (r.errAfter > 0 && len(r.processes) >= r.errAfter) {
		if r.err != nil {
			return nil, r.err
		}
		return nil, context.DeadlineExceeded
	}
	p := &fakeProcess{done: make(chan struct{}), ignoreTerm: r.ignore}
	r.processes = append(r.processes, p)
	if r.start != nil {
		r.start()
	}
	return p, nil
}

func TestValidationAndRunnerFailure(t *testing.T) {
	s := &Supervisor{Config: Config{Runner: &fakeRunner{err: context.Canceled}, SockDir: t.TempDir()}}
	if err := s.Start(context.Background(), "../bad"); err == nil {
		t.Fatal("invalid name accepted")
	}
	if err := s.Start(context.Background(), "wg0"); err == nil {
		t.Fatal("runner failure ignored")
	}
	if s.Running("wg0") || s.Restarts("wg0") != 0 {
		t.Fatal("failed start was retained")
	}
	if err := s.Stop("missing"); err != nil {
		t.Fatal(err)
	}
}

func TestRealSleeperCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := (realSleeper{}).Sleep(ctx, time.Hour); err == nil {
		t.Fatal("expected cancellation")
	}
}

func TestExecRunner(t *testing.T) {
	p, err := (execRunner{}).Start("/bin/true", nil, []string{"PATH=/bin"})
	if err != nil {
		t.Fatal(err)
	}
	if err := p.Wait(); err != nil {
		t.Fatal(err)
	}
}

func TestStartContextCancellation(t *testing.T) {
	s := &Supervisor{Config: Config{SockDir: t.TempDir(), Runner: &fakeRunner{}, StartTimeout: time.Second}}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := s.Start(ctx, "wg0"); err == nil {
		t.Fatal("expected cancellation")
	}
	if len(s.Names()) != 0 {
		t.Fatal("cancelled start retained entry")
	}
}

func TestRestartLaunchFailureRetriesUntilStopped(t *testing.T) {
	dir := t.TempDir()
	l := socket(t, filepath.Join(dir, "wg0.sock"))
	defer l.Close()
	r := &fakeRunner{errAfter: 1}
	sl := &fakeSleeper{wake: make(chan struct{}, 2)}
	s := &Supervisor{Config: Config{SockDir: dir, Runner: r, Sleeper: sl}}
	if err := s.Start(context.Background(), "wg0"); err != nil {
		t.Fatal(err)
	}
	r.mu.Lock()
	p := r.processes[0]
	r.mu.Unlock()
	p.exit()
	select {
	case <-time.After(time.Second):
		t.Fatal("restart did not enter backoff")
	case <-func() <-chan struct{} {
		c := make(chan struct{})
		go func() {
			for {
				sl.mu.Lock()
				n := len(sl.delays)
				sl.mu.Unlock()
				if n > 0 {
					close(c)
					return
				}
				time.Sleep(time.Millisecond)
			}
		}()
		return c
	}():
	}
	sl.wake <- struct{}{}
	deadline := time.After(time.Second)
	for {
		sl.mu.Lock()
		n := len(sl.delays)
		sl.mu.Unlock()
		if n >= 2 {
			break
		}
		select {
		case <-deadline:
			t.Fatal("failed restart was not retried")
		case <-time.After(time.Millisecond):
		}
	}
	if err := s.Stop("wg0"); err != nil {
		t.Fatal(err)
	}
}

type fakeSleeper struct {
	mu     sync.Mutex
	delays []time.Duration
	wake   chan struct{}
}

func (s *fakeSleeper) Sleep(ctx context.Context, d time.Duration) error {
	s.mu.Lock()
	s.delays = append(s.delays, d)
	s.mu.Unlock()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-s.wake:
		return nil
	}
}

func socket(t *testing.T, path string) net.Listener {
	t.Helper()
	l, e := net.Listen("unix", path)
	if e != nil {
		t.Fatal(e)
	}
	go func() {
		for {
			c, e := l.Accept()
			if e != nil {
				return
			}
			_ = c.Close()
		}
	}()
	return l
}

func TestStartReadyIdempotentStopAndAll(t *testing.T) {
	dir := t.TempDir()
	l := socket(t, filepath.Join(dir, "wg0.sock"))
	defer l.Close()
	r := &fakeRunner{}
	s := &Supervisor{Config: Config{SockDir: dir, Runner: r}}
	if e := s.Start(context.Background(), "wg0"); e != nil {
		t.Fatal(e)
	}
	if e := s.Start(context.Background(), "wg0"); e != nil {
		t.Fatal(e)
	}
	if len(s.Names()) != 1 || !s.Running("wg0") {
		t.Fatal("expected running interface")
	}
	s.StopAll()
	if len(s.Names()) != 0 {
		t.Fatal("StopAll left managed processes")
	}
}

func TestStartTimeoutKillsChild(t *testing.T) {
	r := &fakeRunner{}
	s := &Supervisor{Config: Config{SockDir: t.TempDir(), Runner: r, StartTimeout: 30 * time.Millisecond, StopGrace: time.Millisecond}}
	if e := s.Start(context.Background(), "wg0"); e == nil {
		t.Fatal("expected timeout")
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	select {
	case <-r.processes[0].done:
	default:
		t.Fatal("child was not killed")
	}
}

func TestStopEscalates(t *testing.T) {
	dir := t.TempDir()
	l := socket(t, filepath.Join(dir, "wg0.sock"))
	defer l.Close()
	r := &fakeRunner{ignore: true}
	s := &Supervisor{Config: Config{SockDir: dir, Runner: r, StopGrace: time.Millisecond}}
	if e := s.Start(context.Background(), "wg0"); e != nil {
		t.Fatal(e)
	}
	s.Stop("wg0")
	r.mu.Lock()
	defer r.mu.Unlock()
	select {
	case <-r.processes[0].done:
	default:
		t.Fatal("kill was not sent")
	}
}

func TestRestartBackoffCancel(t *testing.T) {
	dir := t.TempDir()
	l := socket(t, filepath.Join(dir, "wg0.sock"))
	defer l.Close()
	r := &fakeRunner{}
	sl := &fakeSleeper{wake: make(chan struct{}, 4)}
	restarted := make(chan string, 4)
	s := &Supervisor{Config: Config{SockDir: dir, Runner: r, Sleeper: sl, OnRestart: func(n string) { restarted <- n }}}
	if e := s.Start(context.Background(), "wg0"); e != nil {
		t.Fatal(e)
	}
	r.mu.Lock()
	first := r.processes[0]
	r.mu.Unlock()
	first.exit()
	deadline := time.After(time.Second)
	for {
		sl.mu.Lock()
		count := len(sl.delays)
		sl.mu.Unlock()
		if count > 0 {
			break
		}
		select {
		case <-deadline:
			t.Fatal("restart did not schedule")
		case <-time.After(time.Millisecond):
		}
	}
	sl.wake <- struct{}{}
	select {
	case n := <-restarted:
		if n != "wg0" {
			t.Fatal(n)
		}
	case <-time.After(time.Second):
		t.Fatal("restart callback missing")
	}
	s.Stop("wg0")
	// A second crash enters backoff, which Stop must cancel.
	r.mu.Lock()
	p := r.processes[len(r.processes)-1]
	r.mu.Unlock()
	p.exit()
	select {
	case <-time.After(time.Second):
	case <-sl.wake:
	}
	s.Stop("wg0")
}

func TestRestartBackoffSequenceAcrossCrashes(t *testing.T) {
	dir := t.TempDir()
	l := socket(t, filepath.Join(dir, "wg0.sock"))
	defer l.Close()
	r := &fakeRunner{}
	sl := &fakeSleeper{wake: make(chan struct{}, 3)}
	callbacks := make(chan string, 3)
	s := &Supervisor{Config: Config{SockDir: dir, Runner: r, Sleeper: sl, OnRestart: func(n string) { callbacks <- n }}}
	if err := s.Start(context.Background(), "wg0"); err != nil {
		t.Fatal(err)
	}
	for i, want := range []time.Duration{time.Second, 2 * time.Second, 4 * time.Second} {
		r.mu.Lock()
		p := r.processes[len(r.processes)-1]
		r.mu.Unlock()
		p.exit()
		deadline := time.After(time.Second)
		for {
			sl.mu.Lock()
			count := len(sl.delays)
			sl.mu.Unlock()
			if count > i {
				break
			}
			select {
			case <-deadline:
				t.Fatal("restart did not enter backoff")
			case <-time.After(time.Millisecond):
			}
		}
		if got := s.Restarts("wg0"); got != uint64(i+1) {
			t.Fatalf("Restarts = %d; want %d", got, i+1)
		}
		sl.mu.Lock()
		got := sl.delays[i]
		sl.mu.Unlock()
		if got != want {
			t.Fatalf("delay[%d] = %s; want %s", i, got, want)
		}
		sl.wake <- struct{}{}
		select {
		case name := <-callbacks:
			if name != "wg0" {
				t.Fatalf("callback name = %q", name)
			}
		case <-time.After(time.Second):
			t.Fatal("restart callback missing")
		}
	}
	if err := s.Stop("wg0"); err != nil {
		t.Fatal(err)
	}
}

func TestEnvironmentIsMinimal(t *testing.T) {
	t.Setenv("SECRET_TEST_VALUE", "secret")
	t.Setenv("PATH", "/bin")
	s := &Supervisor{Config: Config{LogLevel: "error"}}
	env := s.environment()
	joined := ""
	for _, v := range env {
		joined += v + "\n"
	}
	if joined != "PATH=/bin\nWG_PROCESS_FOREGROUND=1\nLOG_LEVEL=error\n" {
		t.Fatal(joined)
	}
}
