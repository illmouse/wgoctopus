package daemon

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"sync"
	"syscall"
	"time"
)

// Process is a started child process.
type Process interface {
	Wait() error
	Signal(os.Signal) error
	Kill() error
}

// Runner starts the daemon with the supplied arguments and environment.
type Runner interface {
	Start(name string, args, env []string) (Process, error)
}

// Clock supplies time for process lifetime accounting.
type Clock interface{ Now() time.Time }

// Sleeper supports cancellable delays, including restart backoff.
type Sleeper interface {
	Sleep(context.Context, time.Duration) error
}

// Config configures the supervisor. Empty values use production defaults.
type Config struct {
	BinPath, SockDir, LogLevel string
	StartTimeout, StopGrace    time.Duration
	Runner                     Runner
	Clock                      Clock
	Sleeper                    Sleeper
	OnRestart                  func(string)
}

// Supervisor manages one amneziawg-go subprocess per interface.
type Supervisor struct {
	Config
	mu      sync.Mutex
	items   map[string]*entry
	stopped bool
}

// SetOnRestart sets the callback invoked after a restarted daemon becomes ready.
func (s *Supervisor) SetOnRestart(callback func(string)) {
	s.mu.Lock()
	s.OnRestart = callback
	s.mu.Unlock()
}

type entry struct {
	process  Process
	done     chan struct{}
	cancel   context.CancelFunc
	started  time.Time
	restarts uint64
}

type execRunner struct{}
type execProcess struct{ cmd *exec.Cmd }

func (execRunner) Start(name string, args, env []string) (Process, error) {
	c := exec.Command(name, args...)
	c.Env = env
	if err := c.Start(); err != nil {
		return nil, err
	}
	return &execProcess{c}, nil
}
func (p *execProcess) Wait() error              { return p.cmd.Wait() }
func (p *execProcess) Signal(s os.Signal) error { return p.cmd.Process.Signal(s) }
func (p *execProcess) Kill() error              { return p.cmd.Process.Kill() }

type realClock struct{}

func (realClock) Now() time.Time { return time.Now() }

type realSleeper struct{}

func (realSleeper) Sleep(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

func (s *Supervisor) defaults() {
	if s.BinPath == "" {
		s.BinPath = "amneziawg-go"
	}
	if s.SockDir == "" {
		s.SockDir = "/var/run/amneziawg"
	}
	if s.StartTimeout <= 0 {
		s.StartTimeout = 10 * time.Second
	}
	if s.StopGrace <= 0 {
		s.StopGrace = 3 * time.Second
	}
	if s.Runner == nil {
		s.Runner = execRunner{}
	}
	if s.Clock == nil {
		s.Clock = realClock{}
	}
	if s.Sleeper == nil {
		s.Sleeper = realSleeper{}
	}
	if s.items == nil {
		s.items = make(map[string]*entry)
	}
}

// Start launches name and waits for its UAPI socket to accept a connection.
func (s *Supervisor) Start(ctx context.Context, name string) error {
	s.mu.Lock()
	s.defaults()
	if s.stopped {
		s.mu.Unlock()
		return errors.New("supervisor stopped")
	}
	if e := s.items[name]; e != nil {
		done := e.done
		s.mu.Unlock()
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-done:
			return fmt.Errorf("daemon %s exited", name)
		default:
			return nil
		}
	}
	e := &entry{}
	s.items[name] = e
	s.mu.Unlock()
	if !validName(name) {
		s.mu.Lock()
		delete(s.items, name)
		s.mu.Unlock()
		return fmt.Errorf("invalid interface name %q", name)
	}
	if err := s.launch(name, e); err != nil {
		s.mu.Lock()
		delete(s.items, name)
		s.mu.Unlock()
		return err
	}
	deadline := time.NewTimer(s.StartTimeout)
	defer deadline.Stop()
	poll := time.NewTicker(25 * time.Millisecond)
	defer poll.Stop()
	for {
		if c, err := net.DialTimeout("unix", filepath.Join(s.SockDir, name+".sock"), 50*time.Millisecond); err == nil {
			_ = c.Close()
			return nil
		}
		select {
		case <-ctx.Done():
			s.Stop(name)
			return ctx.Err()
		case <-e.done:
			return fmt.Errorf("daemon %s exited before socket became ready", name)
		case <-deadline.C:
			s.Stop(name)
			return fmt.Errorf("timed out waiting for daemon %s socket", name)
		case <-poll.C:
		}
	}
}

func (s *Supervisor) environment() []string {
	path := os.Getenv("PATH")
	env := []string{}
	if path != "" {
		env = append(env, "PATH="+path)
	}
	env = append(env, "WG_PROCESS_FOREGROUND=1")
	if s.LogLevel != "" {
		env = append(env, "LOG_LEVEL="+s.LogLevel)
	}
	return env
}

func (s *Supervisor) launch(name string, e *entry) error {
	p, err := s.Runner.Start(s.BinPath, []string{"-f", name}, s.environment())
	if err != nil {
		return err
	}
	ctx, cancel := context.WithCancel(context.Background())
	s.mu.Lock()
	e.process = p
	e.done = make(chan struct{})
	e.cancel = cancel
	e.started = s.Clock.Now()
	done := e.done
	s.mu.Unlock()
	go s.monitor(name, e, p, done, ctx)
	return nil
}

func (s *Supervisor) monitor(name string, e *entry, p Process, done chan struct{}, ctx context.Context) {
	_ = p.Wait()
	s.mu.Lock()
	close(done)
	if s.items[name] != e || e.process != p {
		s.mu.Unlock()
		return
	}
	e.process = nil
	if ctx.Err() != nil {
		s.mu.Unlock()
		return
	}
	if s.Clock.Now().Sub(e.started) >= 60*time.Second {
		e.restarts = 0
	}
	e.restarts++
	n := e.restarts
	s.mu.Unlock()
	go s.restart(name, e, ctx, n)
}

func (s *Supervisor) restart(name string, e *entry, ctx context.Context, n uint64) {
	delay := time.Second
	for i := uint64(1); i < n && delay < 30*time.Second; i++ {
		delay *= 2
	}
	if delay > 30*time.Second {
		delay = 30 * time.Second
	}
	for {
		if s.Sleeper.Sleep(ctx, delay) != nil {
			return
		}
		s.mu.Lock()
		valid := s.items[name] == e && ctx.Err() == nil
		s.mu.Unlock()
		if !valid {
			return
		}
		if err := s.launch(name, e); err == nil {
			if s.waitSocket(ctx, name) == nil && s.OnRestart != nil {
				s.OnRestart(name)
			}
			return
		}
		if delay < 30*time.Second {
			delay *= 2
			if delay > 30*time.Second {
				delay = 30 * time.Second
			}
		}
	}
}

func (s *Supervisor) waitSocket(ctx context.Context, name string) error {
	deadline := time.NewTimer(s.StartTimeout)
	defer deadline.Stop()
	t := time.NewTicker(25 * time.Millisecond)
	defer t.Stop()
	for {
		if c, e := net.DialTimeout("unix", filepath.Join(s.SockDir, name+".sock"), 50*time.Millisecond); e == nil {
			_ = c.Close()
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-deadline.C:
			return errors.New("socket timeout")
		case <-t.C:
		}
	}
}

// Stop terminates a daemon, cancels pending restarts, and removes its stale socket.
func (s *Supervisor) Stop(name string) error {
	s.mu.Lock()
	s.defaults()
	e := s.items[name]
	if e == nil {
		s.mu.Unlock()
		err := os.Remove(filepath.Join(s.SockDir, name+".sock"))
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}
	if e.cancel != nil {
		e.cancel()
	}
	p, done := e.process, e.done
	if p == nil {
		delete(s.items, name)
		s.mu.Unlock()
		err := os.Remove(filepath.Join(s.SockDir, name+".sock"))
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}
	e.process = nil
	s.mu.Unlock()
	if err := p.Signal(syscall.SIGTERM); err != nil {
		_ = p.Kill()
	}
	select {
	case <-done:
	case <-time.After(s.StopGrace):
		_ = p.Kill()
		<-done
	}
	s.mu.Lock()
	if s.items[name] == e {
		delete(s.items, name)
	}
	s.mu.Unlock()
	err := os.Remove(filepath.Join(s.SockDir, name+".sock"))
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	return err
}

// Running reports whether name has a live process.
func (s *Supervisor) Running(name string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.items[name] != nil && s.items[name].process != nil
}

// Names returns the managed interface names in sorted order.
func (s *Supervisor) Names() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]string, 0, len(s.items))
	for n := range s.items {
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}

// Restarts returns the number of restarts scheduled for name.
func (s *Supervisor) Restarts(name string) uint64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	if e := s.items[name]; e != nil {
		return e.restarts
	}
	return 0
}

// StopAll terminates all daemons managed by the supervisor.
func (s *Supervisor) StopAll() error {
	s.mu.Lock()
	s.defaults()
	s.stopped = true
	names := make([]string, 0, len(s.items))
	for n := range s.items {
		names = append(names, n)
	}
	s.mu.Unlock()
	var errs []error
	for _, n := range names {
		if err := s.Stop(n); err != nil && !errors.Is(err, os.ErrNotExist) {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// Validate interface names before constructing socket paths or process arguments.
func validName(name string) bool {
	return name != "" && filepath.Base(name) == name && name != "." && name != ".."
}
