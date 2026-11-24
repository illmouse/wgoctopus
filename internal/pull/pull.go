// Package pull maintains an SSH reverse tunnel to an agent API.
package pull

import (
	"context"
	"crypto/subtle"
	"errors"
	"io"
	"log/slog"
	"math/rand/v2"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"
)

type Config struct {
	Server, User, KeyFile, HostKeyFingerprint, Target string
	KeepAlive, DialTimeout, MinBackoff, MaxBackoff    time.Duration
	Logger                                            *slog.Logger
	Dial                                              func(context.Context, string, string) (net.Conn, error)
	Now                                               func() time.Time
	Sleep                                             func(context.Context, time.Duration) error
}

type Stats struct {
	Connected     bool
	Attempts      uint64
	LastConnected int64
	LastError     string
}
type Runner struct {
	Config Config
	mu     sync.Mutex
	stats  Stats
}

func (r *Runner) snapshot() Stats    { r.mu.Lock(); defer r.mu.Unlock(); return r.stats }
func (r *Runner) set(f func(*Stats)) { r.mu.Lock(); defer r.mu.Unlock(); f(&r.stats) }
func (r *Runner) Stats() Stats       { return r.snapshot() }

func (c Config) defaults() Config {
	if c.KeepAlive <= 0 {
		c.KeepAlive = 30 * time.Second
	}
	if c.DialTimeout <= 0 {
		c.DialTimeout = 15 * time.Second
	}
	if c.MinBackoff <= 0 {
		c.MinBackoff = 2 * time.Second
	}
	if c.MaxBackoff <= 0 {
		c.MaxBackoff = 120 * time.Second
	}
	if c.Dial == nil {
		d := net.Dialer{Timeout: c.DialTimeout}
		c.Dial = func(ctx context.Context, n, a string) (net.Conn, error) { return d.DialContext(ctx, n, a) }
	}
	if c.Now == nil {
		c.Now = time.Now
	}
	if c.Sleep == nil {
		c.Sleep = func(ctx context.Context, d time.Duration) error {
			t := time.NewTimer(d)
			defer t.Stop()
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-t.C:
				return nil
			}
		}
	}
	return c
}

func (r *Runner) Run(ctx context.Context) {
	c := r.Config.defaults()
	backoff := c.MinBackoff
	for ctx.Err() == nil {
		r.set(func(s *Stats) { s.Attempts++ })
		started := c.Now()
		class := r.session(ctx, c)
		r.set(func(s *Stats) { s.Connected = false; s.LastError = class })
		if ctx.Err() != nil {
			return
		}
		if c.Logger != nil {
			c.Logger.Warn("pull tunnel disconnected", "server", c.Server, "class", class)
		}
		if c.Now().Sub(started) > 60*time.Second {
			backoff = c.MinBackoff
		}
		jitter := time.Duration(float64(backoff) * (rand.Float64()*0.4 - 0.2))
		if c.Sleep(ctx, backoff+jitter) != nil {
			return
		}
		backoff *= 2
		if backoff > c.MaxBackoff {
			backoff = c.MaxBackoff
		}
	}
}

func (r *Runner) session(ctx context.Context, c Config) string {
	info, err := os.Stat(c.KeyFile)
	if err != nil || info.Mode().Perm()&0077 != 0 {
		return "key"
	}
	b, err := os.ReadFile(c.KeyFile)
	if err != nil {
		return "key"
	}
	signer, err := ssh.ParsePrivateKey(b)
	if err != nil {
		return "key"
	}
	hostKeyMismatch := false
	callback := func(_ string, _ net.Addr, key ssh.PublicKey) error {
		got := ssh.FingerprintSHA256(key)
		if len(got) != len(c.HostKeyFingerprint) || subtle.ConstantTimeCompare([]byte(got), []byte(c.HostKeyFingerprint)) != 1 {
			hostKeyMismatch = true
			return errors.New("host key mismatch")
		}
		return nil
	}
	conf := &ssh.ClientConfig{User: c.User, Auth: []ssh.AuthMethod{ssh.PublicKeys(signer)}, HostKeyCallback: callback, Timeout: c.DialTimeout}
	conn, err := c.Dial(ctx, "tcp", c.Server)
	if err != nil {
		return "dial"
	}
	// Closing the connection on cancellation aborts a blocked handshake;
	// a deadline bounds a server that accepts TCP but never answers.
	stopWatch := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stopWatch()
	_ = conn.SetDeadline(c.Now().Add(c.DialTimeout))
	clientConn, chans, reqs, err := ssh.NewClientConn(conn, c.Server, conf)
	if err != nil {
		conn.Close()
		switch {
		case hostKeyMismatch:
			return "hostkey"
		case ctx.Err() != nil:
			return ""
		case strings.Contains(err.Error(), "unable to authenticate"):
			return "auth"
		default:
			return "handshake"
		}
	}
	_ = conn.SetDeadline(time.Time{})
	client := ssh.NewClient(clientConn, chans, reqs)
	defer client.Close()
	l, err := client.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return "forward"
	}
	defer l.Close()
	r.set(func(s *Stats) { s.Connected = true; s.LastConnected = c.Now().Unix(); s.LastError = "" })
	failed := make(chan struct{}, 1)
	done := make(chan struct{})
	defer close(done)
	go func() {
		ticker := time.NewTicker(c.KeepAlive)
		defer ticker.Stop()
		failures := 0
		for {
			select {
			case <-done:
				return
			case <-ctx.Done():
				return
			case <-ticker.C:
				// A "failure" reply still proves the peer is alive (OpenSSH
				// answers unknown global requests that way); only errors and
				// timeouts count.
				if _, e := keepalive(client, c.KeepAlive); e != nil {
					failures++
				} else {
					failures = 0
				}
				if failures >= 2 {
					select {
					case failed <- struct{}{}:
					default:
					}
					// Unblock Accept in the main loop.
					_ = client.Close()
					return
				}
			}
		}
	}()
	for {
		select {
		case <-ctx.Done():
			return ""
		case <-failed:
			return "keepalive"
		default:
		}
		conn, err := l.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return ""
			}
			select {
			case <-failed:
				return "keepalive"
			default:
			}
			return "forward"
		}
		go proxy(ctx, conn, c.Target)
	}
}

// keepalive sends one request and gives up after timeout; a server that
// never answers counts as a failure.
func keepalive(client *ssh.Client, timeout time.Duration) (bool, error) {
	type result struct {
		ok  bool
		err error
	}
	ch := make(chan result, 1)
	go func() {
		ok, _, err := client.SendRequest("keepalive@openssh.com", true, nil)
		ch <- result{ok, err}
	}()
	select {
	case r := <-ch:
		return r.ok, r.err
	case <-time.After(timeout):
		return false, errors.New("keepalive timeout")
	}
}

func proxy(ctx context.Context, incoming net.Conn, target string) {
	defer incoming.Close()
	out, err := (&net.Dialer{Timeout: 5 * time.Second}).DialContext(ctx, "tcp", target)
	if err != nil {
		return
	}
	defer out.Close()
	done := make(chan struct{}, 2)
	go func() { _, _ = io.Copy(out, incoming); done <- struct{}{} }()
	go func() { _, _ = io.Copy(incoming, out); done <- struct{}{} }()
	<-done
	incoming.Close()
	out.Close()
	<-done
}
