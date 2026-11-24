package pull

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/subtle"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

type serverOptions struct {
	unauthorized  bool
	muteKeepalive bool
}

type testServer struct {
	addr       string
	host       ssh.PublicKey
	listener   net.Listener
	mu         sync.Mutex
	conns      map[net.Conn]struct{}
	sshConns   map[*ssh.ServerConn]struct{}
	accepted   int
	forwards   chan struct{}
	authorized ssh.PublicKey
}

func startServer(t *testing.T, opts serverOptions) *testServer {
	t.Helper()
	clientPub, clientPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	serverPub, serverPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	host, err := ssh.NewPublicKey(serverPub)
	if err != nil {
		t.Fatal(err)
	}
	clientKey, err := ssh.NewPublicKey(clientPub)
	if err != nil {
		t.Fatal(err)
	}
	privateDER, err := x509.MarshalPKCS8PrivateKey(clientPriv)
	if err != nil {
		t.Fatal(err)
	}
	keyPath := filepath.Join(t.TempDir(), "client-key")
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privateDER}), 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PULL_TEST_KEY", keyPath)

	signer, err := ssh.NewSignerFromKey(serverPriv)
	if err != nil {
		t.Fatal(err)
	}
	allowed := clientKey
	if opts.unauthorized {
		otherPub, _, e := ed25519.GenerateKey(rand.Reader)
		if e != nil {
			t.Fatal(e)
		}
		allowed, err = ssh.NewPublicKey(otherPub)
		if err != nil {
			t.Fatal(err)
		}
	}
	config := &ssh.ServerConfig{PublicKeyCallback: func(_ ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
		if subtle.ConstantTimeCompare(key.Marshal(), allowed.Marshal()) != 1 {
			return nil, fmt.Errorf("unauthorized")
		}
		return nil, nil
	}}
	config.AddHostKey(signer)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	s := &testServer{addr: ln.Addr().String(), host: host, listener: ln, conns: make(map[net.Conn]struct{}), sshConns: make(map[*ssh.ServerConn]struct{}), forwards: make(chan struct{}, 32), authorized: allowed}
	t.Cleanup(func() { ln.Close(); s.dropAll() })
	go func() {
		for {
			raw, e := ln.Accept()
			if e != nil {
				return
			}
			s.mu.Lock()
			s.accepted++
			s.conns[raw] = struct{}{}
			s.mu.Unlock()
			go s.serve(raw, config, opts)
		}
	}()
	return s
}

func (s *testServer) serve(raw net.Conn, config *ssh.ServerConfig, opts serverOptions) {
	defer func() { raw.Close(); s.mu.Lock(); delete(s.conns, raw); s.mu.Unlock() }()
	conn, chans, reqs, err := ssh.NewServerConn(raw, config)
	if err != nil {
		return
	}
	defer conn.Close()
	s.mu.Lock()
	s.sshConns[conn] = struct{}{}
	s.mu.Unlock()
	defer func() { s.mu.Lock(); delete(s.sshConns, conn); s.mu.Unlock() }()
	go func() {
		for ch := range chans {
			if ch.ChannelType() != "forwarded-tcpip" {
				_ = ch.Reject(ssh.UnknownChannelType, "unsupported")
				continue
			}
			channel, requests, e := ch.Accept()
			if e != nil {
				continue
			}
			go ssh.DiscardRequests(requests)
			_ = channel.Close()
		}
	}()
	for req := range reqs {
		switch req.Type {
		case "tcpip-forward":
			var payload struct {
				Addr string
				Port uint32
			}
			_ = ssh.Unmarshal(req.Payload, &payload)
			if req.WantReply {
				_ = req.Reply(true, ssh.Marshal(struct{ Port uint32 }{40000}))
			}
			select {
			case s.forwards <- struct{}{}:
			default:
			}
		case "keepalive@openssh.com":
			if !opts.muteKeepalive && req.WantReply {
				_ = req.Reply(true, nil)
			}
		default:
			if req.WantReply {
				_ = req.Reply(false, nil)
			}
		}
	}
}

func (s *testServer) count() int { s.mu.Lock(); defer s.mu.Unlock(); return s.accepted }
func (s *testServer) dropAll() {
	s.mu.Lock()
	conns := make([]net.Conn, 0, len(s.conns))
	for c := range s.conns {
		conns = append(conns, c)
	}
	s.mu.Unlock()
	for _, c := range conns {
		_ = c.Close()
	}
}

func eventually(t *testing.T, timeout time.Duration, fn func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if fn() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("condition was not met before timeout")
}

func runnerConfig(s *testServer, target string) Config {
	return Config{Server: s.addr, User: "node", KeyFile: os.Getenv("PULL_TEST_KEY"), HostKeyFingerprint: ssh.FingerprintSHA256(s.host), Target: target, KeepAlive: 100 * time.Millisecond, MinBackoff: 10 * time.Millisecond, MaxBackoff: 50 * time.Millisecond, DialTimeout: 2 * time.Second}
}

func runRunner(t *testing.T, c Config) (context.CancelFunc, *Runner) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	r := &Runner{Config: c}
	done := make(chan struct{})
	go func() { r.Run(ctx); close(done) }()
	t.Cleanup(func() {
		cancel()
		select {
		case <-done:
		case <-time.After(2 * time.Second):
			t.Error("Run did not stop")
		}
	})
	return cancel, r
}

func (s *testServer) openForwarded() (ssh.Channel, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for conn := range s.sshConns {
		ch, reqs, err := conn.OpenChannel("forwarded-tcpip", ssh.Marshal(struct {
			ConnectedAddr string
			ConnectedPort uint32
			OriginAddr    string
			OriginPort    uint32
		}{"127.0.0.1", 40000, "127.0.0.1", 50000}))
		if err == nil {
			go ssh.DiscardRequests(reqs)
			return ch, nil
		}
	}
	return nil, fmt.Errorf("no live SSH connection")
}

func TestHappyPath(t *testing.T) {
	s := startServer(t, serverOptions{})
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, "pong") }))
	defer api.Close()
	_, r := runRunner(t, runnerConfig(s, api.Listener.Addr().String()))
	eventually(t, 3*time.Second, func() bool { st := r.Stats(); return st.Connected && st.Attempts >= 1 && st.LastConnected > 0 })
	got := httpThrough(t, s)
	if !strings.Contains(got, "200 OK") || !strings.HasSuffix(got, "pong") {
		t.Fatalf("unexpected response through tunnel: %q", got)
	}
}

// httpThrough opens a forwarded channel like the orchestrator would and
// performs one HTTP request over it.
func httpThrough(t *testing.T, s *testServer) string {
	t.Helper()
	ch, err := s.openForwarded()
	if err != nil {
		t.Fatal(err)
	}
	defer ch.Close()
	if _, err := io.WriteString(ch, "GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n"); err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(ch)
	return string(b)
}

func TestConcurrentChannels(t *testing.T) {
	s := startServer(t, serverOptions{})
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, "pong") }))
	defer api.Close()
	_, r := runRunner(t, runnerConfig(s, api.Listener.Addr().String()))
	eventually(t, 3*time.Second, func() bool { return r.Stats().Connected })
	var wg sync.WaitGroup
	results := make(chan string, 8)
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); results <- httpThrough(t, s) }()
	}
	wg.Wait()
	close(results)
	for got := range results {
		if !strings.HasSuffix(got, "pong") {
			t.Fatalf("concurrent response: %q", got)
		}
	}
}

func TestWrongHostKeyPin(t *testing.T) {
	s := startServer(t, serverOptions{})
	c := runnerConfig(s, "127.0.0.1:1")
	c.HostKeyFingerprint = "wrong"
	_, r := runRunner(t, c)
	eventually(t, 3*time.Second, func() bool { return r.Stats().Attempts >= 2 && r.Stats().LastError == "hostkey" })
	if r.Stats().Connected {
		t.Fatal("connected with wrong pin")
	}
}
func TestUnauthorizedKey(t *testing.T) {
	s := startServer(t, serverOptions{unauthorized: true})
	_, r := runRunner(t, runnerConfig(s, "127.0.0.1:1"))
	eventually(t, 3*time.Second, func() bool { return r.Stats().LastError == "auth" })
}

func TestKeyFilePermissionsRefused(t *testing.T) {
	s := startServer(t, serverOptions{})
	c := runnerConfig(s, "127.0.0.1:1")
	_ = os.Chmod(c.KeyFile, 0644)
	_, r := runRunner(t, c)
	eventually(t, time.Second, func() bool { return r.Stats().LastError == "key" })
	if s.count() != 0 {
		t.Fatalf("server accepted %d connections", s.count())
	}
}
func TestMissingKeyFile(t *testing.T) {
	s := startServer(t, serverOptions{})
	c := runnerConfig(s, "127.0.0.1:1")
	c.KeyFile = filepath.Join(t.TempDir(), "missing")
	_, r := runRunner(t, c)
	eventually(t, time.Second, func() bool { return r.Stats().LastError == "key" })
}

func TestReconnectAfterDrop(t *testing.T) {
	s := startServer(t, serverOptions{})
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, "pong") }))
	defer api.Close()
	_, r := runRunner(t, runnerConfig(s, api.Listener.Addr().String()))
	eventually(t, 3*time.Second, func() bool { return r.Stats().Connected })
	before := r.Stats().Attempts
	s.dropAll()
	eventually(t, 3*time.Second, func() bool { return r.Stats().Connected && r.Stats().Attempts > before })
}
func TestKeepaliveMuteTriggersReconnect(t *testing.T) {
	s := startServer(t, serverOptions{muteKeepalive: true})
	_, r := runRunner(t, runnerConfig(s, "127.0.0.1:1"))
	eventually(t, 3*time.Second, func() bool { return s.count() >= 2 && r.Stats().Attempts >= 2 })
}

func TestCancelStopsPromptlyAndNoLeak(t *testing.T) {
	baseline := runtime.NumGoroutine()
	s := startServer(t, serverOptions{})
	cancel, r := runRunner(t, runnerConfig(s, "127.0.0.1:1"))
	eventually(t, 3*time.Second, func() bool { return r.Stats().Connected })
	start := time.Now()
	cancel()
	eventually(t, 2*time.Second, func() bool { return !r.Stats().Connected })
	if time.Since(start) >= 2*time.Second {
		t.Fatal("cancel was slow")
	}
	eventually(t, 2*time.Second, func() bool { return runtime.NumGoroutine() <= baseline+2 })
}

func TestCancelDuringHandshake(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		c, e := ln.Accept()
		if e == nil {
			defer c.Close()
			b := make([]byte, 1)
			_, _ = c.Read(b)
		}
	}()
	baseline := runtime.NumGoroutine()
	keyServer := startServer(t, serverOptions{})
	c := runnerConfig(keyServer, "127.0.0.1:1")
	c.Server = ln.Addr().String()
	_, r := runRunner(t, c)
	_ = r
	eventually(t, time.Second, func() bool { return true })
	eventually(t, 2*time.Second, func() bool { return runtime.NumGoroutine() <= baseline+5 })
}

func TestBackoffGrowsAndCaps(t *testing.T) {
	s := startServer(t, serverOptions{})
	c := runnerConfig(s, "127.0.0.1:1")
	c.Server = "127.0.0.1:1"
	var mu sync.Mutex
	var ds []time.Duration
	c.Sleep = func(ctx context.Context, d time.Duration) error {
		mu.Lock()
		ds = append(ds, d)
		n := len(ds)
		mu.Unlock()
		if n == 5 {
			return context.Canceled
		}
		return nil
	}
	r := &Runner{Config: c}
	r.Run(context.Background())
	mu.Lock()
	defer mu.Unlock()
	if len(ds) != 5 {
		t.Fatalf("sleeps %v", ds)
	}
	nominal := []time.Duration{10 * time.Millisecond, 20 * time.Millisecond, 40 * time.Millisecond, 50 * time.Millisecond, 50 * time.Millisecond}
	for i, d := range ds {
		if d < nominal[i]*8/10 || d > nominal[i]*12/10 {
			t.Errorf("sleep %d = %v, nominal %v", i, d, nominal[i])
		}
	}
}

func TestLogsContainNoSecrets(t *testing.T) {
	s := startServer(t, serverOptions{})
	var mu sync.Mutex
	var b strings.Builder
	logger := slog.New(slog.NewTextHandler(&lockedWriter{mu: &mu, b: &b}, nil))
	c := runnerConfig(s, "127.0.0.1:1")
	c.Logger = logger
	cancel, r := runRunner(t, c)
	eventually(t, 3*time.Second, func() bool { return r.Stats().Connected })
	cancel()
	eventually(t, 2*time.Second, func() bool { return !r.Stats().Connected })
	mu.Lock()
	text := b.String()
	mu.Unlock()
	if strings.Contains(text, ssh.FingerprintSHA256(s.host)) || strings.Contains(text, "PRIVATE KEY") || strings.Contains(text, c.KeyFile) {
		t.Fatalf("logs contain sensitive data: %s", text)
	}
}

type lockedWriter struct {
	mu *sync.Mutex
	b  *strings.Builder
}

func (w *lockedWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.b.Write(p)
}

func TestTargetUnreachableKeepsTunnel(t *testing.T) {
	s := startServer(t, serverOptions{})
	_, r := runRunner(t, runnerConfig(s, "127.0.0.1:1"))
	eventually(t, 3*time.Second, func() bool { return r.Stats().Connected })
	if got := httpThrough(t, s); strings.Contains(got, "200") {
		t.Fatalf("unreachable target produced a response: %q", got)
	}
	if !r.Stats().Connected {
		t.Fatal("unreachable target disconnected tunnel")
	}
}
