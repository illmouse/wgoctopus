package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/illmouse/wgoctopus/internal/api"
	"github.com/illmouse/wgoctopus/internal/daemon"
	"github.com/illmouse/wgoctopus/internal/hop"
	"github.com/illmouse/wgoctopus/internal/manager"
	"github.com/illmouse/wgoctopus/internal/netsetup"
	"github.com/illmouse/wgoctopus/internal/store"
)

var version = "dev"

type secret string

func (secret) String() string       { return "[redacted]" }
func (secret) LogValue() slog.Value { return slog.StringValue("[redacted]") }

type config struct {
	Listen                                                    string
	Token                                                     secret
	StateDir, DaemonBin, SockDir, IPTablesBin, LogLevel       string
	MetricsPublic, AllowPublicListen, ShowVersion, HopEnabled bool
	ApplyTimeout                                              time.Duration
}

func parseConfig(args []string, getenv func(string) string) (config, error) {
	var c config
	fs := flag.NewFlagSet("wgoctopus-agent", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	listen := fs.String("listen", getenvDefault(getenv, "WGOCTOPUS_LISTEN", ""), "management listen address (required)")
	token := fs.String("token", getenv("WGOCTOPUS_TOKEN"), "bearer token")
	tokenFile := fs.String("token-file", "", "read bearer token from file")
	fs.StringVar(&c.StateDir, "state-dir", getenvDefault(getenv, "WGOCTOPUS_STATE_DIR", "/var/lib/wgoctopus"), "state directory")
	fs.StringVar(&c.DaemonBin, "daemon-bin", "amneziawg-go", "AWG daemon executable")
	fs.StringVar(&c.SockDir, "sock-dir", "/var/run/amneziawg", "AWG UAPI socket directory")
	fs.StringVar(&c.IPTablesBin, "iptables-bin", "iptables", "iptables executable")
	fs.BoolVar(&c.HopEnabled, "hop-enabled", strings.EqualFold(getenv("WGOCTOPUS_HOP_ENABLED"), "true"), "enable hop forwarding mode")
	fs.BoolVar(&c.MetricsPublic, "metrics-public", false, "allow unauthenticated metrics")
	fs.BoolVar(&c.AllowPublicListen, "allow-public-listen", false, "allow listening on all interfaces")
	fs.StringVar(&c.LogLevel, "log-level", "info", "debug, info, warn, or error")
	fs.DurationVar(&c.ApplyTimeout, "apply-timeout", 60*time.Second, "maximum time to wait for a state apply")
	fs.BoolVar(&c.ShowVersion, "version", false, "print version")
	if err := fs.Parse(args); err != nil {
		return c, err
	}
	c.Listen = *listen
	if c.ShowVersion {
		return c, nil
	}
	if c.Listen == "" {
		return c, errors.New("--listen is required")
	}
	host, _, err := net.SplitHostPort(c.Listen)
	if err != nil {
		return c, fmt.Errorf("invalid --listen: %w", err)
	}
	if (host == "" || host == "0.0.0.0" || host == "::") && !c.AllowPublicListen {
		return c, errors.New("public listen address requires --allow-public-listen")
	}
	if *tokenFile != "" {
		b, err := os.ReadFile(*tokenFile)
		if err != nil {
			return c, fmt.Errorf("read token file: %w", err)
		}
		*token = strings.TrimSpace(string(b))
	}
	if strings.TrimSpace(*token) == "" {
		return c, errors.New("token is required")
	}
	c.Token = secret(strings.TrimSpace(*token))
	var level slog.Level
	if err := level.UnmarshalText([]byte(c.LogLevel)); err != nil {
		return c, fmt.Errorf("invalid log level: %w", err)
	}
	return c, nil
}

func getenvDefault(getenv func(string) string, key, fallback string) string {
	if v := getenv(key); v != "" {
		return v
	}
	return fallback
}

func main() {
	cfg, err := parseConfig(os.Args[1:], os.Getenv)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	if cfg.ShowVersion {
		fmt.Println(version)
		return
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	if err := run(ctx, cfg); err != nil {
		slog.Error("agent stopped", "error", err)
		os.Exit(1)
	}
}

func run(ctx context.Context, cfg config) error {
	var level slog.LevelVar
	if err := level.UnmarshalText([]byte(cfg.LogLevel)); err != nil {
		return err
	}
	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: &level})))
	sup := &daemon.Supervisor{Config: daemon.Config{BinPath: cfg.DaemonBin, SockDir: cfg.SockDir}}
	link := netsetup.Netlink{}
	fw := netsetup.IPTables{Path: cfg.IPTablesBin, DefaultEgress: link.DefaultRouteInterface}
	mgr := &manager.Manager{Daemons: sup, Links: link, Firewall: fw, Store: manager.FileStore{Store: store.Store{Dir: cfg.StateDir}}, SocketDir: cfg.SockDir}
	if cfg.HopEnabled {
		mgr.Hop = hop.New(hop.Deps{Path: cfg.IPTablesBin, Conntrack: hop.NetlinkConntrack{}})
	}
	mgr.RegisterRestartHandler()
	collector := mgr.Collector()
	collector.Version = version
	if cfg.HopEnabled {
		collector.HopStats = mgr.HopStats
	}
	srv := &api.Server{Token: string(cfg.Token), AllowMetrics: cfg.MetricsPublic, Applier: mgr, Collector: collector, HopEnabled: cfg.HopEnabled, ApplyTimeout: cfg.ApplyTimeout}
	httpSrv := &http.Server{Addr: cfg.Listen, Handler: srv.Handler(), ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 15 * time.Second, WriteTimeout: 30 * time.Second, IdleTimeout: 60 * time.Second}
	bootCtx, cancelBoot := context.WithCancel(ctx)
	defer cancelBoot()
	bootErr := make(chan error, 1)
	go func() {
		if err := mgr.Boot(bootCtx, 30*time.Second); err != nil && !errors.Is(err, context.Canceled) {
			bootErr <- err
		}
	}()
	serveErr := make(chan error, 1)
	go func() { serveErr <- httpSrv.ListenAndServe() }()
	select {
	case err := <-bootErr:
		cancelBoot()
		_ = httpSrv.Close()
		_ = mgr.Shutdown()
		return fmt.Errorf("boot manager: %w", err)
	case err := <-serveErr:
		if !errors.Is(err, http.ErrServerClosed) {
			cancelBoot()
			_ = mgr.Shutdown()
			return fmt.Errorf("http server: %w", err)
		}
	case <-ctx.Done():
	}
	cancelBoot()
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	shutdownErr := httpSrv.Shutdown(shutdownCtx)
	managerErr := mgr.Shutdown()
	return errors.Join(shutdownErr, managerErr)
}
