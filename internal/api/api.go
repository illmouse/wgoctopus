package api

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/illmouse/wgoctopus/internal/state"
)

// Applier executes a validated desired state.
type Applier interface{ Apply(state.State, bool) error }

// MetricsCollector renders the metrics endpoint's Prometheus exposition.
type MetricsCollector interface{ Render(context.Context) []byte }

type Server struct {
	Token        string
	AllowMetrics bool
	Metrics      func() string
	Collector    MetricsCollector
	Applier      Applier
	HopEnabled   bool
	Apply        func(state.State, bool) error // Deprecated: use Applier.
	ApplyTimeout time.Duration
	applyMu      sync.Mutex
	mu           sync.RWMutex
	applied      state.State
}

type stateSource interface{ Applied() state.State }

func (s *Server) currentState() state.State {
	if source, ok := s.Applier.(stateSource); ok {
		return source.Applied()
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.applied
}

func (s *Server) Handler() http.Handler {
	m := http.NewServeMux()
	m.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(200); fmt.Fprintln(w, "ok") })
	m.HandleFunc("/metrics", func(w http.ResponseWriter, r *http.Request) {
		if !s.AllowMetrics && !s.auth(r) {
			http.Error(w, "unauthorized", 401)
			return
		}
		if s.Collector != nil {
			w.Header().Set("Content-Type", "text/plain; version=0.0.4")
			_, _ = w.Write(s.Collector.Render(r.Context()))
			return
		}
		if s.Metrics != nil {
			w.Header().Set("Content-Type", "text/plain; version=0.0.4")
			fmt.Fprint(w, s.Metrics())
			return
		}
		s.mu.RLock()
		revision := s.applied.Revision
		s.mu.RUnlock()
		fmt.Fprintf(w, "wgoctopus_agent_applied_revision %d\n", revision)
	})
	m.HandleFunc("/v1/state", s.state)
	return m
}
func (s *Server) auth(r *http.Request) bool {
	v := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	return s.Token != "" && len(v) == len(s.Token) && subtle.ConstantTimeCompare([]byte(v), []byte(s.Token)) == 1
}
func (s *Server) state(w http.ResponseWriter, r *http.Request) {
	if !s.auth(r) {
		http.Error(w, "unauthorized", 401)
		return
	}
	switch r.Method {
	case http.MethodGet:
		applied := s.currentState()
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{"revision": applied.Revision, "checksum": applied.Checksum(), "state": applied})
	case http.MethodPut:
		var v state.State
		d := json.NewDecoder(http.MaxBytesReader(w, r.Body, 2<<20))
		d.DisallowUnknownFields()
		if e := d.Decode(&v); e != nil {
			http.Error(w, e.Error(), 422)
			return
		}
		if e := v.Validate(); e != nil {
			http.Error(w, e.Error(), 422)
			return
		}
		if v.Hop != nil && !s.HopEnabled {
			http.Error(w, "hop mode is disabled on this agent (start with --hop-enabled)", 422)
			return
		}
		force := r.URL.Query().Get("allow_dangerous") == "true"
		s.applyMu.Lock()
		defer s.applyMu.Unlock()
		applied := s.currentState()
		if v.Revision <= applied.Revision {
			http.Error(w, "stale revision", 409)
			return
		}
		apply := s.Applier
		if apply != nil || s.Apply != nil {
			var e error
			done := make(chan error, 1)
			if apply != nil {
				go func() { done <- apply.Apply(v, force) }()
			} else {
				go func() { done <- s.Apply(v, force) }()
			}
			timeout := s.ApplyTimeout
			if timeout <= 0 {
				timeout = 60 * time.Second
			}
			select {
			case e = <-done:
			case <-time.After(timeout):
				http.Error(w, "apply timed out", http.StatusGatewayTimeout)
				return
			}
			if e != nil {
				code := 422
				var dangerous interface{ GetReasons() []string }
				if errorsAs(e, &dangerous) {
					code = 409
				} else if strings.Contains(e.Error(), "revision") {
					code = 409
				}
				if code == 409 {
					w.Header().Set("Content-Type", "application/json")
					w.WriteHeader(code)
					_ = json.NewEncoder(w).Encode(map[string]any{"error": e.Error(), "reasons": dangerousReasons(e)})
					return
				}
				http.Error(w, e.Error(), code)
				return
			}
		}
		s.mu.Lock()
		s.applied = v
		s.mu.Unlock()
		w.WriteHeader(204)
	default:
		w.Header().Set("Allow", "GET, PUT")
		http.Error(w, "method not allowed", 405)
	}
}

func dangerousReasons(err error) []string {
	var e interface{ GetReasons() []string }
	if errorsAs(err, &e) {
		return e.GetReasons()
	}
	return []string{err.Error()}
}

func errorsAs(err error, target any) bool  { return errors.As(err, target) }
func (s *Server) SetApplied(v state.State) { s.mu.Lock(); s.applied = v; s.mu.Unlock() }
func Revision(v string) uint64             { n, _ := strconv.ParseUint(v, 10, 64); return n }
