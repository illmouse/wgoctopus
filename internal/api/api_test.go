package api

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/illmouse/wgoctopus/internal/state"
)

type testMetrics struct{}

func (testMetrics) Render(context.Context) []byte { return []byte("metric 1\n") }

type fakeApplier struct {
	err   error
	calls int
	allow bool
}

func (f *fakeApplier) Apply(_ state.State, allow bool) error {
	f.calls++
	f.allow = allow
	return f.err
}

func TestAuthAndStateRead(t *testing.T) {
	s := &Server{Token: "secret"}
	s.SetApplied(state.State{Revision: 4})
	h := s.Handler()
	r := httptest.NewRequest("GET", "/v1/state", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != 401 {
		t.Fatal(w.Code)
	}
	r = httptest.NewRequest("GET", "/v1/state", nil)
	r.Header.Set("Authorization", "Bearer secret")
	w = httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != 200 || !bytes.Contains(w.Body.Bytes(), []byte(s.applied.Checksum())) {
		t.Fatalf("%d %s", w.Code, w.Body.String())
	}
	r = httptest.NewRequest(http.MethodPut, "/v1/state", bytes.NewBufferString(`{"revision":1,"interfaces":[]}`))
	r.Header.Set("Authorization", "Bearer secret")
	w = httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != 409 {
		t.Fatal(w.Code)
	}
}

func TestMetricsCollectorProtection(t *testing.T) {
	s := &Server{Token: "secret", Collector: testMetrics{}}
	h := s.Handler()
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated status = %d", w.Code)
	}
	r := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	r.Header.Set("Authorization", "Bearer secret")
	w = httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusOK || w.Body.String() != "metric 1\n" || w.Header().Get("Content-Type") != "text/plain; version=0.0.4" {
		t.Fatalf("metrics response: %d %q %q", w.Code, w.Body.String(), w.Header().Get("Content-Type"))
	}
	s.AllowMetrics = true
	w = httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("public metrics status = %d", w.Code)
	}
}

func TestPutUsesApplierAndReportsErrors(t *testing.T) {
	valid := `{"revision":5,"interfaces":[]}`
	call := func(s *Server, body, query string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(http.MethodPut, "/v1/state"+query, bytes.NewBufferString(body))
		r.Header.Set("Authorization", "Bearer secret")
		w := httptest.NewRecorder()
		s.Handler().ServeHTTP(w, r)
		return w
	}
	a := &fakeApplier{}
	s := &Server{Token: "secret", Applier: a}
	if w := call(s, valid, ""); w.Code != 204 || a.calls != 1 {
		t.Fatalf("%d %s", w.Code, w.Body.String())
	}
	if w := call(s, `{"revision":6,"interfaces":[]}`, "?allow_dangerous=true"); w.Code != 204 || !a.allow {
		t.Fatalf("%d allow=%v", w.Code, a.allow)
	}
	if w := call(s, `{"revision":6,"interfaces":[]}`, ""); w.Code != 409 {
		t.Fatalf("same revision status %d", w.Code)
	}
	if w := call(s, `{"revision":7,"interfaces":[{}]}`, ""); w.Code != 422 {
		t.Fatalf("validation status %d", w.Code)
	}
	s.applied = state.State{Revision: 8}
	if w := call(s, valid, ""); w.Code != 409 {
		t.Fatalf("stale status %d", w.Code)
	}
	a.err = &apiDangerous{reasons: []string{"jc"}}
	s.applied = state.State{}
	w := call(s, valid, "")
	if w.Code != 409 || !bytes.Contains(w.Body.Bytes(), []byte(`"jc"`)) {
		t.Fatalf("%d %s", w.Code, w.Body.String())
	}
}

type blockingApplier struct{ entered chan struct{} }

func (a blockingApplier) Apply(state.State, bool) error { close(a.entered); select {} }

func TestApplyTimeoutDoesNotBlockReads(t *testing.T) {
	s := &Server{Token: "secret", Applier: blockingApplier{make(chan struct{})}, ApplyTimeout: 20 * time.Millisecond}
	h := s.Handler()
	r := httptest.NewRequest(http.MethodPut, "/v1/state", bytes.NewBufferString(`{"revision":1,"interfaces":[]}`))
	r.Header.Set("Authorization", "Bearer secret")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusGatewayTimeout || !bytes.Contains(w.Body.Bytes(), []byte("apply timed out")) {
		t.Fatalf("%d %s", w.Code, w.Body.String())
	}
	for _, path := range []string{"/healthz", "/v1/state"} {
		r = httptest.NewRequest(http.MethodGet, path, nil)
		if path == "/v1/state" {
			r.Header.Set("Authorization", "Bearer secret")
		}
		w = httptest.NewRecorder()
		done := make(chan struct{})
		go func() { h.ServeHTTP(w, r); close(done) }()
		select {
		case <-done:
		case <-time.After(time.Second):
			t.Fatalf("%s blocked", path)
		}
	}
}

type apiDangerous struct{ reasons []string }

func (e *apiDangerous) Error() string        { return "dangerous changes" }
func (e *apiDangerous) GetReasons() []string { return e.reasons }
