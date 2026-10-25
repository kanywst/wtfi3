package web

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"wtfi3/internal/aggregator"
	"wtfi3/internal/netinfo"
)

func TestIsLoopback(t *testing.T) {
	cases := map[string]bool{
		"127.0.0.1:8080":    true,
		"localhost:8080":    true,
		"[::1]:8080":        true,
		"127.0.0.2:8080":    true,
		":8080":             false,
		"0.0.0.0:8080":      false,
		"192.168.1.10:8080": false,
		"8080":              false,
	}
	for addr, want := range cases {
		if got := IsLoopback(addr); got != want {
			t.Errorf("IsLoopback(%q) = %v, want %v", addr, got, want)
		}
	}
}

func TestLoopbackRejectsForeignHost(t *testing.T) {
	h := New("127.0.0.1:8080", aggregator.New(&netinfo.Self{}, false, "test")).http.Handler
	cases := map[string]int{
		"localhost:8080":        http.StatusOK,
		"127.0.0.1:8080":        http.StatusOK,
		"[::1]:8080":            http.StatusOK,
		"LOCALHOST":             http.StatusOK,
		"attacker.example:8080": http.StatusForbidden,
		"192.168.1.10:8080":     http.StatusForbidden,
		"":                      http.StatusForbidden,
	}
	for host, want := range cases {
		req := httptest.NewRequest(http.MethodGet, "/api/state", nil)
		req.Host = host
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != want {
			t.Errorf("Host %q: status %d, want %d", host, rec.Code, want)
		}
	}
}

// A non-loopback bind is an explicit choice to serve the network, where the
// dashboard is reached by any LAN IP or name, so Host is not checked.
func TestExposedBindAcceptsAnyHost(t *testing.T) {
	h := New(":8080", aggregator.New(&netinfo.Self{}, false, "test")).http.Handler
	req := httptest.NewRequest(http.MethodGet, "/api/state", nil)
	req.Host = "192.168.1.10:8080"
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d, want 200", rec.Code)
	}
}
