// Package web serves the dashboard and the state JSON API.
package web

import (
	"context"
	_ "embed"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"

	"wtfi3/internal/aggregator"
)

//go:embed index.html
var indexHTML []byte

// Server wraps an http.Server that renders the dashboard for a State.
type Server struct {
	http *http.Server
}

// New builds a dashboard server bound to addr, reading from state.
func New(addr string, state *aggregator.State) *Server {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write(indexHTML)
	})
	mux.HandleFunc("/api/state", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(state.Snapshot())
	})
	// Server-Sent Events: push a snapshot on connect and once per second, so the
	// dashboard does not have to poll. Falls back to /api/state on the client if
	// the stream is unavailable.
	mux.HandleFunc("/api/stream", func(w http.ResponseWriter, r *http.Request) {
		flusher, ok := w.(http.Flusher)
		if !ok {
			http.Error(w, "streaming unsupported", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Cache-Control", "no-cache")
		w.Header().Set("Connection", "keep-alive")
		send := func() {
			b, err := json.Marshal(state.Snapshot())
			if err != nil {
				return
			}
			_, _ = fmt.Fprintf(w, "data: %s\n\n", b)
			flusher.Flush()
		}
		send()
		ticker := time.NewTicker(time.Second)
		defer ticker.Stop()
		ctx := r.Context()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				send()
			}
		}
	})
	var handler http.Handler = mux
	if IsLoopback(addr) {
		handler = loopbackHostOnly(mux)
	}
	return &Server{http: &http.Server{
		Addr:              addr,
		Handler:           handler,
		ReadHeaderTimeout: 5 * time.Second,
	}}
}

// IsLoopback reports whether addr (host:port) binds only to the loopback
// interface. ":8080" binds every interface and is not loopback.
func IsLoopback(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return false
	}
	return isLoopbackHost(host)
}

func isLoopbackHost(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// loopbackHostOnly rejects requests whose Host header is not a loopback name.
// Binding to 127.0.0.1 keeps other machines out, but a web page in the local
// browser can still reach it through DNS rebinding (attacker.example resolving
// to 127.0.0.1) and read every captured DNS name and SNI from /api/state. Such
// requests carry the attacker's hostname in Host, so refusing them closes that.
func loopbackHostOnly(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host := r.Host
		if h, _, err := net.SplitHostPort(host); err == nil {
			host = h
		}
		if !isLoopbackHost(strings.Trim(host, "[]")) {
			http.Error(w, "forbidden host", http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// Start begins serving in a background goroutine and returns any bind error via
// the returned channel.
func (s *Server) Start() <-chan error {
	errc := make(chan error, 1)
	go func() {
		if err := s.http.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			errc <- err
		}
		close(errc)
	}()
	return errc
}

// Shutdown gracefully stops the server.
func (s *Server) Shutdown(ctx context.Context) error {
	return s.http.Shutdown(ctx)
}
