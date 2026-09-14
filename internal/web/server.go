// Package web serves the dashboard and the state JSON API.
package web

import (
	"context"
	_ "embed"
	"encoding/json"
	"net/http"
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
	return &Server{http: &http.Server{
		Addr:              addr,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
	}}
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
