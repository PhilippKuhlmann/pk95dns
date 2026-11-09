package dnsserver

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"syscall"
	"time"

	"github.com/miekg/dns"
)

// shutdownTimeout bounds the wait for open TCP connections on shutdown.
const shutdownTimeout = 5 * time.Second

// ListenAndServe binds UDP and TCP on addr and serves until ctx is done. When binding fails
// it reports through Deps.OnListen and Status and retries every 30 seconds.
func (s *Server) ListenAndServe(ctx context.Context, addr string) {
	s.statusMu.Lock()
	s.status = ListenStatus{Listen: addr}
	s.statusMu.Unlock()

	failing := false
	for {
		err := s.serve(ctx, addr, func() {
			s.setStatus(ListenStatus{Listen: addr, UDP: true, TCP: true})
			if failing {
				failing = false
				slog.Info("dns: listening again", "addr", addr)
				s.notify(true, "")
			}
		})
		if ctx.Err() != nil {
			s.setStatus(ListenStatus{Listen: addr})
			return
		}
		msg := bindMessage(addr, err)
		s.setStatus(ListenStatus{Listen: addr, Error: msg})
		if !failing {
			failing = true
			slog.Error("dns: listen failed", "addr", addr, "error", err)
			s.notify(false, msg)
		}
		t := time.NewTimer(s.listenRetry)
		select {
		case <-ctx.Done():
			t.Stop()
			return
		case <-t.C:
		}
	}
}

func (s *Server) setStatus(st ListenStatus) {
	s.statusMu.Lock()
	s.status = st
	s.statusMu.Unlock()
}

func (s *Server) notify(ok bool, msg string) {
	if s.deps.OnListen != nil {
		s.deps.OnListen(ok, msg)
	}
}

// serve binds both sockets, calls started once both serve, and blocks until ctx is done
// (nil) or a listener fails (the error).
func (s *Server) serve(ctx context.Context, addr string, started func()) error {
	pc, err := net.ListenPacket("udp", addr)
	if err != nil {
		return err
	}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		_ = pc.Close()
		return err
	}

	udp := &dns.Server{PacketConn: pc, Handler: s, UDPSize: dns.MaxMsgSize}
	tcp := &dns.Server{Listener: ln, Handler: s}
	servers := []*dns.Server{udp, tcp}

	errc := make(chan error, len(servers))
	ready := make(chan struct{}, len(servers))
	for _, srv := range servers {
		srv.NotifyStartedFunc = func() { ready <- struct{}{} }
		go func() { errc <- srv.ActivateAndServe() }()
	}

	var failure error
	running := len(servers)
	for n := 0; n < len(servers) && failure == nil; {
		select {
		case <-ready:
			n++
		case err := <-errc:
			running--
			failure = serveError(err)
		}
	}
	if failure == nil {
		started()
		select {
		case <-ctx.Done():
		case err := <-errc:
			running--
			failure = serveError(err)
		}
	}

	sctx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
	defer cancel()
	for _, srv := range servers {
		_ = srv.ShutdownContext(sctx)
	}
	// Close the sockets in case a server never started (Shutdown does nothing then).
	_ = pc.Close()
	_ = ln.Close()
	for ; running > 0; running-- {
		<-errc
	}
	if ctx.Err() != nil {
		return nil
	}
	return failure
}

func serveError(err error) error {
	if err == nil {
		return errors.New("DNS-Server wurde unerwartet beendet")
	}
	return err
}

// bindMessage turns a listen error into the German message of /api/status.
func bindMessage(addr string, err error) string {
	port := addr
	if _, p, splitErr := net.SplitHostPort(addr); splitErr == nil {
		port = p
	}
	switch {
	case errors.Is(err, syscall.EADDRINUSE):
		return fmt.Sprintf("Port %s ist belegt (läuft systemd-resolved oder ein anderer DNS-Server?): %v", port, err)
	case errors.Is(err, syscall.EACCES), errors.Is(err, syscall.EPERM), errors.Is(err, os.ErrPermission):
		return fmt.Sprintf("Keine Berechtigung für Port %s: %v", port, err)
	default:
		return fmt.Sprintf("DNS-Server konnte nicht auf %s starten: %v", addr, err)
	}
}
