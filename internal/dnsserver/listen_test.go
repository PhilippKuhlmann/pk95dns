package dnsserver

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/miekg/dns"
)

func TestListenAndServe(t *testing.T) {
	e := newEnv(t, nil)
	port := freePort(t)
	addr := fmt.Sprintf("127.0.0.1:%d", port)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		e.srv.ListenAndServe(ctx, addr)
		close(done)
	}()
	waitFor(t, "listening", func() bool { st := e.srv.Status(); return st.UDP && st.TCP })
	if st := e.srv.Status(); st.Listen != addr || st.Error != "" {
		t.Fatalf("status %+v", st)
	}

	for _, proto := range []string{"udp", "tcp"} {
		c := &dns.Client{Net: proto, Timeout: 3 * time.Second}
		for _, tc := range []struct {
			name   string
			answer string
		}{
			{"plain.example.", "192.0.2.1"},
			{"ads.example.", "0.0.0.0"},
			{"nas.home.lan.", "192.168.1.10"},
		} {
			m := new(dns.Msg)
			m.SetQuestion(tc.name, dns.TypeA)
			resp, _, err := c.Exchange(m, addr)
			if err != nil {
				t.Fatalf("%s %s: %v", proto, tc.name, err)
			}
			if len(resp.Answer) != 1 || resp.Answer[0].(*dns.A).A.String() != tc.answer {
				t.Fatalf("%s %s: %v", proto, tc.name, resp.Answer)
			}
		}
	}
	// A big answer is truncated over UDP and complete over TCP.
	m := new(dns.Msg)
	m.SetQuestion("big.example.", dns.TypeA)
	resp, _, err := (&dns.Client{Net: "udp", Timeout: 3 * time.Second}).Exchange(m, addr)
	if err != nil || !resp.Truncated {
		t.Fatalf("udp big: %v %v", err, resp)
	}
	resp, _, err = (&dns.Client{Net: "tcp", Timeout: 3 * time.Second}).Exchange(m, addr)
	if err != nil || resp.Truncated || len(resp.Answer) != 100 {
		t.Fatalf("tcp big: %v %v", err, resp)
	}

	cancel()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("ListenAndServe did not return")
	}
	if st := e.srv.Status(); st.UDP || st.TCP {
		t.Fatalf("status after stop %+v", st)
	}
	// The port is free again.
	pc, err := net.ListenPacket("udp", addr)
	if err != nil {
		t.Fatalf("udp port still bound: %v", err)
	}
	pc.Close()
}

func TestListenBindFailure(t *testing.T) {
	e := newEnv(t, nil)
	e.srv.listenRetry = 20 * time.Millisecond
	port := freePort(t)
	addr := fmt.Sprintf("127.0.0.1:%d", port)
	blocker, err := net.ListenPacket("udp", addr)
	if err != nil {
		t.Fatal(err)
	}

	var mu sync.Mutex
	var events []string
	e.srv.deps.OnListen = func(ok bool, msg string) {
		mu.Lock()
		defer mu.Unlock()
		events = append(events, fmt.Sprintf("%v|%s", ok, msg))
	}
	snapshot := func() []string {
		mu.Lock()
		defer mu.Unlock()
		return append([]string(nil), events...)
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		e.srv.ListenAndServe(ctx, addr)
		close(done)
	}()
	waitFor(t, "failure", func() bool { return len(snapshot()) == 1 })
	st := e.srv.Status()
	want := fmt.Sprintf("Port %d ist belegt (läuft systemd-resolved oder ein anderer DNS-Server?): ", port)
	if st.UDP || st.TCP || !strings.HasPrefix(st.Error, want) || st.Listen != addr {
		t.Fatalf("status %+v", st)
	}
	if ev := snapshot()[0]; !strings.HasPrefix(ev, "false|"+want) {
		t.Fatalf("event %q", ev)
	}
	// Several retries fail, but OnListen(false) is sent once per streak.
	time.Sleep(100 * time.Millisecond)
	if n := len(snapshot()); n != 1 {
		t.Fatalf("events during streak: %v", snapshot())
	}

	blocker.Close()
	waitFor(t, "recovery", func() bool { return len(snapshot()) == 2 })
	if ev := snapshot()[1]; ev != "true|" {
		t.Fatalf("recovery event %q", ev)
	}
	waitFor(t, "status", func() bool { st := e.srv.Status(); return st.UDP && st.TCP && st.Error == "" })

	c := &dns.Client{Net: "udp", Timeout: 3 * time.Second}
	m := new(dns.Msg)
	m.SetQuestion("plain.example.", dns.TypeA)
	if _, _, err := c.Exchange(m, addr); err != nil {
		t.Fatalf("query after recovery: %v", err)
	}

	cancel()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("ListenAndServe did not return")
	}
}

func TestListenCancelWhileFailing(t *testing.T) {
	e := newEnv(t, nil)
	port := freePort(t)
	addr := fmt.Sprintf("127.0.0.1:%d", port)
	blocker, err := net.Listen("tcp", addr) // UDP works, TCP fails
	if err != nil {
		t.Fatal(err)
	}
	defer blocker.Close()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		e.srv.ListenAndServe(ctx, addr)
		close(done)
	}()
	waitFor(t, "failure", func() bool { return e.srv.Status().Error != "" })
	// The UDP socket was released again.
	pc, err := net.ListenPacket("udp", addr)
	if err != nil {
		t.Fatalf("udp left bound: %v", err)
	}
	pc.Close()
	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("ListenAndServe did not return while waiting for a retry")
	}
}

func TestBindMessage(t *testing.T) {
	tests := []struct {
		name string
		addr string
		err  error
		want string
	}{
		{"in use", ":53", &net.OpError{Op: "listen", Net: "udp", Err: syscall.EADDRINUSE}, "Port 53 ist belegt (läuft systemd-resolved oder ein anderer DNS-Server?): "},
		{"permission", "0.0.0.0:53", &net.OpError{Op: "listen", Net: "udp", Err: syscall.EACCES}, "Keine Berechtigung für Port 53: "},
		{"other", "[::1]:5353", errors.New("kaputt"), "DNS-Server konnte nicht auf [::1]:5353 starten: kaputt"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := bindMessage(tt.addr, tt.err); !strings.HasPrefix(got, tt.want) {
				t.Fatalf("got %q, want prefix %q", got, tt.want)
			}
		})
	}
}
