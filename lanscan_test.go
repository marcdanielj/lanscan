package main

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
	"time"
)

// serve starts a throwaway listener on localhost and hands each connection to
// fn. Real sockets, because the thing under test is socket behaviour.
func serve(t *testing.T, fn func(net.Conn)) netip.AddrPort {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() { defer c.Close(); fn(c) }()
		}
	}()
	ap, err := netip.ParseAddrPort(ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	return ap
}

func probeOne(t *testing.T, ap netip.AddrPort) (Result, bool) {
	t.Helper()
	return probe(context.Background(), ap, time.Second, 500*time.Millisecond)
}

// A server that greets first must be read, not spoken to.
func TestBannerServerIsIdentified(t *testing.T) {
	ap := serve(t, func(c net.Conn) {
		io.WriteString(c, "SSH-2.0-OpenSSH_9.6\r\n")
		time.Sleep(50 * time.Millisecond)
	})
	r, ok := probeOne(t, ap)
	if !ok {
		t.Fatal("open port reported closed")
	}
	if r.Service != "ssh" {
		t.Errorf("service = %q, want ssh", r.Service)
	}
	if !strings.Contains(r.Detail, "OpenSSH_9.6") {
		t.Errorf("detail = %q, want the banner", r.Detail)
	}
	if r.Guessed {
		t.Error("banner was read, so the service should not be marked a guess")
	}
}

// A server that waits must be spoken to first - this is the case a
// listen-only scanner gets wrong.
func TestSilentServerGetsHTTPProbe(t *testing.T) {
	ap := serve(t, func(c net.Conn) {
		buf := make([]byte, 256)
		if _, err := c.Read(buf); err != nil { // wait for the client to speak
			return
		}
		io.WriteString(c, "HTTP/1.1 200 OK\r\nServer: nginx/1.25.3\r\n\r\n<html><title>hi</title></html>")
	})
	r, ok := probeOne(t, ap)
	if !ok {
		t.Fatal("open port reported closed")
	}
	if r.Service != "http" {
		t.Errorf("service = %q, want http", r.Service)
	}
	if !strings.Contains(r.Detail, "nginx/1.25.3") {
		t.Errorf("detail = %q, want the Server header", r.Detail)
	}
}

// Ollama is identified from its root response body, not its port, so it is
// still found when it has been moved.
func TestOllamaIdentifiedOffItsDefaultPort(t *testing.T) {
	ap := serve(t, func(c net.Conn) {
		buf := make([]byte, 256)
		if _, err := c.Read(buf); err != nil {
			return
		}
		io.WriteString(c, "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\nOllama is running")
	})
	r, _ := probeOne(t, ap)
	if r.Service != "ollama" {
		t.Errorf("service = %q, want ollama (port was %d, not 11434)", r.Service, ap.Port())
	}
}

// An open port that says nothing at all is a guess, and must say so.
func TestSilentPortIsMarkedGuessed(t *testing.T) {
	ap := serve(t, func(c net.Conn) { time.Sleep(2 * time.Second) })
	r, ok := probeOne(t, ap)
	if !ok {
		t.Fatal("open port reported closed")
	}
	if !r.Guessed {
		t.Error("nothing was learned on the wire, so Guessed must be true")
	}
}

func TestClosedPortIsNotReported(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ap, _ := netip.ParseAddrPort(ln.Addr().String())
	ln.Close() // now nothing is listening there
	if _, ok := probe(context.Background(), ap, 300*time.Millisecond, 100*time.Millisecond); ok {
		t.Error("closed port reported as open")
	}
}

// Cancelling must drain the pool and close the channel, or a caller ranging
// over the results hangs forever.
func TestSweepStopsOnCancel(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	var targets []netip.AddrPort
	base := netip.MustParseAddr("192.0.2.1") // TEST-NET-1: guaranteed to go nowhere
	for i := 0; i < 5000; i++ {
		targets = append(targets, netip.AddrPortFrom(base, uint16(1024+i)))
	}
	ch := sweep(ctx, targets, 64, 2*time.Second, time.Second)
	cancel()

	done := make(chan struct{})
	go func() {
		for range ch { //nolint:revive // draining
		}
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("sweep did not stop after cancel")
	}
}

func TestParsePorts(t *testing.T) {
	got, err := parsePorts("80, 8000-8002, 80")
	if err != nil {
		t.Fatal(err)
	}
	want := []uint16{80, 8000, 8001, 8002} // deduped, order preserved
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("got %v, want %v", got, want)
		}
	}
	for _, bad := range []string{"0", "70000", "abc", "100-50", ""} {
		if _, err := parsePorts(bad); err == nil {
			t.Errorf("parsePorts(%q) should have failed", bad)
		}
	}
}

func TestHostsTrimsNetworkAndBroadcast(t *testing.T) {
	got := hosts(netip.MustParsePrefix("192.168.1.0/24"))
	if len(got) != 254 {
		t.Fatalf("got %d hosts, want 254", len(got))
	}
	if got[0].String() != "192.168.1.1" || got[253].String() != "192.168.1.254" {
		t.Errorf("range is %s..%s", got[0], got[253])
	}
	// A /32 is one host and has no network or broadcast address to trim.
	if n := len(hosts(netip.MustParsePrefix("10.0.0.7/32"))); n != 1 {
		t.Errorf("/32 gave %d hosts, want 1", n)
	}
}

// The TLS path must complete a real handshake and report the negotiated
// parameters, not just label the port "https".
func TestTLSProbeReportsHandshake(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer srv.Close()
	ap, err := netip.ParseAddrPort(strings.TrimPrefix(srv.URL, "https://"))
	if err != nil {
		t.Fatal(err)
	}
	// Dial the real port, but fingerprint as if it were 443 to take the TLS branch.
	conn, err := net.DialTimeout("tcp", ap.String(), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	svc, detail, guessed := fingerprint(conn, 443, time.Second)
	if svc != "https" {
		t.Fatalf("service = %q (%s), want https", svc, detail)
	}
	if guessed {
		t.Error("a completed handshake is evidence, not a guess")
	}
	if !strings.Contains(detail, "TLS1.") {
		t.Errorf("detail = %q, want a negotiated TLS version", detail)
	}
}

// A plaintext server on a TLS port must fail the handshake and say so rather
// than being reported as working https.
func TestTLSProbeOnPlaintextPortFails(t *testing.T) {
	ap := serve(t, func(c net.Conn) { io.WriteString(c, "not tls at all\r\n") })
	conn, err := net.DialTimeout("tcp", ap.String(), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	svc, _, guessed := fingerprint(conn, 443, 500*time.Millisecond)
	if svc == "https" {
		t.Error("plaintext server reported as https")
	}
	if !guessed {
		t.Error("failed handshake must be marked uncertain")
	}
}
