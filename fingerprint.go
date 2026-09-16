package main

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"time"
)

// tlsPorts are spoken in TLS from the first byte, so a plaintext probe would
// only ever earn a handshake_failure alert. We start the handshake instead.
var tlsPorts = map[uint16]bool{443: true, 465: true, 636: true, 993: true, 995: true, 8443: true}

// portHints label a port when nothing on the wire identifies the service. A
// hint is a guess about convention, never evidence — callers mark it as such.
var portHints = map[uint16]string{
	21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns", 80: "http",
	110: "pop3", 143: "imap", 443: "https", 445: "smb", 631: "ipp",
	1433: "mssql", 3000: "http", 3306: "mysql", 3389: "rdp", 5000: "http",
	5432: "postgres", 5900: "vnc", 6379: "redis", 8000: "http", 8080: "http",
	8443: "https", 9000: "http", 11434: "ollama", 27017: "mongodb",
}

// fingerprint identifies what is listening, and reports how sure it is.
//
// The split that matters: some servers greet you the moment you connect (SSH,
// SMTP, FTP, MySQL) and some wait for you to speak first (HTTP). You cannot
// know which you are facing, so listen briefly — a short read that times out is
// itself the signal that the peer is waiting, and only then do we send a
// request. Probing HTTP first would hang every banner protocol for the full
// timeout and teach us nothing.
func fingerprint(conn net.Conn, port uint16, grab time.Duration) (service, detail string, guessed bool) {
	if tlsPorts[port] {
		return tlsProbe(conn, grab)
	}

	_ = conn.SetReadDeadline(time.Now().Add(grab))
	buf := make([]byte, 512)
	n, err := conn.Read(buf)
	if n > 0 {
		svc, d := classifyBanner(buf[:n], port)
		return svc, d, false
	}
	if !isTimeout(err) {
		// Closed or reset on us without a word: port is open but tells us nothing.
		return portHints[port], "", true
	}

	// Silence means the peer is waiting for us. Speak HTTP.
	_ = conn.SetWriteDeadline(time.Now().Add(grab))
	req := fmt.Sprintf("GET / HTTP/1.1\r\nHost: %s\r\nUser-Agent: lanscan\r\nAccept: */*\r\nConnection: close\r\n\r\n",
		conn.RemoteAddr().String())
	if _, err := io.WriteString(conn, req); err != nil {
		return portHints[port], "", true
	}

	_ = conn.SetReadDeadline(time.Now().Add(grab))
	var resp bytes.Buffer
	// Cap the read: a scanner must never let a peer decide how much memory it uses.
	_, _ = io.CopyN(&resp, conn, 4096)
	if resp.Len() == 0 {
		return portHints[port], "", true
	}
	return classifyHTTP(resp.Bytes(), port)
}

// classifyBanner reads a greeting the server volunteered.
func classifyBanner(b []byte, port uint16) (service, detail string) {
	line := printable(firstLine(b))
	switch {
	case strings.HasPrefix(line, "SSH-"):
		return "ssh", line
	case strings.HasPrefix(line, "220"):
		// 220 is the greeting for both SMTP and FTP; the port breaks the tie.
		if port == 25 || port == 587 || port == 465 {
			return "smtp", line
		}
		return "ftp", line
	case strings.HasPrefix(line, "* OK"):
		return "imap", line
	case strings.HasPrefix(line, "+OK"):
		return "pop3", line
	case strings.HasPrefix(line, "-ERR") || strings.Contains(line, "NOAUTH"):
		return "redis", line
	case strings.HasPrefix(line, "RFB "):
		return "vnc", line
	}
	// MySQL opens with a length-prefixed handshake: 3 bytes length, 1 sequence,
	// then protocol version 10 and a NUL-terminated server version string.
	if port == 3306 && len(b) > 5 && b[4] == 10 {
		if v, _, ok := bytes.Cut(b[5:], []byte{0}); ok {
			return "mysql", printable(string(v))
		}
	}
	if s := portHints[port]; s != "" {
		return s, line
	}
	return "unknown", line
}

// classifyHTTP pulls the status line, Server header, and enough of the body to
// recognise services that announce themselves in plain text.
func classifyHTTP(b []byte, port uint16) (service, detail string, guessed bool) {
	head, body, _ := bytes.Cut(b, []byte("\r\n\r\n"))

	var status, server string
	sc := bufio.NewScanner(bytes.NewReader(head))
	for sc.Scan() {
		line := sc.Text()
		switch {
		case strings.HasPrefix(line, "HTTP/"):
			status = strings.TrimSpace(line)
		case strings.HasPrefix(strings.ToLower(line), "server:"):
			server = strings.TrimSpace(line[len("server:"):])
		}
	}
	if status == "" {
		// Answered, but not in HTTP. Fall back to the port's convention.
		return portHints[port], printable(firstLine(b)), true
	}

	service = "http"
	// Ollama answers its root with exactly this, which saves a second request.
	if bytes.Contains(body, []byte("Ollama is running")) {
		service = "ollama"
	}

	detail = strings.TrimPrefix(status, "HTTP/1.1 ")
	detail = strings.TrimPrefix(detail, "HTTP/1.0 ")
	if server != "" {
		detail += " · " + server
	} else if t := htmlTitle(body); t != "" {
		detail += " · " + t
	}
	return service, printable(detail), false
}

// tlsProbe completes a handshake and reports the negotiated parameters.
//
// InsecureSkipVerify is deliberate and load-bearing: we are fingerprinting
// arbitrary hosts by IP, so the certificate is evidence to report, never a
// trust decision. Nothing here sends data — we read the cert and hang up.
func tlsProbe(conn net.Conn, grab time.Duration) (service, detail string, guessed bool) {
	_ = conn.SetDeadline(time.Now().Add(grab))
	c := tls.Client(conn, &tls.Config{
		InsecureSkipVerify: true, //nolint:gosec // fingerprinting, not trusting
		NextProtos:         []string{"h2", "http/1.1"},
	})
	if err := c.Handshake(); err != nil {
		return "tls?", "handshake failed", true
	}
	st := c.ConnectionState()
	parts := []string{tlsVersion(st.Version)}
	if st.NegotiatedProtocol != "" {
		parts = append(parts, "alpn="+st.NegotiatedProtocol)
	}
	if len(st.PeerCertificates) > 0 {
		if cn := st.PeerCertificates[0].Subject.CommonName; cn != "" {
			parts = append(parts, "cn="+cn)
		}
	}
	return "https", printable(strings.Join(parts, " ")), false
}

func tlsVersion(v uint16) string {
	switch v {
	case tls.VersionTLS10:
		return "TLS1.0"
	case tls.VersionTLS11:
		return "TLS1.1"
	case tls.VersionTLS12:
		return "TLS1.2"
	case tls.VersionTLS13:
		return "TLS1.3"
	}
	return fmt.Sprintf("TLS(0x%04x)", v)
}

func firstLine(b []byte) string {
	if i := bytes.IndexAny(b, "\r\n"); i >= 0 {
		return string(b[:i])
	}
	return string(b)
}

func htmlTitle(body []byte) string {
	lower := bytes.ToLower(body)
	i := bytes.Index(lower, []byte("<title>"))
	if i < 0 {
		return ""
	}
	rest := body[i+len("<title>"):]
	j := bytes.Index(bytes.ToLower(rest), []byte("</title>"))
	if j < 0 {
		return ""
	}
	return strings.TrimSpace(string(rest[:j]))
}

// printable keeps banners from smuggling control codes into the terminal.
func printable(s string) string {
	s = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return -1
		}
		return r
	}, s)
	s = strings.TrimSpace(s)
	if len(s) > 72 {
		s = s[:69] + "..."
	}
	return s
}

func isTimeout(err error) bool {
	var ne net.Error
	return errors.As(err, &ne) && ne.Timeout()
}
