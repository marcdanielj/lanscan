# lanscan

A concurrent network scanner that identifies services by **what they say on the wire**, not by what port they happen to sit on.

Go standard library only. No dependencies.

```
$ lanscan -net 127.0.0.1 -ports 1-20000
scanning 127.0.0.1/32 · 1 hosts x 20000 ports · 512 workers

127.0.0.1
  53     dns?         2.6ms
  5000   http         0.4ms  403 Forbidden · AirTunes/980.77.5
  7000   http         2.8ms  403 Forbidden · AirTunes/980.77.5
  11434  ollama       2.6ms  200 OK

4 open · 20000 probes in 1.207s
```

That is a real run, not a mock-up. Three things in it are the whole pitch: ports 5000 and 7000 are *conventionally* "http", and the `Server` header says they are actually macOS AirPlay; port 11434 was confirmed as Ollama by its response body rather than assumed from its port; and port 53 is marked `dns?` because nothing answered — the `?` is the tool declining to guess.

A trailing `?` means the service was inferred from the port number and nothing on the wire confirmed it. That distinction is the point of the tool.

## Why this is not just `nmap -sV`

It isn't better than nmap. It's a study of the three problems a scanner has to solve, written small enough to read in one sitting.

### 1. Some servers greet you; some wait for you

This is the part naive scanners get wrong. Connect to SSH, SMTP, FTP, or MySQL and the **server speaks first** — a banner arrives unprompted. Connect to HTTP and the server says nothing at all; it is waiting for a request. A scanner that only listens will time out on every web server. A scanner that only sends `GET /` will corrupt or hang every banner protocol.

`lanscan` listens first with a short deadline, and treats **the timeout itself as the signal**:

```go
n, err := conn.Read(buf)
if n > 0 {
    return classifyBanner(buf[:n], port)   // it greeted us
}
if !isTimeout(err) {
    return portHints[port], "", true       // it hung up without a word
}
// Silence means the peer is waiting for us. Speak HTTP.
```

Ordering matters: listening costs one timeout on HTTP ports, while speaking first costs a *wrong answer* on every banner protocol. The cheap mistake is the one worth making.

**Tradeoff, on purpose:** every HTTP service costs a full `-grab` window (600ms default) before we give up waiting for a banner. Speaking HTTP immediately on "probably web" ports would cut that, but reintroduces exactly the port-guessing this tool exists to avoid. Since the delay is per-connection and fully parallel, concurrency absorbs it — 20,000 probes still finish in ~1.2s. Tune with `-grab` if you disagree.

### 2. Concurrency has to be bounded

One goroutine per target is easy to write and breaks on contact with a real network: a `/16` is 65,536 hosts, and the file-descriptor limit arrives long before the memory limit.

A fixed worker pool reading from an **unbuffered** job channel keeps open sockets flat regardless of target-set size, and gives back-pressure for free — the generator can't run ahead and build a queue nobody asked it to hold.

`context` cancellation threads through `DialContext`, so Ctrl-C tears down in-flight dials instead of stranding sockets, and still prints what was found. There's a test for exactly that, because a results channel that doesn't close on cancel hangs the caller forever.

### 3. A guess must be labelled as a guess

Port 11434 is *conventionally* Ollama. It is not *evidence* of Ollama. `lanscan` tracks whether a result came from the wire or from a lookup table and renders the difference — because a scanner that confidently mislabels is worse than one that admits uncertainty.

Ollama is detected from the `Ollama is running` body at `/`, so it's still found when someone moves it off 11434. There's a test for that too.

## What it identifies

| From the wire | How |
|---|---|
| SSH, SMTP, FTP, IMAP, POP3, Redis, VNC | greeting banner |
| MySQL | length-prefixed handshake — protocol byte, then the NUL-terminated version string |
| HTTP | status line, `Server` header, `<title>` fallback |
| Ollama | response body at `/` |
| HTTPS | full TLS handshake: negotiated version, ALPN, certificate CN |

TLS ports are handshaked rather than probed in plaintext, since sending `GET /` to port 443 only ever earns a `handshake_failure` alert.

> `InsecureSkipVerify` is deliberate here and commented as such. We fingerprint arbitrary hosts by IP, so the certificate is **evidence to report, never a trust decision** — the tool reads the cert and hangs up. It never sends data over these connections.

## Install

```bash
go install github.com/marcdanielj/lanscan@latest
```

Or from source:

```bash
git clone https://github.com/marcdanielj/lanscan && cd lanscan
go build -o lanscan .
go test ./...
```

## Usage

```bash
lanscan                             # auto-detect and scan this machine's subnet
lanscan -net 192.168.1.0/24         # a specific network
lanscan -net 10.0.0.5 -ports 1-1024 # one host, a port range
lanscan -json | jq 'select(.service == "ollama")'
```

| Flag | Default | |
|---|---|---|
| `-net` | local subnet | CIDR, or a bare IP for a single host |
| `-ports` | 15 common ports | comma-separated, ranges allowed |
| `-workers` | `256` | concurrent dials in flight |
| `-timeout` | `800ms` | TCP connect timeout |
| `-grab` | `600ms` | how long to wait for a banner or response |
| `-json` | off | newline-delimited JSON, streamed as results arrive |

A runaway prefix is capped at 2²⁰ probes rather than silently scanning for hours.

## Tests

Every test drives a **real socket** on `127.0.0.1` — the behaviour under test is socket behaviour, so mocking it would test nothing.

```
TestBannerServerIsIdentified          server greets first  -> read it
TestSilentServerGetsHTTPProbe         server waits         -> speak first
TestOllamaIdentifiedOffItsDefaultPort identify by body, not port
TestSilentPortIsMarkedGuessed         no evidence -> say so
TestClosedPortIsNotReported           no false positives
TestSweepStopsOnCancel                cancel drains the pool and closes the channel
TestTLSProbeReportsHandshake          real handshake, real cert
TestTLSProbeOnPlaintextPortFails      plaintext on :443 is not "https"
TestParsePorts                        ranges, dedupe, and the bad input
TestHostsTrimsNetworkAndBroadcast     /24 is 254 hosts; /32 is 1
```

## Scope

Only scan networks you own or are authorised to test. This is a TCP connect scanner — it completes normal handshakes and makes no attempt to be stealthy, because hiding from the network's owner isn't a thing a diagnostic tool should do.

Not implemented, deliberately: UDP, OS fingerprinting, and raw/SYN scanning (which needs root and a hand-rolled IP stack). Each is a different project.

## Licence

MIT
