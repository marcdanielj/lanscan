package main

import (
	"context"
	"net"
	"net/netip"
	"sync"
	"time"
)

// Result is one open port and what we could learn about it.
type Result struct {
	Addr    netip.AddrPort `json:"addr"`
	Service string         `json:"service"`
	Detail  string         `json:"detail,omitempty"`
	Guessed bool           `json:"guessed"` // service inferred from port number, not the wire
	RTTms   float64        `json:"rtt_ms"`
}

// sweep dials every target with a fixed pool of workers and streams whatever
// answers back on the returned channel.
//
// The pool is the whole point: one goroutine per target would be simpler to
// write, but a /16 is 65k hosts and the file-descriptor limit is the first
// thing that breaks. Bounded workers keep open sockets flat no matter how
// large the target set, and back-pressure on an unbuffered job channel means
// the generator never builds a queue we would have to hold in memory.
//
// The channel closes when the sweep is done or ctx is cancelled, whichever
// comes first, so a caller ranging over it always terminates.
func sweep(ctx context.Context, targets []netip.AddrPort, workers int, timeout, grab time.Duration) <-chan Result {
	if workers < 1 {
		workers = 1
	}
	jobs := make(chan netip.AddrPort)
	out := make(chan Result)

	var wg sync.WaitGroup
	wg.Add(workers)
	for i := 0; i < workers; i++ {
		go func() {
			defer wg.Done()
			for ap := range jobs {
				r, ok := probe(ctx, ap, timeout, grab)
				if !ok {
					continue
				}
				select {
				case out <- r:
				case <-ctx.Done():
					return
				}
			}
		}()
	}

	go func() {
		defer close(jobs)
		for _, ap := range targets {
			select {
			case jobs <- ap:
			case <-ctx.Done():
				return
			}
		}
	}()

	go func() {
		wg.Wait()
		close(out)
	}()

	return out
}

// probe opens one TCP connection and fingerprints it. A refused or timed-out
// dial is the common case, not an error worth reporting.
func probe(ctx context.Context, ap netip.AddrPort, timeout, grab time.Duration) (Result, bool) {
	d := net.Dialer{Timeout: timeout}
	start := time.Now()
	conn, err := d.DialContext(ctx, "tcp", ap.String())
	if err != nil {
		return Result{}, false
	}
	// RTT is measured at connect, before fingerprinting, so the number reflects
	// the network round trip and not how slowly the service composes a banner.
	rtt := time.Since(start)
	defer conn.Close()

	svc, detail, guessed := fingerprint(conn, ap.Port(), grab)
	return Result{
		Addr:    ap,
		Service: svc,
		Detail:  detail,
		Guessed: guessed,
		RTTms:   float64(rtt.Microseconds()) / 1000,
	}, true
}

// hosts expands a prefix into the addresses worth dialing, dropping the network
// and broadcast addresses for IPv4 networks that have them.
func hosts(p netip.Prefix) []netip.Addr {
	p = p.Masked()
	var out []netip.Addr
	for a := p.Addr(); a.IsValid() && p.Contains(a); a = a.Next() {
		out = append(out, a)
	}
	if p.Addr().Is4() && p.Bits() <= 30 && len(out) >= 2 {
		out = out[1 : len(out)-1]
	}
	return out
}

// localPrefix finds the subnet this machine sits on, so the common case needs
// no arguments.
func localPrefix() (netip.Prefix, bool) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return netip.Prefix{}, false
	}
	for _, ifc := range ifaces {
		if ifc.Flags&net.FlagUp == 0 || ifc.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, err := ifc.Addrs()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			ipn, ok := a.(*net.IPNet)
			if !ok {
				continue
			}
			ip4 := ipn.IP.To4()
			if ip4 == nil {
				continue
			}
			addr, ok := netip.AddrFromSlice(ip4)
			if !ok {
				continue
			}
			ones, _ := ipn.Mask.Size()
			return netip.PrefixFrom(addr, ones).Masked(), true
		}
	}
	return netip.Prefix{}, false
}
