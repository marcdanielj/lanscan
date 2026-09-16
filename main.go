// lanscan sweeps a local network and reports what is listening, identifying
// services from what they actually say on the wire rather than from the port
// number alone.
package main

import (
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net/netip"
	"os"
	"os/signal"
	"slices"
	"strconv"
	"strings"
	"time"
)

// defaultPorts is a short list on purpose: a sweep people actually wait for
// beats an exhaustive one they cancel.
const defaultPorts = "22,80,443,445,3000,3306,5000,5432,6379,8000,8080,8443,9000,11434,27017"

// maxTargets caps a run so a mistyped prefix cannot turn into an hours-long
// scan of somebody else's network.
const maxTargets = 1 << 20

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "lanscan:", err)
		os.Exit(1)
	}
}

func run() error {
	var (
		netFlag  = flag.String("net", "", "CIDR to scan (default: this machine's subnet)")
		portFlag = flag.String("ports", defaultPorts, "ports: comma-separated, ranges allowed (e.g. 22,80,8000-8100)")
		workers  = flag.Int("workers", 256, "concurrent dials in flight")
		timeout  = flag.Duration("timeout", 800*time.Millisecond, "TCP connect timeout")
		grab     = flag.Duration("grab", 600*time.Millisecond, "how long to wait for a banner or response")
		asJSON   = flag.Bool("json", false, "emit newline-delimited JSON instead of a table")
	)
	flag.Usage = usage
	flag.Parse()

	prefix, err := targetPrefix(*netFlag)
	if err != nil {
		return err
	}
	ports, err := parsePorts(*portFlag)
	if err != nil {
		return err
	}

	addrs := hosts(prefix)
	if n := len(addrs) * len(ports); n > maxTargets {
		return fmt.Errorf("%s x %d ports = %d probes, over the %d cap; narrow the prefix or the port list",
			prefix, len(ports), n, maxTargets)
	}

	targets := make([]netip.AddrPort, 0, len(addrs)*len(ports))
	for _, a := range addrs {
		for _, p := range ports {
			targets = append(targets, netip.AddrPortFrom(a, p))
		}
	}

	// Ctrl-C cancels in-flight dials instead of stranding open sockets, and
	// still prints whatever was found before the interrupt.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	if !*asJSON {
		fmt.Fprintf(os.Stderr, "scanning %s · %d hosts x %d ports · %d workers\n",
			prefix, len(addrs), len(ports), *workers)
	}

	start := time.Now()
	var found []Result
	enc := json.NewEncoder(os.Stdout)
	for r := range sweep(ctx, targets, *workers, *timeout, *grab) {
		if *asJSON {
			// Stream JSON so a long scan can be piped into something live.
			if err := enc.Encode(r); err != nil {
				return err
			}
			continue
		}
		found = append(found, r)
	}

	if *asJSON {
		return ctx.Err()
	}
	printTable(found, time.Since(start), len(targets))
	return ctx.Err()
}

func targetPrefix(s string) (netip.Prefix, error) {
	if s != "" {
		p, err := netip.ParsePrefix(s)
		if err != nil {
			// Accept a bare address as a single host, which is the usual typo.
			if a, aerr := netip.ParseAddr(s); aerr == nil {
				return netip.PrefixFrom(a, a.BitLen()), nil
			}
			return netip.Prefix{}, fmt.Errorf("bad -net %q: %w", s, err)
		}
		return p.Masked(), nil
	}
	p, ok := localPrefix()
	if !ok {
		return netip.Prefix{}, errors.New("could not detect a local IPv4 subnet; pass -net")
	}
	return p, nil
}

func parsePorts(s string) ([]uint16, error) {
	var out []uint16
	seen := make(map[uint16]bool)
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		loStr, hiStr := part, part
		if a, b, ok := strings.Cut(part, "-"); ok {
			loStr, hiStr = strings.TrimSpace(a), strings.TrimSpace(b)
		}
		lo, err := strconv.ParseUint(loStr, 10, 16)
		if err != nil {
			return nil, fmt.Errorf("bad port %q", part)
		}
		hi, err := strconv.ParseUint(hiStr, 10, 16)
		if err != nil {
			return nil, fmt.Errorf("bad port %q", part)
		}
		if lo == 0 || hi == 0 {
			return nil, fmt.Errorf("port 0 is not dialable: %q", part)
		}
		if lo > hi {
			return nil, fmt.Errorf("reversed range %q", part)
		}
		for p := lo; p <= hi; p++ {
			if !seen[uint16(p)] {
				seen[uint16(p)] = true
				out = append(out, uint16(p))
			}
		}
	}
	if len(out) == 0 {
		return nil, errors.New("no ports to scan")
	}
	return out, nil
}

func printTable(rs []Result, took time.Duration, probes int) {
	if len(rs) == 0 {
		fmt.Printf("\nnothing listening · %d probes in %s\n", probes, took.Round(time.Millisecond))
		return
	}
	slices.SortFunc(rs, func(a, b Result) int {
		return cmp.Or(
			a.Addr.Addr().Compare(b.Addr.Addr()),
			cmp.Compare(a.Addr.Port(), b.Addr.Port()),
		)
	})

	fmt.Println()
	var host netip.Addr
	for _, r := range rs {
		if r.Addr.Addr() != host {
			host = r.Addr.Addr()
			fmt.Printf("%s\n", host)
		}
		svc := r.Service
		if svc == "" {
			svc = "?"
		}
		if r.Guessed {
			svc += "?" // inferred from the port, not confirmed on the wire
		}
		line := fmt.Sprintf("  %-6d %-9s %6.1fms", r.Addr.Port(), svc, r.RTTms)
		if r.Detail != "" {
			line += "  " + r.Detail
		}
		fmt.Println(line)
	}
	fmt.Printf("\n%d open · %d probes in %s\n", len(rs), probes, took.Round(time.Millisecond))
}

func usage() {
	fmt.Fprint(os.Stderr, `lanscan - find what is listening on a network you control

usage: lanscan [flags]

  lanscan                          scan this machine's subnet
  lanscan -net 192.168.1.0/24      scan a specific network
  lanscan -net 10.0.0.5 -ports 1-1024
  lanscan -json | jq 'select(.service=="ollama")'

Only scan networks you own or are authorised to test.

flags:
`)
	flag.PrintDefaults()
}
