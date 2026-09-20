package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"io"
	"strings"
	"time"

	"veil/circuit"
	"veil/directory"
)

func circuitCheck(ctx context.Context, args []string, out, diagnostics io.Writer) (result error) {
	f := flag.NewFlagSet("circuit-check", flag.ContinueOnError)
	f.SetOutput(diagnostics)
	state := f.String("state", "", "existing private directory cache and guard state (exclusive owner required)")
	authorities := f.String("authorities", "", "comma-separated trusted authority RSA fingerprints")
	port := f.Uint("port", 443, "destination port for exit-policy selection; no stream is opened")
	ipv6 := f.Bool("ipv6", false, "select an exit permitting the port over IPv6")
	timeout := f.Duration("timeout", time.Minute, "total circuit build timeout")
	if err := f.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}
	if f.NArg() != 0 || *state == "" || *authorities == "" || *port == 0 || *port > 65535 || *timeout <= 0 {
		return errors.New("circuit-check requires -state, -authorities, a port in 1..65535, and a positive timeout")
	}
	roots, err := parseAuthorities(strings.Split(*authorities, ","))
	if err != nil {
		return err
	}
	lock, err := directory.LockState(*state)
	if err != nil {
		return err
	}
	defer func() { result = errors.Join(result, lock.Close()) }()
	cache, err := directory.NewCache(*state, roots)
	if err != nil {
		return err
	}
	s, err := cache.Load(time.Now())
	if err != nil {
		return err
	}
	guards, err := directory.NewGuardStore(*state)
	if err != nil {
		return err
	}
	c, err := circuit.Build(ctx, s, guards, circuit.Options{Port: uint16(*port), IPv6: *ipv6, BuildTimeout: *timeout})
	if err != nil {
		return err
	}
	defer c.Close()
	// Avoid printing the selected path or circuit keys in routine diagnostics.
	return json.NewEncoder(out).Encode(struct {
		Hops int    `json:"authenticated_hops"`
		Port uint16 `json:"exit_port"`
		IPv6 bool   `json:"ipv6"`
	}{3, uint16(*port), *ipv6})
}
