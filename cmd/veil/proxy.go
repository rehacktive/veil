package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"time"

	"veil/client"
	"veil/directory"
	"veil/socks5"
)

func proxy(ctx context.Context, args []string, out, diagnostics io.Writer) (result error) {
	f := flag.NewFlagSet("proxy", flag.ContinueOnError)
	f.SetOutput(diagnostics)
	public := f.Bool("public", false, "use bundled public Tor authority/fallback pins; no bootstrap JSON needed")
	config := f.String("config", "", "bootstrap JSON with trusted authority and relay pins")
	state := f.String("state", "", "private state directory; one process must own it")
	listen := f.String("listen", "127.0.0.1:9050", "numeric loopback SOCKS5 listener")
	bootstrap := f.Duration("bootstrap-timeout", 2*time.Minute, "maximum wait for a live verified directory (public default: 10m)")
	connect := f.Duration("connect-timeout", time.Minute, "per-connection circuit build and stream timeout")
	onionTimeout := f.Duration("onion-timeout", 3*time.Minute, "total v3 onion descriptor/introduction/rendezvous setup timeout")
	build := f.Duration("build-timeout", 20*time.Second, "maximum time for each circuit build attempt")
	attempts := f.Int("build-attempts", 3, "maximum circuit build attempts per connection (1..5); streams are not retried")
	idle := f.Duration("idle-timeout", 5*time.Minute, "close a connection after this long without traffic")
	lifetime := f.Duration("max-lifetime", time.Hour, "maximum lifetime of each connection")
	maxConnections := f.Int("max-connections", 16, "maximum concurrent connections, including handshakes (1..256)")
	reuse := f.Bool("circuit-reuse", true, "reuse circuits only within matching SOCKS tokens and destinations")
	circuitAge := f.Duration("circuit-max-age", 10*time.Minute, "stop attaching streams to old circuits; let active streams finish")
	circuitIdle := f.Duration("circuit-idle-timeout", 2*time.Minute, "close idle pooled circuits")
	maxPool := f.Int("max-pooled-circuits", 16, "maximum pooled circuits including builds and draining circuits (1..256)")
	if err := f.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}
	if *circuitAge <= 0 || *circuitIdle <= 0 || *maxPool < 1 || *maxPool > 256 || f.NArg() != 0 || (*public && *config != "" || !*public && *config == "") || *state == "" || *bootstrap <= 0 || *connect <= 0 || *onionTimeout <= 0 || *build <= 0 || *attempts < 1 || *attempts > 5 || *idle <= 0 || *lifetime <= 0 || *maxConnections < 1 || *maxConnections > 256 {
		return errors.New("proxy requires exactly one of -public or -config, -state, positive timeouts, -build-attempts in 1..5, and -max-connections in 1..256")
	}
	if *public {
		explicit := false
		f.Visit(func(v *flag.Flag) {
			if v.Name == "bootstrap-timeout" {
				explicit = true
			}
		})
		if !explicit {
			*bootstrap = 10 * time.Minute
		}
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	// Bind before opening state or bootstrapping, to report occupied/unsafe
	// listeners promptly. Accept starts only after a verified directory is live.
	listener, err := socks5.Listen(ctx, *listen)
	if err != nil {
		return err
	}
	defer listener.Close()
	lock, err := directory.LockState(*state)
	if err != nil {
		return err
	}
	defer func() { result = errors.Join(result, lock.Close()) }()
	var manager *directory.Manager
	var guards *directory.GuardStore
	if *public {
		manager, guards, err = openPublicDirectory(*state)
	} else {
		manager, guards, err = openDirectory(*config, *state)
	}
	if err != nil {
		return err
	}

	if *public {
		if _, err := fmt.Fprintln(diagnostics, "Loading the public Tor directory; first bootstrap may take several minutes..."); err != nil {
			return err
		}
		progressCtx, stopProgress := context.WithCancel(ctx)
		progressDone := make(chan struct{})
		go func() { defer close(progressDone); publicProgress(progressCtx, manager, diagnostics) }()
		defer func() { stopProgress(); <-progressDone }()
	}
	dialer, err := client.New(ctx, manager, guards, client.Options{DisableReuse: !*reuse, CircuitMaxAge: *circuitAge, CircuitIdleTimeout: *circuitIdle, MaxPooledCircuits: *maxPool, BuildTimeout: *build, ConnectTimeout: *connect, OnionTimeout: *onionTimeout, BuildAttempts: *attempts, MaxCircuits: *maxConnections})
	if err != nil {
		return err
	}
	defer func() { result = errors.Join(result, dialer.Close()) }()
	return serveProxy(ctx, listener, manager, dialer.DialContext, *bootstrap, socks5.Options{ConnectTimeout: *connect, OnionTimeout: *onionTimeout, IdleTimeout: *idle, MaxLifetime: *lifetime, MaxConnections: *maxConnections}, out)
}

type proxyDirectory interface {
	Run(context.Context) error
	Snapshot() (*directory.Snapshot, error)
}

func serveProxy(ctx context.Context, listener net.Listener, manager proxyDirectory, dial socks5.DialFunc, bootstrap time.Duration, options socks5.Options, out io.Writer) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	defer listener.Close()
	done := make(chan error, 1)
	go func() { done <- manager.Run(ctx) }()
	consumed := false
	defer func() {
		cancel()
		if !consumed {
			<-done
		}
	}()
	startup, stop := context.WithTimeout(ctx, bootstrap)
	err, consumed := waitDirectory(startup, manager, done)
	stop()
	if err != nil {
		return err
	}
	status := struct {
		Event     string `json:"event"`
		Listen    string `json:"listen"`
		Isolation string `json:"isolation"`
	}{"socks5_ready", listener.Addr().String(), "SOCKS tokens + destination; untagged connections dedicated"}
	if err = json.NewEncoder(out).Encode(status); err != nil {
		return err
	}
	served := make(chan error, 1)
	go func() { served <- socks5.Serve(ctx, listener, dial, options) }()
	select {
	case err = <-done:
		consumed = true
		cancel()
		<-served
	case err = <-served:
		cancel()
	}
	if errors.Is(err, context.Canceled) {
		return nil
	}
	return err
}

func waitDirectory(ctx context.Context, m interface {
	Snapshot() (*directory.Snapshot, error)
}, done <-chan error) (error, bool) {
	tick := time.NewTicker(50 * time.Millisecond)
	defer tick.Stop()
	for {
		if _, err := m.Snapshot(); err == nil {
			return nil, false
		}
		select {
		case err := <-done:
			return err, true
		case <-ctx.Done():
			return ctx.Err(), false
		case <-tick.C:
		}
	}
}

func openPublicDirectory(state string) (*directory.Manager, *directory.GuardStore, error) {
	roots, sources, err := directory.Mainnet()
	if err != nil {
		return nil, nil, err
	}
	cache, err := directory.NewCache(state, roots)
	if err != nil {
		return nil, nil, err
	}
	guards, err := directory.NewGuardStore(state)
	if err != nil {
		return nil, nil, err
	}
	manager, err := directory.NewManager(cache, guards, sources, directory.ManagerOptions{Attempts: 8, AttemptTimeout: 3 * time.Minute, RetryCap: 30 * time.Second})
	return manager, guards, err
}

func publicProgress(ctx context.Context, m *directory.Manager, out io.Writer) {
	tick := time.NewTicker(5 * time.Second)
	defer tick.Stop()
	previous := ""
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
		}
		status := m.Status()
		if status.Live {
			return
		}
		if status.Phase == "" {
			continue
		}
		line := fmt.Sprintf("directory: %s; %d requests, %d bytes; failed attempts=%d\n", status.Phase, status.DownloadRequests, status.DownloadBytes, status.Failures)
		if line != previous {
			if _, err := io.WriteString(out, line); err != nil {
				return
			}
			previous = line
		}
	}
}
