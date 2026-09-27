package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"io"
	"time"
	"veil/directory"
	"veil/internal/diagnostics"
	"veil/service"
)

func hostService(ctx context.Context, args []string, out, output io.Writer) (result error) {
	f := flag.NewFlagSet("service", flag.ContinueOnError)
	f.SetOutput(output)
	public := f.Bool("public", false, "use the public Tor network")
	config := f.String("config", "", "trusted private-network bootstrap JSON")
	state := f.String("state", "", "private service state directory; contains persistent onion identity and hostname")
	target := f.String("target", "127.0.0.1:8080", "numeric loopback TCP backend")
	port := f.Uint("port", 80, "onion service virtual TCP port")
	debug := f.Bool("debug", false, "log service activity to stderr")
	quiet := f.Bool("quiet", false, "suppress operational logs; fatal errors remain visible")
	statusJSON := f.Bool("status-json", false, "emit directory and service status changes as JSON on stdout")
	bootstrap := f.Duration("bootstrap-timeout", 10*time.Minute, "directory bootstrap deadline")
	maxRend := f.Int("max-rendezvous", 16, "maximum concurrent rendezvous circuits (1..64)")
	maxStreams := f.Int("max-streams", 32, "maximum total forwarded streams (1..256)")
	if err := f.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}
	if f.NArg() != 0 || (*public == (*config != "")) || *state == "" || *port == 0 || *port > 65535 || *bootstrap <= 0 {
		return errors.New("service requires exactly one of -public/-config, -state, a port in 1..65535 and positive bootstrap timeout")
	}
	if *debug && *quiet {
		return errors.New("-debug and -quiet cannot be used together")
	}
	logger := diagnostics.NewCLI(*debug, *quiet, output)
	diagnostics.Info(ctx, logger, "service_starting", "message", "Starting Veil onion service", "port", *port, "public", *public)
	defer func() {
		diagnostics.Info(ctx, logger, "service_stopped", "message", "Veil onion service stopped", "error", result)
	}()
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
	identity, err := directory.OpenServiceIdentity(*state)
	if err != nil {
		return err
	}
	h, err := service.New(manager, guards, identity, service.Options{Port: uint16(*port), Target: *target, Logger: logger, MaxRendezvous: *maxRend, MaxStreams: *maxStreams})
	if err != nil {
		return err
	}
	address, err := identity.Address()
	if err != nil {
		return err
	}
	diagnostics.Log(ctx, logger, "service_identity", "onion", address, "port", *port, "target", *target)
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	if *statusJSON {
		reportCtx, stopReport := context.WithCancel(context.WithoutCancel(ctx))
		reported := make(chan error, 1)
		go func() {
			err := reportServiceStatus(reportCtx, out, manager, h)
			if err != nil {
				cancel()
			}
			reported <- err
		}()
		defer func() { stopReport(); result = errors.Join(result, <-reported) }()
	}
	done := make(chan error, 1)
	go func() { done <- manager.Run(ctx) }()
	consumed := false
	defer func() {
		cancel()
		if !consumed {
			<-done
		}
	}()
	if logger != nil {
		diagnostics.Info(ctx, logger, "directory_bootstrap", "message", "Loading cached directory or downloading a verified directory; first startup may take several minutes")
		progressCtx, stop := context.WithCancel(ctx)
		stopped := make(chan struct{})
		go func() { defer close(stopped); directoryProgress(progressCtx, manager, logger) }()
		defer func() { stop(); <-stopped }()
	}
	startup, stop := context.WithTimeout(ctx, *bootstrap)
	err, consumed = waitDirectory(startup, manager, done)
	stop()
	if err != nil {
		if errors.Is(err, context.Canceled) {
			return nil
		}
		return err
	}
	diagnostics.Info(ctx, logger, "directory_ready", "message", "Verified directory is ready; establishing onion introduction points")
	serving := make(chan error, 1)
	go func() { serving <- h.Run(ctx) }()
	select {
	case err = <-done:
		consumed = true
		cancel()
		<-serving
	case err = <-serving:
		cancel()
	}
	if errors.Is(err, context.Canceled) {
		return nil
	}
	return err
}

type serviceStatusSnapshot struct {
	Directory directory.BootstrapProgress `json:"directory"`
	Service   service.Status              `json:"service"`
}

func reportServiceStatus(ctx context.Context, out io.Writer, manager *directory.Manager, host *service.Host) error {
	return writeServiceStatus(ctx, out, func() serviceStatusSnapshot {
		return serviceStatusSnapshot{Directory: manager.BootstrapProgress(), Service: host.Status()}
	})
}

// Coalesce changes without an event queue. Shutdown emits one final snapshot.
func writeServiceStatus(ctx context.Context, out io.Writer, snapshot func() serviceStatusSnapshot) error {
	tick := time.NewTicker(250 * time.Millisecond)
	defer tick.Stop()
	var previous string
	emit := func() error {
		raw, err := json.Marshal(snapshot())
		if err != nil {
			return err
		}
		if string(raw) == previous {
			return nil
		}
		line := append(raw, '\n')
		n, err := out.Write(line)
		if err != nil {
			return err
		}
		if n != len(line) {
			return io.ErrShortWrite
		}
		previous = string(raw)
		return nil
	}
	for {
		if err := emit(); err != nil {
			return err
		}
		select {
		case <-ctx.Done():
			return emit()
		case <-tick.C:
		}
	}
}
