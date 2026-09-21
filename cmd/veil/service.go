package main

import (
	"context"
	"errors"
	"flag"
	"io"
	"time"
	"veil/directory"
	"veil/internal/diagnostics"
	"veil/service"
)

func hostService(ctx context.Context, args []string, output io.Writer) (result error) {
	f := flag.NewFlagSet("service", flag.ContinueOnError)
	f.SetOutput(output)
	public := f.Bool("public", false, "use the public Tor network")
	config := f.String("config", "", "trusted private-network bootstrap JSON")
	state := f.String("state", "", "private service state directory; contains persistent onion identity and hostname")
	target := f.String("target", "127.0.0.1:8080", "numeric loopback TCP backend")
	port := f.Uint("port", 80, "onion service virtual TCP port")
	debug := f.Bool("debug", false, "log service activity to stderr")
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
	logger := diagnostics.New(*debug, output)
	defer func() { diagnostics.Log(ctx, logger, "service_stopped", "error", result) }()
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
	diagnostics.Log(ctx, logger, "service_starting", "onion", address, "port", *port, "target", *target)
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
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
