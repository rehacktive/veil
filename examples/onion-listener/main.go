// A native Go HTTP server reachable through an onion net.Listener.
// Run: go run ./examples/onion-listener -state ./state-listener
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"veil/directory"
	"veil/service"
)

func main() {
	state := flag.String("state", "./state-listener", "private persistent service state directory")
	port := flag.Uint("port", 80, "onion virtual TCP port")
	flag.Parse()
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := run(ctx, *state, *port); err != nil && !errors.Is(err, context.Canceled) {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(parent context.Context, state string, port uint) error {
	if port == 0 || port > 65535 {
		return errors.New("port must be in 1..65535")
	}
	lock, err := directory.LockState(state)
	if err != nil {
		return err
	}
	defer lock.Close()
	roots, sources, err := directory.Mainnet()
	if err != nil {
		return err
	}
	cache, err := directory.NewCache(state, roots)
	if err != nil {
		return err
	}
	guards, err := directory.NewGuardStore(state)
	if err != nil {
		return err
	}
	manager, err := directory.NewManager(cache, guards, sources, directory.ManagerOptions{Attempts: 8, AttemptTimeout: 8 * time.Minute})
	if err != nil {
		return err
	}
	identity, err := directory.OpenServiceIdentity(state)
	if err != nil {
		return err
	}

	ctx, cancel := context.WithCancelCause(parent)
	managed := make(chan struct{})
	go func() {
		defer close(managed)
		cancel(manager.Run(ctx))
	}()
	defer func() { cancel(context.Canceled); <-managed }()
	bootstrap := time.NewTimer(10 * time.Minute)
	defer bootstrap.Stop()
	tick := time.NewTicker(100 * time.Millisecond)
	defer tick.Stop()
	for {
		if _, err := manager.Snapshot(); err == nil {
			break
		}
		select {
		case <-ctx.Done():
			return context.Cause(ctx)
		case <-bootstrap.C:
			return errors.New("directory bootstrap timed out")
		case <-tick.C:
		}
	}

	listener, err := service.Listen(ctx, manager, guards, identity, service.Options{
		Port: uint16(port), Logger: slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelDebug})),
	})
	if err != nil {
		return err
	}
	defer func() { _ = listener.Close(); cancel(context.Canceled); <-listener.Done() }()
	fmt.Printf("Onion address: http://%s/ (publication continues in the background)\n", listener.Addr())
	server := &http.Server{
		ReadHeaderTimeout: 30 * time.Second,
		IdleTimeout:       time.Minute,
		Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			_, _ = io.WriteString(w, "Hello from a native Veil listener!\n")
		}),
	}
	defer server.Close()
	err = server.Serve(listener)
	if ctx.Err() != nil {
		return context.Cause(ctx)
	}
	return err
}
