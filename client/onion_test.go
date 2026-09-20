package client

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"veil/circuit"
	"veil/directory"
	"veil/onion"
)

func TestOnionRoutingNeverFallsBackToExit(t *testing.T) {
	const host = "2gzyxa5ihm7nsggfxnu52rck2vv4rvmdlkiu3zzui5du4xyclen53wid.onion"
	for _, mode := range []string{"success", "build failure", "stream failure", "unavailable", "malformed"} {
		t.Run(mode, func(t *testing.T) {
			d, err := newDialer(context.Background(), source{err: directory.ErrTime}, Options{ConnectTimeout: time.Second, OnionTimeout: time.Minute}, func(context.Context, *directory.Snapshot, circuit.Options) (streamCircuit, error) {
				t.Error("onion routed through exit builder")
				return nil, errors.New("exit forbidden")
			})
			if err != nil {
				t.Fatal(err)
			}
			var c *fakeCircuit
			called := false
			d.onionBuild = func(life, setup context.Context, name string, port uint16) (streamCircuit, error) {
				called = true
				deadline, _ := setup.Deadline()
				if strings.ToLower(name) != host || port != 80 || time.Until(deadline) < 30*time.Second {
					t.Error("wrong onion setup arguments")
				}
				if mode == "build failure" {
					return nil, onion.ErrAuthentication
				}
				c = &fakeCircuit{ctx: life}
				if mode == "stream failure" {
					c.fail = errors.New("stream failed")
				}
				return c, nil
			}
			address := strings.ToUpper(host) + ":80"
			if mode == "unavailable" {
				d.onionBuild = nil
			}
			if mode == "malformed" {
				address = "invalid.onion:80"
			}
			conn, err := d.DialContext(context.Background(), "tcp6", address)
			if mode == "success" {
				if err != nil {
					t.Fatal(err)
				}
				conn.Close()
			} else if err == nil {
				conn.Close()
				t.Fatal("accepted failure")
			}
			if (mode == "malformed" || mode == "unavailable") && called {
				t.Fatal("invalid onion reached builder")
			}
			if len(d.slots) != 0 || c != nil && (c.closed.Load() != 1 || c.ctx.Err() == nil) {
				t.Fatal("onion resources leaked")
			}
		})
	}
}
