package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/netip"
	"os"
	"strings"
	"testing"
	"time"
	"veil/directory"
)

func TestDirectoryCheckCLI(t *testing.T) {
	pins := "0B8997614EC647C1C6B6A044E2B5408F0B823FB0,5B591AD684C1AB8E0AB76C839E93FD097526A4BC,8A1777F0BF97344A7ABB97530EEEE38A5BDE8A4D,D190BF3B00E311A9AEB6D62B51980E9B2109BAD1"
	args := []string{"directory-check", "-certificates", "../../directory/testdata/authorities.txt", "-consensus", "../../directory/testdata/consensus.txt", "-microdescriptors", "../../directory/testdata/microdescriptors.txt", "-authorities", pins, "-at", "2000-01-01T00:02:30Z"}
	var out bytes.Buffer
	if err := run(args, strings.NewReader(""), &out, io.Discard); err != nil {
		t.Fatal(err)
	}
	var result struct {
		Relays              int
		AuthoritySignatures int `json:"authority_signatures"`
	}
	if err := json.Unmarshal(out.Bytes(), &result); err != nil || result.Relays != 7 || result.AuthoritySignatures != 4 {
		t.Fatalf("%s %v", out.String(), err)
	}
	if err := run(args[:len(args)-2], strings.NewReader(""), io.Discard, io.Discard); err == nil {
		t.Fatal("accepted expired fixtures at current time")
	}
	if err := run(args, strings.NewReader(""), failingWriter{}, io.Discard); err == nil {
		t.Fatal("ignored output error")
	}
	for _, command := range []string{"directory-check", "directory-bootstrap", "directory-watch"} {
		if err := run([]string{command, "-h"}, strings.NewReader(""), io.Discard, io.Discard); err != nil {
			t.Fatal(err)
		}
		if err := run([]string{command}, strings.NewReader(""), io.Discard, io.Discard); err == nil {
			t.Fatal("accepted missing flags")
		}
	}
}
func TestDirectoryBootstrapInvalidConfig(t *testing.T) {
	for _, config := range []string{`{}`, `{"unknown":true}`, `{} {}`, `{"authorities":["bad"]}`, `{"authorities":["1111111111111111111111111111111111111111"],"relay":{"address":"127.0.0.1:1"}}`} {
		dir := t.TempDir()
		path := dir + "/config.json"
		if err := os.WriteFile(path, []byte(config), 0600); err != nil {
			t.Fatal(err)
		}
		if err := directoryBootstrap(context.Background(), []string{"-config", path, "-state", dir + "/state"}, io.Discard, io.Discard); err == nil {
			t.Fatal("accepted", config)
		}
	}
}

func TestWatchRecoversExpiredCache(t *testing.T) {
	// An expired authenticated cache must enter recovery instead of terminating
	// with ErrTime. The unavailable local relay keeps it waiting until canceled.
	dir := t.TempDir()
	os.Chmod(dir, 0700)
	certs, err := os.ReadFile("../../directory/testdata/authorities.txt")
	if err != nil {
		t.Fatal(err)
	}
	consensus, err := os.ReadFile("../../directory/testdata/consensus.txt")
	if err != nil {
		t.Fatal(err)
	}
	micro, err := os.ReadFile("../../directory/testdata/microdescriptors.txt")
	if err != nil {
		t.Fatal(err)
	}
	d := directory.Documents{Certificates: certs, Consensus: consensus, Microdescriptors: micro}
	raw, _ := json.Marshal(d)
	if err := os.WriteFile(dir+"/directory.json", raw, 0600); err != nil {
		t.Fatal(err)
	}
	roots, err := parseAuthorities([]string{"0B8997614EC647C1C6B6A044E2B5408F0B823FB0", "5B591AD684C1AB8E0AB76C839E93FD097526A4BC", "8A1777F0BF97344A7ABB97530EEEE38A5BDE8A4D", "D190BF3B00E311A9AEB6D62B51980E9B2109BAD1"})
	if err != nil {
		t.Fatal(err)
	}
	cache, err := directory.NewCache(dir, roots)
	if err != nil {
		t.Fatal(err)
	}
	guards, err := directory.NewGuardStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	source := directory.TorSource{OnionKey: [32]byte{1}}
	source.Target.Address = netip.MustParseAddrPort("127.0.0.1:1")
	source.Target.Identity.RSA = [20]byte{1}
	source.Target.Identity.Ed25519 = [32]byte{1}
	manager, err := directory.NewManager(cache, guards, []directory.TorSource{source}, directory.ManagerOptions{})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 250*time.Millisecond)
	defer cancel()
	if err := watchDirectory(ctx, manager, io.Discard); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal(err)
	}
	if _, err := manager.Snapshot(); !errors.Is(err, directory.ErrTime) {
		t.Fatal("expired cache exposed during recovery", err)
	}
	if manager.Status().Directory.Relays == 0 {
		t.Fatal("expired cache was not authenticated for recovery")
	}
}
