package main

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/netip"
	"os"
	"strings"
	"time"

	"veil/channel"
	"veil/directory"
)

func parseAuthorities(value []string) ([]directory.Fingerprint, error) {
	var roots []directory.Fingerprint
	for _, s := range value {
		f, err := directory.ParseFingerprint(s)
		if err != nil {
			return nil, err
		}
		roots = append(roots, f)
	}
	if len(roots) == 0 {
		return nil, errors.New("explicit authority identity pins are required")
	}
	return roots, nil
}
func readBounded(path string, limit int64) ([]byte, error) {
	f, err := os.Open(path) // #nosec G304 -- Local CLI flags intentionally select input files; paths never come from a relay or directory document.
	if err != nil {
		return nil, err
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > limit {
		return nil, fmt.Errorf("file exceeds %d bytes", limit)
	}
	return b, nil
}
func directoryCheck(args []string, out, diagnostics io.Writer) error {
	f := flag.NewFlagSet("directory-check", flag.ContinueOnError)
	f.SetOutput(diagnostics)
	certs := f.String("certificates", "", "authority certificate bundle")
	consensus := f.String("consensus", "", "microdescriptor consensus")
	micro := f.String("microdescriptors", "", "wire microdescriptor bundle (no annotations)")
	authorities := f.String("authorities", "", "comma-separated trusted authority RSA fingerprints")
	at := f.String("at", "", "offline validation time, RFC3339 (default: current time)")
	if err := f.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}
	if f.NArg() != 0 || *certs == "" || *consensus == "" || *micro == "" || *authorities == "" {
		return errors.New("directory-check requires -certificates, -consensus, -microdescriptors, and -authorities")
	}
	roots, err := parseAuthorities(strings.Split(*authorities, ","))
	if err != nil {
		return err
	}
	now := time.Now()
	if *at != "" {
		now, err = time.Parse(time.RFC3339, *at)
		if err != nil {
			return err
		}
	}
	var d directory.Documents
	if d.Certificates, err = readBounded(*certs, directory.MaxCertificatesSize); err != nil {
		return err
	}
	if d.Consensus, err = readBounded(*consensus, directory.MaxConsensusSize); err != nil {
		return err
	}
	if d.Microdescriptors, err = readBounded(*micro, directory.MaxMicrodescriptorsSize); err != nil {
		return err
	}
	s, err := directory.Verify(d, roots, now)
	if err != nil {
		return err
	}
	return json.NewEncoder(out).Encode(s.Info())
}

type bootstrapConfig struct {
	Authorities []string `json:"authorities"`
	Relay       struct {
		Address string `json:"address"`
		RSA     string `json:"rsa"`
		Ed25519 string `json:"ed25519"`
		NTor    string `json:"ntor"`
	} `json:"relay"`
}

func directoryBootstrap(ctx context.Context, args []string, out, diagnostics io.Writer) error {
	return directoryManage(ctx, args, out, diagnostics, false)
}

func directoryManage(ctx context.Context, args []string, out, diagnostics io.Writer, watch bool) (result error) {
	command := "directory-bootstrap"
	defaultTimeout := 5 * time.Minute
	if watch {
		command = "directory-watch"
		defaultTimeout = 0
	}
	f := flag.NewFlagSet(command, flag.ContinueOnError)
	f.SetOutput(diagnostics)
	config := f.String("config", "", "JSON containing authority pins and trusted bootstrap relay keys (hex)")
	state := f.String("state", "", "private state directory (0700)")
	timeout := f.Duration("timeout", defaultTimeout, "total timeout (directory-watch: 0 means run until interrupted)")
	if err := f.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}
	if f.NArg() != 0 || *config == "" || *state == "" || *timeout < 0 || (!watch && *timeout == 0) {
		return fmt.Errorf("%s requires -config, -state, and a valid -timeout", command)
	}
	lock, err := directory.LockState(*state)
	if err != nil {
		return err
	}
	defer func() { result = errors.Join(result, lock.Close()) }()
	manager, _, err := openDirectory(*config, *state)
	if err != nil {
		return err
	}
	if *timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, *timeout)
		defer cancel()
	}
	if !watch {
		snapshot, err := manager.Refresh(ctx)
		if err != nil {
			return err
		}
		return json.NewEncoder(out).Encode(snapshot.Info())
	}
	return watchDirectory(ctx, manager, out)
}

func watchDirectory(ctx context.Context, manager *directory.Manager, out io.Writer) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- manager.Run(ctx) }()
	tick := time.NewTicker(100 * time.Millisecond)
	defer tick.Stop()
	var previous []byte
	emit := func() error {
		status := manager.Status()
		if status.Directory.Relays == 0 && status.LastError == "" {
			return nil
		}
		b, err := json.Marshal(status)
		if err != nil {
			return err
		}
		if bytes.Equal(previous, b) {
			return nil
		}
		if _, err := out.Write(append(b, '\n')); err != nil {
			return err
		}
		previous = b
		return nil
	}
	for {
		select {
		case err := <-done:
			if e := emit(); e != nil {
				return e
			}
			return err
		case <-tick.C:
			if err := emit(); err != nil {
				cancel()
				<-done
				return err
			}
		}
	}
}

func loadBootstrap(config string) ([]directory.Fingerprint, directory.TorSource, error) {
	raw, err := readBounded(config, 16384)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, directory.TorSource{}, fmt.Errorf("%w; create this JSON file with trusted authority and relay keys (see README.md, Directory verification and bootstrap), or run scripts/check_local_directory.py --demo with --tor and --gencert for a temporary local network", err)
		}
		return nil, directory.TorSource{}, err
	}
	var cfg bootstrapConfig
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&cfg); err != nil {
		return nil, directory.TorSource{}, err
	}
	var extra any
	if err := dec.Decode(&extra); err != io.EOF {
		return nil, directory.TorSource{}, errors.New("trailing configuration data")
	}
	roots, err := parseAuthorities(cfg.Authorities)
	if err != nil {
		return nil, directory.TorSource{}, err
	}
	address, err := netip.ParseAddrPort(cfg.Relay.Address)
	if err != nil {
		return nil, directory.TorSource{}, err
	}
	source := directory.TorSource{Target: channel.Target{Address: address}}
	for _, key := range []struct {
		value string
		dest  []byte
	}{{cfg.Relay.RSA, source.Target.Identity.RSA[:]}, {cfg.Relay.Ed25519, source.Target.Identity.Ed25519[:]}, {cfg.Relay.NTor, source.OnionKey[:]}} {
		b, err := hex.DecodeString(key.value)
		if err != nil || len(b) != len(key.dest) {
			return nil, directory.TorSource{}, errors.New("bootstrap relay keys must be exact-length hexadecimal")
		}
		copy(key.dest, b)
	}
	return roots, source, nil
}

func openDirectory(config, state string) (*directory.Manager, *directory.GuardStore, error) {
	roots, source, err := loadBootstrap(config)
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
	manager, err := directory.NewManager(cache, guards, []directory.TorSource{source}, directory.ManagerOptions{})
	return manager, guards, err
}
