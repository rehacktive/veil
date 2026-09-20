// Command veil provides protocol tooling for Veil, a staged native Go rewrite of Arti.
package main

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"

	"veil/cell"
)

const version = "0.10.0-dev"

const usage = `Veil: a native Go rewrite of Arti, stage 6 (SOCKS5 and v3 onion client)

Usage:
  veil version
  veil proxy (-public | -config FILE) -state DIRECTORY [-listen 127.0.0.1:9050]
  veil inspect [-link 4|5] [-handshake] [-payload] < cells.bin
  veil channel-check -address IP:port -rsa HEX -ed25519 HEX [-timeout 30s]
  veil directory-check -certificates FILE -consensus FILE -microdescriptors FILE -authorities CSV [-at RFC3339]
  veil directory-bootstrap -config FILE -state DIRECTORY [-timeout 5m]
  veil directory-watch -config FILE -state DIRECTORY [-timeout 0]
  veil circuit-check -state DIRECTORY -authorities CSV [-port 443] [-ipv6] [-timeout 1m]

inspect reads binary Tor channel frames and writes one JSON object per frame.
-handshake first reads VERSIONS and selects the highest supported link protocol.
-payload includes the full payload as hex, including fixed-cell padding.

channel-check verifies a relay's channel against both supplied identity pins,
prints connection metadata as JSON, then closes it. It opens no circuits.

directory-check verifies local documents without networking. directory-bootstrap
uses an explicitly pinned relay to download, verify, and privately cache them.
directory-watch restores cached state and refreshes it until interrupted,
printing JSON only when status changes. circuit-check re-verifies a live cache,
selects and authenticates a three-hop circuit, then closes it. It requires
exclusive access to its state directory. The Go Circuit.DialContext API provides
TCP streams. proxy maintains the directory, accepts loopback SOCKS5 CONNECT
requests for public internet and v3 onion services, with a fresh application
circuit per connection. Onion setup has a separate -onion-timeout (default 3m).
-public uses bundled Tor
authority/fallback pins; -config selects a controlled network. Use make proxy-demo
for a temporary local test or make public-proxy for public-network testing.
`

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := runContext(ctx, os.Args[1:], os.Stdin, os.Stdout, os.Stderr); err != nil {
		fmt.Fprintln(os.Stderr, "veil:", err)
		os.Exit(1)
	}
}

func run(args []string, in io.Reader, out, diagnostics io.Writer) error {
	return runContext(context.Background(), args, in, out, diagnostics)
}

func runContext(ctx context.Context, args []string, in io.Reader, out, diagnostics io.Writer) error {
	if len(args) == 0 {
		_, err := io.WriteString(out, usage)
		return err
	}
	switch args[0] {
	case "help", "-h", "--help":
		_, err := io.WriteString(out, usage)
		return err
	case "version":
		if len(args) != 1 {
			return errors.New("version takes no arguments")
		}
		_, err := fmt.Fprintf(out, "Veil %s (stage 6; native SOCKS5 and v3 onion client)\n", version)
		return err
	case "proxy":
		return proxy(ctx, args[1:], out, diagnostics)
	case "inspect":
		return inspect(args[1:], in, out, diagnostics)
	case "directory-check":
		return directoryCheck(args[1:], out, diagnostics)
	case "directory-watch":
		return directoryManage(ctx, args[1:], out, diagnostics, true)
	case "directory-bootstrap":
		return directoryBootstrap(ctx, args[1:], out, diagnostics)
	case "channel-check":
		return channelCheck(ctx, args[1:], out, diagnostics)
	case "circuit-check":
		return circuitCheck(ctx, args[1:], out, diagnostics)
	default:
		return fmt.Errorf("unknown command %q; run veil help", args[0])
	}
}

func inspect(args []string, in io.Reader, out, diagnostics io.Writer) error {
	flags := flag.NewFlagSet("inspect", flag.ContinueOnError)
	flags.SetOutput(diagnostics)
	link := flags.Int("link", 4, "negotiated link protocol (4 or 5)")
	handshake := flags.Bool("handshake", false, "read initial VERSIONS frame")
	payload := flags.Bool("payload", false, "include payload hex")
	if err := flags.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("inspect reads binary data from stdin; unexpected arguments")
	}
	if *link != 4 && *link != 5 {
		return errors.New("-link must be 4 or 5")
	}
	linkSet := false
	flags.Visit(func(f *flag.Flag) {
		if f.Name == "link" {
			linkSet = true
		}
	})
	if *handshake && linkSet {
		return errors.New("choose either -handshake or -link")
	}
	selectedLink := uint16(4)
	if *link == 5 {
		selectedLink = 5
	}
	enc := json.NewEncoder(out)
	if *handshake {
		versions, err := cell.ReadVersions(in)
		if err != nil {
			return fmt.Errorf("VERSIONS: %w", err)
		}
		selected, err := cell.NegotiateVersion(versions, []uint16{4, 5})
		if err != nil {
			return err
		}
		selectedLink = selected
		if err := enc.Encode(struct {
			Command  string   `json:"command"`
			Versions []uint16 `json:"versions"`
			Selected uint16   `json:"selected"`
		}{"VERSIONS", versions, selected}); err != nil {
			return err
		}
	}
	c, err := cell.NewCodec(selectedLink)
	if err != nil {
		return err
	}
	for index := 0; ; index++ {
		frame, err := c.Read(in)
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return fmt.Errorf("cell %d: %w", index, err)
		}
		record := struct {
			CircuitID uint32 `json:"circuit_id"`
			Command   string `json:"command"`
			CommandID uint8  `json:"command_id"`
			Length    int    `json:"length"`
			Payload   string `json:"payload_hex,omitempty"`
		}{CircuitID: frame.CircuitID, Command: frame.Command.String(), CommandID: uint8(frame.Command), Length: len(frame.Payload)}
		if *payload {
			record.Payload = hex.EncodeToString(frame.Payload)
		}
		if err := enc.Encode(record); err != nil {
			return err
		}
	}
}
