package main

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/netip"
	"time"

	"veil/channel"
)

func channelCheck(ctx context.Context, args []string, out, diagnostics io.Writer) error {
	flags := flag.NewFlagSet("channel-check", flag.ContinueOnError)
	flags.SetOutput(diagnostics)
	address := flags.String("address", "", "numeric relay IP:port (IPv6 in brackets)")
	rsaID := flags.String("rsa", "", "trusted RSA identity fingerprint, 40 hexadecimal characters")
	edID := flags.String("ed25519", "", "trusted Ed25519 identity key, 64 hexadecimal characters")
	timeout := flags.Duration("timeout", 30*time.Second, "TCP/TLS/Tor handshake timeout")
	if err := flags.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("channel-check takes flags only")
	}
	if *timeout <= 0 {
		return errors.New("-timeout must be positive")
	}
	addr, err := netip.ParseAddrPort(*address)
	if err != nil {
		return errors.New("-address must be a numeric IP:port")
	}
	target := channel.Target{Address: addr}
	rsaPin, err := hex.DecodeString(*rsaID)
	if err != nil || len(rsaPin) != len(target.Identity.RSA) {
		return errors.New("-rsa must contain exactly 40 hexadecimal characters")
	}
	edPin, err := hex.DecodeString(*edID)
	if err != nil || len(edPin) != len(target.Identity.Ed25519) {
		return errors.New("-ed25519 must contain exactly 64 hexadecimal characters")
	}
	copy(target.Identity.RSA[:], rsaPin)
	copy(target.Identity.Ed25519[:], edPin)
	ch, err := channel.Dial(ctx, target, channel.Options{HandshakeTimeout: *timeout})
	if err != nil {
		return err
	}
	defer ch.Close()
	info := ch.Info()
	return json.NewEncoder(out).Encode(struct {
		Address string    `json:"address"`
		RSA     string    `json:"rsa_identity"`
		Ed25519 string    `json:"ed25519_identity"`
		Link    uint16    `json:"link_protocol"`
		TLS     string    `json:"tls_version"`
		Expires time.Time `json:"certificates_expire"`
	}{addr.String(), hex.EncodeToString(info.Identity.RSA[:]), hex.EncodeToString(info.Identity.Ed25519[:]), info.LinkVersion, fmt.Sprintf("0x%04x", info.TLSVersion), info.CertificatesExpire})
}
