package service

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"
	"veil/circuit"
	"veil/directory"
	"veil/internal/diagnostics"
	"veil/onion"
)

func (h *Host) publish(ctx context.Context, s *directory.Snapshot, g *generation, periods []directory.ServicePeriod) error {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Minute)
	defer cancel()
	var subs [][32]byte
	for _, p := range periods {
		_, sub, err := onion.Blind(h.identity.Public(), p.Period, p.Minutes)
		if err != nil {
			return err
		}
		subs = append(subs, sub)
	}
	g.mu.Lock()
	// Keep older subcredentials for cached descriptors until these intro keys
	// retire. The lifetime bounds this set even on shortened private periods.
	for _, sub := range subs {
		seen := false
		for _, old := range g.subs {
			if old == sub {
				seen = true
			}
		}
		if !seen {
			g.subs = append(g.subs, sub)
		}
	}
	if len(g.subs) > 8 {
		g.mu.Unlock()
		return errRotate
	}
	g.mu.Unlock()
	intros := make([]onion.Introduction, len(g.intros))
	for j, i := range g.intros {
		intros[j] = i.key.Public
	}
	var failures []error
	for _, p := range periods {
		seed, revision, err := h.identity.ReserveDescriptor()
		if err != nil {
			return &persistentError{err}
		}
		created := time.Now()
		raw, err := onion.CreateDescriptor(seed, p.Period, p.Minutes, revision, intros, created)
		clear(seed[:])
		if err != nil {
			return err
		}
		blinded, _, err := onion.Blind(h.identity.Public(), p.Period, p.Minutes)
		if err != nil {
			return err
		}
		targets, err := s.ServiceDirectories(blinded, p, time.Now())
		if err != nil {
			return err
		}
		successes := 0
		for _, target := range targets {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			// An HSDir may accept a descriptor even if its reply is lost. Retain
			// advertised keys before the upload, including on partial failure.
			if expiry := onion.ServiceDescriptorExpiry(created); expiry.After(g.retainUntil) {
				g.retainUntil = expiry
			}
			err = h.upload(ctx, s, target, raw)
			if err == nil {
				successes++
			} else {
				diagnostics.Log(ctx, h.options.Logger, "service_upload_failed", "error", err)
			}
		}
		diagnostics.Log(ctx, h.options.Logger, "service_descriptor_published", "period", p.Period, "directories", successes, "total", len(targets))
		if successes != len(targets) || successes == 0 {
			failures = append(failures, errors.New("descriptor publication incomplete; retry scheduled"))
		}
	}
	return errors.Join(failures...)
}
func (h *Host) uploadDescriptor(parent context.Context, s *directory.Snapshot, target directory.Relay, raw []byte) error {
	ctx, cancel := context.WithTimeout(parent, 45*time.Second)
	defer cancel()
	c, err := h.build(ctx, s, &target, circuit.OnionDirectory)
	if err != nil {
		return err
	}
	defer c.Close()
	conn, err := c.DialDirectory(ctx)
	if err != nil {
		return err
	}
	defer conn.Close()
	deadline, _ := ctx.Deadline()
	if err := conn.SetDeadline(deadline); err != nil {
		return err
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, "http://onion-directory/tor/hs/3/publish", bytes.NewReader(raw))
	if err != nil {
		return err
	}
	request.Close = true
	if err := request.Write(conn); err != nil {
		return err
	}
	response, err := http.ReadResponse(bufio.NewReader(io.LimitReader(conn, 16384)), request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode != 200 {
		return fmt.Errorf("onion directory rejected descriptor (HTTP %d)", response.StatusCode)
	}
	return nil
}
