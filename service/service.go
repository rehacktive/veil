// Package service hosts an experimental public v3 onion service over native Tor
// circuits. It exposes exactly one virtual port to one numeric loopback backend.
package service

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"net"
	"net/netip"
	"sync"
	"time"

	"veil/cell"
	"veil/circuit"
	"veil/directory"
	"veil/internal/diagnostics"
	"veil/onion"
)

type Options struct {
	Port          uint16
	Target        string
	Logger        *slog.Logger
	MaxRendezvous int
	MaxStreams    int
	BuildTimeout  time.Duration
	IdleTimeout   time.Duration
	MaxLifetime   time.Duration
}
type snapshotSource interface {
	Snapshot() (*directory.Snapshot, error)
}
type buildFunc func(context.Context, *directory.Snapshot, *directory.Relay, circuit.OnionPurpose) (*circuit.Circuit, error)
type Host struct {
	source            snapshotSource
	identity          *directory.ServiceIdentity
	options           Options
	build             buildFunc
	selectIntro       func(*directory.Snapshot, []directory.Fingerprint) (directory.Relay, error)
	sessions, streams chan struct{}
	runMu             sync.Mutex
}

func New(manager *directory.Manager, guards *directory.GuardStore, identity *directory.ServiceIdentity, options Options) (*Host, error) {
	if manager == nil || guards == nil || identity == nil {
		return nil, errors.New("service requires directory, guards and identity")
	}
	target, err := netip.ParseAddrPort(options.Target)
	if err != nil || !target.Addr().IsLoopback() || target.Addr().Zone() != "" || target.Port() == 0 || options.Port == 0 {
		return nil, errors.New("service requires a virtual port and numeric loopback target IP:port")
	}
	if options.MaxRendezvous == 0 {
		options.MaxRendezvous = 16
	}
	if options.MaxStreams == 0 {
		options.MaxStreams = 32
	}
	if options.BuildTimeout == 0 {
		options.BuildTimeout = 20 * time.Second
	}
	if options.IdleTimeout == 0 {
		options.IdleTimeout = 5 * time.Minute
	}
	if options.MaxLifetime == 0 {
		options.MaxLifetime = time.Hour
	}
	if options.MaxRendezvous < 1 || options.MaxRendezvous > 64 || options.MaxStreams < 1 || options.MaxStreams > 256 || options.BuildTimeout < 0 || options.IdleTimeout < 0 || options.MaxLifetime < 0 {
		return nil, errors.New("invalid service resource limits")
	}
	h := &Host{source: manager, identity: identity, options: options, sessions: make(chan struct{}, options.MaxRendezvous), streams: make(chan struct{}, options.MaxStreams)}
	h.selectIntro = func(s *directory.Snapshot, excluded []directory.Fingerprint) (directory.Relay, error) {
		return s.SelectIntroduction(excluded, time.Now())
	}
	h.build = func(ctx context.Context, s *directory.Snapshot, target *directory.Relay, purpose circuit.OnionPurpose) (*circuit.Circuit, error) {
		return circuit.BuildInternal(ctx, s, guards, target, purpose, options.BuildTimeout)
	}
	return h, nil
}

type introduction struct {
	circuit *circuit.Circuit
	key     *onion.ServiceIntroduction
	// Owned by this introduction's single receive loop. Saturation retires the
	// circuit instead of evicting history while its encryption key remains live.
	clients map[[32]byte]bool
}
type generation struct {
	intros   []*introduction
	mu       sync.RWMutex
	subs     [][32]byte
	cookies  map[[20]byte]bool
	window   time.Time
	received int
}
type persistentError struct{ error }

var errRotate = errors.New("rotating service introduction keys")

// Run owns all circuits and workers until cancellation. Circuit failures rebuild
// introduction points with fresh keys and republish; guard state is never reset.
func (h *Host) Run(ctx context.Context) error {
	if !h.runMu.TryLock() {
		return errors.New("service is already running")
	}
	defer h.runMu.Unlock()
	for failures := 0; ; {
		err := h.runGeneration(ctx)
		if ctx.Err() != nil {
			return ctx.Err()
		}
		var state *persistentError
		if errors.As(err, &state) {
			return err
		}
		if errors.Is(err, errRotate) {
			failures = 0
			continue
		}
		failures++
		if failures >= 10 {
			return fmt.Errorf("service recovery exhausted: %w", err)
		}
		diagnostics.Log(ctx, h.options.Logger, "service_recovering", "error", err, "attempt", failures)
		timer := time.NewTimer(min(time.Minute, time.Duration(failures)*5*time.Second))
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		}
	}
}
func relayLinks(r directory.Relay) []cell.LinkSpec {
	address := binary.BigEndian.AppendUint16(r.Address().Addr().AsSlice(), r.Address().Port())
	kind := byte(cell.LinkIPv4)
	if r.Address().Addr().Is6() {
		kind = cell.LinkIPv6
	}
	id := r.Target().Identity
	return []cell.LinkSpec{{Type: kind, Data: address}, {Type: cell.LinkRSAIdentity, Data: append([]byte{}, id.RSA[:]...)}, {Type: cell.LinkEd25519Identity, Data: append([]byte{}, id.Ed25519[:]...)}}
}
func (h *Host) runGeneration(parent context.Context) error {
	ctx, cancel := context.WithCancel(parent)
	g := &generation{cookies: make(map[[20]byte]bool)}
	var workers sync.WaitGroup
	defer func() {
		cancel()
		for _, i := range g.intros {
			_ = i.circuit.Close()
		}
		workers.Wait()
	}()
	var excluded []directory.Fingerprint
	for tries := 0; len(g.intros) < 3 && tries < 9; tries++ {
		s, err := h.source.Snapshot()
		if err != nil {
			return err
		}
		target, err := h.selectIntro(s, excluded)
		if err != nil {
			return err
		}
		c, err := h.build(ctx, s, &target, circuit.OnionServiceIntroduction)
		if err != nil {
			diagnostics.Log(ctx, h.options.Logger, "service_intro_build_failed", "error", err)
			continue
		}
		intro, err := onion.NewServiceIntroduction(relayLinks(target), target.NTor().OnionKey)
		if err != nil {
			_ = c.Close()
			return err
		}
		setup, stop := context.WithTimeout(ctx, h.options.BuildTimeout)
		err = c.EstablishIntroduction(setup, intro.Establish)
		stop()
		if err != nil {
			_ = c.Close()
			diagnostics.Log(ctx, h.options.Logger, "service_intro_failed", "error", err)
			continue
		}
		g.intros = append(g.intros, &introduction{circuit: c, key: intro, clients: make(map[[32]byte]bool)})
		excluded = append(excluded, target.Identity())
		diagnostics.Log(ctx, h.options.Logger, "service_intro_ready", "relay", target.Address().String())
	}
	if len(g.intros) != 3 {
		return errors.New("could not establish three introduction points")
	}
	failed := make(chan error, len(g.intros))
	// Readers start before publishing. Subcredentials are installed by publish
	// before a descriptor is uploaded, so prompt client introductions can succeed.
	for _, i := range g.intros {
		workers.Add(1)
		go func() { defer workers.Done(); failed <- h.readIntroductions(ctx, g, i, &workers) }()
	}
	var lastPeriods []directory.ServicePeriod
	nextPublish := time.Time{}
	tick := time.NewTicker(time.Minute)
	defer tick.Stop()
	rotate := time.NewTimer(2 * time.Hour)
	defer rotate.Stop()
	for {
		s, err := h.source.Snapshot()
		if err != nil {
			return err
		}
		periods, err := s.ServicePeriods(time.Now())
		if err != nil {
			return err
		}
		changed := len(lastPeriods) != len(periods)
		if !changed {
			for j := range periods {
				if periods[j] != lastPeriods[j] {
					changed = true
				}
			}
		}
		if changed || !time.Now().Before(nextPublish) {
			err = h.publish(ctx, s, g, periods)
			var state *persistentError
			if errors.Is(err, errRotate) || errors.As(err, &state) {
				return err
			}
			if err != nil {
				diagnostics.Log(ctx, h.options.Logger, "service_publish_failed", "error", err)
				nextPublish = time.Now().Add(time.Minute)
			} else {
				lastPeriods = periods
				jitter, e := rand.Int(rand.Reader, big.NewInt(3601))
				if e != nil {
					return e
				}
				nextPublish = time.Now().Add(time.Hour + time.Duration(jitter.Int64())*time.Second)
				diagnostics.Log(ctx, h.options.Logger, "service_ready", "port", h.options.Port, "target", h.options.Target)
			}
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case err := <-failed:
			return err
		case <-rotate.C:
			return errRotate
		case <-tick.C:
		}
	}
}

func (h *Host) readIntroductions(ctx context.Context, g *generation, i *introduction, workers *sync.WaitGroup) error {
	for {
		m, err := i.circuit.Receive(ctx)
		if err != nil {
			return err
		}
		if m.Command != cell.RelayIntroduce2 {
			return circuit.ErrProtocol
		}
		if !g.allowIntroduction(time.Now()) {
			continue
		}
		g.mu.RLock()
		subs := append([][32]byte{}, g.subs...)
		g.mu.RUnlock()
		var request onion.ServiceRequest
		valid := false
		for _, sub := range subs {
			request, err = i.key.Accept(m.Data, sub)
			if err == nil {
				valid = true
				break
			}
		}
		if !valid {
			diagnostics.Log(ctx, h.options.Logger, "service_intro_rejected")
			continue
		}
		admitted, err := g.remember(i, request)
		if err != nil {
			clear(request.Keys[:])
			return err
		}
		if !admitted {
			clear(request.Keys[:])
			continue
		}
		select {
		case h.sessions <- struct{}{}:
			workers.Add(1)
			go func(r onion.ServiceRequest) {
				defer workers.Done()
				defer func() { <-h.sessions }()
				h.rendezvous(ctx, r)
			}(request)
		default:
			clear(request.Keys[:])
			diagnostics.Log(ctx, h.options.Logger, "service_capacity_rejected")
		}
	}
}
func (h *Host) rendezvous(parent context.Context, r onion.ServiceRequest) {
	defer clear(r.Keys[:])
	ctx, cancel := context.WithTimeout(parent, h.options.MaxLifetime)
	defer cancel()
	s, err := h.source.Snapshot()
	if err != nil {
		return
	}
	var rsa directory.Fingerprint
	var ed [32]byte
	for _, l := range r.Links {
		if l.Type == cell.LinkRSAIdentity {
			copy(rsa[:], l.Data)
		}
		if l.Type == cell.LinkEd25519Identity {
			copy(ed[:], l.Data)
		}
	}
	target, err := s.RelayByIdentity(rsa, ed)
	// This first milestone accepts only relay data matching the live consensus;
	// client-provided addresses never become direct connection destinations.
	if err != nil || target.NTor().OnionKey != r.OnionKey {
		diagnostics.Log(ctx, h.options.Logger, "service_rendezvous_rejected", "reason", "relay identity or onion key mismatch")
		return
	}
	expected := relayLinks(target)
	if len(expected) != len(r.Links) {
		diagnostics.Log(ctx, h.options.Logger, "service_rendezvous_rejected", "reason", "unsupported link count", "links", len(r.Links), "expected", len(expected))
		return
	}
	for j := range expected {
		if expected[j].Type != r.Links[j].Type || !equalBytes(expected[j].Data, r.Links[j].Data) {
			diagnostics.Log(ctx, h.options.Logger, "service_rendezvous_rejected", "reason", "unsupported link value or order", "link_type", r.Links[j].Type, "expected_type", expected[j].Type)
			return
		}
	}
	c, err := h.build(ctx, s, &target, circuit.OnionServiceRendezvous)
	if err != nil {
		diagnostics.Log(ctx, h.options.Logger, "service_rendezvous_failed", "error", err)
		return
	}
	defer c.Close()
	setup, stop := context.WithTimeout(ctx, h.options.BuildTimeout)
	err = c.JoinService(setup, r.Cookie, r.Reply, r.Keys, h.options.Port)
	stop()
	clear(r.Keys[:])
	if err != nil {
		return
	}
	diagnostics.Log(ctx, h.options.Logger, "service_rendezvous_ready")
	var streams sync.WaitGroup
	defer func() { cancel(); _ = c.Close(); streams.Wait() }()
	for {
		request, err := c.AcceptService(ctx)
		if err != nil {
			return
		}
		select {
		case h.streams <- struct{}{}:
			streams.Add(1)
			go func() { defer streams.Done(); defer func() { <-h.streams }(); h.forward(ctx, request) }()
		default:
			_ = request.Close()
		}
	}
}
func equalBytes(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for j := range a {
		if a[j] != b[j] {
			return false
		}
	}
	return true
}
func (h *Host) forward(ctx context.Context, request *circuit.IncomingStream) {
	defer request.Close()
	dialer := net.Dialer{Timeout: 10 * time.Second}
	local, err := dialer.DialContext(ctx, "tcp", h.options.Target)
	if err != nil {
		diagnostics.Log(ctx, h.options.Logger, "service_backend_failed", "error", err)
		return
	}
	defer local.Close()
	remote, err := request.Accept(ctx)
	if err != nil {
		return
	}
	defer remote.Close()
	diagnostics.Log(ctx, h.options.Logger, "service_stream_open")
	defer diagnostics.Log(ctx, h.options.Logger, "service_stream_closed")
	stop := context.AfterFunc(ctx, func() { _ = local.Close(); _ = remote.Close() })
	defer stop()
	var mu sync.Mutex
	touch := func() error {
		mu.Lock()
		defer mu.Unlock()
		deadline := time.Now().Add(h.options.IdleTimeout)
		return errors.Join(local.SetDeadline(deadline), remote.SetDeadline(deadline))
	}
	if touch() != nil {
		return
	}
	done := make(chan struct{}, 2)
	copyData := func(dst, src net.Conn) {
		defer func() { done <- struct{}{} }()
		_, _ = io.CopyBuffer(touchConn{dst, touch}, touchConn{src, touch}, make([]byte, 32768))
	}
	go copyData(local, remote)
	go copyData(remote, local)
	<-done
	_ = local.Close()
	_ = remote.Close()
	<-done
}

type touchConn struct {
	net.Conn
	touch func() error
}

func (c touchConn) Read(b []byte) (int, error) {
	n, err := c.Conn.Read(b)
	if n > 0 {
		err = errors.Join(err, c.touch())
	}
	return n, err
}
func (c touchConn) Write(b []byte) (int, error) {
	n, err := c.Conn.Write(b)
	if n > 0 {
		err = errors.Join(err, c.touch())
	}
	return n, err
}

// Shared cookie history prevents replay through another introduction circuit.
func (g *generation) remember(i *introduction, r onion.ServiceRequest) (bool, error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if i.clients[r.ClientKey] || g.cookies[r.Cookie] {
		return false, nil
	}
	if len(i.clients) >= 4096 || len(g.cookies) >= 12288 {
		return false, errRotate
	}
	i.clients[r.ClientKey] = true
	g.cookies[r.Cookie] = true
	return true, nil
}
func (g *generation) allowIntroduction(now time.Time) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.window.IsZero() || now.Sub(g.window) >= time.Second {
		g.window = now
		g.received = 0
	}
	if g.received >= 64 {
		return false
	}
	g.received++
	return true
}
