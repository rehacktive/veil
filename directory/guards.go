package directory

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"
)

// GuardStore implements the default, unrestricted sampled/confirmed/primary
// guard context. Hold a StateLock for the shared cache/guard owner. Do not copy it.
// Circuit builders must use Select and report outcomes through GuardAttempt;
// Guard and SelectPath only preview a primary guard for offline path planning.
type GuardStore struct {
	path         string
	mu           sync.Mutex
	loaded       bool
	state        guardState
	runtime      map[Fingerprint]*guardRuntime
	primary      []Fingerprint
	next         uint64
	attempts     map[uint64]*GuardAttempt
	lastInternet time.Time
	params       guardParams
	poisoned     error
}
type guardRecord struct {
	RSA            Fingerprint
	Ed25519        [32]byte
	Added          time.Time
	AddedBy        string
	Listed         bool
	Unlisted       time.Time
	Confirmed      time.Time
	ConfirmedOrder uint64
}
type guardState struct {
	Version int
	// RSA and Ed25519 read Veil's version-1 single-guard state during migration.
	RSA             Fingerprint `json:",omitempty"`
	Ed25519         [32]byte    `json:",omitempty"`
	Sample          []guardRecord
	ConsensusTime   time.Time
	ConsensusDigest [32]byte
}
type reachability struct {
	no      bool
	retryAt time.Time
	delay   time.Duration
}
type guardRuntime struct {
	connection, directory reachability
	pending               uint64
	pendingSince          time.Time
}
type guardParams struct {
	lifetime, confirmed, unlisted, connectTimeout, idleTimeout, internetDown time.Duration
	minSample, maxSample, threshold, primary, dataUse, dirUse                int
}

func parameters(s *Snapshot) guardParams {
	value := func(key string, def, lo, hi int64) int64 {
		v, ok := s.consensus.params[key]
		if !ok {
			return def
		}
		return max(lo, min(hi, v))
	}
	days := func(key string, def int64) time.Duration {
		return time.Duration(value(key, def, 1, 3650)) * 24 * time.Hour
	}
	count := func(key string, def int64) int { return int(value(key, def, 1, 1024)) }
	seconds := func(key string, def int64) time.Duration {
		return time.Duration(value(key, def, 1, 2147483647)) * time.Second
	}
	return guardParams{days("guard-lifetime-days", 120), days("guard-confirmed-min-lifetime-days", 60), days("guard-remove-unlisted-guards-after-days", 20), seconds("guard-nonprimary-guard-connect-timeout", 15), seconds("guard-nonprimary-guard-idle-timeout", 600), seconds("guard-internet-likely-down-interval", 600), count("guard-min-filtered-sample-size", 20), count("guard-max-sample-size", 60), int(value("guard-max-sample-threshold", 20, 1, 100)), count("guard-n-primary-guards", 3), count("guard-n-primary-guards-to-use", 1), count("guard-n-primary-dir-guards-to-use", 3)}
}
func NewGuardStore(path string) (*GuardStore, error) {
	if path == "" {
		return nil, errors.New("guard directory required")
	}
	if err := privateDirectory(path); err != nil {
		return nil, err
	}
	return &GuardStore{path: path, runtime: map[Fingerprint]*guardRuntime{}, attempts: map[uint64]*GuardAttempt{}}, nil
}
func guardEligible(r Relay) bool {
	return eligible(r) && r.HasFlag("Guard") && r.HasFlag("Stable") && r.HasFlag("V2Dir")
}
func (g *GuardStore) load(now time.Time) error {
	if g.poisoned != nil {
		return g.poisoned
	}
	if g.loaded {
		return nil
	}
	b, err := readPrivate(filepath.Join(g.path, "guard.json"), 1<<20)
	if errors.Is(err, os.ErrNotExist) {
		g.state.Version = 2
		g.loaded = true
		return nil
	}
	if err != nil {
		return err
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	g.state = guardState{}
	if err := dec.Decode(&g.state); err != nil {
		return fmt.Errorf("%w: guard state: %v", ErrPath, err)
	}
	var extra any
	if dec.Decode(&extra) != io.EOF {
		return fmt.Errorf("%w: trailing guard state", ErrPath)
	}
	if g.state.Version == 1 {
		if g.state.RSA == (Fingerprint{}) || g.state.Ed25519 == ([32]byte{}) {
			return fmt.Errorf("%w: invalid legacy guard", ErrPath)
		}
		g.state = guardState{Version: 2, Sample: []guardRecord{{RSA: g.state.RSA, Ed25519: g.state.Ed25519, Added: now, AddedBy: "Veil legacy migration", Listed: true}}}
	}
	if g.state.Version != 2 || len(g.state.Sample) > 1024 {
		return fmt.Errorf("%w: guard state version/size", ErrPath)
	}
	seen := map[Fingerprint]bool{}
	order := map[uint64]bool{}
	for _, r := range g.state.Sample {
		if seen[r.RSA] || r.RSA == (Fingerprint{}) || r.Ed25519 == ([32]byte{}) || r.Added.IsZero() || (r.Confirmed.IsZero() != (r.ConfirmedOrder == 0)) || (!r.Confirmed.IsZero() && order[r.ConfirmedOrder]) || r.Listed != r.Unlisted.IsZero() {
			return fmt.Errorf("%w: inconsistent guard state", ErrPath)
		}
		seen[r.RSA] = true
		order[r.ConfirmedOrder] = true
	}
	g.loaded = true
	return nil
}
func (g *GuardStore) save() error {
	b, err := json.Marshal(g.state)
	if err == nil {
		err = writePrivate(g.path, "guard.json", b)
	}
	if err != nil {
		g.poisoned = fmt.Errorf("guard persistence failed; reopen store before use: %w", err)
	}
	return g.poisoned
}
func (g *GuardStore) rt(id Fingerprint) *guardRuntime {
	r := g.runtime[id]
	if r == nil {
		r = &guardRuntime{}
		g.runtime[id] = r
	}
	return r
}
func (g *GuardStore) isPrimary(id Fingerprint) bool {
	for _, p := range g.primary {
		if p == id {
			return true
		}
	}
	return false
}
func (g *GuardStore) record(id Fingerprint) *guardRecord {
	for i := range g.state.Sample {
		if g.state.Sample[i].RSA == id {
			return &g.state.Sample[i]
		}
	}
	return nil
}
func (g *GuardStore) order() []Fingerprint {
	var confirmed, other []guardRecord
	for _, r := range g.state.Sample {
		if !r.Listed {
			continue
		}
		if !r.Confirmed.IsZero() {
			confirmed = append(confirmed, r)
		} else {
			other = append(other, r)
		}
	}
	sort.SliceStable(confirmed, func(i, j int) bool { return confirmed[i].ConfirmedOrder < confirmed[j].ConfirmedOrder })
	var ids []Fingerprint
	for _, r := range confirmed {
		ids = append(ids, r.RSA)
	}
	for _, r := range other {
		ids = append(ids, r.RSA)
	}
	return ids
}
func (g *GuardStore) rebuildPrimary() {
	ordered := g.order()
	var ids []Fingerprint
	add := func(id Fingerprint) {
		r := g.record(id)
		if r == nil || !r.Listed {
			return
		}
		for _, old := range ids {
			if old == id {
				return
			}
		}
		if len(ids) < g.params.primary {
			ids = append(ids, id)
		}
	}
	for _, id := range ordered {
		if !g.record(id).Confirmed.IsZero() {
			add(id)
		}
	}
	for _, id := range g.primary {
		add(id)
	}
	for _, id := range ordered {
		add(id)
	}
	g.primary = ids
	for _, id := range ids {
		g.rt(id).pending = 0
	}
}
func (g *GuardStore) reachable(id Fingerprint, directory bool, now time.Time) bool {
	r := g.rt(id)
	if r.connection.no && !now.Before(r.connection.retryAt) {
		r.connection.no = false
	}
	if r.directory.no && !now.Before(r.directory.retryAt) {
		r.directory.no = false
	}
	return !r.connection.no && (!directory || !r.directory.no)
}

// update only expires or samples guards from a live, non-rollback consensus.
// A recently expired snapshot may locate existing guards for directory recovery
// but must never expand the sample or authorize an application path.
func (g *GuardStore) update(s *Snapshot, now time.Time, directory bool) (err error) {
	if s == nil || s.consensus == nil {
		return ErrTime
	}
	live := s.Valid(now)
	if !live && (!directory || now.Before(s.consensus.validAfter) || !now.Before(s.consensus.validUntil.Add(24*time.Hour))) {
		return ErrTime
	}
	if err := g.load(now); err != nil {
		return err
	}
	if s.consensus.validAfter.Before(g.state.ConsensusTime) || (s.consensus.validAfter.Equal(g.state.ConsensusTime) && g.state.ConsensusDigest != s.consensus.digest) {
		return fmt.Errorf("%w: guard consensus rollback/conflict", ErrTrust)
	}
	g.params = parameters(s)
	if !live {
		g.rebuildPrimary()
		return nil
	}
	before, _ := json.Marshal(g.state)
	defer func() {
		if err != nil {
			g.poisoned = err
		}
	}()
	candidates := map[Fingerprint]Relay{}
	var ordered []Relay
	for _, r := range s.relays {
		if guardEligible(r) {
			candidates[r.Identity()] = r
			ordered = append(ordered, r)
		}
	}
	kept := make([]guardRecord, 0, len(g.state.Sample))
	for _, r := range g.state.Sample {
		relay, ok := candidates[r.RSA]
		listed := ok && relay.descriptor.ed25519 == r.Ed25519
		if listed {
			r.Listed = true
			r.Unlisted = time.Time{}
		} else if r.Listed {
			r.Listed = false
			var err error
			r.Unlisted, err = randomizedDate(s.consensus.validAfter, g.params.unlisted/5)
			if err != nil {
				return err
			}
		}
		expired := !r.Unlisted.IsZero() && !now.Before(r.Unlisted.Add(g.params.unlisted))
		if !r.Confirmed.IsZero() {
			expired = expired || !now.Before(r.Confirmed.Add(g.params.confirmed))
		} else {
			expired = expired || !now.Before(r.Added.Add(g.params.lifetime))
		}
		if !expired {
			kept = append(kept, r)
		} else {
			for _, a := range g.attempts {
				if a.relay.Identity() == r.RSA {
					a.closeLocked()
				}
			}
			delete(g.runtime, r.RSA)
		}
	}
	g.state.Sample = kept
	// Sample caps are expressed as counts in the current guard specification.
	maximum := max(g.params.minSample, min(g.params.maxSample, len(ordered)*g.params.threshold/100))
	usable := 0
	for _, r := range g.state.Sample {
		if r.Listed && g.reachable(r.RSA, directory, now) {
			usable++
		}
		delete(candidates, r.RSA)
	}
	for usable < g.params.minSample && len(g.state.Sample) < maximum {
		remaining := make([]Relay, 0, len(candidates))
		for _, r := range ordered {
			if _, ok := candidates[r.Identity()]; ok {
				remaining = append(remaining, r)
			}
		}
		if len(remaining) == 0 {
			break
		}
		r, err := choose(s, remaining, "guard")
		if err != nil {
			if errors.Is(err, ErrPath) {
				break
			}
			return err
		}
		added, err := randomizedDate(now, g.params.lifetime/10)
		if err != nil {
			return err
		}
		g.state.Sample = append(g.state.Sample, guardRecord{RSA: r.Identity(), Ed25519: r.descriptor.ed25519, Added: added, AddedBy: "Veil 0.4", Listed: true})
		delete(candidates, r.Identity())
		usable++
	}
	g.state.ConsensusTime = s.consensus.validAfter
	g.state.ConsensusDigest = s.consensus.digest
	g.rebuildPrimary()
	after, _ := json.Marshal(g.state)
	if !bytes.Equal(before, after) {
		return g.save()
	}
	return nil
}

// Guard previews the first primary guard without recording a circuit attempt.
func (g *GuardStore) Guard(s *Snapshot, now time.Time) (Relay, error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if err := g.update(s, now, false); err != nil {
		return Relay{}, err
	}
	for _, id := range g.primary {
		if g.reachable(id, false, now) {
			for _, r := range s.relays {
				if r.Identity() == id && r.descriptor.ed25519 == g.record(id).Ed25519 && guardEligible(r) {
					return r, nil
				}
			}
		}
	}
	return Relay{}, ErrPath
}

// GuardAttempt owns a circuit's guard choice. Success reports an authenticated
// circuit, not merely a TCP/TLS connection. Call Usability before application
// traffic and Close when abandoning the attempt. All methods are concurrency-safe.
type GuardAttempt struct {
	store                       *GuardStore
	token                       uint64
	relay                       Relay
	directory                   bool
	excluded                    map[Fingerprint]bool
	primaryAtSelection          bool
	succeeded, complete, closed bool
	succeededAt                 time.Time
}
type GuardUsability uint8

const (
	GuardWaiting GuardUsability = iota
	GuardUsable
	GuardUnusable
)

var ErrGuardWaiting = errors.New("circuit is waiting for a preferred guard")

func (a *GuardAttempt) Relay() Relay { return a.relay }

// Select samples before applying circuit restrictions. Exclusions apply to RSA
// identities; callers must expand family/subnet restrictions when needed.
func (g *GuardStore) Select(s *Snapshot, directory bool, excluded []Fingerprint, now time.Time) (*GuardAttempt, error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if err := g.update(s, now, directory); err != nil {
		return nil, err
	}
	if len(g.attempts) >= 1024 {
		return nil, fmt.Errorf("%w: too many guard attempts", ErrPath)
	}
	blocked := map[Fingerprint]bool{}
	for _, id := range excluded {
		blocked[id] = true
	}
	relays := map[Fingerprint]Relay{}
	for _, r := range s.relays {
		record := g.record(r.Identity())
		if record != nil && record.Listed && r.descriptor.ed25519 == record.Ed25519 && guardEligible(r) {
			relays[r.Identity()] = r
		}
	}
	usable := func(id Fingerprint) bool {
		_, ok := relays[id]
		return ok && !blocked[id] && g.reachable(id, directory, now)
	}
	var pool []Fingerprint
	n := g.params.dataUse
	if directory {
		n = g.params.dirUse
	}
	reachable := 0
	for _, id := range g.primary {
		if _, ok := relays[id]; ok && g.reachable(id, directory, now) {
			reachable++
			if reachable <= n && !blocked[id] {
				pool = append(pool, id)
			}
		}
	}
	var id Fingerprint
	if len(pool) > 0 {
		index, err := randomDuration(time.Duration(len(pool)))
		if err != nil {
			return nil, err
		}
		id = pool[int(index)]
	} else {
		for _, p := range g.primary {
			if usable(p) {
				id = p
				break
			}
		}
	}
	primary := id != (Fingerprint{})
	if !primary {
		var pendingConfirmed Fingerprint
		for _, p := range g.order() {
			if g.record(p).Confirmed.IsZero() || !usable(p) {
				continue
			}
			if g.rt(p).pending == 0 {
				id = p
				break
			}
			if pendingConfirmed == (Fingerprint{}) {
				pendingConfirmed = p
			}
		}
		if id == (Fingerprint{}) {
			id = pendingConfirmed
		}
		if id == (Fingerprint{}) {
			for _, p := range g.order() {
				if usable(p) && g.rt(p).pending == 0 {
					id = p
					break
				}
			}
		}
	}
	if id == (Fingerprint{}) {
		// Exhaustion resets reachability within the existing bounded sample, never
		// discarding identities or treating a download failure as a reason to rotate.
		anyReachable := false
		for p := range relays {
			if g.reachable(p, directory, now) {
				anyReachable = true
			}
		}
		if !anyReachable {
			for p := range relays {
				rt := g.rt(p)
				rt.connection.no = false
				if directory {
					rt.directory.no = false
				}
			}
		}
		return nil, ErrPath
	}
	g.next++
	a := &GuardAttempt{store: g, token: g.next, relay: relays[id], directory: directory, excluded: blocked, primaryAtSelection: primary}
	g.attempts[a.token] = a
	if !primary {
		rt := g.rt(id)
		rt.pending = a.token
		rt.pendingSince = now
	}
	return a, nil
}
func (a *GuardAttempt) Success(now time.Time) error {
	g := a.store
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.poisoned != nil {
		return g.poisoned
	}
	if a.closed || a.succeeded {
		return errors.New("guard attempt already reported")
	}
	record := g.record(a.relay.Identity())
	if record == nil {
		return ErrPath
	}
	rt := g.rt(record.RSA)
	rt.connection = reachability{}
	if a.directory {
		rt.directory = reachability{}
	}
	if rt.pending == a.token {
		rt.pending = 0
	}
	wasOffline := g.lastInternet.IsZero() || now.Sub(g.lastInternet) > g.params.internetDown
	if !a.primaryAtSelection && wasOffline {
		for _, id := range g.primary {
			r := g.rt(id)
			r.connection.no = false
			if a.directory {
				r.directory.no = false
			}
		}
	}
	g.lastInternet = now
	if record.Confirmed.IsZero() {
		confirmed, err := randomizedDate(now, g.params.lifetime/10)
		if err != nil {
			return err
		}
		var last uint64
		for _, r := range g.state.Sample {
			last = max(last, r.ConfirmedOrder)
		}
		if last == ^uint64(0) {
			return errors.New("guard confirmation order exhausted")
		}
		record.Confirmed = confirmed
		record.ConfirmedOrder = last + 1
		if err := g.save(); err != nil {
			return err
		}
		g.rebuildPrimary()
	}
	a.succeeded = true
	a.succeededAt = now
	a.complete = a.primaryAtSelection
	return nil
}

// Failure marks either a connection failure, or a directory-only failure after
// successful circuit authentication. Cancellation should call Close instead.
func (a *GuardAttempt) Failure(now time.Time, directoryOnly bool) error {
	g := a.store
	g.mu.Lock()
	defer g.mu.Unlock()
	if a.closed {
		return errors.New("guard attempt is closed")
	}
	rt := g.rt(a.relay.Identity())
	reach := &rt.connection
	base, cap := 10*time.Minute, 36*time.Hour
	if g.isPrimary(a.relay.Identity()) {
		base, cap = 30*time.Second, 6*time.Hour
	}
	if directoryOnly {
		if !a.directory {
			return errors.New("directory failure on data attempt")
		}
		reach = &rt.directory
		base = max(base, time.Minute)
	}
	delay, err := retryDelay(reach.delay, base, cap)
	if err != nil {
		return err
	}
	*reach = reachability{no: true, retryAt: now.Add(delay), delay: delay}
	a.closeLocked()
	return nil
}
func (a *GuardAttempt) Usability(now time.Time) GuardUsability {
	g := a.store
	g.mu.Lock()
	defer g.mu.Unlock()
	if a.closed || g.poisoned != nil || g.record(a.relay.Identity()) == nil {
		return GuardUnusable
	}
	if !a.succeeded {
		return GuardWaiting
	}
	if a.complete {
		return GuardUsable
	}
	if g.isPrimary(a.relay.Identity()) {
		a.complete = true
		return GuardUsable
	}
	if now.Sub(a.succeededAt) >= g.params.idleTimeout {
		return GuardUnusable
	}
	for _, id := range g.order() {
		if id == a.relay.Identity() {
			break
		}
		if a.excluded[id] || !g.reachable(id, a.directory, now) {
			continue
		}
		rt := g.rt(id)
		if !g.isPrimary(id) && rt.pending != 0 && now.Sub(rt.pendingSince) >= g.params.connectTimeout {
			continue
		}
		return GuardWaiting
	}
	a.complete = true
	return GuardUsable
}
func (a *GuardAttempt) closeLocked() {
	if a.closed {
		return
	}
	a.closed = true
	rt := a.store.rt(a.relay.Identity())
	if rt.pending == a.token {
		rt.pending = 0
	}
	delete(a.store.attempts, a.token)
}
func (a *GuardAttempt) Close() { g := a.store; g.mu.Lock(); defer g.mu.Unlock(); a.closeLocked() }
