package directory

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

// JSON base64 expansion of all bounded documents, plus framing overhead.
const maxCacheSize = (MaxConsensusSize+MaxCertificatesSize+MaxMicrodescriptorsSize)*4/3 + (1 << 20)

// Source fetches bounded, untrusted directory bytes. The native implementation
// is TorSource. Tests may inject a source without opening network connections.
type Source interface {
	Fetch(context.Context, string, int) ([]byte, error)
}

// Bootstrap authenticates a complete directory. Certificates and consensus are
// verified before requesting microdescriptors; all digest requests are sorted
// and batched independently of the paths that will later be selected.
func Bootstrap(ctx context.Context, source Source, roots []Fingerprint, now time.Time) (*Snapshot, Documents, error) {
	return bootstrap(ctx, source, roots, now, Documents{})
}

func bootstrap(ctx context.Context, source Source, roots []Fingerprint, now time.Time, previous Documents) (*Snapshot, Documents, error) {
	started := time.Now()
	var d Documents
	if _, err := newAuthoritySet(roots); err != nil {
		return nil, d, err
	}
	if source == nil {
		return nil, d, errors.New("directory source is required")
	}
	var err error
	if d.Certificates, err = source.Fetch(ctx, "/tor/keys/all", MaxCertificatesSize); err != nil {
		return nil, d, err
	}
	set, err := authorities(d.Certificates, roots, now)
	if err != nil {
		return nil, d, err
	}
	var pins []string
	for root := range set.roots {
		pins = append(pins, strings.ToUpper(root.String()))
	}
	sort.Strings(pins)
	if d.Consensus, err = source.Fetch(ctx, "/tor/status-vote/current/consensus-microdesc/"+strings.Join(pins, "+"), MaxConsensusSize); err != nil {
		return nil, d, err
	}
	c, err := verifyConsensus(d.Consensus, set, now)
	if err != nil {
		return nil, d, err
	}
	digests := map[string]bool{}
	for _, r := range c.relays {
		digests[base64.RawStdEncoding.EncodeToString(r.digest[:])] = true
	}
	known := map[string][]byte{}
	if len(previous.Microdescriptors) > 0 {
		parts, err := splitMicrodescriptors(previous.Microdescriptors, MaxMicrodescriptorsSize)
		if err != nil {
			return nil, d, err
		}
		for _, part := range parts {
			hash := sha256.Sum256(part)
			key := base64.RawStdEncoding.EncodeToString(hash[:])
			if digests[key] {
				known[key] = part
			}
		}
	}
	var sorted, missing []string
	for key := range digests {
		sorted = append(sorted, key)
		if known[key] == nil {
			missing = append(missing, key)
		}
	}
	sort.Strings(sorted)
	sort.Strings(missing)
	for start := 0; start < len(missing); start += 64 {
		end := min(start+64, len(missing))
		requested := map[string]bool{}
		for _, key := range missing[start:end] {
			requested[key] = true
		}
		b, err := source.Fetch(ctx, "/tor/micro/d/"+strings.Join(missing[start:end], "-"), MaxMicrodescriptorBatch)
		if err != nil {
			return nil, d, err
		}
		parts, err := splitMicrodescriptors(b, MaxMicrodescriptorBatch)
		if err != nil {
			return nil, d, err
		}
		for _, part := range parts {
			hash := sha256.Sum256(part)
			key := base64.RawStdEncoding.EncodeToString(hash[:])
			if !requested[key] || known[key] != nil {
				return nil, d, fmt.Errorf("%w: unrequested/duplicate microdescriptor", ErrTrust)
			}
			known[key] = part
		}
		for key := range requested {
			if known[key] == nil {
				return nil, d, fmt.Errorf("%w: missing requested microdescriptor", ErrTrust)
			}
		}
	}
	for _, key := range sorted {
		if len(d.Microdescriptors)+len(known[key]) > MaxMicrodescriptorsSize {
			return nil, d, fmt.Errorf("%w: combined microdescriptors exceed %d bytes", ErrDocument, MaxMicrodescriptorsSize)
		}
		d.Microdescriptors = append(d.Microdescriptors, known[key]...)
	}
	if err := ctx.Err(); err != nil {
		return nil, d, err
	}
	s, err := complete(c, d.Microdescriptors)
	if err != nil {
		return nil, d, err
	}
	if !s.Valid(now.Add(time.Since(started))) {
		return nil, d, ErrTime
	}
	return s, d, nil
}

// Cache serializes operations within this instance. Use one owner per cache
// directory; cross-process locking is not implemented. Manager handles refresh.
// Cached bytes never replace authority verification or validity checks.
type Cache struct {
	path  string
	roots []Fingerprint
	mu    sync.Mutex
}

func NewCache(path string, roots []Fingerprint) (*Cache, error) {
	if _, err := newAuthoritySet(roots); err != nil {
		return nil, err
	}
	if path == "" {
		return nil, errors.New("cache directory is required")
	}
	if err := privateDirectory(path); err != nil {
		return nil, err
	}
	return &Cache{path: path, roots: append([]Fingerprint(nil), roots...)}, nil
}
func (c *Cache) Load(now time.Time) (*Snapshot, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	d, err := c.read()
	if err != nil {
		return nil, err
	}
	return Verify(d, c.roots, now)
}
func (c *Cache) read() (Documents, error) {
	var d Documents
	b, err := readPrivate(filepath.Join(c.path, "directory.json"), maxCacheSize)
	if err != nil {
		return d, err
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&d); err != nil {
		return d, err
	}
	var extra any
	if err := dec.Decode(&extra); err != io.EOF {
		return d, fmt.Errorf("%w: trailing cache data", ErrDocument)
	}
	return d, nil
}

// Store re-verifies both incoming and existing cache documents. It rejects
// older or conflicting consensuses, including after the old one expires.
func (c *Cache) Store(d Documents, now time.Time) (*Snapshot, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	s, err := Verify(d, c.roots, now)
	if err != nil {
		return nil, err
	}
	old, err := c.read()
	if err == nil {
		items, e := lex(old.Consensus, MaxConsensusSize)
		if e != nil {
			return nil, e
		}
		var at time.Time
		for _, it := range items {
			if it.key == "valid-after" {
				at, e = date(it.args)
				if e != nil {
					return nil, e
				}
				break
			}
		}
		previous, e := Verify(old, c.roots, at)
		if e != nil {
			return nil, fmt.Errorf("cached directory cannot be authenticated: %w", e)
		}
		if s.consensus.validAfter.Before(previous.consensus.validAfter) || (s.consensus.validAfter.Equal(previous.consensus.validAfter) && s.consensus.digest != previous.consensus.digest) {
			return nil, fmt.Errorf("%w: consensus rollback or conflict", ErrTrust)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	b, err := json.Marshal(d)
	if err != nil {
		return nil, err
	}
	if len(b) > maxCacheSize {
		return nil, ErrDocument
	}
	if err := writePrivate(c.path, "directory.json", b); err != nil {
		return nil, err
	}
	return s, nil
}
func privateDirectory(path string) error {
	if err := os.MkdirAll(path, 0700); err != nil {
		return err
	}
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !info.IsDir() || info.Mode().Perm()&0077 != 0 {
		return errors.New("state directory must be a real directory accessible only to its owner (0700)")
	}
	return nil
}
func readPrivate(path string, limit int64) ([]byte, error) {
	if limit < 0 || limit > maxCacheSize {
		return nil, errors.New("invalid state file size limit")
	}
	root, err := os.OpenRoot(filepath.Dir(path))
	if err != nil {
		return nil, err
	}
	defer root.Close()
	name := filepath.Base(path)
	info, err := root.Lstat(name)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 || info.Size() > limit {
		return nil, errors.New("state file must be regular, private (0600), and within size limit")
	}
	// Root prevents a replacement symlink from escaping the state directory.
	f, err := root.Open(name)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	opened, err := f.Stat()
	if err != nil {
		return nil, err
	}
	// Validate the opened inode as well as the earlier directory entry: a file
	// replacement or permission change must not bypass the private-file policy.
	if !os.SameFile(info, opened) || !opened.Mode().IsRegular() || opened.Mode().Perm()&0077 != 0 || opened.Size() > limit {
		return nil, errors.New("state file changed or is not regular, private, and within size limit")
	}
	b, err := io.ReadAll(io.LimitReader(f, limit+1))
	if int64(len(b)) > limit {
		return nil, ErrDocument
	}
	return b, err
}
func writePrivate(dir, name string, b []byte) error {
	if name == "" || name == "." || name == ".." || filepath.Base(name) != name {
		return errors.New("state filename must be a single path component")
	}
	if err := privateDirectory(dir); err != nil {
		return err
	}
	f, err := os.CreateTemp(dir, ".pending-*")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	defer f.Close()
	if _, err := f.Write(b); err != nil {
		return err
	}
	if err := f.Sync(); err != nil {
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := os.Rename(f.Name(), filepath.Join(dir, name)); err != nil {
		return err
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		return err
	}
	defer root.Close()
	directory, err := root.Open(".")
	if err != nil {
		return err
	}
	defer directory.Close()
	return directory.Sync()
}

// restore authenticates even recently expired documents at their original
// valid-after timestamp. Only Manager uses these for directory guard recovery;
// Cache.Load and Manager.Snapshot never return expired data as usable.
func (c *Cache) restore(now time.Time) (*Snapshot, Documents, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	d, err := c.read()
	if err != nil {
		return nil, d, err
	}
	items, err := lex(d.Consensus, MaxConsensusSize)
	if err != nil {
		return nil, d, err
	}
	var at time.Time
	for _, it := range items {
		if it.key == "valid-after" {
			at, err = date(it.args)
			if err != nil {
				return nil, d, err
			}
			break
		}
	}
	s, err := Verify(d, c.roots, at)
	if err != nil {
		return nil, d, err
	}
	if now.Before(s.consensus.validAfter) || !now.Before(s.consensus.validUntil.Add(24*time.Hour)) {
		return nil, d, ErrTime
	}
	return s, d, nil
}
