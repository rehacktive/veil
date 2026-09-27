package directory

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"testing"
	"time"
)

func largeBootstrapFixture(t *testing.T, count int) (Documents, []Fingerprint, time.Time, map[string][]byte) {
	t.Helper()
	d, roots, now, sign := signedFixture(t)
	first := bytes.Index(d.Consensus, []byte("\nr ")) + 1
	footer := bytes.Index(d.Consensus, []byte("directory-footer\n"))
	end := bytes.Index(d.Consensus, []byte("directory-signature "))
	var relays, descriptors bytes.Buffer
	parts := make(map[string][]byte)
	for i := 0; i < count; i++ {
		key := sha256.Sum256([]byte(fmt.Sprint(i)))
		encoded := base64.RawStdEncoding.EncodeToString(key[:])
		part := []byte("onion-key\nntor-onion-key " + encoded + "\nid ed25519 " + encoded + "\np accept 80,443\n")
		digest := sha256.Sum256(part)
		name := base64.RawStdEncoding.EncodeToString(digest[:])
		parts[name] = part
		descriptors.Write(part)
		fmt.Fprintf(&relays, "r test%d %s 2000-01-01 00:00:00 127.0.0.1 9001 0\nm %s\ns Exit Fast Guard HSDir Running Stable V2Dir Valid\npr Cons=2 Desc=2 DirCache=2 HSDir=2 HSIntro=4 HSRend=2 Link=4-5 Microdesc=2 Relay=2\nw Bandwidth=100\n", i, base64.RawStdEncoding.EncodeToString(key[:20]), name)
	}
	body := append(append(append([]byte(nil), d.Consensus[:first]...), relays.Bytes()...), d.Consensus[footer:end]...)
	d.Consensus = sign(body)
	d.Microdescriptors = descriptors.Bytes()
	if _, err := Verify(d, roots, now); err != nil {
		t.Fatal(err)
	}
	return d, roots, now, parts
}

func requestedDescriptors(t *testing.T, path string, parts map[string][]byte) []byte {
	t.Helper()
	keys := strings.Split(strings.TrimPrefix(path, "/tor/micro/d/"), "-")
	if len(keys) > 64 {
		t.Fatal("per-request budget exceeded")
	}
	var result []byte
	for _, key := range keys {
		part, ok := parts[key]
		if !ok {
			t.Fatal("requested a digest outside current consensus", key)
		}
		result = append(result, part...)
	}
	return result
}

func TestManagerResumesVerifiedBatches(t *testing.T) {
	d, roots, now, parts := largeBootstrapFixture(t, 130)
	m, _ := testManager(t, d, roots, now)
	attempts, requests, delivered, bytesRead := 0, 0, 0, 0
	seen := make(map[string]bool)
	m.factory = func(context.Context, TorSource, *GuardAttempt) (Source, io.Closer) {
		attempts++
		inAttempt := 0
		return sourceFunc(func(ctx context.Context, path string, limit int) ([]byte, error) {
			requests++
			if !strings.HasPrefix(path, "/tor/micro/d/") {
				b, err := (&fixtureSource{d: d}).Fetch(ctx, path, limit)
				bytesRead += len(b)
				return b, err
			}
			inAttempt++
			if attempts == 1 && inAttempt == 2 {
				if _, err := m.Snapshot(); err == nil {
					t.Fatal("partial snapshot exposed")
				}
				return nil, io.ErrUnexpectedEOF
			}
			b := requestedDescriptors(t, path, parts)
			for _, key := range strings.Split(strings.TrimPrefix(path, "/tor/micro/d/"), "-") {
				if seen[key] {
					t.Fatal("verified batch downloaded again", key)
				}
				seen[key] = true
				delivered++
			}
			bytesRead += len(b)
			return b, nil
		}), closerFunc(func() error { return nil })
	}
	if _, err := m.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	if attempts != 2 || requests != 8 || delivered != 130 {
		t.Fatal(attempts, requests, delivered)
	}
	status := m.Status()
	if status.DownloadRequests != requests-1 || status.DownloadBytes != int64(bytesRead) || status.Microdescriptors != 130 || !status.Live {
		t.Fatal(status)
	}
	if _, err := m.cache.Load(now); err != nil {
		t.Fatal("complete cache invalid", err)
	}
	t.Log("130 descriptors delivered once across two attempts; the former restart redownloaded the first 64 (194 total)")
}

func TestBootstrapResumeRebindsToNewConsensus(t *testing.T) {
	d, roots, now, parts := largeBootstrapFixture(t, 130)
	requests := 0
	source := sourceFunc(func(ctx context.Context, path string, limit int) ([]byte, error) {
		if !strings.HasPrefix(path, "/tor/micro/d/") {
			return (&fixtureSource{d: d}).Fetch(ctx, path, limit)
		}
		requests++
		if requests == 2 {
			return nil, io.EOF
		}
		return requestedDescriptors(t, path, parts), nil
	})
	snapshot, partial, err := bootstrap(context.Background(), source, roots, now, Documents{})
	if !errors.Is(err, io.EOF) || snapshot != nil {
		t.Fatal(snapshot, err)
	}
	completed, err := splitMicrodescriptors(partial.Microdescriptors, MaxMicrodescriptorsSize)
	if err != nil || len(completed) != 64 {
		t.Fatal(len(completed), err)
	}
	// A different signed consensus must filter all irrelevant partial entries.
	other, otherRoots, otherTime := fixture(t)
	if _, docs, err := bootstrap(context.Background(), &fixtureSource{d: other}, otherRoots, otherTime, partial); err != nil || len(docs.Microdescriptors) != len(other.Microdescriptors) {
		t.Fatal(err)
	}
	forged := other
	forged.Consensus = bytes.Replace(other.Consensus, []byte("Bandwidth=208"), []byte("Bandwidth=209"), 1)
	f := &fixtureSource{d: forged}
	if _, _, err := bootstrap(context.Background(), f, otherRoots, otherTime, partial); !errors.Is(err, ErrTrust) || len(f.requests) != 2 {
		t.Fatal(err, f.requests)
	}
}

func TestBootstrapNeverRetainsInvalidBatch(t *testing.T) {
	d, roots, now, parts := largeBootstrapFixture(t, 130)
	for _, mode := range []string{"duplicate", "missing", "unrequested"} {
		t.Run(mode, func(t *testing.T) {
			requests := 0
			source := sourceFunc(func(ctx context.Context, path string, limit int) ([]byte, error) {
				if !strings.HasPrefix(path, "/tor/micro/d/") {
					return (&fixtureSource{d: d}).Fetch(ctx, path, limit)
				}
				requests++
				b := requestedDescriptors(t, path, parts)
				if requests != 2 {
					return b, nil
				}
				batch, err := splitMicrodescriptors(b, MaxMicrodescriptorBatch)
				if err != nil {
					t.Fatal(err)
				}
				switch mode {
				case "duplicate":
					b = append(b, batch[0]...)
				case "missing":
					b = bytes.Join(batch[1:], nil)
				case "unrequested":
					b = append(b, []byte("onion-key\nntor-onion-key invalid\n")...)
				}
				return b, nil
			})
			snapshot, partial, err := bootstrap(context.Background(), source, roots, now, Documents{})
			if snapshot != nil || !errors.Is(err, ErrTrust) {
				t.Fatal(err)
			}
			completed, err := splitMicrodescriptors(partial.Microdescriptors, MaxMicrodescriptorsSize)
			if err != nil || len(completed) != 64 {
				t.Fatal("invalid batch leaked into resume state", len(completed), err)
			}
		})
	}
}

func TestPartialBootstrapDoesNotPersistAcrossRefreshes(t *testing.T) {
	d, roots, now, parts := largeBootstrapFixture(t, 130)
	m, _ := testManager(t, d, roots, now)
	m.options.Attempts = 1
	firstBatches := 0
	m.factory = func(context.Context, TorSource, *GuardAttempt) (Source, io.Closer) {
		requests := 0
		return sourceFunc(func(ctx context.Context, path string, limit int) ([]byte, error) {
			if !strings.HasPrefix(path, "/tor/micro/d/") {
				return (&fixtureSource{d: d}).Fetch(ctx, path, limit)
			}
			requests++
			if requests == 2 {
				return nil, io.EOF
			}
			firstBatches++
			if len(strings.Split(strings.TrimPrefix(path, "/tor/micro/d/"), "-")) != 64 {
				t.Fatal("partial data escaped a refresh")
			}
			return requestedDescriptors(t, path, parts), nil
		}), closerFunc(func() error { return nil })
	}
	for i := 0; i < 2; i++ {
		if _, err := m.Refresh(context.Background()); !errors.Is(err, io.EOF) {
			t.Fatal(err)
		}
		if _, err := m.Snapshot(); err == nil {
			t.Fatal("partial directory exposed")
		}
		if _, err := m.cache.Load(now); !errors.Is(err, os.ErrNotExist) {
			t.Fatal("partial cache persisted", err)
		}
	}
	if firstBatches != 2 {
		t.Fatal(firstBatches)
	}
}
