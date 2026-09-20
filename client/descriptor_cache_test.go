package client

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"
	"veil/cell"
	"veil/onion"
)

func TestDescriptorCacheExpiryRollbackAndIsolation(t *testing.T) {
	c := newDescriptorCache()
	now := time.Now()
	c.now = func() time.Time { return now }
	key := descriptorKey{scope: [32]byte{1}, blinded: [32]byte{2}}
	revision := uint64(10)
	digest := [32]byte{10}
	calls := 0
	fetch := func(context.Context) (*onion.Descriptor, [32]byte, error) {
		calls++
		return &onion.Descriptor{Revision: revision, Expires: now.Add(time.Minute), Introductions: []onion.Introduction{{Links: []cell.LinkSpec{{Type: 0, Data: []byte{1}}}}}}, digest, nil
	}
	end := now.Add(time.Hour)
	first, err := c.load(context.Background(), key, end, fetch)
	if err != nil {
		t.Fatal(err)
	}
	first.Introductions[0].Links[0].Data[0] = 9
	again, err := c.load(context.Background(), key, end, fetch)
	if err != nil || calls != 1 || again.Introductions[0].Links[0].Data[0] != 1 {
		t.Fatal("cache alias or refetch", err)
	}
	now = now.Add(2 * time.Minute)
	revision = 9
	if _, err = c.load(context.Background(), key, end, fetch); !errors.Is(err, errDescriptorRollback) {
		t.Fatal("rollback accepted", err)
	}
	revision = 10
	digest[0] = 11
	if _, err = c.load(context.Background(), key, end, fetch); !errors.Is(err, errDescriptorRollback) {
		t.Fatal("revision conflict accepted", err)
	}
	digest[0] = 10
	if _, err = c.load(context.Background(), key, end, fetch); !errors.Is(err, onion.ErrDescriptor) {
		t.Fatal("same revision extended lifetime", err)
	}
	revision = 11
	digest[0] = 11
	if _, err = c.load(context.Background(), key, end, fetch); err != nil {
		t.Fatal("new revision rejected", err)
	}
	revision = 1
	key.scope[0] = 3
	if _, err = c.load(context.Background(), key, end, fetch); err != nil {
		t.Fatal("scope histories mixed", err)
	}
	key.blinded[0] = 4
	if _, err = c.load(context.Background(), key, end, fetch); err != nil {
		t.Fatal("period histories mixed", err)
	}
	now = end
	if _, err = c.load(context.Background(), key, end, fetch); !errors.Is(err, onion.ErrDescriptor) {
		t.Fatal("expired period accepted", err)
	}
	if len(c.records) != 0 {
		t.Fatal("expired histories retained")
	}
}
func TestDescriptorCacheCoalescingCancellationAndBounds(t *testing.T) {
	c := newDescriptorCache()
	end := time.Now().Add(time.Hour)
	key := descriptorKey{scope: [32]byte{1}}
	gate := make(chan struct{})
	started := make(chan struct{}, 1)
	var calls atomic.Int32
	fetch := func(ctx context.Context) (*onion.Descriptor, [32]byte, error) {
		calls.Add(1)
		select {
		case started <- struct{}{}:
		default:
		}
		select {
		case <-ctx.Done():
			return nil, [32]byte{}, ctx.Err()
		case <-gate:
		}
		return &onion.Descriptor{Revision: 1, Expires: end}, [32]byte{}, nil
	}
	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := c.load(context.Background(), key, end, fetch); err != nil {
				t.Error(err)
			}
		}()
	}
	<-started
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	if _, err := c.load(ctx, key, end, fetch); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal(err)
	}
	cancel()
	close(gate)
	wg.Wait()
	if calls.Load() != 1 {
		t.Fatal("duplicate descriptor fetch", calls.Load())
	}
	for i := 1; i < maxDescriptors; i++ {
		key.scope[0] = byte(i + 1)
		if _, err := c.load(context.Background(), key, end, fetch); err != nil {
			t.Fatal(err)
		}
	}
	key.scope = [32]byte{0, 1}
	if _, err := c.load(context.Background(), key, end, fetch); !errors.Is(err, errDescriptorCacheFull) {
		t.Fatal("live history evicted", err)
	}
	c.close()
	if len(c.records) != 0 {
		t.Fatal("cache retained after Close")
	}
	if _, err := c.load(context.Background(), key, end, fetch); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
}
func TestDescriptorCacheRejectsUnverifiedFetchAndPeriodOverrun(t *testing.T) {
	c := newDescriptorCache()
	key := descriptorKey{}
	end := time.Now().Add(time.Minute)
	bad := func(context.Context) (*onion.Descriptor, [32]byte, error) {
		return nil, [32]byte{}, onion.ErrAuthentication
	}
	if _, err := c.load(context.Background(), key, end, bad); !errors.Is(err, onion.ErrAuthentication) || len(c.records) != 0 {
		t.Fatal(err)
	}
	good := func(context.Context) (*onion.Descriptor, [32]byte, error) {
		return &onion.Descriptor{Expires: end.Add(time.Hour)}, [32]byte{}, nil
	}
	d, err := c.load(context.Background(), key, end, good)
	if err != nil || !d.Expires.Equal(end) {
		t.Fatal("period expiry not enforced", err)
	}
}

func TestDescriptorCacheCloseDuringFetch(t *testing.T) {
	c := newDescriptorCache()
	gate := make(chan struct{})
	started := make(chan struct{})
	end := time.Now().Add(time.Hour)
	result := make(chan error, 1)
	go func() {
		_, err := c.load(context.Background(), descriptorKey{}, end, func(context.Context) (*onion.Descriptor, [32]byte, error) {
			close(started)
			<-gate
			return &onion.Descriptor{Expires: end}, [32]byte{}, nil
		})
		result <- err
	}()
	<-started
	c.close()
	close(gate)
	if err := <-result; !errors.Is(err, context.Canceled) {
		t.Fatal("fetch repopulated closed cache", err)
	}
	if len(c.records) != 0 {
		t.Fatal("closed cache repopulated")
	}
}
