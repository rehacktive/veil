package client

import (
	"context"
	"errors"
	"sync"
	"time"
	"veil/cell"
	"veil/onion"
)

var errDescriptorRollback = errors.New("onion descriptor revision rollback or conflict")
var errDescriptorCacheFull = errors.New("onion descriptor revision cache is full for this period")

const maxDescriptors = 128

type descriptorKey struct{ scope, blinded [32]byte }
type descriptorRecord struct {
	descriptor         *onion.Descriptor
	revision           uint64
	digest             [32]byte
	verified           bool
	expires, periodEnd time.Time
	loading            chan struct{}
}
type descriptorCache struct {
	mu      sync.Mutex
	records map[descriptorKey]*descriptorRecord
	now     func() time.Time
	closed  bool
}

func newDescriptorCache() *descriptorCache {
	return &descriptorCache{records: make(map[descriptorKey]*descriptorRecord), now: time.Now}
}
func (c *descriptorCache) close() { c.mu.Lock(); c.closed = true; clear(c.records); c.mu.Unlock() }
func cloneDescriptor(d *onion.Descriptor) *onion.Descriptor {
	out := *d
	out.Introductions = append([]onion.Introduction(nil), d.Introductions...)
	for i := range out.Introductions {
		out.Introductions[i].Links = append([]cell.LinkSpec(nil), d.Introductions[i].Links...)
		for j := range out.Introductions[i].Links {
			out.Introductions[i].Links[j].Data = append([]byte(nil), d.Introductions[i].Links[j].Data...)
		}
	}
	return &out
}

// Keep the revision floor through the blinded-key period, even after plaintext
// expires. Never evict a live floor to make room: memory exhaustion fails closed.
// Concurrent requests for the same scope/key share one descriptor fetch.
func (c *descriptorCache) load(ctx context.Context, key descriptorKey, periodEnd time.Time, fetch func(context.Context) (*onion.Descriptor, [32]byte, error)) (*onion.Descriptor, error) {
	for {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		c.mu.Lock()
		if c.closed {
			c.mu.Unlock()
			return nil, context.Canceled
		}
		now := c.now()
		for k, r := range c.records {
			if r.loading == nil && !now.Before(r.periodEnd) {
				delete(c.records, k)
			} else if !now.Before(r.expires) {
				r.descriptor = nil
			}
		}
		if !now.Before(periodEnd) {
			c.mu.Unlock()
			return nil, onion.ErrDescriptor
		}
		r := c.records[key]
		if r == nil {
			if len(c.records) >= maxDescriptors {
				c.mu.Unlock()
				return nil, errDescriptorCacheFull
			}
			r = &descriptorRecord{periodEnd: periodEnd}
			c.records[key] = r
		}
		if r.descriptor != nil {
			d := cloneDescriptor(r.descriptor)
			c.mu.Unlock()
			return d, nil
		}
		if r.loading != nil {
			wait := r.loading
			c.mu.Unlock()
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-wait:
			}
			continue
		}
		r.loading = make(chan struct{})
		c.mu.Unlock()
		d, digest, err := fetch(ctx)
		c.mu.Lock()
		close(r.loading)
		r.loading = nil
		if err == nil && (ctx.Err() != nil || c.closed) {
			err = context.Canceled
			if ctx.Err() != nil {
				err = ctx.Err()
			}
		}
		if err == nil {
			if d == nil || !c.now().Before(d.Expires) || !c.now().Before(r.periodEnd) {
				err = onion.ErrDescriptor
			} else if r.verified && (d.Revision < r.revision || d.Revision == r.revision && digest != r.digest) {
				err = errDescriptorRollback
			} else {
				copy := cloneDescriptor(d)
				if copy.Expires.After(r.periodEnd) {
					copy.Expires = r.periodEnd
				}
				if r.verified && copy.Revision == r.revision && copy.Expires.After(r.expires) {
					copy.Expires = r.expires
				}
				if !c.now().Before(copy.Expires) {
					err = onion.ErrDescriptor
				} else {
					r.descriptor = copy
					r.expires = copy.Expires
					r.revision = copy.Revision
					r.digest = digest
					r.verified = true
				}
			}
		}
		if err != nil {
			if !r.verified {
				delete(c.records, key)
			}
			c.mu.Unlock()
			return nil, err
		}
		out := cloneDescriptor(r.descriptor)
		c.mu.Unlock()
		return out, nil
	}
}
