package service

import (
	"context"
	"errors"
	"sync"
	"time"
)

// PublicationStatus describes one period in the latest publication round.
// Uploaded counts acknowledged uploads, not independently verified reachability.
type PublicationStatus struct {
	Period    uint64    `json:"period"`
	Uploaded  int       `json:"uploaded"`
	Attempted int       `json:"attempted"`
	Total     int       `json:"total"`
	Expires   time.Time `json:"expires"`
}

// Status is a snapshot of local hosting activity. Ready means all selected
// HSDirs acknowledged the latest round and its three introduction points remain
// active. Partial publication may already allow clients to connect. Neither
// state guarantees end-to-end reachability. Retained generations can keep older
// descriptors usable while the current generation is recovering or publishing.
type Status struct {
	Phase                 string              `json:"phase"`
	Running               bool                `json:"running"`
	Ready                 bool                `json:"ready"`
	IntroductionPoints    int                 `json:"introduction_points"`
	RetainedIntroductions int                 `json:"retained_introductions"`
	Publications          []PublicationStatus `json:"publications,omitempty"`
	NextAttempt           time.Time           `json:"next_attempt"`
	LastError             string              `json:"last_error,omitempty"`
}

type hostStatus struct {
	mu       sync.RWMutex
	value    Status
	current  *generation
	retained []*generation
}

// Status returns an independent, concurrency-safe snapshot. LastError can
// contain transport diagnostics; no keys or descriptor contents are included.
func (h *Host) Status() Status {
	h.status.mu.RLock()
	defer h.status.mu.RUnlock()
	s := h.status.value
	s.Publications = append([]PublicationStatus(nil), s.Publications...)
	if s.Phase == "" {
		s.Phase = "starting"
	}
	if g := h.status.current; g != nil && g.ctx.Err() == nil {
		s.IntroductionPoints = int(g.alive.Load())
	}
	for _, g := range h.status.retained {
		if g.ctx.Err() == nil {
			s.RetainedIntroductions += int(g.alive.Load())
		}
	}
	s.Ready = s.Running && s.Phase == "ready" && s.IntroductionPoints == 3 && len(s.Publications) == 2
	for _, p := range s.Publications {
		if p.Uploaded != p.Total || p.Total == 0 || !time.Now().Before(p.Expires) {
			s.Ready = false
		}
	}
	if s.Phase == "ready" && !s.Ready {
		s.Phase = "degraded"
	}
	return s
}

func (h *Host) updateStatus(update func(*Status)) {
	h.status.mu.Lock()
	defer h.status.mu.Unlock()
	update(&h.status.value)
}

func (h *Host) generationStatus(current *generation, retained []*generation) {
	h.status.mu.Lock()
	defer h.status.mu.Unlock()
	h.status.current = current
	h.status.retained = append([]*generation(nil), retained...)
}

func (h *Host) stopStatus(err error) {
	h.generationStatus(nil, nil)
	h.updateStatus(func(s *Status) {
		s.Running = false
		s.Phase = "stopped"
		s.NextAttempt = time.Time{}
		if err != nil && !errors.Is(err, context.Canceled) {
			s.Phase = "failed"
			s.LastError = err.Error()
		}
	})
}

func (h *Host) publicationResult(err error, next time.Time) {
	h.updateStatus(func(s *Status) {
		s.NextAttempt = next
		s.LastError = ""
		s.Phase = "ready"
		if err != nil {
			s.LastError = err.Error()
			s.Phase = "retrying"
			for _, p := range s.Publications {
				if p.Uploaded > 0 {
					s.Phase = "partial"
				}
			}
		}
	})
}

// Status returns the host status. A closed listener reports draining while
// accepted streams finish, and never reports readiness for new streams.
func (l *Listener) Status() Status {
	s := l.host.Status()
	select {
	case <-l.closed:
		s.Ready = false
		if s.Running {
			s.Phase = "draining"
		}
	default:
	}
	return s
}
