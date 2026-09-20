package directory

import "errors"

// CircuitWindow returns the supported fixed circuit package window from the
// verified consensus. Deliver windows remain 1000. Veil requires authenticated
// SENDME v1 even when a consensus permits older unauthenticated SENDMEs.
func (s *Snapshot) CircuitWindow() (int, error) {
	if s == nil || s.consensus == nil {
		return 0, ErrTime
	}
	for _, key := range []string{"sendme_emit_min_version", "sendme_accept_min_version"} {
		if s.consensus.params[key] > 1 {
			return 0, errors.New("directory requires an unsupported SENDME version")
		}
	}
	w := int64(1000)
	if v, ok := s.consensus.params["circwindow"]; ok {
		w = max(100, min(1000, v))
	}
	// Non-integral SENDME increments cannot synchronize the legacy tag ledger
	// with peers whose deliver window starts at 1000. Fail before dialing.
	if w%100 != 0 {
		return 0, errors.New("unsupported circuit window: must be a multiple of 100")
	}
	return int(w), nil
}
