package directory

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"math"
	"os"
	"path/filepath"
	"sync"

	"veil/onion"
)

// ServiceIdentity is owned under the same exclusive StateLock as guards/cache.
// A revision reservation is durably written before descriptor publication.
type ServiceIdentity struct {
	mu       sync.Mutex
	path     string
	seed     [32]byte
	revision uint64
}

func OpenServiceIdentity(path string) (*ServiceIdentity, error) {
	b, err := readPrivate(filepath.Join(path, "onion-identity"), 40)
	s := &ServiceIdentity{path: path}
	if errors.Is(err, os.ErrNotExist) {
		if _, e := readPrivate(filepath.Join(path, "hostname"), 256); e == nil {
			return nil, errors.New("onion identity missing but hostname exists; restore the identity instead of replacing this address")
		} else if !errors.Is(e, os.ErrNotExist) {
			return nil, e
		}
		if _, err := rand.Read(s.seed[:]); err != nil {
			return nil, err
		}
		var counter [8]byte
		if _, err := rand.Read(counter[:]); err != nil {
			return nil, err
		}
		s.revision = binary.BigEndian.Uint64(counter[:]) >> 16
		if err := s.save(); err != nil {
			return nil, err
		}
	} else {
		if err != nil {
			return nil, err
		}
		defer clear(b)
		if len(b) != 40 {
			return nil, errors.New("invalid onion identity state; refusing to replace it")
		}
		copy(s.seed[:], b[:32])
		s.revision = binary.BigEndian.Uint64(b[32:])
	}
	address, err := s.Address()
	if err != nil {
		return nil, err
	}
	if err := writePrivate(path, "hostname", []byte(address+"\n")); err != nil {
		return nil, err
	}
	return s, nil
}
func (s *ServiceIdentity) Public() [32]byte {
	s.mu.Lock()
	defer s.mu.Unlock()
	key := ed25519.NewKeyFromSeed(s.seed[:])
	defer clear(key)
	var public [32]byte
	copy(public[:], key[32:])
	return public
}
func (s *ServiceIdentity) Address() (string, error) { return onion.Address(s.Public()) }
func (s *ServiceIdentity) ReserveDescriptor() (seed [32]byte, revision uint64, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.revision == math.MaxUint64 {
		return seed, 0, errors.New("onion revision counter exhausted")
	}
	s.revision++
	if err = s.save(); err != nil {
		return seed, 0, err
	}
	return s.seed, s.revision, nil
}
func (s *ServiceIdentity) save() error {
	b := binary.BigEndian.AppendUint64(append([]byte{}, s.seed[:]...), s.revision)
	defer clear(b)
	return writePrivate(s.path, "onion-identity", b)
}
