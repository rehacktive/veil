package directory

import (
	"encoding/base64"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestServiceIdentityPersistsAndRejectsUnsafeState(t *testing.T) {
	path := t.TempDir()
	if err := os.Chmod(path, 0700); err != nil {
		t.Fatal(err)
	}
	lock, err := LockState(path)
	if err != nil {
		t.Fatal(err)
	}
	defer lock.Close()
	a, err := OpenServiceIdentity(path)
	if err != nil {
		t.Fatal(err)
	}
	name, _ := a.Address()
	seed, rev, err := a.ReserveDescriptor()
	if err != nil {
		t.Fatal(err)
	}
	b, err := OpenServiceIdentity(path)
	if err != nil {
		t.Fatal(err)
	}
	name2, _ := b.Address()
	seed2, rev2, err := b.ReserveDescriptor()
	if err != nil || name != name2 || seed != seed2 || rev2 != rev+1 {
		t.Fatal("identity or revision changed", err)
	}
	file := filepath.Join(path, "onion-identity")
	if err := os.Chmod(file, 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenServiceIdentity(path); err == nil {
		t.Fatal("public key file accepted")
	}
	if err := os.Remove(file); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenServiceIdentity(path); err == nil {
		t.Fatal("missing identity silently replaced despite existing hostname")
	}
	if err := os.Symlink(filepath.Join(path, "hostname"), file); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenServiceIdentity(path); err == nil {
		t.Fatal("symlink key accepted")
	}
}
func TestServicePeriodsOverlapClientRing(t *testing.T) {
	for _, hour := range []int{0, 11, 12, 23} {
		now := time.Date(2026, 9, 21, hour, 0, 0, 0, time.UTC)
		s := pathFixture()
		s.consensus.validAfter = now
		s.consensus.freshUntil = now.Add(time.Hour)
		s.consensus.validUntil = now.Add(3 * time.Hour)
		prev, cur := [32]byte{1}, [32]byte{2}
		s.consensus.sharedRandom = [2][]string{{"9", base64.StdEncoding.EncodeToString(prev[:])}, {"9", base64.StdEncoding.EncodeToString(cur[:])}}
		periods, err := s.ServicePeriods(now)
		if err != nil {
			t.Fatal(err)
		}
		p, m, srv, err := s.OnionPeriod(now)
		if err != nil {
			t.Fatal(err)
		}
		found := false
		for _, candidate := range periods {
			if candidate.Period == p && candidate.Minutes == m && candidate.SRV == srv {
				found = true
			}
		}
		if !found || len(periods) != 2 || periods[1].Period != periods[0].Period+1 || periods[0].SRV != prev || periods[1].SRV != cur {
			t.Fatal("incorrect overlap", hour, periods)
		}
	}
}
