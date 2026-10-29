package directory

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestMainnetBootstrap(t *testing.T) {
	if os.Getenv("VEIL_TOR_INTEGRATION") != "1" {
		t.Skip("set VEIL_TOR_INTEGRATION=1 to bootstrap against the public Tor network")
	}
	roots, sources, err := Mainnet()
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "veil")
	lock, err := LockState(path)
	if err != nil {
		t.Fatal(err)
	}
	defer lock.Close()
	cache, err := NewCache(path, roots)
	if err != nil {
		t.Fatal(err)
	}
	guards, err := NewGuardStore(path)
	if err != nil {
		t.Fatal(err)
	}
	manager, err := NewManager(cache, guards, sources, ManagerOptions{
		Attempts: 8, AttemptTimeout: 8 * time.Minute, RetryCap: 30 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	snapshot, err := manager.Refresh(ctx)
	if err != nil {
		t.Fatalf("public bootstrap: %v; status: %+v", err, manager.Status())
	}
	if !snapshot.Valid(time.Now()) || !manager.BootstrapProgress().Ready {
		t.Fatal("bootstrap completed without a live verified directory")
	}
	for _, line := range bytes.Split(manager.docs.Consensus, []byte("\n")) {
		if bytes.HasPrefix(line, []byte("required-client-protocols ")) {
			t.Logf("%s", line)
		}
	}
	t.Logf("public Tor directory verified: %+v", snapshot.Info())
}
