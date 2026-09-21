package service

import (
	"context"
	"testing"
	"time"
	"veil/directory"
	"veil/onion"
)

func TestBackendAndResourceBoundaries(t *testing.T) {
	for _, target := range []string{"example.com:80", "192.0.2.1:80", "0.0.0.0:80", "127.0.0.1:0", "[::]:80", "[fe80::1%lo0]:80"} {
		if _, err := New(&directory.Manager{}, &directory.GuardStore{}, &directory.ServiceIdentity{}, Options{Target: target, Port: 80}); err == nil {
			t.Fatal("unsafe backend accepted", target)
		}
	}
	for _, target := range []string{"127.0.0.1:8080", "[::1]:8080"} {
		if _, err := New(&directory.Manager{}, &directory.GuardStore{}, &directory.ServiceIdentity{}, Options{Target: target, Port: 80}); err != nil {
			t.Fatal(err)
		}
	}
	for _, o := range []Options{{Target: "127.0.0.1:8080"}, {Target: "127.0.0.1:8080", Port: 80, MaxRendezvous: 65}, {Target: "127.0.0.1:8080", Port: 80, MaxStreams: 257}, {Target: "127.0.0.1:8080", Port: 80, MaxLifetime: -1}} {
		if _, err := New(&directory.Manager{}, &directory.GuardStore{}, &directory.ServiceIdentity{}, o); err == nil {
			t.Fatal("invalid limits accepted")
		}
	}
}
func TestReplayAndIntroductionFloodBounds(t *testing.T) {
	g := newGeneration(context.Background(), newIntroductionAdmission(), nil)
	defer g.close()
	i := &introduction{clients: make(map[[32]byte]bool)}
	other := &introduction{clients: make(map[[32]byte]bool)}
	r := onion.ServiceRequest{ClientKey: [32]byte{1}, Cookie: [20]byte{2}}
	if ok, err := g.remember(i, r); !ok || err != nil {
		t.Fatal(err)
	}
	if ok, _ := g.remember(other, r); ok {
		t.Fatal("cross-introduction replay accepted")
	}
	r.Cookie = [20]byte{3}
	if ok, _ := g.remember(i, r); ok {
		t.Fatal("reused client key accepted")
	}
	for j := 0; j < 4096; j++ {
		var key [32]byte
		key[0] = byte(j % 256)
		key[1] = byte(j / 256)
		i.clients[key] = true
	}
	r.ClientKey = [32]byte{1, 1, 1}
	if ok, err := g.remember(i, r); ok || err == nil {
		t.Fatal("replay capacity did not fail closed")
	}
	now := time.Now()
	for j := 0; j < 64; j++ {
		if !g.admission.allow(now) {
			t.Fatal(j)
		}
	}
	if g.admission.allow(now) {
		t.Fatal("introduction CPU budget not bounded")
	}
	if !g.admission.allow(now.Add(time.Second)) {
		t.Fatal("rate budget did not replenish")
	}
}
