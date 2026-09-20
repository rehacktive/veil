package isolation

import (
	"context"
	"testing"
)

func TestIsolationScopes(t *testing.T) {
	base := context.Background()
	a, _ := Scope(WithToken(base, "a"))
	b, _ := Scope(WithToken(base, "b"))
	if a == b {
		t.Fatal("tokens collide")
	}
	if _, ok := Scope(WithToken(WithToken(base, "a"), "")); ok {
		t.Fatal("scope not cleared")
	}
	x, _ := Scope(WithSOCKS(base, []byte("ab"), []byte("c")))
	y, _ := Scope(WithSOCKS(base, []byte("a"), []byte("bc")))
	if x == y {
		t.Fatal("credential framing is ambiguous")
	}
	user, password := []byte("user"), []byte("password")
	ctx := WithSOCKS(base, user, password)
	before, _ := Scope(ctx)
	clear(user)
	clear(password)
	after, _ := Scope(ctx)
	if before != after {
		t.Fatal("retained raw token backing storage")
	}
	seen := map[[32]byte]bool{}
	for _, pair := range [][2]string{{"127.0.0.1", "127.0.0.1:9050"}, {"127.0.0.2", "127.0.0.1:9050"}, {"127.0.0.1", "127.0.0.1:9150"}} {
		id, _ := Scope(WithProxyBoundary(ctx, pair[0], pair[1]))
		if seen[id] {
			t.Fatal("proxy boundary lost")
		}
		seen[id] = true
	}
	if _, ok := Scope(WithProxyBoundary(base, "127.0.0.1", "127.0.0.1:9050")); ok {
		t.Fatal("untagged sharing enabled")
	}
}
