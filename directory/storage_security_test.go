package directory

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func TestPrivateStateFileBoundaries(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "state.json")
	if err := writePrivate(dir, "state.json", []byte("private")); err != nil {
		t.Fatal(err)
	}
	b, err := readPrivate(path, 7)
	if err != nil || !bytes.Equal(b, []byte("private")) {
		t.Fatal(string(b), err)
	}
	for _, limit := range []int64{-1, 0, 6, maxCacheSize + 1} {
		if b, err := readPrivate(path, limit); err == nil || len(b) != 0 {
			t.Fatal("accepted invalid bound", limit, err)
		}
	}
	if err := os.Chmod(path, 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := readPrivate(path, 7); err == nil {
		t.Fatal("accepted public state file")
	}
	if err := os.Chmod(path, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := readPrivate(dir, 64); err == nil {
		t.Fatal("accepted directory as state file")
	}
	for _, target := range []string{"state.json", filepath.Join(t.TempDir(), "outside.json")} {
		if filepath.IsAbs(target) {
			if err := os.WriteFile(target, []byte("outside"), 0600); err != nil {
				t.Fatal(err)
			}
		}
		link := filepath.Join(dir, "link.json")
		if err := os.Symlink(target, link); err != nil {
			t.Fatal(err)
		}
		if b, err := readPrivate(link, 64); err == nil || len(b) != 0 {
			t.Fatal("followed state symlink", target, err)
		}
		if err := os.Remove(link); err != nil {
			t.Fatal(err)
		}
	}
	for _, name := range []string{"", ".", "..", "../escaped.json", "nested/file.json", filepath.Join(dir, "absolute.json")} {
		if err := writePrivate(dir, name, []byte("bad")); err == nil {
			t.Fatal("accepted invalid filename", name)
		}
	}
	// Atomic replacement must replace a symlink itself without touching its target.
	out := filepath.Join(t.TempDir(), "outside.json")
	if err := os.WriteFile(out, []byte("original"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(out, path); err != nil {
		t.Fatal(err)
	}
	if err := writePrivate(dir, "state.json", []byte("new")); err != nil {
		t.Fatal(err)
	}
	b, err = os.ReadFile(out)
	if err != nil || string(b) != "original" {
		t.Fatal("write escaped state directory", string(b), err)
	}
	b, err = readPrivate(path, 3)
	if err != nil || string(b) != "new" {
		t.Fatal(string(b), err)
	}
}

func TestDirectoryIntegerWidths(t *testing.T) {
	for _, s := range []string{"-2147483648", "2147483647", "0", "-0"} {
		if _, err := signedNumber(s, 32); err != nil {
			t.Fatal(s, err)
		}
	}
	for _, s := range []string{"-2147483649", "2147483648", "+1", "--1", "-", " 1"} {
		if _, err := signedNumber(s, 32); err == nil {
			t.Fatal("accepted invalid signed parameter", s)
		}
	}
	for _, s := range []string{"0", "65535"} {
		if _, err := number16(s); err != nil {
			t.Fatal(s, err)
		}
	}
	for _, s := range []string{"-1", "+1", "65536", "18446744073709551615", "", "1.0"} {
		if _, err := number16(s); err == nil {
			t.Fatal("accepted oversized/nondecimal uint16", s)
		}
	}
	p, err := parseProtocols([]string{"Test=0,65535"})
	if err != nil || !p.has("Test", 65535) || p.has("Test", 1) {
		t.Fatal(p, err)
	}
	if _, err := parseProtocols([]string{"Test=65536"}); err == nil {
		t.Fatal("accepted oversized protocol")
	}
	policy, err := parsePolicy([]string{"accept", "65535"})
	if err != nil || !policy.allows(65535) || policy.allows(1) {
		t.Fatal(policy, err)
	}
}
