package directory

import (
	"os"
	"testing"
	"time"
)

func fixture(t *testing.T) (Documents, []Fingerprint, time.Time) {
	t.Helper()
	read := func(name string) []byte {
		b, err := os.ReadFile("testdata/" + name)
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	d := Documents{read("authorities.txt"), read("consensus.txt"), read("microdescriptors.txt")}
	var roots []Fingerprint
	for _, s := range []string{"0B8997614EC647C1C6B6A044E2B5408F0B823FB0", "5B591AD684C1AB8E0AB76C839E93FD097526A4BC", "8A1777F0BF97344A7ABB97530EEEE38A5BDE8A4D", "D190BF3B00E311A9AEB6D62B51980E9B2109BAD1"} {
		f, err := ParseFingerprint(s)
		if err != nil {
			t.Fatal(err)
		}
		roots = append(roots, f)
	}
	return d, roots, time.Date(2000, 1, 1, 0, 2, 30, 0, time.UTC)
}
func TestUpstreamDirectory(t *testing.T) {
	d, roots, now := fixture(t)
	s, err := Verify(d, roots, now)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("%+v", s.Info())
}
