package circuit

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"testing"
	"time"

	"veil/channel"
	"veil/directory"
)

func verifiedNetwork(t *testing.T, n *testNetwork) *directory.Snapshot {
	t.Helper()
	id, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal(err)
	}
	signing, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal(err)
	}
	idDER := x509.MarshalPKCS1PublicKey(&id.PublicKey)
	signDER := x509.MarshalPKCS1PublicKey(&signing.PublicKey)
	fp := directory.Fingerprint(sha1.Sum(idDER))
	signer := directory.Fingerprint(sha1.Sum(signDER))
	pemBytes := func(label string, b []byte) []byte { return pem.EncodeToMemory(&pem.Block{Type: label, Bytes: b}) }
	sign := func(k *rsa.PrivateKey, b []byte) []byte {
		s, err := rsa.SignPKCS1v15(rand.Reader, k, crypto.Hash(0), b)
		if err != nil {
			t.Fatal(err)
		}
		return s
	}
	now := time.Now().UTC()
	date := func(d time.Duration) string { return now.Add(d).Format("2006-01-02 15:04:05") }
	cert := []byte(fmt.Sprintf("dir-key-certificate-version 3\nfingerprint %s\ndir-key-published %s\ndir-key-expires %s\ndir-identity-key\n%sdir-signing-key\n%sdir-key-crosscert\n%sdir-key-certification\n", fp, date(-time.Hour), date(time.Hour), pemBytes("RSA PUBLIC KEY", idDER), pemBytes("RSA PUBLIC KEY", signDER), pemBytes("ID SIGNATURE", sign(signing, fp[:]))))
	certDigest := sha1.Sum(cert)
	cert = append(cert, pemBytes("SIGNATURE", sign(id, certDigest[:]))...)
	consensus := fmt.Sprintf("network-status-version 3 microdesc\nvote-status consensus\nconsensus-method 35\nvalid-after %s\nfresh-until %s\nvalid-until %s\nvoting-delay 4 4\nknown-flags Exit Fast Guard Running Stable V2Dir Valid\nrequired-client-protocols Link=4 Relay=2\ndir-source local %s localhost 127.0.0.1 7000 9000\n", date(-time.Minute), date(time.Hour/2), date(time.Hour), fp)
	var descriptors []byte
	b64 := base64.RawStdEncoding.EncodeToString
	for i, h := range n.hops {
		policy := "reject 1-65535"
		flags := "Fast Running Stable V2Dir Valid"
		if i == 0 {
			flags = "Guard " + flags
		}
		if i == 2 {
			flags = "Exit " + flags
			policy = "accept 443"
		}
		md := []byte(fmt.Sprintf("onion-key\nntor-onion-key %s\nid ed25519 %s\np %s\n", b64(h.ntor.OnionKey[:]), b64(h.target.Identity.Ed25519[:]), policy))
		digest := sha256.Sum256(md)
		descriptors = append(descriptors, md...)
		consensus += fmt.Sprintf("r relay%d %s %s %s %d 0\nm %s\ns %s\npr Link=4-5 Relay=2\nw Bandwidth=100\n", i, b64(h.ntor.Identity[:]), date(-time.Minute), h.target.Address.Addr(), h.target.Address.Port(), b64(digest[:]), flags)
	}
	consensus += "directory-footer\nbandwidth-weights Wgg=10000 Wgd=10000 Wed=10000 Wee=10000 Wmm=10000 Wmd=10000 Wmg=10000 Wme=10000\n"
	digest := sha256.Sum256([]byte(consensus + "directory-signature "))
	consensus += fmt.Sprintf("directory-signature sha256 %s %s\n%s", fp, signer, pemBytes("SIGNATURE", sign(signing, digest[:])))
	s, err := directory.Verify(directory.Documents{Certificates: cert, Consensus: []byte(consensus), Microdescriptors: descriptors}, []directory.Fingerprint{fp}, now)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestVerifiedSelectionAndPersistentAttempt(t *testing.T) {
	n := network(t)
	s := verifiedNetwork(t, n)
	state := t.TempDir()
	if err := os.Chmod(state, 0700); err != nil {
		t.Fatal(err)
	}
	g, err := directory.NewGuardStore(state)
	if err != nil {
		t.Fatal(err)
	}
	c, err := buildSelected(context.Background(), s, g, Options{Port: 443}, n.dial)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	p := c.Path()
	if p.Guard.NTor() != n.hops[0].ntor || p.Middle.NTor() != n.hops[1].ntor || p.Exit.NTor() != n.hops[2].ntor {
		t.Fatal("selected incorrect verified path")
	}
	raw, err := os.ReadFile(state + "/guard.json")
	if err != nil {
		t.Fatal(err)
	}
	var persisted struct {
		Sample []struct{ ConfirmedOrder uint64 }
	}
	if err := json.Unmarshal(raw, &persisted); err != nil {
		t.Fatal(err)
	}
	if len(persisted.Sample) != 1 || persisted.Sample[0].ConfirmedOrder == 0 {
		t.Fatal("full circuit did not confirm tracked guard")
	}
	// No compatible exit must fail before dialing, without consuming attempts.
	for i := 0; i < 1030; i++ {
		_, err := buildSelected(context.Background(), s, g, Options{Port: 80}, func(context.Context, channel.Target, channel.Options) (transport, error) {
			t.Fatal("dialed without compatible exit")
			return nil, nil
		})
		if !errors.Is(err, directory.ErrPath) {
			t.Fatal(err)
		}
	}
	a, err := g.Select(s, false, nil, time.Now())
	if err != nil {
		t.Fatal("leaked guard attempts", err)
	}
	a.Close()
}

func TestPublicBuildInvalidInputs(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := Build(ctx, nil, nil, Options{}); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	state := t.TempDir()
	os.Chmod(state, 0700)
	g, err := directory.NewGuardStore(state)
	if err != nil {
		t.Fatal(err)
	}
	for _, o := range []Options{{}, {Port: 443, BuildTimeout: -1}, {Port: 443}} {
		if _, err := Build(context.Background(), nil, g, o); err == nil {
			t.Fatal("accepted missing snapshot/options")
		}
	}
	if _, err := Build(context.Background(), nil, nil, Options{Port: 443}); err == nil {
		t.Fatal("accepted missing guard store")
	}
}
