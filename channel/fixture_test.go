package channel

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"fmt"
	"math/big"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	"veil/cell"
	"veil/torcert"
)

type relayFixture struct {
	tlsCert tls.Certificate
	certs   []cell.Certificate
	target  Target
}

var fixtureOnce sync.Once
var fixtureValue relayFixture
var fixtureError error

func fixture(t *testing.T) relayFixture {
	t.Helper()
	fixtureOnce.Do(func() { fixtureValue, fixtureError = makeFixture() })
	if fixtureError != nil {
		t.Fatal(fixtureError)
	}
	return fixtureValue // Callers must not mutate shared certificate byte slices.
}

func makeFixture() (relayFixture, error) {
	var f relayFixture
	now := time.Now()
	rsaKey, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		return f, err
	}
	root := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test RSA identity"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(48 * time.Hour), SignatureAlgorithm: x509.SHA256WithRSA}
	rootDER, err := x509.CreateCertificate(rand.Reader, root, root, &rsaKey.PublicKey, rsaKey)
	if err != nil {
		return f, err
	}
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return f, err
	}
	leaf := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "test Tor TLS leaf"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(48 * time.Hour), KeyUsage: x509.KeyUsageDigitalSignature}
	leafDER, err := x509.CreateCertificate(rand.Reader, leaf, leaf, &leafKey.PublicKey, leafKey)
	if err != nil {
		return f, err
	}
	idPublic, idPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return f, err
	}
	signPublic, signPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return f, err
	}
	expHours := uint32(now.Add(24*time.Hour).Unix() / 3600)
	edCert := func(kind, keyType byte, subject []byte, signer ed25519.PrivateKey, includeSigner bool) []byte {
		b := make([]byte, 40)
		b[0], b[1], b[6] = 1, kind, keyType
		binary.BigEndian.PutUint32(b[2:6], expHours)
		copy(b[7:39], subject)
		if includeSigner {
			b[39] = 1
			b = append(b, 0, 32, 4, 0)
			b = append(b, signer.Public().(ed25519.PublicKey)...)
		}
		return append(b, ed25519.Sign(signer, b)...)
	}
	signing := edCert(4, 1, signPublic, idPrivate, true)
	digest := sha256.Sum256(leafDER)
	link := edCert(5, 3, digest[:], signPrivate, false)
	cross := make([]byte, 36)
	copy(cross, idPublic)
	binary.BigEndian.PutUint32(cross[32:36], expHours)
	h := sha256.New()
	h.Write([]byte("Tor TLS RSA/Ed25519 cross-certificate"))
	h.Write(cross)
	signature, err := rsa.SignPKCS1v15(rand.Reader, rsaKey, crypto.Hash(0), h.Sum(nil))
	if err != nil {
		return f, err
	}
	cross = append(cross, byte(len(signature)))
	cross = append(cross, signature...)
	f.tlsCert = tls.Certificate{Certificate: [][]byte{leafDER}, PrivateKey: leafKey}
	f.certs = []cell.Certificate{{Type: 2, Body: rootDER}, {Type: 4, Body: signing}, {Type: 5, Body: link}, {Type: 7, Body: cross}}
	f.target.Address = netip.MustParseAddrPort("127.0.0.1:9001")
	f.target.Identity.RSA = sha1.Sum(x509.MarshalPKCS1PublicKey(&rsaKey.PublicKey))
	copy(f.target.Identity.Ed25519[:], idPublic)
	if _, err := torcert.Verify(f.certs, leafDER, f.target.Identity, now); err != nil {
		return f, err
	}
	return f, nil
}

func (f relayFixture) frames(t *testing.T) []cell.Cell {
	t.Helper()
	certs, err := cell.EncodeCerts(f.certs)
	if err != nil {
		t.Fatal(err)
	}
	challenge, err := cell.EncodeAuthChallenge(cell.AuthChallengeMessage{Challenge: [32]byte{42}, Methods: []uint16{3}})
	if err != nil {
		t.Fatal(err)
	}
	netinfo, err := cell.EncodeNetInfo(cell.NetInfoMessage{Timestamp: uint32(time.Now().Unix()), OtherAddress: netip.MustParseAddr("192.0.2.1"), MyAddresses: []netip.Addr{f.target.Address.Addr()}})
	if err != nil {
		t.Fatal(err)
	}
	return []cell.Cell{{Command: cell.Certs, Payload: certs}, {Command: cell.AuthChallenge, Payload: challenge}, {Command: cell.NetInfo, Payload: netinfo}}
}

// serveHandshake is a local relay fixture, not C Tor. Certificate encoding and
// verification are also covered by independent checked-in Arti fixtures.
func serveHandshake(raw net.Conn, f relayFixture, frames []cell.Cell, versions []uint16, maxTLS uint16, configure ...func(*tls.Config)) (*tls.Conn, *cell.Codec, error) {
	config := &tls.Config{Certificates: []tls.Certificate{f.tlsCert}, MinVersion: tls.VersionTLS12, MaxVersion: maxTLS}
	for _, edit := range configure {
		edit(config)
	}
	conn := tls.Server(raw, config)
	if err := conn.Handshake(); err != nil {
		return nil, nil, err
	}
	peer, err := cell.ReadVersions(conn)
	if err != nil {
		return nil, nil, err
	}
	if err := cell.WriteVersions(conn, versions); err != nil {
		return nil, nil, err
	}
	version, err := cell.NegotiateVersion(peer, versions)
	if err != nil {
		return nil, nil, err
	}
	codec, err := cell.NewCodec(version)
	if err != nil {
		return nil, nil, err
	}
	for _, frame := range frames {
		if err := codec.Write(conn, frame); err != nil {
			return nil, nil, err
		}
	}
	frame, err := codec.Read(conn)
	if err != nil {
		return nil, nil, err
	}
	if frame.Command != cell.NetInfo {
		return nil, nil, fmt.Errorf("client sent %s instead of NETINFO", frame.Command)
	}
	netinfo, err := cell.DecodeNetInfo(frame.Payload)
	if err != nil {
		return nil, nil, err
	}
	if netinfo.Timestamp != 0 || len(netinfo.MyAddresses) != 0 || netinfo.OtherAddress != f.target.Address.Addr() {
		return nil, nil, fmt.Errorf("invalid client NETINFO: %+v", netinfo)
	}
	return conn, codec, nil
}

func pipeHandshake(t *testing.T, ctx context.Context, f relayFixture, frames []cell.Cell, versions []uint16, maxTLS uint16, after func(*tls.Conn, *cell.Codec) error) (*Channel, error, <-chan error) {
	t.Helper()
	client, server := net.Pipe()
	done := make(chan error, 1)
	_ = server.SetDeadline(time.Now().Add(5 * time.Second))
	go func() {
		defer close(done)
		defer server.Close()
		conn, codec, err := serveHandshake(server, f, frames, versions, maxTLS)
		if err == nil && after != nil {
			err = after(conn, codec)
		}
		done <- err
	}()
	hctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	ch, err := connect(ctx, hctx, client, f.target, Options{QueueSize: 2})
	t.Cleanup(func() {
		if ch != nil {
			ch.Close()
		}
		client.Close()
		server.Close()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Error("relay goroutine did not exit")
		}
	})
	return ch, err, done
}
