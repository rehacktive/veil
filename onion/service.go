package onion

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha3"
	"crypto/sha512"
	"crypto/subtle"
	"encoding/base64"
	"encoding/binary"
	"encoding/pem"
	"fmt"
	"time"

	"filippo.io/edwards25519"
	"filippo.io/edwards25519/field"
	"veil/cell"
)

// ServiceIntroduction owns fresh keys for one introduction circuit. Replay state
// must live as long as these keys; never reuse them after losing that state.
type ServiceIntroduction struct {
	Public     Introduction
	auth       ed25519.PrivateKey
	encryption *ecdh.PrivateKey
}

func NewServiceIntroduction(links []cell.LinkSpec, onionKey [32]byte) (*ServiceIntroduction, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	b, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	intro := &ServiceIntroduction{auth: priv, encryption: b, Public: Introduction{Links: links, OnionKey: onionKey}}
	copy(intro.Public.AuthKey[:], pub)
	copy(intro.Public.EncryptionKey[:], b.PublicKey().Bytes())
	return intro, nil
}

func (i *ServiceIntroduction) Establish(binding [20]byte) []byte {
	if i == nil || len(i.auth) != ed25519.PrivateKeySize {
		return nil
	}
	b := append([]byte{2, 0, 32}, i.Public.AuthKey[:]...)
	b = append(b, 0)
	tag := mac(binding[:], b)
	b = append(b, tag[:]...)
	signature := ed25519.Sign(i.auth, join([]byte("Tor establish-intro cell v1"), b))
	b = binary.BigEndian.AppendUint16(b, 64)
	return append(b, signature...)
}

// ServiceRequest is authenticated introduction data. The caller must reject
// repeated client keys and cookies before connecting to its rendezvous relay.
// Keys are in client order and must be reversed for the service virtual hop.
type ServiceRequest struct {
	Cookie    [20]byte
	ClientKey [32]byte
	OnionKey  [32]byte
	Links     []cell.LinkSpec
	Reply     [64]byte
	Keys      [128]byte
}

func skipExtensions(b []byte) ([]byte, error) {
	if len(b) < 1 {
		return nil, ErrAuthentication
	}
	n := int(b[0])
	b = b[1:]
	for j := 0; j < n; j++ {
		if len(b) < 2 || int(b[1]) > len(b)-2 {
			return nil, ErrAuthentication
		}
		b = b[2+int(b[1]):]
	}
	return b, nil
}

func (i *ServiceIntroduction) Accept(raw []byte, sub [32]byte) (r ServiceRequest, err error) {
	if i == nil || i.encryption == nil || len(raw) < 120 || len(raw) > 490 || !bytes.Equal(raw[:20], make([]byte, 20)) || raw[20] != 2 || binary.BigEndian.Uint16(raw[21:23]) != 32 || !bytes.Equal(raw[23:55], i.Public.AuthKey[:]) {
		return r, ErrAuthentication
	}
	encrypted, err := skipExtensions(raw[55:])
	if err != nil || len(encrypted) < 64 {
		return r, ErrAuthentication
	}
	X, err := ecdh.X25519().NewPublicKey(encrypted[:32])
	if err != nil {
		return r, ErrAuthentication
	}
	xb, err := i.encryption.ECDH(X)
	if err != nil {
		return r, ErrAuthentication
	}
	defer clear(xb)
	input := join(xb, i.Public.AuthKey[:], X.Bytes(), i.Public.EncryptionKey[:], []byte(proto), []byte(proto+":hs_key_extract"), []byte(proto+":hs_key_expand"), sub[:])
	encKeys := sha3.SumSHAKE256(input, 64)
	clear(input)
	defer clear(encKeys)
	tag := mac(encKeys[32:], raw[:len(raw)-32])
	if subtle.ConstantTimeCompare(tag[:], raw[len(raw)-32:]) != 1 {
		return r, ErrAuthentication
	}
	plain := bytes.Clone(encrypted[32 : len(encrypted)-32])
	defer clear(plain)
	block, err := aes.NewCipher(encKeys[:32])
	if err != nil {
		return r, err
	}
	cipher.NewCTR(block, make([]byte, 16)).XORKeyStream(plain, plain) // #nosec G407 -- hs-ntor specifies zero IV with a key derived from this introduction's ephemeral X25519 key; replays are rejected by the service.
	if len(plain) < 21 {
		return r, ErrAuthentication
	}
	copy(r.Cookie[:], plain[:20])
	copy(r.ClientKey[:], X.Bytes())
	// No congestion-control negotiation is advertised or accepted by this host.
	ext := plain[20:]
	if ext[0] != 0 {
		return r, ErrAuthentication
	}
	body, err := skipExtensions(ext)
	if err != nil || len(body) < 36 || body[0] != 1 || binary.BigEndian.Uint16(body[1:3]) != 32 {
		return r, ErrAuthentication
	}
	copy(r.OnionKey[:], body[3:35])
	links := body[35:]
	end := 1
	for j := 0; j < int(links[0]); j++ {
		if len(links)-end < 2 || int(links[end+1]) > len(links)-end-2 {
			return r, ErrAuthentication
		}
		end += 2 + int(links[end+1])
	}
	r.Links, err = parseLinks(links[:end])
	if err != nil {
		return r, err
	}
	y, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return r, err
	}
	xy, err := y.ECDH(X)
	if err != nil {
		return r, ErrAuthentication
	}
	defer clear(xy)
	secret := join(xy, xb, i.Public.AuthKey[:], i.Public.EncryptionKey[:], X.Bytes(), y.PublicKey().Bytes(), []byte(proto))
	defer clear(secret)
	seed := mac(secret, []byte(proto+":hs_key_extract"))
	defer clear(seed[:])
	verify := mac(secret, []byte(proto+":hs_verify"))
	auth := mac(join(verify[:], i.Public.AuthKey[:], i.Public.EncryptionKey[:], y.PublicKey().Bytes(), X.Bytes(), []byte(proto), []byte("Server")), []byte(proto+":hs_mac"))
	copy(r.Reply[:32], y.PublicKey().Bytes())
	copy(r.Reply[32:], auth[:])
	kdf := join(seed[:], []byte(proto+":hs_key_expand"))
	material := sha3.SumSHAKE256(kdf, 128)
	copy(r.Keys[:], material)
	clear(kdf)
	clear(material)
	return r, nil
}

func signExpanded(scalar *edwards25519.Scalar, prefix []byte, public [32]byte, message []byte) []byte {
	hash := sha512.Sum512(join(prefix, message))
	r, _ := new(edwards25519.Scalar).SetUniformBytes(hash[:])
	R := new(edwards25519.Point).ScalarBaseMult(r).Bytes()
	hash = sha512.Sum512(join(R, public[:], message))
	k, _ := new(edwards25519.Scalar).SetUniformBytes(hash[:])
	S := new(edwards25519.Scalar).MultiplyAdd(k, scalar, r)
	return join(R, S.Bytes())
}
func certificate(kind byte, subject, signer [32]byte, expires time.Time, sign func([]byte) []byte) ([]byte, error) {
	hours := (expires.Unix() + 3599) / 3600
	if hours < 1 || hours > 4294967295 {
		return nil, ErrDescriptor
	}
	b := binary.BigEndian.AppendUint32([]byte{1, kind}, uint32(hours))
	b = append(b, 1)
	b = append(b, subject[:]...)
	b = append(b, 1, 0, 32, 4, 0)
	b = append(b, signer[:]...)
	return append(b, sign(b)...), nil
}
func armor(label string, b []byte) string {
	return string(pem.EncodeToMemory(&pem.Block{Type: label, Bytes: b}))
}
func encode64(b []byte) string { return base64.RawStdEncoding.EncodeToString(b) }

// CreateDescriptor builds a public v3 descriptor for a caller-supplied period.
// Seed is the persistent Ed25519 identity seed. Revision must strictly increase
// on every regeneration, including after restart. No client authorization or PoW.
func CreateDescriptor(seed [32]byte, period, minutes, revision uint64, intros []Introduction, now time.Time) ([]byte, error) {
	if len(intros) < 1 || len(intros) > 20 {
		return nil, ErrDescriptor
	}
	private := ed25519.NewKeyFromSeed(seed[:])
	defer clear(private)
	var identity [32]byte
	copy(identity[:], private[32:])
	blinded, sub, err := Blind(identity, period, minutes)
	if err != nil {
		return nil, err
	}
	factor, err := blindingFactor(identity, period, minutes)
	if err != nil {
		return nil, err
	}
	expanded := sha512.Sum512(seed[:])
	defer clear(expanded[:])
	scalar, err := new(edwards25519.Scalar).SetBytesWithClamping(expanded[:32])
	if err != nil {
		return nil, err
	}
	scalar.Multiply(scalar, factor)
	prefix := sha512.Sum512(join([]byte("Derive temporary signing key hash input"), expanded[32:]))
	defer clear(prefix[:])
	pub, signing, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	defer clear(signing)
	var signer [32]byte
	copy(signer[:], pub)
	expiry := ServiceDescriptorExpiry(now)
	cert, err := certificate(8, signer, blinded, expiry, func(b []byte) []byte { return signExpanded(scalar, prefix[:32], blinded, b) })
	if err != nil {
		return nil, err
	}
	inner := "create2-formats 2\n"
	for _, i := range intros {
		count := len(i.Links)
		if count > 32 {
			return nil, ErrDescriptor
		}
		links := []byte{byte(count)}
		for _, l := range i.Links {
			size := len(l.Data)
			if size > 255 {
				return nil, ErrDescriptor
			}
			links = append(links, l.Type, byte(size))
			links = append(links, l.Data...)
		}
		if _, err := parseLinks(links); err != nil {
			return nil, err
		}
		sign := func(b []byte) []byte { return ed25519.Sign(signing, b) }
		auth, err := certificate(9, i.AuthKey, signer, expiry, sign)
		if err != nil {
			return nil, err
		}
		u, err := new(field.Element).SetBytes(i.EncryptionKey[:])
		if err != nil {
			return nil, err
		}
		one := new(field.Element).One()
		den := new(field.Element).Add(u, one)
		if den.Equal(new(field.Element).Zero()) == 1 {
			return nil, ErrDescriptor
		}
		y := new(field.Element).Multiply(new(field.Element).Subtract(u, one), new(field.Element).Invert(den))
		var subject [32]byte
		copy(subject[:], y.Bytes())
		enc, err := certificate(11, subject, signer, expiry, sign)
		if err != nil {
			return nil, err
		}
		inner += fmt.Sprintf("introduction-point %s\nonion-key ntor %s\nauth-key\n%senc-key ntor %s\nenc-key-cert\n%s", encode64(links), encode64(i.OnionKey[:]), armor("ED25519 CERT", auth), encode64(i.EncryptionKey[:]), armor("ED25519 CERT", enc))
	}
	encrypted, err := encryptLayer([]byte(inner), blinded, sub, revision, "hsdir-encrypted-data", false)
	if err != nil {
		return nil, err
	}
	ephemeral, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	middle := "desc-auth-type x25519\ndesc-auth-ephemeral-key " + encode64(ephemeral.PublicKey().Bytes()) + "\n"
	for j := 0; j < 16; j++ {
		var fake [40]byte
		if _, err := rand.Read(fake[:]); err != nil {
			return nil, err
		}
		middle += fmt.Sprintf("auth-client %s %s %s\n", encode64(fake[:8]), encode64(fake[8:24]), encode64(fake[24:]))
	}
	middle += "encrypted\n" + armor("MESSAGE", encrypted)
	outer, err := encryptLayer([]byte(middle), blinded, sub, revision, "hsdir-superencrypted-data", true)
	if err != nil {
		return nil, err
	}
	result := []byte(fmt.Sprintf("hs-descriptor 3\ndescriptor-lifetime 180\ndescriptor-signing-key-cert\n%srevision-counter %d\nsuperencrypted\n%s", armor("ED25519 CERT", cert), revision, armor("MESSAGE", outer)))
	signature := ed25519.Sign(signing, join([]byte("Tor onion service descriptor sig v3"), result))
	result = append(result, []byte("signature "+encode64(signature)+"\n")...)
	if len(result) > MaxDescriptorSize {
		return nil, ErrDescriptor
	}
	return result, nil
}

// ServiceDescriptorExpiry is the absolute certificate expiry used by
// CreateDescriptor. A client fetching a cached descriptor later can still use
// its introduction points until this time, irrespective of newer revisions.
// Tor certificate times are rounded up to whole Unix hours.
func ServiceDescriptorExpiry(created time.Time) time.Time {
	return time.Unix(((created.Add(4*time.Hour).Unix()+3599)/3600)*3600, 0)
}

func encryptLayer(plain []byte, blinded, sub [32]byte, revision uint64, label string, pad bool) ([]byte, error) {
	if pad {
		padded := make([]byte, ((len(plain)+9999)/10000)*10000)
		copy(padded, plain)
		plain = padded
	}
	var salt [16]byte
	if _, err := rand.Read(salt[:]); err != nil {
		return nil, err
	}
	input := join(blinded[:], sub[:])
	input = binary.BigEndian.AppendUint64(input, revision)
	input = append(input, salt[:]...)
	input = append(input, label...)
	keys := sha3.SumSHAKE256(input, 80)
	defer clear(keys)
	block, err := aes.NewCipher(keys[:32])
	if err != nil {
		return nil, err
	}
	out := append(salt[:0:0], salt[:]...)
	out = append(out, plain...)
	cipher.NewCTR(block, keys[32:48]).XORKeyStream(out[16:], out[16:])
	m := binary.BigEndian.AppendUint64(nil, 32)
	m = append(m, keys[48:]...)
	m = binary.BigEndian.AppendUint64(m, 16)
	m = append(m, out...)
	tag := sha3.Sum256(m)
	clear(m)
	return append(out, tag[:]...), nil
}
