// Package onion implements the Chaum-style layered ("onion") encryption used
// by the mixnet. Each layer uses hybrid (KEM/DEM) encryption:
//
//   - KEM: an ephemeral X25519 key agreement against the recipient mix's
//     static public key produces a fresh shared secret (the symmetric key is
//     thus *encapsulated* to the mix's public key, never sent in the clear).
//   - DEM: the layer contents are sealed with AES-256-GCM (an authenticated
//     cipher) under a key derived from that shared secret via HKDF-SHA256,
//     with a fresh random nonce per layer.
//
// This gives hybrid encryption per layer;
// the payload is never encrypted directly under a public key. Everything here
// uses only the Go standard library (crypto/ecdh, crypto/aes, crypto/cipher,
// crypto/sha256, crypto/hmac, crypto/rand), so the security core builds and is
// unit-tested without any external dependency.
package onion

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

// Wire/field sizes (bytes).
const (
	KeySize   = 32 // X25519 public/private key length
	EphSize   = 32 // ephemeral X25519 public key carried in each layer
	NonceSize = 12 // AES-GCM nonce
	TagSize   = 16 // AES-GCM authentication tag
)

// hkdfInfo domain-separates this protocol's key derivation.
var hkdfInfo = []byte("mixnet/v1 layer key")

// curve is the single X25519 curve instance used throughout.
func curve() ecdh.Curve { return ecdh.X25519() }

// PublicKey and PrivateKey are exported aliases for the X25519 key types, so
// other packages can hold keys without importing crypto/ecdh directly.
type (
	PublicKey  = ecdh.PublicKey
	PrivateKey = ecdh.PrivateKey
)

// KeyPair is an X25519 static keypair belonging to a mix or a client.
type KeyPair struct {
	Priv *ecdh.PrivateKey
	Pub  *ecdh.PublicKey
}

// GenerateKeyPair creates a fresh X25519 keypair from the system CSPRNG.
func GenerateKeyPair() (*KeyPair, error) {
	priv, err := curve().GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate x25519 key: %w", err)
	}
	return &KeyPair{Priv: priv, Pub: priv.PublicKey()}, nil
}

// PublicKeyFromBytes parses a 32-byte X25519 public key.
func PublicKeyFromBytes(b []byte) (*ecdh.PublicKey, error) {
	if len(b) != KeySize {
		return nil, fmt.Errorf("public key must be %d bytes, got %d", KeySize, len(b))
	}
	return curve().NewPublicKey(b)
}

// PrivateKeyFromBytes parses a 32-byte X25519 private key.
func PrivateKeyFromBytes(b []byte) (*ecdh.PrivateKey, error) {
	if len(b) != KeySize {
		return nil, fmt.Errorf("private key must be %d bytes, got %d", KeySize, len(b))
	}
	return curve().NewPrivateKey(b)
}

// hkdfSHA256 implements RFC 5869 (extract-then-expand) for a single output
// block, which is all we need (a 32-byte AES key). Implemented locally to keep
// the security core dependency-free.
func hkdfSHA256(secret, salt, info []byte, outLen int) []byte {
	if salt == nil {
		salt = make([]byte, sha256.Size)
	}
	// Extract.
	prkMAC := hmac.New(sha256.New, salt)
	prkMAC.Write(secret)
	prk := prkMAC.Sum(nil)

	// Expand.
	var out []byte
	var t []byte
	counter := byte(1)
	for len(out) < outLen {
		h := hmac.New(sha256.New, prk)
		h.Write(t)
		h.Write(info)
		h.Write([]byte{counter})
		t = h.Sum(nil)
		out = append(out, t...)
		counter++
	}
	return out[:outLen]
}

// deriveKey turns an X25519 shared secret into a 32-byte AES-256 key. The
// ephemeral public key is folded into the HKDF salt so that distinct layers
// (even to the same mix) derive independent keys.
func deriveKey(shared, ephPub []byte) []byte {
	return hkdfSHA256(shared, ephPub, hkdfInfo, 32)
}

// aad builds the additional-authenticated-data for a layer. Binding the round
// number into the AEAD means a layer cannot be silently re-tagged into a
// different round; a tampered round field causes authenticated decryption to
// fail, so the packet is dropped.
func aad(round uint64) []byte {
	b := make([]byte, 8)
	binary.BigEndian.PutUint64(b, round)
	return b
}

// seal encapsulates a fresh symmetric key to `peerPub` and AEAD-seals
// `plaintext`. The returned blob is the on-wire layer:
//
//	ephPub(32) || nonce(12) || ciphertext+tag
//
// Decapsulation only requires the holder of the matching private key.
func seal(plaintext []byte, peerPub *ecdh.PublicKey, round uint64) ([]byte, error) {
	eph, err := curve().GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("ephemeral keygen: %w", err)
	}
	shared, err := eph.ECDH(peerPub)
	if err != nil {
		return nil, fmt.Errorf("ecdh: %w", err)
	}
	ephPub := eph.PublicKey().Bytes()
	key := deriveKey(shared, ephPub)

	gcm, err := newGCM(key)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, NonceSize)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("nonce: %w", err)
	}
	ct := gcm.Seal(nil, nonce, plaintext, aad(round))

	out := make([]byte, 0, EphSize+NonceSize+len(ct))
	out = append(out, ephPub...)
	out = append(out, nonce...)
	out = append(out, ct...)
	return out, nil
}

// open reverses seal using `priv`. It fails (returns an error) if the layer is
// truncated, the round does not match, or the authentication tag is invalid —
// i.e. any tampering with this layer is detected here.
func open(layer []byte, priv *ecdh.PrivateKey, round uint64) ([]byte, error) {
	if len(layer) < EphSize+NonceSize+TagSize {
		return nil, errors.New("layer too short")
	}
	ephPub := layer[:EphSize]
	nonce := layer[EphSize : EphSize+NonceSize]
	ct := layer[EphSize+NonceSize:]

	peer, err := curve().NewPublicKey(ephPub)
	if err != nil {
		return nil, fmt.Errorf("bad ephemeral key: %w", err)
	}
	shared, err := priv.ECDH(peer)
	if err != nil {
		return nil, fmt.Errorf("ecdh: %w", err)
	}
	key := deriveKey(shared, ephPub)

	gcm, err := newGCM(key)
	if err != nil {
		return nil, err
	}
	pt, err := gcm.Open(nil, nonce, ct, aad(round))
	if err != nil {
		return nil, fmt.Errorf("authenticated decryption failed: %w", err)
	}
	return pt, nil
}

func newGCM(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("aes: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("gcm: %w", err)
	}
	return gcm, nil
}
