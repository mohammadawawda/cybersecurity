package onion

import (
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// SavePrivateKey writes a base64-encoded X25519 private key to `path` (mode
// 0600). SavePublicKey writes the corresponding public key.
func SavePrivateKey(path string, kp *KeyPair) error {
	enc := base64.StdEncoding.EncodeToString(kp.Priv.Bytes())
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	return os.WriteFile(path, []byte(enc+"\n"), 0o600)
}

// SavePublicKey writes a base64-encoded X25519 public key to `path`.
func SavePublicKey(path string, kp *KeyPair) error {
	enc := base64.StdEncoding.EncodeToString(kp.Pub.Bytes())
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	return os.WriteFile(path, []byte(enc+"\n"), 0o644)
}

// LoadPublicKey reads a base64-encoded X25519 public key from `path`.
func LoadPublicKey(path string) (*PublicKey, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read public key %s: %w", path, err)
	}
	b, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(raw)))
	if err != nil {
		return nil, fmt.Errorf("decode public key %s: %w", path, err)
	}
	return PublicKeyFromBytes(b)
}

// LoadPrivateKey reads a base64-encoded X25519 private key from `path`.
func LoadPrivateKey(path string) (*PrivateKey, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read private key %s: %w", path, err)
	}
	b, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(raw)))
	if err != nil {
		return nil, fmt.Errorf("decode private key %s: %w", path, err)
	}
	return PrivateKeyFromBytes(b)
}
