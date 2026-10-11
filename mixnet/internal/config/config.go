// Package config loads the shared mixnet configuration (the
// config.json schema) and resolves the public/private key material each party
// needs before a round begins. This bootstrap step is for
// technical convenience only and is not part of the privacy protocol.
package config

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"mixnet/internal/onion"
)

// Party is a mix server or a client entry in the configuration.
type Party struct {
	ID            string `json:"id"`
	Address       string `json:"address"`
	PublicKeyFile string `json:"public_key_file"`
}

// Config mirrors config/config.json.
type Config struct {
	MessagesPerRound  int    `json:"messages_per_round"`
	RoundTimeoutMS    int    `json:"round_timeout_ms"`
	PaddedPayloadSize int    `json:"padded_payload_size"`
	FinalMix          string `json:"final_mix"`

	MixServers []Party `json:"mix_servers"`
	Clients    []Party `json:"clients"`

	// dir is the directory the config was loaded from, used to resolve the
	// relative key/cert paths it references.
	dir string `json:"-"`
}

// Load reads and validates a config file.
func Load(path string) (*Config, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}
	var c Config
	if err := json.Unmarshal(raw, &c); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}
	c.dir = filepath.Dir(abs)
	if err := c.validate(); err != nil {
		return nil, err
	}
	return &c, nil
}

func (c *Config) validate() error {
	if c.MessagesPerRound < 1 {
		return fmt.Errorf("messages_per_round must be >= 1")
	}
	if c.PaddedPayloadSize < onion.PayloadOverhead+1 {
		return fmt.Errorf("padded_payload_size too small")
	}
	if len(c.MixServers) == 0 {
		return fmt.Errorf("no mix servers configured")
	}
	if c.FinalMix == "" {
		c.FinalMix = c.MixServers[len(c.MixServers)-1].ID
	}
	if c.MixByID(c.FinalMix) == nil {
		return fmt.Errorf("final_mix %q not among mix_servers", c.FinalMix)
	}
	return nil
}

// Dir returns the directory the config file lives in.
func (c *Config) Dir() string { return c.dir }

// resolve makes a config-relative path absolute.
func (c *Config) resolve(p string) string {
	if filepath.IsAbs(p) {
		return p
	}
	return filepath.Join(c.dir, p)
}

// MixByID returns the mix server with the given id, or nil.
func (c *Config) MixByID(id string) *Party {
	for i := range c.MixServers {
		if c.MixServers[i].ID == id {
			return &c.MixServers[i]
		}
	}
	return nil
}

// ClientByID returns the client with the given id, or nil.
func (c *Config) ClientByID(id string) *Party {
	for i := range c.Clients {
		if c.Clients[i].ID == id {
			return &c.Clients[i]
		}
	}
	return nil
}

// PartyByID searches both mixes and clients.
func (c *Config) PartyByID(id string) *Party {
	if p := c.MixByID(id); p != nil {
		return p
	}
	return c.ClientByID(id)
}

// IsFinalMix reports whether the given mix id is the exit mix.
func (c *Config) IsFinalMix(id string) bool { return id == c.FinalMix }

// LoadPublicKey loads a party's X25519 public key from its configured file.
func (c *Config) LoadPublicKey(p *Party) (*onion.PublicKey, error) {
	return onion.LoadPublicKey(c.resolve(p.PublicKeyFile))
}

// PrivateKeyPath returns the conventional private-key path for an id. Public
// keys live at keys/<id>.pub (per config) and private keys at keys/<id>.key
// in the same directory.
func (c *Config) PrivateKeyPath(id string) string {
	return c.resolve(filepath.Join("keys", id+".key"))
}

// LoadPrivateKey loads a party's own X25519 private key.
func (c *Config) LoadPrivateKey(id string) (*onion.PrivateKey, error) {
	return onion.LoadPrivateKey(c.PrivateKeyPath(id))
}

// Hops converts a list of mix ids (processing order) into onion.Hop values,
// loading each mix's public key.
func (c *Config) Hops(ids []string) ([]onion.Hop, error) {
	hops := make([]onion.Hop, 0, len(ids))
	for _, id := range ids {
		p := c.MixByID(id)
		if p == nil {
			return nil, fmt.Errorf("unknown mix %q in path", id)
		}
		pub, err := c.LoadPublicKey(p)
		if err != nil {
			return nil, err
		}
		hops = append(hops, onion.Hop{ID: id, Pub: pub})
	}
	return hops, nil
}
