// Package client implements the mixnet client: it builds onion-encrypted
// messages (prepare_message), submits them to the first mix over TLS, polls the
// final mix for blobs addressed to it (poll_messages), and decrypts those blobs
// locally with its own private key — confirming the client is the final
// decryptor.
package client

import (
	"context"
	"crypto/rand"
	"fmt"
	"time"

	"google.golang.org/grpc"

	"mixnet/internal/config"
	"mixnet/internal/onion"
	"mixnet/internal/transport"
	mixnetpb "mixnet/proto"
)

// Options configures a client.
type Options struct {
	Config    *config.Config
	ID        string   // this client's id
	Recipient string   // default recipient id
	Path      []string // mix ids in processing order (outermost first)
	CAFile    string   // CA cert to verify mixes
	Verbose   bool
}

// Client talks to the mix cascade.
type Client struct {
	cfg       *config.Config
	id        string
	recipient string
	path      []string
	caFile    string
	priv      *onion.PrivateKey
	verbose   bool
}

// Received is a decrypted message recovered by polling.
type Received struct {
	Round     uint64
	Plaintext []byte
}

// New builds a client and loads its own private key (used to decrypt the blobs
// it polls).
func New(o Options) (*Client, error) {
	priv, err := o.Config.LoadPrivateKey(o.ID)
	if err != nil {
		return nil, fmt.Errorf("load private key for %s: %w", o.ID, err)
	}
	if len(o.Path) == 0 {
		return nil, fmt.Errorf("empty mix path")
	}
	return &Client{
		cfg:       o.Config,
		id:        o.ID,
		recipient: o.Recipient,
		path:      o.Path,
		caFile:    o.CAFile,
		priv:      priv,
		verbose:   o.Verbose,
	}, nil
}

// Prepare implements prepare_message: it constructs the multilayer encrypted
// packet for `message` addressed to `recipient`, to be processed in `round`.
// When dummy is true it builds cover traffic (dropped at the exit mix).
func (c *Client) Prepare(message []byte, recipient string, round uint64, dummy bool) ([]byte, error) {
	rcptParty := c.cfg.PartyByID(recipient)
	if rcptParty == nil {
		return nil, fmt.Errorf("unknown recipient %q", recipient)
	}
	rcptPub, err := c.cfg.LoadPublicKey(rcptParty)
	if err != nil {
		return nil, fmt.Errorf("load recipient public key: %w", err)
	}
	hops, err := c.cfg.Hops(c.path)
	if err != nil {
		return nil, err
	}
	var flags byte
	if dummy {
		flags |= onion.FlagDummy
	}
	return onion.BuildOnion(message, recipient, rcptPub, hops, round, flags, c.cfg.PaddedPayloadSize)
}

// Send submits a prepared onion packet to the first mix in the path.
func (c *Client) Send(ctx context.Context, packet []byte, round uint64) error {
	first := c.path[0]
	party := c.cfg.MixByID(first)
	if party == nil {
		return fmt.Errorf("unknown first mix %q", first)
	}
	creds, err := transport.ClientCredentials(c.caFile, first)
	if err != nil {
		return err
	}
	conn, err := grpc.NewClient(party.Address, grpc.WithTransportCredentials(creds))
	if err != nil {
		return fmt.Errorf("dial first mix %s: %w", first, err)
	}
	defer conn.Close()

	reply, err := mixnetpb.NewMixServerClient(conn).ForwardMessage(ctx,
		&mixnetpb.ForwardRequest{Payload: packet, Round: round},
		grpc.WaitForReady(true))
	if err != nil {
		return fmt.Errorf("forward to %s: %w", first, err)
	}
	if !reply.GetAccepted() {
		return fmt.Errorf("first mix rejected packet: %s", reply.GetDetail())
	}
	return nil
}

// SendMessage is prepare_message + forward for a real message.
func (c *Client) SendMessage(ctx context.Context, message []byte, recipient string, round uint64) error {
	packet, err := c.Prepare(message, recipient, round, false)
	if err != nil {
		return err
	}
	return c.Send(ctx, packet, round)
}

// SendDummy submits one cover-traffic packet for the given round (used to keep
// the batch full when a real message is not available).
func (c *Client) SendDummy(ctx context.Context, round uint64) error {
	filler := make([]byte, 16)
	_, _ = rand.Read(filler)
	packet, err := c.Prepare(filler, c.id, round, true)
	if err != nil {
		return err
	}
	return c.Send(ctx, packet, round)
}

// Poll implements poll_messages: it asks the final mix for blobs delivered to
// this client and decrypts each locally. Blobs that fail to decrypt are skipped.
func (c *Client) Poll(ctx context.Context) ([]Received, error) {
	final := c.cfg.FinalMix
	party := c.cfg.MixByID(final)
	if party == nil {
		return nil, fmt.Errorf("unknown final mix %q", final)
	}
	creds, err := transport.ClientCredentials(c.caFile, final)
	if err != nil {
		return nil, err
	}
	conn, err := grpc.NewClient(party.Address, grpc.WithTransportCredentials(creds))
	if err != nil {
		return nil, fmt.Errorf("dial final mix %s: %w", final, err)
	}
	defer conn.Close()

	reply, err := mixnetpb.NewMixServerClient(conn).PollMessages(ctx,
		&mixnetpb.PollRequest{RecipientId: c.id}, grpc.WaitForReady(true))
	if err != nil {
		return nil, fmt.Errorf("poll %s: %w", final, err)
	}

	var out []Received
	for _, m := range reply.GetMessages() {
		pt, err := onion.OpenFromRecipient(m.GetCiphertext(), c.priv, m.GetRound())
		if err != nil {
			if c.verbose {
				fmt.Printf("[%s] skipped undecryptable blob (round %d): %v\n", c.id, m.GetRound(), err)
			}
			continue
		}
		out = append(out, Received{Round: m.GetRound(), Plaintext: pt})
	}
	return out, nil
}

// PollUntil polls repeatedly until at least `want` messages arrive or the
// timeout elapses, returning whatever was received.
func (c *Client) PollUntil(ctx context.Context, want int, timeout time.Duration) ([]Received, error) {
	deadline := time.Now().Add(timeout)
	var all []Received
	for time.Now().Before(deadline) {
		got, err := c.Poll(ctx)
		if err == nil && len(got) > 0 {
			all = append(all, got...)
			if len(all) >= want {
				return all, nil
			}
		}
		time.Sleep(300 * time.Millisecond)
	}
	return all, nil
}
