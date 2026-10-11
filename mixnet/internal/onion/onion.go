package onion

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
)

// Layer type byte (first byte of a decrypted routing header).
const (
	TypeRelay   byte = 1 // forward `Inner` to the mix named by `NextHop`
	TypeDeliver byte = 2 // `NextHop` is a recipient; `Inner` is the recipient blob
)

// Flag bits (second byte of a decrypted routing header).
const (
	FlagDummy byte = 1 << 0 // cover traffic; the exit mix drops it after batching
)

// Header field sizes.
const (
	addrFieldSize = 32                    // fixed-width next-hop label (zero-padded)
	headerSize    = 1 + 1 + addrFieldSize // type + flags + next-hop
	lenPrefixSize = 4                     // uint32 length prefix inside the padded payload
)

// PayloadOverhead is the number of bytes consumed inside the padded payload
// slot by the length prefix; the usable message is PayloadSize-PayloadOverhead.
const PayloadOverhead = lenPrefixSize

// Hop describes one mix in the forward path, in processing order (the first
// element is the first mix to touch the packet / the outermost layer).
type Hop struct {
	ID  string     // mix identifier, e.g. "server1"
	Pub *PublicKey // mix static public key
}

// padPayload places `msg` into a fixed-size slot of `size` bytes:
//
//	uint32(len(msg)) || msg || zero padding
//
// so that the on-wire size is independent of the actual message length.
func padPayload(msg []byte, size int) ([]byte, error) {
	if size < lenPrefixSize {
		return nil, fmt.Errorf("payload size %d too small", size)
	}
	if len(msg) > size-lenPrefixSize {
		return nil, fmt.Errorf("message of %d bytes exceeds payload capacity %d",
			len(msg), size-lenPrefixSize)
	}
	buf := make([]byte, size)
	binary.BigEndian.PutUint32(buf[:lenPrefixSize], uint32(len(msg)))
	copy(buf[lenPrefixSize:], msg)
	return buf, nil
}

// unpadPayload reverses padPayload.
func unpadPayload(buf []byte) ([]byte, error) {
	if len(buf) < lenPrefixSize {
		return nil, errors.New("padded payload too short")
	}
	n := binary.BigEndian.Uint32(buf[:lenPrefixSize])
	if int(n) > len(buf)-lenPrefixSize {
		return nil, errors.New("corrupt payload length prefix")
	}
	out := make([]byte, n)
	copy(out, buf[lenPrefixSize:lenPrefixSize+int(n)])
	return out, nil
}

func encodeAddr(id string) ([]byte, error) {
	if len(id) > addrFieldSize {
		return nil, fmt.Errorf("address %q exceeds %d bytes", id, addrFieldSize)
	}
	b := make([]byte, addrFieldSize)
	copy(b, id)
	return b, nil
}

func decodeAddr(b []byte) string {
	// Trim trailing zero padding.
	n := len(b)
	for n > 0 && b[n-1] == 0 {
		n--
	}
	return string(b[:n])
}

func buildHeader(t, flags byte, nextHop string) ([]byte, error) {
	addr, err := encodeAddr(nextHop)
	if err != nil {
		return nil, err
	}
	h := make([]byte, 0, headerSize)
	h = append(h, t, flags)
	h = append(h, addr...)
	return h, nil
}

// SealToRecipient produces the innermost blob that only the *recipient* can
// open. The exit mix relays this blob unopened; the recipient decrypts it
// locally after polling. The message is padded to `payloadSize` first.
func SealToRecipient(msg []byte, recipientPub *PublicKey, round uint64, payloadSize int) ([]byte, error) {
	padded, err := padPayload(msg, payloadSize)
	if err != nil {
		return nil, err
	}
	return seal(padded, recipientPub, round)
}

// OpenFromRecipient is run by the recipient on a polled blob to recover the
// original message.
func OpenFromRecipient(blob []byte, priv *PrivateKey, round uint64) ([]byte, error) {
	padded, err := open(blob, priv, round)
	if err != nil {
		return nil, err
	}
	return unpadPayload(padded)
}

// BuildOnion constructs the full multi-layer packet for one message.
//
//	message       the plaintext to deliver
//	recipientID   identifier the exit mix stores the blob under (poll key)
//	recipientPub  recipient's X25519 public key (innermost encryption target)
//	hops          mixes in processing order (hops[0] peels first)
//	round         round number bound into every layer's AEAD
//	flags         e.g. FlagDummy for cover traffic
//	payloadSize   fixed padded payload slot size (from config)
//
// Returned bytes are the outermost layer, ready to hand to hops[0].
func BuildOnion(message []byte, recipientID string, recipientPub *PublicKey,
	hops []Hop, round uint64, flags byte, payloadSize int) ([]byte, error) {

	if len(hops) == 0 {
		return nil, errors.New("at least one hop required")
	}

	// Innermost: encrypt the message to the recipient.
	body, err := SealToRecipient(message, recipientPub, round, payloadSize)
	if err != nil {
		return nil, fmt.Errorf("seal to recipient: %w", err)
	}

	// Wrap layers from the last hop (exit mix) outward to the first hop.
	for i := len(hops) - 1; i >= 0; i-- {
		var header []byte
		if i == len(hops)-1 {
			// Exit mix delivers to the recipient.
			header, err = buildHeader(TypeDeliver, flags, recipientID)
		} else {
			// Intermediate mix relays to the next mix in the path.
			header, err = buildHeader(TypeRelay, flags, hops[i+1].ID)
		}
		if err != nil {
			return nil, err
		}
		plaintext := append(header, body...)
		layer, err := seal(plaintext, hops[i].Pub, round)
		if err != nil {
			return nil, fmt.Errorf("seal layer for %s: %w", hops[i].ID, err)
		}
		body = layer
	}
	return body, nil
}

// Peeled is the result of a mix removing one layer.
type Peeled struct {
	Type    byte   // TypeRelay or TypeDeliver
	Flags   byte   // e.g. FlagDummy
	NextHop string // next mix id (relay) or recipient id (deliver)
	Inner   []byte // next layer (relay) or recipient blob (deliver)
}

// IsDummy reports whether this peeled message is cover traffic.
func (p *Peeled) IsDummy() bool { return p.Flags&FlagDummy != 0 }

// Peel removes exactly one layer using the mix's private key. It authenticates
// the layer (detecting tampering) and binds the supplied round.
func Peel(layer []byte, priv *PrivateKey, round uint64) (*Peeled, error) {
	pt, err := open(layer, priv, round)
	if err != nil {
		return nil, err
	}
	if len(pt) < headerSize {
		return nil, errors.New("decrypted layer shorter than header")
	}
	t := pt[0]
	flags := pt[1]
	nextHop := decodeAddr(pt[2 : 2+addrFieldSize])
	inner := make([]byte, len(pt)-headerSize)
	copy(inner, pt[headerSize:])

	if t != TypeRelay && t != TypeDeliver {
		return nil, fmt.Errorf("unknown layer type %d", t)
	}
	return &Peeled{Type: t, Flags: flags, NextHop: nextHop, Inner: inner}, nil
}

// Digest returns a stable identifier for a received layer, used by mixes for
// replay detection. Two identical wire packets hash to the same value.
func Digest(layer []byte) [32]byte {
	return sha256.Sum256(layer)
}

// OuterPacketSize returns the exact on-wire size of the outermost packet for a
// path of nHops mixes and the given padded payload size. Because all of these
// inputs are fixed by configuration, every client's outer packet is identical
// in length, so size never distinguishes messages within a round.
func OuterPacketSize(nHops, payloadSize int) int {
	// Innermost recipient blob.
	size := EphSize + NonceSize + payloadSize + TagSize
	// Each mix layer adds a header plus KEM/DEM overhead.
	for i := 0; i < nHops; i++ {
		size = EphSize + NonceSize + (headerSize + size) + TagSize
	}
	return size
}
