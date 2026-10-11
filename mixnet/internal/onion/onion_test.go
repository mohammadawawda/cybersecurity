package onion

import (
	"bytes"
	"testing"
)

// makeHops creates n mix keypairs and returns the hops plus their private keys.
func makeHops(t *testing.T, n int) ([]Hop, []*PrivateKey) {
	t.Helper()
	hops := make([]Hop, n)
	privs := make([]*PrivateKey, n)
	for i := 0; i < n; i++ {
		kp, err := GenerateKeyPair()
		if err != nil {
			t.Fatalf("keygen: %v", err)
		}
		hops[i] = Hop{ID: mixID(i), Pub: kp.Pub}
		privs[i] = kp.Priv
	}
	return hops, privs
}

func mixID(i int) string {
	return string(rune('a'+i)) + "-mix"
}

// peelCascade drives a built onion through the full set of mixes and returns
// the recipient blob plus the exit-mix routing decision.
func peelCascade(t *testing.T, outer []byte, privs []*PrivateKey, round uint64) *Peeled {
	t.Helper()
	layer := outer
	var last *Peeled
	for i := 0; i < len(privs); i++ {
		p, err := Peel(layer, privs[i], round)
		if err != nil {
			t.Fatalf("peel hop %d: %v", i, err)
		}
		last = p
		layer = p.Inner
		if i < len(privs)-1 && p.Type != TypeRelay {
			t.Fatalf("hop %d: expected relay, got type %d", i, p.Type)
		}
	}
	if last.Type != TypeDeliver {
		t.Fatalf("exit hop: expected deliver, got type %d", last.Type)
	}
	return last
}

func TestOnionRoundTrip(t *testing.T) {
	const round = 7
	const payloadSize = 1024
	hops, privs := makeHops(t, 3)

	rcpt, err := GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	msg := []byte("the treaty is signed at dawn")

	outer, err := BuildOnion(msg, "recipient-1", rcpt.Pub, hops, round, 0, payloadSize)
	if err != nil {
		t.Fatalf("build: %v", err)
	}

	exit := peelCascade(t, outer, privs, round)
	if exit.NextHop != "recipient-1" {
		t.Fatalf("exit next hop = %q, want recipient-1", exit.NextHop)
	}

	got, err := OpenFromRecipient(exit.Inner, rcpt.Priv, round)
	if err != nil {
		t.Fatalf("recipient open: %v", err)
	}
	if !bytes.Equal(got, msg) {
		t.Fatalf("recovered %q, want %q", got, msg)
	}
}

// TestFixedLength verifies the outer packet length is independent of the
// plaintext content (fixed length padding).
func TestFixedLength(t *testing.T) {
	const round = 1
	const payloadSize = 1024
	hops, _ := makeHops(t, 3)
	rcpt, _ := GenerateKeyPair()

	sizes := []int{0, 1, 64, 500, payloadSize - PayloadOverhead}
	var lengths []int
	for _, s := range sizes {
		outer, err := BuildOnion(bytes.Repeat([]byte{'x'}, s), "r", rcpt.Pub, hops, round, 0, payloadSize)
		if err != nil {
			t.Fatalf("build size %d: %v", s, err)
		}
		lengths = append(lengths, len(outer))
	}
	for i := 1; i < len(lengths); i++ {
		if lengths[i] != lengths[0] {
			t.Fatalf("packet length varies with plaintext: %v", lengths)
		}
	}
	if want := OuterPacketSize(3, payloadSize); lengths[0] != want {
		t.Fatalf("outer size = %d, predicted %d", lengths[0], want)
	}
}

// TestOversizedMessageRejected ensures messages that don't fit the padded slot
// are rejected rather than silently truncated.
func TestOversizedMessageRejected(t *testing.T) {
	hops, _ := makeHops(t, 3)
	rcpt, _ := GenerateKeyPair()
	big := bytes.Repeat([]byte{'y'}, 1024) // no room for the 4-byte length prefix
	if _, err := BuildOnion(big, "r", rcpt.Pub, hops, 1, 0, 1024); err == nil {
		t.Fatal("expected error for oversized message, got nil")
	}
}

// TestTamperDetected confirms that flipping a byte in any layer causes
// authenticated decryption to fail (per-layer integrity).
func TestTamperDetected(t *testing.T) {
	const round = 3
	hops, privs := makeHops(t, 3)
	rcpt, _ := GenerateKeyPair()
	outer, err := BuildOnion([]byte("secret"), "r", rcpt.Pub, hops, round, 0, 1024)
	if err != nil {
		t.Fatal(err)
	}
	// Flip a byte inside the ciphertext region of the outer layer.
	tampered := append([]byte(nil), outer...)
	idx := EphSize + NonceSize + 1
	tampered[idx] ^= 0xFF
	if _, err := Peel(tampered, privs[0], round); err == nil {
		t.Fatal("expected authentication failure on tampered layer, got nil")
	}
}

// TestWrongRoundRejected confirms the round number is bound into the AEAD.
func TestWrongRoundRejected(t *testing.T) {
	hops, privs := makeHops(t, 3)
	rcpt, _ := GenerateKeyPair()
	outer, err := BuildOnion([]byte("hi"), "r", rcpt.Pub, hops, 5, 0, 1024)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Peel(outer, privs[0], 6); err == nil {
		t.Fatal("expected failure when peeling with wrong round, got nil")
	}
}

// TestWrongKeyRejected confirms a mix cannot open a layer addressed to another
// mix (sender/receiver unlinkability rests on this).
func TestWrongKeyRejected(t *testing.T) {
	hops, _ := makeHops(t, 3)
	rcpt, _ := GenerateKeyPair()
	outer, err := BuildOnion([]byte("hi"), "r", rcpt.Pub, hops, 1, 0, 1024)
	if err != nil {
		t.Fatal(err)
	}
	wrong, _ := GenerateKeyPair()
	if _, err := Peel(outer, wrong.Priv, 1); err == nil {
		t.Fatal("expected failure peeling with wrong key, got nil")
	}
}

// TestDummyFlagPropagates checks cover-traffic flagging survives the cascade.
func TestDummyFlagPropagates(t *testing.T) {
	hops, privs := makeHops(t, 3)
	rcpt, _ := GenerateKeyPair()
	outer, err := BuildOnion([]byte(""), "r", rcpt.Pub, hops, 1, FlagDummy, 1024)
	if err != nil {
		t.Fatal(err)
	}
	exit := peelCascade(t, outer, privs, 1)
	if !exit.IsDummy() {
		t.Fatal("dummy flag did not reach the exit mix")
	}
}

// TestDigestStable confirms identical packets share a replay digest and
// distinct packets do not.
func TestDigestStable(t *testing.T) {
	hops, _ := makeHops(t, 3)
	rcpt, _ := GenerateKeyPair()
	a, _ := BuildOnion([]byte("m"), "r", rcpt.Pub, hops, 1, 0, 1024)
	b, _ := BuildOnion([]byte("m"), "r", rcpt.Pub, hops, 1, 0, 1024)
	if Digest(a) != Digest(a) {
		t.Fatal("digest not deterministic")
	}
	// Fresh ephemeral keys/nonces make two encryptions of the same message
	// differ on the wire — so their digests must differ.
	if Digest(a) == Digest(b) {
		t.Fatal("independently built packets collided (nonces not random?)")
	}
}
