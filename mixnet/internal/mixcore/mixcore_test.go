package mixcore

import (
	"fmt"
	"sync"
	"testing"
	"time"

	"mixnet/internal/onion"
)

// memnet wires several mix cores together in memory and collects deliveries,
// so a full cascade runs without gRPC.
type memnet struct {
	mu      sync.Mutex
	mixes   map[string]*Mix
	inbox   map[string][]delivered
	flushes map[uint64]int
}

type delivered struct {
	round uint64
	blob  []byte
}

func newMemnet() *memnet {
	return &memnet{
		mixes:   map[string]*Mix{},
		inbox:   map[string][]delivered{},
		flushes: map[uint64]int{},
	}
}

// sink adapts a memnet to the Sink interface for a particular mix.
type sink struct{ net *memnet }

func (s sink) Relay(round uint64, nextMix string, inner []byte) error {
	s.net.mu.Lock()
	target := s.net.mixes[nextMix]
	s.net.mu.Unlock()
	if target == nil {
		return fmt.Errorf("no such mix %q", nextMix)
	}
	res := target.Submit(inner, round)
	if !res.Accepted {
		return fmt.Errorf("relay rejected: %s", res.Detail)
	}
	return nil
}

func (s sink) Deliver(round uint64, recipientID string, blob []byte) error {
	s.net.mu.Lock()
	defer s.net.mu.Unlock()
	s.net.inbox[recipientID] = append(s.net.inbox[recipientID], delivered{round, blob})
	return nil
}

func (s sink) RoundFlushed(round uint64, n int) {
	s.net.mu.Lock()
	defer s.net.mu.Unlock()
	s.net.flushes[round] += n
}

func (n *memnet) poll(id string) []delivered {
	n.mu.Lock()
	defer n.mu.Unlock()
	return append([]delivered(nil), n.inbox[id]...)
}

// buildCascade creates a 3-mix cascade with the given batch size and timeout.
func buildCascade(t *testing.T, batch int, timeout time.Duration) (*memnet, []onion.Hop, []*onion.KeyPair) {
	t.Helper()
	net := newMemnet()
	ids := []string{"server1", "server2", "server3"}
	var hops []onion.Hop
	var kps []*onion.KeyPair
	for i, id := range ids {
		kp, err := onion.GenerateKeyPair()
		if err != nil {
			t.Fatal(err)
		}
		kps = append(kps, kp)
		hops = append(hops, onion.Hop{ID: id, Pub: kp.Pub})
		net.mixes[id] = New(Options{
			ID:        id,
			Priv:      kp.Priv,
			BatchSize: batch,
			Timeout:   timeout,
			IsFinal:   i == len(ids)-1,
			Sink:      sink{net},
		})
	}
	return net, hops, kps
}

// TestCascadeDelivery sends two messages through a batch-of-two cascade and
// checks both arrive and decrypt correctly.
func TestCascadeDelivery(t *testing.T) {
	const round = 1
	const payload = 1024
	net, hops, _ := buildCascade(t, 2, 2*time.Second)

	alice, _ := onion.GenerateKeyPair()
	bob, _ := onion.GenerateKeyPair()

	msgAB := []byte("alice to bob: meet at noon")
	msgBA := []byte("bob to alice: understood")

	onionAB, err := onion.BuildOnion(msgAB, "bob", bob.Pub, hops, round, 0, payload)
	if err != nil {
		t.Fatal(err)
	}
	onionBA, err := onion.BuildOnion(msgBA, "alice", alice.Pub, hops, round, 0, payload)
	if err != nil {
		t.Fatal(err)
	}

	// Submit both to the first mix; the batch of two flushes synchronously.
	net.mixes["server1"].Submit(onionAB, round)
	net.mixes["server1"].Submit(onionBA, round)

	bobInbox := net.poll("bob")
	aliceInbox := net.poll("alice")
	if len(bobInbox) != 1 || len(aliceInbox) != 1 {
		t.Fatalf("inbox sizes bob=%d alice=%d, want 1 each", len(bobInbox), len(aliceInbox))
	}

	gotAB, err := onion.OpenFromRecipient(bobInbox[0].blob, bob.Priv, round)
	if err != nil {
		t.Fatal(err)
	}
	if string(gotAB) != string(msgAB) {
		t.Fatalf("bob got %q, want %q", gotAB, msgAB)
	}
	gotBA, err := onion.OpenFromRecipient(aliceInbox[0].blob, alice.Priv, round)
	if err != nil {
		t.Fatal(err)
	}
	if string(gotBA) != string(msgBA) {
		t.Fatalf("alice got %q, want %q", gotBA, msgBA)
	}
}

// TestBatchHolding confirms a mix does NOT release messages before the batch
// is full (the batching property that defends anonymity).
func TestBatchHolding(t *testing.T) {
	const round = 4
	net, hops, _ := buildCascade(t, 2, time.Hour) // effectively no timeout
	bob, _ := onion.GenerateKeyPair()

	o1, _ := onion.BuildOnion([]byte("first"), "bob", bob.Pub, hops, round, 0, 1024)
	net.mixes["server1"].Submit(o1, round)

	if got := net.poll("bob"); len(got) != 0 {
		t.Fatalf("message delivered before batch full: %d", len(got))
	}

	o2, _ := onion.BuildOnion([]byte("second"), "bob", bob.Pub, hops, round, 0, 1024)
	net.mixes["server1"].Submit(o2, round)

	if got := net.poll("bob"); len(got) != 2 {
		t.Fatalf("after filling batch, delivered %d, want 2", len(got))
	}
}

// TestReplayDropped confirms a duplicate wire packet is rejected by the entry
// mix and never enters the batch.
func TestReplayDropped(t *testing.T) {
	const round = 9
	net, hops, _ := buildCascade(t, 2, time.Hour)
	bob, _ := onion.GenerateKeyPair()
	o1, _ := onion.BuildOnion([]byte("m"), "bob", bob.Pub, hops, round, 0, 1024)

	r1 := net.mixes["server1"].Submit(o1, round)
	r2 := net.mixes["server1"].Submit(o1, round) // exact replay
	if !r1.Accepted {
		t.Fatal("first submission should be accepted")
	}
	if r2.Accepted {
		t.Fatal("replayed submission should be rejected")
	}
}

// TestTimeoutPartialBatch confirms that when the round timeout elapses before
// the batch fills, the partial batch is processed (liveness over a reduced
// anonymity set).
func TestTimeoutPartialBatch(t *testing.T) {
	const round = 2
	net, hops, _ := buildCascade(t, 2, 120*time.Millisecond)
	bob, _ := onion.GenerateKeyPair()

	o1, _ := onion.BuildOnion([]byte("solo"), "bob", bob.Pub, hops, round, 0, 1024)
	net.mixes["server1"].Submit(o1, round) // only 1 of 2

	// Wait for the timeout to cascade through all three mixes.
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if len(net.poll("bob")) == 1 {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	got := net.poll("bob")
	if len(got) != 1 {
		t.Fatalf("partial batch not delivered after timeout: got %d", len(got))
	}
	msg, err := onion.OpenFromRecipient(got[0].blob, bob.Priv, round)
	if err != nil || string(msg) != "solo" {
		t.Fatalf("partial delivery decrypt: msg=%q err=%v", msg, err)
	}
}

// TestShuffleUnbiased sanity-checks that the secure shuffle visits all
// positions (a weak statistical guard against an identity permutation bug).
func TestShuffleUnbiased(t *testing.T) {
	const n, trials = 6, 4000
	counts := make([][]int, n)
	for i := range counts {
		counts[i] = make([]int, n)
	}
	for tr := 0; tr < trials; tr++ {
		s := make([]int, n)
		for i := range s {
			s[i] = i
		}
		secureShuffle(s)
		for pos, val := range s {
			counts[pos][val]++
		}
	}
	exp := float64(trials) / float64(n)
	for pos := 0; pos < n; pos++ {
		for val := 0; val < n; val++ {
			c := float64(counts[pos][val])
			if c < exp*0.6 || c > exp*1.4 {
				t.Fatalf("element %d lands at position %d %v times (expected ~%.0f); shuffle looks biased",
					val, pos, counts[pos][val], exp)
			}
		}
	}
}
