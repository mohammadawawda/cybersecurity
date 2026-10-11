// Package mixcore implements the network-agnostic logic of a mix server:
// per-round batching, replay detection, a cryptographically random shuffle,
// and the relay-vs-deliver routing decision. It depends only on the onion
// package, so the full cascade can be exercised in-process by unit tests and
// benchmarks without gRPC, TLS, or Docker.
package mixcore

import (
	"crypto/rand"
	"math/big"
	"sync"
	"time"

	"mixnet/internal/onion"
)

// Sink is the side-effecting boundary of a mix: how it forwards to the next
// mix, how the exit mix delivers to recipients, and a notification when a
// round's batch has been processed (used by the exit mix to write its
// per-round output file).
type Sink interface {
	// Relay forwards an inner layer to the next mix in the static path.
	Relay(round uint64, nextMix string, inner []byte) error
	// Deliver stores a recipient blob for later polling (exit mix only).
	Deliver(round uint64, recipientID string, blob []byte) error
	// RoundFlushed is invoked once after a round's batch has been shuffled
	// and dispatched. `delivered` counts non-dummy messages delivered to
	// recipients at this hop (0 at non-exit mixes).
	RoundFlushed(round uint64, delivered int)
}

// Logger is an optional structured logging hook.
type Logger func(format string, args ...any)

func (l Logger) printf(format string, args ...any) {
	if l != nil {
		l(format, args...)
	}
}

// Mix is the core state machine for one mix server.
type Mix struct {
	id        string
	priv      *onion.PrivateKey
	batchSize int
	timeout   time.Duration
	isFinal   bool
	sink      Sink
	log       Logger

	mu     sync.Mutex
	rounds map[uint64]*roundState
	seen   map[[32]byte]struct{} // global replay set
}

type item struct {
	typ     byte
	flags   byte
	nextHop string
	inner   []byte
}

type roundState struct {
	items   []item
	timer   *time.Timer
	flushed bool
}

// Options configures a Mix.
type Options struct {
	ID        string
	Priv      *onion.PrivateKey
	BatchSize int
	Timeout   time.Duration
	IsFinal   bool
	Sink      Sink
	Log       Logger
}

// New creates a mix core.
func New(o Options) *Mix {
	return &Mix{
		id:        o.ID,
		priv:      o.Priv,
		batchSize: o.BatchSize,
		timeout:   o.Timeout,
		isFinal:   o.IsFinal,
		sink:      o.Sink,
		log:       o.Log,
		rounds:    make(map[uint64]*roundState),
		seen:      make(map[[32]byte]struct{}),
	}
}

// SubmitResult reports how an incoming packet was handled.
type SubmitResult struct {
	Accepted bool
	Detail   string
}

// Submit processes one onion-encrypted, round-tagged packet: it rejects
// replays, peels exactly one layer, and buffers the result for its round. When
// the round's batch is complete it is flushed (shuffled and dispatched).
func (m *Mix) Submit(layer []byte, round uint64) SubmitResult {
	digest := onion.Digest(layer)

	m.mu.Lock()
	if _, dup := m.seen[digest]; dup {
		m.mu.Unlock()
		m.log.printf("[%s] dropped replayed packet (round %d)", m.id, round)
		return SubmitResult{Accepted: false, Detail: "replay"}
	}
	m.seen[digest] = struct{}{}
	m.mu.Unlock()

	peeled, err := onion.Peel(layer, m.priv, round)
	if err != nil {
		m.log.printf("[%s] dropped undecryptable packet (round %d): %v", m.id, round, err)
		return SubmitResult{Accepted: false, Detail: "decrypt failed"}
	}

	m.mu.Lock()
	rs := m.rounds[round]
	if rs == nil {
		rs = &roundState{}
		m.rounds[round] = rs
		// Start the liveness timeout when the first packet of a round arrives.
		r := round
		rs.timer = time.AfterFunc(m.timeout, func() { m.onTimeout(r) })
	}
	if rs.flushed {
		m.mu.Unlock()
		m.log.printf("[%s] dropped late packet for already-flushed round %d", m.id, round)
		return SubmitResult{Accepted: false, Detail: "round closed"}
	}
	rs.items = append(rs.items, item{peeled.Type, peeled.Flags, peeled.NextHop, peeled.Inner})
	full := len(rs.items) >= m.batchSize
	m.mu.Unlock()

	if full {
		m.flush(round, false)
	}
	return SubmitResult{Accepted: true, Detail: "buffered"}
}

// onTimeout flushes a round's partial batch if it hasn't already filled.
func (m *Mix) onTimeout(round uint64) {
	m.flush(round, true)
}

// flush shuffles and dispatches a round's buffered packets exactly once.
func (m *Mix) flush(round uint64, byTimeout bool) {
	m.mu.Lock()
	rs := m.rounds[round]
	if rs == nil || rs.flushed {
		m.mu.Unlock()
		return
	}
	rs.flushed = true
	if rs.timer != nil {
		rs.timer.Stop()
	}
	batch := rs.items
	rs.items = nil
	m.mu.Unlock()

	if byTimeout && len(batch) < m.batchSize {
		m.log.printf("[%s] round %d timed out with %d/%d packets; "+
			"processing partial batch (anonymity set reduced to %d)",
			m.id, round, len(batch), m.batchSize, len(batch))
	}

	secureShuffle(batch)

	delivered := 0
	for _, it := range batch {
		switch it.typ {
		case onion.TypeRelay:
			if err := m.sink.Relay(round, it.nextHop, it.inner); err != nil {
				m.log.printf("[%s] relay to %s failed (round %d): %v", m.id, it.nextHop, round, err)
			}
		case onion.TypeDeliver:
			if it.flags&onion.FlagDummy != 0 {
				// Cover traffic: counted toward the batch, then discarded.
				m.log.printf("[%s] discarded dummy at exit (round %d)", m.id, round)
				continue
			}
			if err := m.sink.Deliver(round, it.nextHop, it.inner); err != nil {
				m.log.printf("[%s] deliver to %s failed (round %d): %v", m.id, it.nextHop, round, err)
				continue
			}
			delivered++
		}
	}
	m.sink.RoundFlushed(round, delivered)
	m.log.printf("[%s] flushed round %d: %d packets (%d delivered)", m.id, round, len(batch), delivered)
}

// Forget releases per-round bookkeeping once a round is fully processed
// (replay state is intentionally retained).
func (m *Mix) Forget(round uint64) {
	m.mu.Lock()
	delete(m.rounds, round)
	m.mu.Unlock()
}

// secureShuffle performs an in-place Fisher–Yates shuffle using the system
// CSPRNG, so the output order reveals nothing about the input order. This
// unlinkability between a mix's inputs and outputs is the crux of mixing.
func secureShuffle[T any](s []T) {
	for i := len(s) - 1; i > 0; i-- {
		jBig, err := rand.Int(rand.Reader, big.NewInt(int64(i+1)))
		if err != nil {
			// rand.Reader failing is catastrophic; fall back to no swap for
			// this index rather than producing biased output.
			continue
		}
		j := int(jBig.Int64())
		s[i], s[j] = s[j], s[i]
	}
}
