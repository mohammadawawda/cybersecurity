// Command bench measures the runtime performance of the mixnet primitives and
// the in-process mix cascade, and writes the results as a tidy CSV for plotting.
//
// It deliberately exercises the same onion and mixcore packages used by the
// production gRPC servers, but with no network, TLS, or Docker, so the numbers
// reflect pure cryptographic and batching cost. Three quantities are measured,
// each as a function of two independent variables, plus an unencrypted/unmixed
// baseline for comparison:
//
//   - prep:        client-side message preparation (BuildOnion)
//   - mix_layer:   mix-side decrypt-and-forward of one round at one hop
//   - end_to_end:  full traversal of a round through all three mixes to delivery
//
// Sweeps:
//   - clients ∈ {2,5,10} at a fixed plaintext size (aggregate, per-round cost)
//   - plaintext ∈ {8,64,256,512,1020} at 2 clients (per-message/per-layer cost)
//
// Because every on-wire packet is padded to a constant length, the plaintext
// sweep varies only the plaintext while the wire size stays fixed; the column
// payload_bytes records the plaintext length.
//
// Usage: go run ./bench [-out results.csv] [-fast]
package main

import (
	"encoding/csv"
	"flag"
	"fmt"
	"log"
	"os"
	"strconv"
	"time"

	"mixnet/internal/mixcore"
	"mixnet/internal/onion"
)

const (
	numHops     = 3    // server1 -> server2 -> server3
	paddedSize  = 1024 // fixed on-wire payload slot (config padded_payload_size)
	recipientID = "client2"
)

var (
	clientCounts  = []int{2, 5, 10}
	plaintextSize = []int{8, 64, 256, 512, 1020} // up to paddedSize-4
	fixedPlain    = 256                          // plaintext size for the clients sweep
	fixedClients  = 2                            // client count for the plaintext sweep
)

// row is one CSV record.
type row struct {
	metric    string // prep | mix_layer | end_to_end
	sweep     string // clients | payload
	x         int    // x-axis value for this sweep
	clients   int
	payload   int // plaintext bytes
	iters     int
	meanUS    float64
	encrypted int // 1 real, 0 baseline
}

func main() {
	out := flag.String("out", "bench/results.csv", "output CSV path")
	fast := flag.Bool("fast", false, "fewer iterations for a quick smoke run")
	flag.Parse()

	iterScale := 1
	if *fast {
		iterScale = 10 // 10x fewer iterations
	}

	cascadeKeys := newCascadeKeys()

	var rows []row
	rows = append(rows, sweepClients(cascadeKeys, iterScale)...)
	rows = append(rows, sweepPayload(cascadeKeys, iterScale)...)

	if err := writeCSV(*out, rows); err != nil {
		log.Fatalf("write csv: %v", err)
	}
	fmt.Printf("wrote %d rows to %s\n", len(rows), *out)
	summarize(rows)
}

// cascadeKeys holds the static keypairs for the three mixes and the recipient,
// plus the hop list a client uses to build an onion.
type cascadeKeys struct {
	privs   []*onion.PrivateKey
	hops    []onion.Hop
	recPriv *onion.PrivateKey
	recPub  *onion.PublicKey
}

func newCascadeKeys() *cascadeKeys {
	ck := &cascadeKeys{privs: make([]*onion.PrivateKey, numHops)}
	for i := 0; i < numHops; i++ {
		kp, err := onion.GenerateKeyPair()
		if err != nil {
			log.Fatalf("keygen mix %d: %v", i, err)
		}
		ck.privs[i] = kp.Priv
		ck.hops = append(ck.hops, onion.Hop{ID: fmt.Sprintf("server%d", i+1), Pub: kp.Pub})
	}
	rk, err := onion.GenerateKeyPair()
	if err != nil {
		log.Fatalf("keygen recipient: %v", err)
	}
	ck.recPriv, ck.recPub = rk.Priv, rk.Pub
	return ck
}

// ---- in-process cascade -----------------------------------------------------

// store counts deliveries; the cascade runs synchronously in one goroutine when
// a batch fills, so a plain counter (no mutex) is sufficient.
type store struct{ delivered int }

func (s *store) reset() { s.delivered = 0 }

// chainSink wires one mix to the next, and the exit mix to the delivery store.
type chainSink struct {
	self  int
	mixes []*mixcore.Mix
	store *store
}

func (s *chainSink) Relay(round uint64, _ string, inner []byte) error {
	s.mixes[s.self+1].Submit(inner, round)
	return nil
}
func (s *chainSink) Deliver(_ uint64, _ string, _ []byte) error {
	s.store.delivered++
	return nil
}
func (s *chainSink) RoundFlushed(uint64, int) {}

func buildCascade(ck *cascadeKeys, batchSize int, st *store) []*mixcore.Mix {
	sinks := make([]*chainSink, numHops)
	mixes := make([]*mixcore.Mix, numHops)
	for i := 0; i < numHops; i++ {
		sinks[i] = &chainSink{self: i, store: st}
		mixes[i] = mixcore.New(mixcore.Options{
			ID:        fmt.Sprintf("server%d", i+1),
			Priv:      ck.privs[i],
			BatchSize: batchSize,
			Timeout:   time.Hour, // never fire during a benchmark
			IsFinal:   i == numHops-1,
			Sink:      sinks[i],
		})
	}
	for i := range sinks {
		sinks[i].mixes = mixes
	}
	return mixes
}

// ---- clients sweep (aggregate per-round cost) -------------------------------

func sweepClients(ck *cascadeKeys, scale int) []row {
	var rows []row
	msg := make([]byte, fixedPlain)
	for i := range msg {
		msg[i] = byte(i)
	}
	for _, c := range clientCounts {
		// prep: total time for c clients to each prepare one message.
		iters := 2000 / scale
		rows = append(rows, row{"prep", "clients", c, c, fixedPlain, iters,
			meanUS(iters, func() {
				for k := 0; k < c; k++ {
					if _, err := onion.BuildOnion(msg, recipientID, ck.recPub, ck.hops, 1, 0, paddedSize); err != nil {
						log.Fatal(err)
					}
				}
			}), 1})

		// prep baseline: c clients each pad-and-copy, no crypto.
		rows = append(rows, row{"prep", "clients", c, c, fixedPlain, iters,
			meanUS(iters, func() {
				for k := 0; k < c; k++ {
					_ = prepareBaseline(msg, paddedSize)
				}
			}), 0})

		// mix_layer: first mix peels a full batch of c outer layers (+ shuffle).
		// Pre-build c onions per timed iteration with fresh keys (avoids replay).
		miters := 1000 / scale
		rows = append(rows, row{"mix_layer", "clients", c, c, fixedPlain, miters,
			meanUS(miters, func() {
				st := &store{}
				m := mixcore.New(mixcore.Options{
					ID: "server1", Priv: ck.privs[0], BatchSize: c,
					Timeout: time.Hour, Sink: &discardSink{st},
				})
				for k := 0; k < c; k++ {
					o, err := onion.BuildOnion(msg, recipientID, ck.recPub, ck.hops, 1, 0, paddedSize)
					if err != nil {
						log.Fatal(err)
					}
					m.Submit(o, 1)
				}
			}), 1})

		// mix_layer baseline: forward c packets by copying bytes only.
		sz := onion.OuterPacketSize(numHops, paddedSize)
		rows = append(rows, row{"mix_layer", "clients", c, c, fixedPlain, miters,
			meanUS(miters, func() {
				for k := 0; k < c; k++ {
					_ = copyForward(sz)
				}
			}), 0})

		// end_to_end: full batch of c traverses all three mixes to delivery.
		eiters := 500 / scale
		rows = append(rows, row{"end_to_end", "clients", c, c, fixedPlain, eiters,
			meanUS(eiters, func() {
				st := &store{}
				mixes := buildCascade(ck, c, st)
				built := make([][]byte, c)
				for k := 0; k < c; k++ {
					o, err := onion.BuildOnion(msg, recipientID, ck.recPub, ck.hops, 1, 0, paddedSize)
					if err != nil {
						log.Fatal(err)
					}
					built[k] = o
				}
				// timed region: submit the whole batch; the final submit drives
				// the synchronous cascade down to delivery.
				for _, o := range built {
					mixes[0].Submit(o, 1)
				}
				if st.delivered != c {
					log.Fatalf("clients=%d delivered=%d", c, st.delivered)
				}
			}), 1})

		// end_to_end baseline: c messages padded and delivered directly.
		rows = append(rows, row{"end_to_end", "clients", c, c, fixedPlain, eiters,
			meanUS(eiters, func() {
				st := &store{}
				for k := 0; k < c; k++ {
					_ = prepareBaseline(msg, paddedSize)
					st.delivered++
				}
			}), 0})
	}
	return rows
}

// ---- payload sweep (per-message / per-layer cost) ---------------------------

func sweepPayload(ck *cascadeKeys, scale int) []row {
	var rows []row
	for _, p := range plaintextSize {
		msg := make([]byte, p)
		for i := range msg {
			msg[i] = byte(i)
		}

		// prep: one BuildOnion.
		iters := 5000 / scale
		rows = append(rows, row{"prep", "payload", p, fixedClients, p, iters,
			meanUS(iters, func() {
				if _, err := onion.BuildOnion(msg, recipientID, ck.recPub, ck.hops, 1, 0, paddedSize); err != nil {
					log.Fatal(err)
				}
			}), 1})
		rows = append(rows, row{"prep", "payload", p, fixedClients, p, iters,
			meanUS(iters, func() { _ = prepareBaseline(msg, paddedSize) }), 0})

		// mix_layer: peel exactly one (outer) layer.
		outer, err := onion.BuildOnion(msg, recipientID, ck.recPub, ck.hops, 1, 0, paddedSize)
		if err != nil {
			log.Fatal(err)
		}
		piters := 5000 / scale
		rows = append(rows, row{"mix_layer", "payload", p, fixedClients, p, piters,
			meanUS(piters, func() {
				if _, err := onion.Peel(outer, ck.privs[0], 1); err != nil {
					log.Fatal(err)
				}
			}), 1})
		sz := len(outer)
		rows = append(rows, row{"mix_layer", "payload", p, fixedClients, p, piters,
			meanUS(piters, func() { _ = copyForward(sz) }), 0})

		// end_to_end: a batch of fixedClients messages of this plaintext size.
		eiters := 1000 / scale
		rows = append(rows, row{"end_to_end", "payload", p, fixedClients, p, eiters,
			meanUS(eiters, func() {
				st := &store{}
				mixes := buildCascade(ck, fixedClients, st)
				built := make([][]byte, fixedClients)
				for k := 0; k < fixedClients; k++ {
					o, err := onion.BuildOnion(msg, recipientID, ck.recPub, ck.hops, 1, 0, paddedSize)
					if err != nil {
						log.Fatal(err)
					}
					built[k] = o
				}
				for _, o := range built {
					mixes[0].Submit(o, 1)
				}
				if st.delivered != fixedClients {
					log.Fatalf("payload=%d delivered=%d", p, st.delivered)
				}
			}), 1})
		rows = append(rows, row{"end_to_end", "payload", p, fixedClients, p, eiters,
			meanUS(eiters, func() {
				st := &store{}
				for k := 0; k < fixedClients; k++ {
					_ = prepareBaseline(msg, paddedSize)
					st.delivered++
				}
			}), 0})
	}
	return rows
}

// ---- baselines & helpers ----------------------------------------------------

// prepareBaseline models an unencrypted, unmixed "preparation": place the
// message into a fixed-length slot with a length prefix. No KEM, no AEAD.
func prepareBaseline(msg []byte, size int) []byte {
	buf := make([]byte, size)
	n := len(msg)
	buf[0] = byte(n >> 24)
	buf[1] = byte(n >> 16)
	buf[2] = byte(n >> 8)
	buf[3] = byte(n)
	copy(buf[4:], msg)
	return buf
}

// copyForward models a naive relay that forwards a packet without decrypting,
// i.e. just copies the bytes onward.
func copyForward(size int) []byte {
	src := make([]byte, size)
	dst := make([]byte, size)
	copy(dst, src)
	return dst
}

// discardSink swallows relays/deliveries (used when timing a single hop).
type discardSink struct{ st *store }

func (d *discardSink) Relay(uint64, string, []byte) error { return nil }
func (d *discardSink) Deliver(uint64, string, []byte) error {
	d.st.delivered++
	return nil
}
func (d *discardSink) RoundFlushed(uint64, int) {}

// meanUS runs fn `iters` times and returns the mean wall time in microseconds.
func meanUS(iters int, fn func()) float64 {
	if iters < 1 {
		iters = 1
	}
	// brief warmup to amortize first-call effects
	for i := 0; i < iters/10+1; i++ {
		fn()
	}
	start := time.Now()
	for i := 0; i < iters; i++ {
		fn()
	}
	return float64(time.Since(start).Nanoseconds()) / float64(iters) / 1000.0
}

func writeCSV(path string, rows []row) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	w := csv.NewWriter(f)
	defer w.Flush()
	if err := w.Write([]string{
		"metric", "sweep", "x", "clients", "payload_bytes", "iters", "mean_us", "encrypted",
	}); err != nil {
		return err
	}
	for _, r := range rows {
		rec := []string{
			r.metric, r.sweep, strconv.Itoa(r.x), strconv.Itoa(r.clients),
			strconv.Itoa(r.payload), strconv.Itoa(r.iters),
			strconv.FormatFloat(r.meanUS, 'f', 4, 64), strconv.Itoa(r.encrypted),
		}
		if err := w.Write(rec); err != nil {
			return err
		}
	}
	return nil
}

// summarize prints a compact human-readable table to stdout.
func summarize(rows []row) {
	fmt.Println("\nmetric      sweep    x      clients payload enc   mean_us")
	fmt.Println("--------------------------------------------------------------")
	for _, r := range rows {
		fmt.Printf("%-11s %-8s %-6d %-7d %-7d %-5d %9.3f\n",
			r.metric, r.sweep, r.x, r.clients, r.payload, r.encrypted, r.meanUS)
	}
}
