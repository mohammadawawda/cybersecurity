// Package mixserver is the gRPC front end for one mix server. It wraps the
// network-agnostic mixcore engine: incoming ForwardMessage RPCs are fed to the
// core, the core's Sink callbacks relay peeled layers to the next mix over TLS
// (or, at the exit mix, store recipient blobs for polling and append them to a
// per-round output file), and recipients retrieve their blobs via PollMessages.
package mixserver

import (
	"context"
	"encoding/base64"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"google.golang.org/grpc"

	"mixnet/internal/config"
	"mixnet/internal/mixcore"
	"mixnet/internal/transport"
	mixnetpb "mixnet/proto"
)

// Options configures a mix server.
type Options struct {
	Config    *config.Config
	ID        string // this mix's id, e.g. "server1"
	IsFinal   bool   // whether this is the exit mix
	CAFile    string // CA certificate (to verify peer mixes)
	CertFile  string // this mix's TLS certificate
	KeyFile   string // this mix's TLS private key
	OutputDir string // where the exit mix writes per-round files
	Verbose   bool
}

type delivery struct {
	recipientID string
	blob        []byte
}

// Server is a running mix server.
type Server struct {
	mixnetpb.UnimplementedMixServerServer

	cfg       *config.Config
	id        string
	isFinal   bool
	caFile    string
	certFile  string
	keyFile   string
	outputDir string
	verbose   bool

	core *mixcore.Mix
	grpc *grpc.Server

	mu         sync.Mutex
	inbox      map[string][]*mixnetpb.DeliveredMessage // recipient id -> queued blobs
	roundDeliv map[uint64][]delivery                   // round -> deliveries (exit mix output)
	conns      map[string]*grpc.ClientConn             // next-mix id -> connection
	clients    map[string]mixnetpb.MixServerClient     // next-mix id -> stub
}

// New builds a mix server, loading this mix's private key and wiring the core
// engine to use this server as its Sink.
func New(o Options) (*Server, error) {
	priv, err := o.Config.LoadPrivateKey(o.ID)
	if err != nil {
		return nil, fmt.Errorf("load private key for %s: %w", o.ID, err)
	}
	s := &Server{
		cfg:        o.Config,
		id:         o.ID,
		isFinal:    o.IsFinal,
		caFile:     o.CAFile,
		certFile:   o.CertFile,
		keyFile:    o.KeyFile,
		outputDir:  o.OutputDir,
		verbose:    o.Verbose,
		inbox:      make(map[string][]*mixnetpb.DeliveredMessage),
		roundDeliv: make(map[uint64][]delivery),
		conns:      make(map[string]*grpc.ClientConn),
		clients:    make(map[string]mixnetpb.MixServerClient),
	}

	var logger mixcore.Logger
	if o.Verbose {
		logger = func(format string, args ...any) { fmt.Printf(format+"\n", args...) }
	}
	s.core = mixcore.New(mixcore.Options{
		ID:        o.ID,
		Priv:      priv,
		BatchSize: o.Config.MessagesPerRound,
		Timeout:   time.Duration(o.Config.RoundTimeoutMS) * time.Millisecond,
		IsFinal:   o.IsFinal,
		Sink:      s,
		Log:       logger,
	})
	return s, nil
}

// ---- mixcore.Sink implementation ---------------------------------------

// Relay forwards a peeled inner layer to the next mix over a TLS gRPC channel.
func (s *Server) Relay(round uint64, nextMix string, inner []byte) error {
	client, err := s.clientTo(nextMix)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	reply, err := client.ForwardMessage(ctx, &mixnetpb.ForwardRequest{
		Payload: inner,
		Round:   round,
	}, grpc.WaitForReady(true))
	if err != nil {
		return fmt.Errorf("relay to %s: %w", nextMix, err)
	}
	if !reply.GetAccepted() {
		return fmt.Errorf("relay to %s rejected: %s", nextMix, reply.GetDetail())
	}
	return nil
}

// Deliver stores a recipient blob for later polling (exit mix only) and records
// it for the per-round output file.
func (s *Server) Deliver(round uint64, recipientID string, blob []byte) error {
	cp := make([]byte, len(blob))
	copy(cp, blob)
	s.mu.Lock()
	s.inbox[recipientID] = append(s.inbox[recipientID], &mixnetpb.DeliveredMessage{
		Ciphertext: cp,
		Round:      round,
	})
	s.roundDeliv[round] = append(s.roundDeliv[round], delivery{recipientID, cp})
	s.mu.Unlock()
	return nil
}

// RoundFlushed is called once per round after dispatch. At the exit mix it
// writes the round's deliveries to a file for inspection/testing.
func (s *Server) RoundFlushed(round uint64, delivered int) {
	if !s.isFinal {
		return
	}
	s.mu.Lock()
	deliveries := s.roundDeliv[round]
	delete(s.roundDeliv, round)
	s.mu.Unlock()

	if err := s.writeRoundFile(round, deliveries); err != nil {
		fmt.Printf("[%s] failed to write round %d output: %v\n", s.id, round, err)
	}
}

func (s *Server) writeRoundFile(round uint64, deliveries []delivery) error {
	if s.outputDir == "" {
		return nil
	}
	if err := os.MkdirAll(s.outputDir, 0o755); err != nil {
		return err
	}
	path := filepath.Join(s.outputDir, fmt.Sprintf("round_%d.txt", round))
	var b strings.Builder
	fmt.Fprintf(&b, "round %d: %d message(s) delivered by exit mix %s\n", round, len(deliveries), s.id)
	for i, d := range deliveries {
		fmt.Fprintf(&b, "[%d] recipient=%s ciphertext_b64=%s\n",
			i, d.recipientID, base64.StdEncoding.EncodeToString(d.blob))
	}
	return os.WriteFile(path, []byte(b.String()), 0o644)
}

// clientTo returns a cached gRPC stub for the named mix, dialing it (lazily,
// over TLS) on first use.
func (s *Server) clientTo(mixID string) (mixnetpb.MixServerClient, error) {
	s.mu.Lock()
	if c, ok := s.clients[mixID]; ok {
		s.mu.Unlock()
		return c, nil
	}
	s.mu.Unlock()

	party := s.cfg.MixByID(mixID)
	if party == nil {
		return nil, fmt.Errorf("unknown next-hop mix %q", mixID)
	}
	creds, err := transport.ClientCredentials(s.caFile, mixID)
	if err != nil {
		return nil, err
	}
	conn, err := grpc.NewClient(party.Address, grpc.WithTransportCredentials(creds))
	if err != nil {
		return nil, fmt.Errorf("dial %s (%s): %w", mixID, party.Address, err)
	}
	client := mixnetpb.NewMixServerClient(conn)

	s.mu.Lock()
	// Another goroutine may have dialed concurrently; keep the first.
	if existing, ok := s.clients[mixID]; ok {
		s.mu.Unlock()
		_ = conn.Close()
		return existing, nil
	}
	s.conns[mixID] = conn
	s.clients[mixID] = client
	s.mu.Unlock()
	return client, nil
}

// ---- gRPC MixServer implementation -------------------------------------

// ForwardMessage hands one packet to the core engine.
func (s *Server) ForwardMessage(_ context.Context, req *mixnetpb.ForwardRequest) (*mixnetpb.ForwardReply, error) {
	res := s.core.Submit(req.GetPayload(), req.GetRound())
	return &mixnetpb.ForwardReply{Accepted: res.Accepted, Detail: res.Detail}, nil
}

// PollMessages returns and clears the blobs queued for a recipient.
func (s *Server) PollMessages(_ context.Context, req *mixnetpb.PollRequest) (*mixnetpb.PollReply, error) {
	s.mu.Lock()
	msgs := s.inbox[req.GetRecipientId()]
	delete(s.inbox, req.GetRecipientId())
	s.mu.Unlock()
	return &mixnetpb.PollReply{Messages: msgs}, nil
}

// Health reports that this mix is serving.
func (s *Server) Health(_ context.Context, _ *mixnetpb.HealthRequest) (*mixnetpb.HealthReply, error) {
	return &mixnetpb.HealthReply{Serving: true, Id: s.id}, nil
}

// ---- lifecycle ---------------------------------------------------------

// Serve binds the mix's address and serves gRPC over TLS until ctx is canceled.
func (s *Server) Serve(ctx context.Context) error {
	party := s.cfg.MixByID(s.id)
	if party == nil {
		return fmt.Errorf("mix %q not in config", s.id)
	}
	// Listen on the port from the configured address (host is the container's).
	_, port, err := net.SplitHostPort(party.Address)
	if err != nil {
		return fmt.Errorf("bad address %q: %w", party.Address, err)
	}
	lis, err := net.Listen("tcp", ":"+port)
	if err != nil {
		return fmt.Errorf("listen on :%s: %w", port, err)
	}

	creds, err := transport.ServerCredentials(s.certFile, s.keyFile)
	if err != nil {
		return err
	}
	s.grpc = grpc.NewServer(grpc.Creds(creds))
	mixnetpb.RegisterMixServerServer(s.grpc, s)

	fmt.Printf("[%s] mix server listening on :%s (final=%v)\n", s.id, port, s.isFinal)

	errCh := make(chan error, 1)
	go func() { errCh <- s.grpc.Serve(lis) }()

	select {
	case <-ctx.Done():
		s.grpc.GracefulStop()
		s.closeConns()
		return nil
	case err := <-errCh:
		s.closeConns()
		return err
	}
}

func (s *Server) closeConns() {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, c := range s.conns {
		_ = c.Close()
	}
}
