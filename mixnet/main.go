// Command mixnet is the single binary shared by every container in the mixnet.
// The role is chosen by the first CLI argument (server | client | healthcheck |
// keygen); if none is given it falls back to the ROLE environment variable
// (ROLE=mix runs a mix server), which is how the docker-compose mix services
// start without a command override.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"google.golang.org/grpc"

	"mixnet/internal/client"
	"mixnet/internal/config"
	"mixnet/internal/mixserver"
	"mixnet/internal/onion"
	"mixnet/internal/transport"
	mixnetpb "mixnet/proto"
)

func main() {
	args := os.Args[1:]
	// When ENTRYPOINT is the binary and docker-compose's `command` also begins
	// with the binary path, argv repeats it (e.g. ["/app/mixnet","client",...]
	// after the entrypoint). Drop any leading tokens that name this executable
	// so both `mixnet client ...` and `/app/mixnet /app/mixnet client ...` work.
	self := filepath.Base(os.Args[0])
	for len(args) > 0 && (args[0] == os.Args[0] || filepath.Base(args[0]) == self) {
		args = args[1:]
	}
	cmd := ""
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		cmd = args[0]
		args = args[1:]
	}
	if cmd == "" {
		// No subcommand: fall back to ROLE (the mix services rely on this).
		if strings.EqualFold(os.Getenv("ROLE"), "mix") {
			cmd = "server"
		}
	}

	var err error
	switch cmd {
	case "server":
		err = runServer(args)
	case "client":
		err = runClient(args)
	case "healthcheck":
		err = runHealthcheck(args)
	case "keygen":
		err = runKeygen(args)
	default:
		fmt.Fprintf(os.Stderr, "usage: mixnet <server|client|healthcheck|keygen> [flags]\n")
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}

// ---- path resolution ---------------------------------------------------

func firstExisting(paths ...string) string {
	for _, p := range paths {
		if p == "" {
			continue
		}
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	// Fall back to the last candidate even if missing (clearer error later).
	if len(paths) > 0 {
		return paths[len(paths)-1]
	}
	return ""
}

func configPath() string {
	if p := os.Getenv("MIXNET_CONFIG"); p != "" {
		return p
	}
	return firstExisting("/app/config/config.json", "config/config.json")
}

func tlsDir() string {
	if p := os.Getenv("MIXNET_TLS_DIR"); p != "" {
		return p
	}
	return firstExisting("/app/tls", "tls")
}

func outputDir() string {
	if p := os.Getenv("MIXNET_OUTPUT_DIR"); p != "" {
		return p
	}
	return firstExisting("/app/output", "output")
}

func resolveRelative(dir, p string) string {
	if filepath.IsAbs(p) {
		return p
	}
	return filepath.Join(dir, p)
}

// ---- server ------------------------------------------------------------

func runServer(args []string) error {
	fs := flag.NewFlagSet("server", flag.ExitOnError)
	id := fs.String("id", os.Getenv("SERVER_ID"), "this mix server's id")
	cfgPath := fs.String("config", configPath(), "config file path")
	_ = fs.Parse(args)

	if *id == "" {
		return fmt.Errorf("server id required (--id or SERVER_ID)")
	}
	cfg, err := config.Load(*cfgPath)
	if err != nil {
		return err
	}
	if cfg.MixByID(*id) == nil {
		return fmt.Errorf("mix %q not present in config", *id)
	}

	isFinal := cfg.IsFinalMix(*id)
	if strings.EqualFold(os.Getenv("FINAL_MIX"), "true") {
		isFinal = true
	}

	td := tlsDir()
	srv, err := mixserver.New(mixserver.Options{
		Config:    cfg,
		ID:        *id,
		IsFinal:   isFinal,
		CAFile:    filepath.Join(td, "ca.crt"),
		CertFile:  filepath.Join(td, *id+".crt"),
		KeyFile:   filepath.Join(td, *id+".key"),
		OutputDir: outputDir(),
		Verbose:   true,
	})
	if err != nil {
		return err
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	return srv.Serve(ctx)
}

// ---- client ------------------------------------------------------------

func runClient(args []string) error {
	fs := flag.NewFlagSet("client", flag.ExitOnError)
	id := fs.String("id", "", "this client's id")
	recipient := fs.String("recipient", "", "recipient id")
	pathCSV := fs.String("path", "", "comma-separated mix ids, outermost first (e.g. server1,server2,server3)")
	cfgPath := fs.String("config", configPath(), "config file path")
	message := fs.String("message", "", "message to send (default: a greeting)")
	round := fs.Uint64("round", 1, "round number")
	dummies := fs.Int("dummies", 0, "number of cover-traffic packets to also send")
	wait := fs.Duration("wait", 15*time.Second, "how long to poll for a reply")
	_ = fs.Parse(args)

	if *id == "" || *recipient == "" || *pathCSV == "" {
		return fmt.Errorf("--id, --recipient and --path are required")
	}
	cfg, err := config.Load(*cfgPath)
	if err != nil {
		return err
	}
	path := splitCSV(*pathCSV)

	c, err := client.New(client.Options{
		Config:    cfg,
		ID:        *id,
		Recipient: *recipient,
		Path:      path,
		CAFile:    filepath.Join(tlsDir(), "ca.crt"),
		Verbose:   true,
	})
	if err != nil {
		return err
	}

	msg := *message
	if msg == "" {
		msg = fmt.Sprintf("hello from %s to %s (round %d)", *id, *recipient, *round)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	fmt.Printf("[%s] sending to %s via %s in round %d\n", *id, *recipient, strings.Join(path, "->"), *round)
	if err := c.SendMessage(ctx, []byte(msg), *recipient, *round); err != nil {
		return err
	}
	for i := 0; i < *dummies; i++ {
		if err := c.SendDummy(ctx, *round); err != nil {
			return fmt.Errorf("send dummy: %w", err)
		}
	}

	// Poll for messages addressed to us (the reply in the demo).
	received, err := c.PollUntil(ctx, 1, *wait)
	if err != nil {
		return err
	}
	if len(received) == 0 {
		fmt.Printf("[%s] no messages received within %s\n", *id, *wait)
		return nil
	}
	for _, r := range received {
		fmt.Printf("[%s] RECEIVED (round %d): %q\n", *id, r.Round, string(r.Plaintext))
	}
	return nil
}

// ---- healthcheck -------------------------------------------------------

func runHealthcheck(args []string) error {
	fs := flag.NewFlagSet("healthcheck", flag.ExitOnError)
	id := fs.String("id", os.Getenv("SERVER_ID"), "this mix server's id")
	cfgPath := fs.String("config", configPath(), "config file path")
	_ = fs.Parse(args)

	if *id == "" {
		return fmt.Errorf("healthcheck requires --id or SERVER_ID")
	}
	cfg, err := config.Load(*cfgPath)
	if err != nil {
		return err
	}
	party := cfg.MixByID(*id)
	if party == nil {
		return fmt.Errorf("mix %q not in config", *id)
	}
	_, port, err := splitHostPort(party.Address)
	if err != nil {
		return err
	}
	creds, err := transport.ClientCredentials(filepath.Join(tlsDir(), "ca.crt"), *id)
	if err != nil {
		return err
	}
	conn, err := grpc.NewClient("127.0.0.1:"+port, grpc.WithTransportCredentials(creds))
	if err != nil {
		return err
	}
	defer conn.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	reply, err := mixnetpb.NewMixServerClient(conn).Health(ctx,
		&mixnetpb.HealthRequest{}, grpc.WaitForReady(false))
	if err != nil {
		return fmt.Errorf("health rpc: %w", err)
	}
	if !reply.GetServing() {
		return fmt.Errorf("mix %q reports not serving", *id)
	}
	return nil
}

// ---- keygen ------------------------------------------------------------

func runKeygen(args []string) error {
	fs := flag.NewFlagSet("keygen", flag.ExitOnError)
	cfgPath := fs.String("config", configPath(), "config file path")
	_ = fs.Parse(args)

	cfg, err := config.Load(*cfgPath)
	if err != nil {
		return err
	}
	parties := append([]config.Party{}, cfg.MixServers...)
	parties = append(parties, cfg.Clients...)

	for _, p := range parties {
		kp, err := onion.GenerateKeyPair()
		if err != nil {
			return err
		}
		pubPath := resolveRelative(cfg.Dir(), p.PublicKeyFile)
		privPath := cfg.PrivateKeyPath(p.ID)
		if err := onion.SavePublicKey(pubPath, kp); err != nil {
			return fmt.Errorf("save public key for %s: %w", p.ID, err)
		}
		if err := onion.SavePrivateKey(privPath, kp); err != nil {
			return fmt.Errorf("save private key for %s: %w", p.ID, err)
		}
		fmt.Printf("generated keypair for %-8s -> %s , %s\n", p.ID, pubPath, privPath)
	}
	return nil
}

// ---- helpers -----------------------------------------------------------

func splitCSV(s string) []string {
	var out []string
	for _, part := range strings.Split(s, ",") {
		if p := strings.TrimSpace(part); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// splitHostPort is net.SplitHostPort with a clearer error wrapper.
func splitHostPort(addr string) (string, string, error) {
	i := strings.LastIndex(addr, ":")
	if i < 0 {
		return "", "", fmt.Errorf("address %q has no port", addr)
	}
	return addr[:i], addr[i+1:], nil
}
