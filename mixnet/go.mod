module mixnet

go 1.22.2

// Direct dependencies for the gRPC transport. `go mod tidy` (run by the
// Dockerfile during the image build) resolves the full set of indirect
// dependencies and produces go.sum. The security core, in-process mix cascade,
// and benchmark harness depend only on the Go standard library and build
// without any of these.
require (
	google.golang.org/grpc v1.64.1
	google.golang.org/protobuf v1.34.2
)
