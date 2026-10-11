# syntax=docker/dockerfile:1
#
# Multi-stage Dockerfile for the mixnet. One image serves every role; the role
# is chosen at runtime by docker-compose (ROLE=mix for servers, or an explicit
# `client ...` command). The build resolves external modules (gRPC, protobuf)
# with `go mod tidy`, so only go.mod needs to be committed and go.sum is
# generated during the build. This requires network access to the Go module
# proxy at build time.

############################
# Build stage
############################
FROM golang:1.22-bookworm AS build
WORKDIR /src

COPY . .

# Resolve the import graph and pin versions consistent with go.mod, producing
# go.sum, then build a static binary for the slim runtime image.
RUN go mod tidy \
    && CGO_ENABLED=0 GOOS=linux go build -trimpath -o /out/mixnet .

############################
# Runtime stage
############################
FROM debian:bookworm-slim AS runtime

# ca-certificates is present for completeness; the mix verifies peers against a
# private CA mounted at /app/tls, not the system trust store.
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY --from=build /out/mixnet /app/mixnet

# config/, tls/ and output/ are provided at runtime via docker-compose volumes.
ENTRYPOINT ["/app/mixnet"]
