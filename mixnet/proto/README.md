# Generated gRPC code

`mixnet.pb.go` and `mixnet_grpc.pb.go` are generated from `mixnet.proto` and are
committed so the Docker build needs no `protoc`. To regenerate after editing the
proto:

```bash
protoc --go_out=. --go_opt=paths=source_relative \
       --go-grpc_out=. --go-grpc_opt=paths=source_relative \
       proto/mixnet.proto
```

This requires `protoc` plus the `protoc-gen-go` and `protoc-gen-go-grpc`
plugins on `PATH`. The `option go_package = "mixnet/proto;mixnetpb"` in the
proto places the generated package at this path.
