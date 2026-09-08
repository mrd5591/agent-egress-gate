# Build stage. CGO stays off: the binary uses nothing that needs it, and a
# static binary keeps the runtime image free of a libc to patch.
FROM golang:1.27-alpine AS build

WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/egressgate ./cmd/egressgate

# Runtime. Alpine rather than distroless for wget, which the ECS health check
# uses. Trading a slightly larger attack surface for a health check that
# actually runs is the right way round; a container nobody can probe is not
# safer.
#
# The gate reads its policy from a file or from the environment and writes its
# audit log to stdout, so it needs nothing writable. The task definition runs
# it with a read-only root filesystem.
FROM alpine:3.24

RUN apk add --no-cache ca-certificates \
    && addgroup -g 65532 -S gate \
    && adduser -u 65532 -S -G gate gate

COPY --from=build /out/egressgate /usr/local/bin/egressgate

USER 65532:65532

EXPOSE 8080 9090

ENTRYPOINT ["/usr/local/bin/egressgate"]
CMD ["serve", "--policy", "/etc/egressgate/policy.yaml", "--listen", "0.0.0.0:8080", "--admin", "0.0.0.0:9090"]
