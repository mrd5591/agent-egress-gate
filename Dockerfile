# Build stage. CGO stays off: the binary uses nothing that needs it, and a
# static binary keeps the runtime image free of a libc to patch.
# Both base images are pinned by digest, not just by tag. Every other tool in
# this build -- terraform, tflint, golangci-lint, govulncheck -- is pinned to an
# exact version on the stated principle that an unpinned tool works today and
# fails later for reasons nobody wrote down. The two inputs that actually ship
# were the unpinned ones, and a tag is mutable: `alpine:3.24` is whatever was
# last pushed under that name.
#
# To refresh: `docker buildx imagetools inspect <image>:<tag>` prints the
# current digest, or let Dependabot do it -- the docker ecosystem is configured
# in .github/dependabot.yml and updates a digest pin in place. Keep the tag
# alongside the digest; it is what makes the pin readable.
FROM golang:1.27-alpine@sha256:cf6fca6641884b8433441b2b0652976f975e1d0fdd26d177eaaf8596087f3125 AS build

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
FROM alpine:3.24@sha256:28bd5fe8b56d1bd048e5babf5b10710ebe0bae67db86916198a6eec434943f8b

RUN apk add --no-cache ca-certificates \
    && addgroup -g 65532 -S gate \
    && adduser -u 65532 -S -G gate gate

COPY --from=build /out/egressgate /usr/local/bin/egressgate

USER 65532:65532

EXPOSE 8080 9090

ENTRYPOINT ["/usr/local/bin/egressgate"]
CMD ["serve", "--policy", "/etc/egressgate/policy.yaml", "--listen", "0.0.0.0:8080", "--admin", "0.0.0.0:9090"]
