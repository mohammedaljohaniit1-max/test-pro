# syntax=docker/dockerfile:1.7
# ---------------------------------------------------------------------------
# Stage 1: build static binaries with the module cache and build cache mounted.
# ---------------------------------------------------------------------------
FROM golang:1.23-alpine AS build
WORKDIR /src
ENV CGO_ENABLED=0 GOFLAGS=-trimpath
COPY go.mod ./
RUN --mount=type=cache,target=/go/pkg/mod go mod download
COPY . .
ARG VERSION=dev
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    go build -ldflags="-s -w -X github.com/mohammedaljohaniit1-max/test-pro/internal/server.Version=${VERSION}" \
      -o /out/tempora ./cmd/tempora && \
    go build -ldflags="-s -w" -o /out/tempora-bench ./cmd/tempora-bench && \
    /out/tempora check rules

# ---------------------------------------------------------------------------
# Stage 2: run tests in the image build (docker build --target test .)
# ---------------------------------------------------------------------------
FROM build AS test
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    go vet ./... && go test -count=1 ./...

# ---------------------------------------------------------------------------
# Stage 3: minimal runtime — distroless static, non-root, no shell.
# ---------------------------------------------------------------------------
FROM gcr.io/distroless/static-debian12:nonroot AS runtime
WORKDIR /app
COPY --from=build /out/tempora /usr/local/bin/tempora
COPY --from=build /out/tempora-bench /usr/local/bin/tempora-bench
COPY --chown=nonroot:nonroot rules /app/rules
ENV TEMPORA_HTTP_ADDR=:8080 \
    TEMPORA_TCP_ADDR=:9090 \
    TEMPORA_RULES=/app/rules \
    TEMPORA_WAL_DIR=/data/wal \
    TEMPORA_LOG_FORMAT=json
VOLUME ["/data"]
EXPOSE 8080 9090
USER nonroot:nonroot
HEALTHCHECK NONE
ENTRYPOINT ["/usr/local/bin/tempora"]
