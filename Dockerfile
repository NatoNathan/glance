FROM --platform=$BUILDPLATFORM golang:1.27.1-alpine3.24 AS builder

ARG TARGETOS
ARG TARGETARCH
ARG TARGETVARIANT
ARG VERSION=dev

WORKDIR /app

COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod go mod download

COPY . .
# Cross compiled instead of built under emulation, which is much slower for non native platforms
RUN --mount=type=cache,target=/go/pkg/mod --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH GOARM=${TARGETVARIANT#v} \
    go build -ldflags "-s -w -X github.com/glanceapp/glance/internal/glance.buildVersion=$VERSION" .

# Static image with CA certificates and timezone data, the binary doesn't need anything else
FROM gcr.io/distroless/static-debian13:nonroot

WORKDIR /app
COPY --from=builder /app/glance .

USER nonroot:nonroot
EXPOSE 8080/tcp
ENTRYPOINT ["/app/glance", "--config", "/app/config/glance.yml"]
