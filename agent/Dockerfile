ARG AWG_GO_REF=v3.1.20261116
FROM golang:1.25-alpine AS awg
ARG AWG_GO_REF
ARG VERSION=dev
RUN apk add --no-cache git
RUN git clone --depth 1 --branch "$AWG_GO_REF" https://github.com/amnezia-vpn/amneziawg-go /src
WORKDIR /src
RUN CGO_ENABLED=0 go build -trimpath -ldflags='-s -w' -o /out/amneziawg-go ./

FROM golang:1.25-alpine AS builder
WORKDIR /src
COPY go.mod go.sum* ./
RUN go mod download
COPY cmd ./cmd
COPY internal ./internal
ARG VERSION=dev
RUN CGO_ENABLED=0 go build -trimpath -ldflags "-s -w -X main.version=${VERSION}" -o /out/wgoctopus-agent ./cmd/wgoctopus-agent

FROM alpine:3.22
RUN apk add --no-cache iptables && mkdir -p /var/run/amneziawg /var/lib/wgoctopus
COPY --from=awg /out/amneziawg-go /usr/local/bin/amneziawg-go
COPY --from=builder /out/wgoctopus-agent /usr/local/bin/wgoctopus-agent
ARG VERSION=dev
LABEL org.opencontainers.image.title="wgoctopus-agent" \
      org.opencontainers.image.source="https://github.com/illmouse/wgoctopus" \
      org.opencontainers.image.licenses="MIT" \
      org.opencontainers.image.version="${VERSION}"
VOLUME /var/lib/wgoctopus
ENTRYPOINT ["/usr/local/bin/wgoctopus-agent"]
