# PK95 DNS als Container für PK95 Core (ghcr.io/philippkuhlmann/pk95-dns) oder eigenständig.
# Läuft mit network_mode host: DNS auf Port 53 (UDP und TCP) des LXC bzw. Hosts, damit die echten
# Client-Adressen ankommen (Docker-NAT würde sie verstecken). API und Oberfläche auf Port 8053.
# Läuft als root im Container (Port 53, keine Datei-Capabilities im unprivilegierten LXC).

# Die Build-Stufe läuft auf der Plattform des Builders und kompiliert quer (schneller als Go unter QEMU).
FROM --platform=$BUILDPLATFORM golang:1.26-trixie AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
ARG VERSION=1.0.0
ARG TARGETOS=linux
ARG TARGETARCH=amd64
# Reines Go (modernc.org/sqlite): statisches Binary, baut ohne cgo auch für arm64.
RUN CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} \
	go build -trimpath -ldflags "-s -w -X main.version=${VERSION}" -o /out/pk95dns .

FROM debian:trixie-slim
RUN apt-get update \
	&& apt-get install -y --no-install-recommends ca-certificates tzdata \
	&& rm -rf /var/lib/apt/lists/*
COPY --from=build /out/pk95dns /usr/local/bin/pk95dns

# Datenbank, Listenkopien und Startpasswort überstehen ein neues Image.
VOLUME ["/var/lib/pk95dns"]
ENV PK95DNS_LISTEN=0.0.0.0:8053 \
	PK95DNS_DATA_DIR=/var/lib/pk95dns
EXPOSE 53/udp 53/tcp 8053
STOPSIGNAL SIGTERM
ENTRYPOINT ["/usr/local/bin/pk95dns"]
