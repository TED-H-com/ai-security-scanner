# syntax=docker/dockerfile:1.7@sha256:a57df69d0ea827fb7266491f2813635de6f17269be881f696fbfdf2d83dda33e

ARG SOURCE_DATE_EPOCH=1793171438

FROM --platform=$BUILDPLATFORM golang:1.26.10-alpine@sha256:87c65a688975c0b1d4585d204874c45ca78354670e3a5f11368c5a492303d696 AS build

ARG TARGETOS
ARG TARGETARCH

ENV CGO_ENABLED=0 \
    GOTOOLCHAIN=local \
    SOURCE_DATE_EPOCH=1793171438

WORKDIR /src/launcher
COPY engines/images/external-launcher/go.mod engines/images/external-launcher/main.go engines/images/external-launcher/main_test.go ./
COPY engines/images/external-launcher/testdata ./testdata/
RUN go test ./... \
    && GOOS=${TARGETOS} GOARCH=${TARGETARCH} go build \
        -buildvcs=false -trimpath -ldflags='-s -w -buildid=' \
        -o /out/ai-security-scanner-engine-entrypoint .

ADD --checksum=sha256:d31032cbd2ddb35ed547469ed9d8382203180aa1854fdeb94d022fb1f2d332bf \
    https://github.com/projectdiscovery/naabu/archive/041b70fd396e95b5ed2c19f879c18247078243bc.tar.gz \
    /tmp/naabu-source.tar.gz

RUN mkdir -p /src/naabu \
    && tar -xzf /tmp/naabu-source.tar.gz --strip-components=1 -C /src/naabu \
    && cd /src/naabu \
    && grep -Fq 'const Version = `2.7.0`' pkg/runner/banners.go \
    && echo '859119b672267d1274fc4de8b8752bdcf68becc1b714f83be622279b77ff638c  go.sum' | sha256sum -c - \
    && go mod verify \
    && GOOS=${TARGETOS} GOARCH=${TARGETARCH} go build \
        -mod=readonly -buildvcs=false -trimpath -ldflags='-s -w -buildid=' \
        -o /out/naabu ./cmd/naabu \
    && go version -m /out/naabu | grep -Fq 'github.com/projectdiscovery/naabu/v2' \
    && mkdir -p /rootfs/run/ai-security-scanner /rootfs/output /rootfs/workspace /rootfs/tmp \
    && chmod 1777 /rootfs/tmp \
    && : > /rootfs/run/ai-security-scanner/.keep \
    && : > /rootfs/output/.keep \
    && : > /rootfs/workspace/.keep \
    && : > /rootfs/tmp/.keep

FROM scratch

LABEL org.opencontainers.image.title="ai-security-scanner Naabu engine" \
      org.opencontainers.image.description="Grant-local, SOCKS-enforced TCP connect discovery for ai-security-scanner" \
      org.opencontainers.image.source="https://github.com/projectdiscovery/naabu" \
      org.opencontainers.image.revision="041b70fd396e95b5ed2c19f879c18247078243bc" \
      org.opencontainers.image.version="2.7.0-1" \
      org.opencontainers.image.licenses="Apache-2.0 AND MIT" \
      io.ai-security-scanner.source-archive-sha256="d31032cbd2ddb35ed547469ed9d8382203180aa1854fdeb94d022fb1f2d332bf"

ENV HOME="/tmp" \
    SSL_CERT_FILE="/etc/ssl/certs/ca-certificates.crt" \
    XDG_CACHE_HOME="/tmp/cache" \
    XDG_CONFIG_HOME="/tmp/config"

COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=build /lib/ld-musl-*.so.1 /lib/
COPY --from=build /out/naabu /usr/local/bin/naabu
COPY --from=build /out/ai-security-scanner-engine-entrypoint /usr/local/bin/ai-security-scanner-engine-entrypoint
COPY LICENSE /usr/share/licenses/ai-security-scanner/LICENSE
COPY --from=build /src/naabu/LICENSE.md /usr/share/licenses/naabu/LICENSE.md
COPY --from=build /rootfs /

WORKDIR /workspace
USER 65532:65532
ENTRYPOINT ["/usr/local/bin/ai-security-scanner-engine-entrypoint"]
