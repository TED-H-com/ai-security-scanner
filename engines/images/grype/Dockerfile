# syntax=docker/dockerfile:1.7@sha256:a57df69d0ea827fb7266491f2813635de6f17269be881f696fbfdf2d83dda33e

FROM --platform=$BUILDPLATFORM golang:1.26.10-alpine@sha256:87c65a688975c0b1d4585d204874c45ca78354670e3a5f11368c5a492303d696 AS launcher

ARG TARGETOS
ARG TARGETARCH

ENV CGO_ENABLED=0 GOTOOLCHAIN=local SOURCE_DATE_EPOCH=1793912568

WORKDIR /src/launcher
COPY engines/images/local-launcher/go.mod engines/images/local-launcher/main.go engines/images/local-launcher/main_test.go ./
RUN go test ./... && GOOS=${TARGETOS} GOARCH=${TARGETARCH} go build \
    -buildvcs=false -trimpath -ldflags='-s -w -buildid=' \
    -o /out/ai-security-scanner-engine-entrypoint .

FROM --platform=$BUILDPLATFORM golang:1.26.10-alpine@sha256:87c65a688975c0b1d4585d204874c45ca78354670e3a5f11368c5a492303d696 AS build

ARG TARGETOS
ARG TARGETARCH

ENV CGO_ENABLED=0 GOTOOLCHAIN=local SOURCE_DATE_EPOCH=1793912568

RUN apk add --no-cache zstd=1.5.7-r2

ADD --checksum=sha256:8437ff52818e5afe968a9b2cdba6d02e606e5087070d5f72afc27ec1537f97d5 \
    https://github.com/anchore/grype/archive/82d7a0ea911946b99343c672056867d372f9b319.tar.gz \
    /tmp/grype-source.tar.gz
RUN mkdir -p /src/grype \
    && tar -xzf /tmp/grype-source.tar.gz --strip-components=1 -C /src/grype \
    && cd /src/grype \
    && echo 'd823897c07892e63750aa8b8c19d9987de3c4a699c1e3b28dc79a138c658c78b  go.sum' | sha256sum -c - \
    && go mod verify \
    && cd /src/grype/cmd/grype \
    && GOOS=${TARGETOS} GOARCH=${TARGETARCH} go build -mod=readonly -buildvcs=false -trimpath \
       -ldflags='-s -w -buildid= -extldflags=-static -X main.version=0.121.2 -X main.gitCommit=82d7a0ea911946b99343c672056867d372f9b319 -X main.buildDate=2026-11-05T21:02:48Z -X main.gitDescription=v0.121.2' \
       -o /out/grype . \
    && mkdir -p /rootfs/opt/ai-security-scanner/grype-db/6 /rootfs/output /rootfs/workspace /rootfs/tmp \
    && chmod 1777 /rootfs/tmp

COPY .engine-cache/offline/grype/db.tar.zst /tmp/grype-db.tar.zst
COPY engines/images/grype/import.json /tmp/grype-import.json
RUN echo '9fbc8d8f2428cd715ffc9591cce16c4179955a7f45c76c12fbcb9cea8dc93813  /tmp/grype-db.tar.zst' | sha256sum -c - \
    && zstd --decompress --stdout /tmp/grype-db.tar.zst > /tmp/grype-db.tar \
    && tar -xf /tmp/grype-db.tar -C /rootfs/opt/ai-security-scanner/grype-db/6 \
    && echo '420d0ac2f976acb4bf46e19bd1779f3043a868a77ca8e9debf18c3d196728344  /rootfs/opt/ai-security-scanner/grype-db/6/vulnerability.db' | sha256sum -c - \
    && test "$(stat -c '%s' /rootfs/opt/ai-security-scanner/grype-db/6/vulnerability.db)" = 2565357568 \
    && cp /tmp/grype-import.json /rootfs/opt/ai-security-scanner/grype-db/6/import.json \
    && chmod -R a-w /rootfs/opt/ai-security-scanner/grype-db

FROM scratch

LABEL org.opencontainers.image.title="ai-security-scanner Grype engine" \
      org.opencontainers.image.description="Pinned-source Grype with a checksum-verified offline vulnerability database" \
      org.opencontainers.image.source="https://github.com/anchore/grype" \
      org.opencontainers.image.revision="82d7a0ea911946b99343c672056867d372f9b319" \
      org.opencontainers.image.version="0.121.2-1" \
      org.opencontainers.image.licenses="Apache-2.0" \
      io.ai-security-scanner.database-archive="sha256:9fbc8d8f2428cd715ffc9591cce16c4179955a7f45c76c12fbcb9cea8dc93813"

ENV GRYPE_CHECK_FOR_APP_UPDATE="false" GRYPE_DB_AUTO_UPDATE="false" GRYPE_DB_CACHE_DIR="/opt/ai-security-scanner/grype-db" HOME="/tmp/ai-security-scanner-home" XDG_CACHE_HOME="/tmp/ai-security-scanner-cache"

COPY --from=build /out/grype /usr/local/bin/grype
COPY --from=launcher /out/ai-security-scanner-engine-entrypoint /usr/local/bin/ai-security-scanner-engine-entrypoint
COPY --from=build /src/grype/LICENSE /usr/share/licenses/grype/LICENSE
COPY engines/images/grype/DATABASE-NOTICE.md /usr/share/licenses/grype/DATABASE-NOTICE.md
COPY LICENSE /usr/share/licenses/ai-security-scanner/LICENSE
COPY --from=build /rootfs /

WORKDIR /workspace
USER 65532:65532
ENTRYPOINT ["/usr/local/bin/ai-security-scanner-engine-entrypoint"]
