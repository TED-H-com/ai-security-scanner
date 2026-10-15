# syntax=docker/dockerfile:1.7@sha256:a57df69d0ea827fb7266491f2813635de6f17269be881f696fbfdf2d83dda33e

FROM --platform=$BUILDPLATFORM golang:1.26.8-alpine@sha256:8ac98ca534ac3f51e1f420a1dd2c15e74c75cfa0f23f3ad27eb5d7236c349a0c AS launcher

ARG TARGETOS
ARG TARGETARCH

ENV CGO_ENABLED=0 GOTOOLCHAIN=local SOURCE_DATE_EPOCH=1791304928

WORKDIR /src/launcher
COPY engines/images/local-launcher/go.mod engines/images/local-launcher/main.go engines/images/local-launcher/main_test.go ./
RUN go test ./... && GOOS=${TARGETOS} GOARCH=${TARGETARCH} go build \
    -buildvcs=false -trimpath -ldflags='-s -w -buildid=' \
    -o /out/ai-security-scanner-engine-entrypoint .

FROM --platform=$BUILDPLATFORM golang:1.26.8-alpine@sha256:8ac98ca534ac3f51e1f420a1dd2c15e74c75cfa0f23f3ad27eb5d7236c349a0c AS build

ARG TARGETOS
ARG TARGETARCH

ENV CGO_ENABLED=0 GOTOOLCHAIN=local SOURCE_DATE_EPOCH=1791304928

RUN apk add --no-cache zstd=1.5.7-r2

ADD --checksum=sha256:238f5623555bed2190d8db85c3f48c8d50b13d230644ada3a9756acc702eec37 \
    https://github.com/anchore/grype/archive/6f8d854af29d3a3086b11a84afa51554a2a245fe.tar.gz \
    /tmp/grype-source.tar.gz
RUN mkdir -p /src/grype \
    && tar -xzf /tmp/grype-source.tar.gz --strip-components=1 -C /src/grype \
    && cd /src/grype \
    && echo 'f99cc9d2351c0247045b3c7b3f4720e71c3c4b175359e3a18eee3d395bd23cd1  go.sum' | sha256sum -c - \
    && go mod verify \
    && cd /src/grype/cmd/grype \
    && GOOS=${TARGETOS} GOARCH=${TARGETARCH} go build -mod=readonly -buildvcs=false -trimpath \
       -ldflags='-s -w -buildid= -extldflags=-static -X main.version=0.120.1 -X main.gitCommit=6f8d854af29d3a3086b11a84afa51554a2a245fe -X main.buildDate=2026-10-06T16:42:08Z -X main.gitDescription=v0.120.1' \
       -o /out/grype . \
    && mkdir -p /rootfs/opt/ai-security-scanner/grype-db/6 /rootfs/output /rootfs/workspace /rootfs/tmp \
    && chmod 1777 /rootfs/tmp

COPY .engine-cache/offline/grype/db.tar.zst /tmp/grype-db.tar.zst
COPY engines/images/grype/import.json /tmp/grype-import.json
RUN echo '30d8bcd3c09e03c9f734c522e104c1387e285e3f6e33da2ee7b55f521daadb3f  /tmp/grype-db.tar.zst' | sha256sum -c - \
    && zstd --decompress --stdout /tmp/grype-db.tar.zst > /tmp/grype-db.tar \
    && tar -xf /tmp/grype-db.tar -C /rootfs/opt/ai-security-scanner/grype-db/6 \
    && echo '8be8779b1b6fd721e6127c092bd25d5875e25cd511def5d9e7d026fb45189058  /rootfs/opt/ai-security-scanner/grype-db/6/vulnerability.db' | sha256sum -c - \
    && cp /tmp/grype-import.json /rootfs/opt/ai-security-scanner/grype-db/6/import.json \
    && chmod -R a-w /rootfs/opt/ai-security-scanner/grype-db

FROM scratch

LABEL org.opencontainers.image.title="ai-security-scanner Grype engine" \
      org.opencontainers.image.description="Pinned-source Grype with a checksum-verified offline vulnerability database" \
      org.opencontainers.image.source="https://github.com/anchore/grype" \
      org.opencontainers.image.revision="6f8d854af29d3a3086b11a84afa51554a2a245fe" \
      org.opencontainers.image.version="0.120.1-1" \
      org.opencontainers.image.licenses="Apache-2.0" \
      io.ai-security-scanner.database-archive="sha256:30d8bcd3c09e03c9f734c522e104c1387e285e3f6e33da2ee7b55f521daadb3f"

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
