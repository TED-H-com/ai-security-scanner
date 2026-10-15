# syntax=docker/dockerfile:1.7@sha256:a57df69d0ea827fb7266491f2813635de6f17269be881f696fbfdf2d83dda33e

FROM --platform=$BUILDPLATFORM golang:1.27.2-alpine@sha256:f92b6ef800e499660581efdabdf25d9d817a9d124eaf900924f0504e7e27e12d AS launcher

ARG TARGETOS
ARG TARGETARCH

ENV CGO_ENABLED=0 GOTOOLCHAIN=local GOEXPERIMENT=jsonv2 SOURCE_DATE_EPOCH=1791974941

WORKDIR /src/launcher
COPY engines/images/local-launcher/go.mod engines/images/local-launcher/main.go engines/images/local-launcher/main_test.go ./
RUN go test ./... && GOOS=${TARGETOS} GOARCH=${TARGETARCH} go build \
    -buildvcs=false -trimpath -ldflags='-s -w -buildid=' \
    -o /out/ai-security-scanner-engine-entrypoint .

FROM --platform=$BUILDPLATFORM golang:1.27.2-alpine@sha256:f92b6ef800e499660581efdabdf25d9d817a9d124eaf900924f0504e7e27e12d AS build

ARG TARGETOS
ARG TARGETARCH

ENV CGO_ENABLED=0 GOTOOLCHAIN=local GOEXPERIMENT=jsonv2 SOURCE_DATE_EPOCH=1791974941

ADD --checksum=sha256:2800c0c0991830fa2236817f77448e657cbabc77acf04a71cd4d0afcea66d6c0 \
    https://github.com/aquasecurity/trivy/archive/531360e5d2a88e732373f1614ba99a38738538b8.tar.gz \
    /tmp/trivy-source.tar.gz
RUN --mount=type=cache,id=ai-security-scanner-trivy-go-mod,target=/go/pkg/mod,sharing=locked \
    --mount=type=cache,id=ai-security-scanner-trivy-go-build,target=/root/.cache/go-build,sharing=locked \
    mkdir -p /src/trivy \
    && tar -xzf /tmp/trivy-source.tar.gz --strip-components=1 -C /src/trivy \
    && cd /src/trivy \
    && echo '25f644f393818a3b88155a18fa0cb34487f40d9e4fe58d6964add86293668093  go.sum' | sha256sum -c - \
    && go mod verify \
    && GOOS=${TARGETOS} GOARCH=${TARGETARCH} go build -mod=readonly -buildvcs=false -trimpath \
       -ldflags='-s -w -buildid= -X=github.com/aquasecurity/trivy/pkg/version/app.ver=0.76.0' \
       -o /out/trivy ./cmd/trivy \
    && mkdir -p /rootfs/opt/ai-security-scanner/trivy-cache/db \
         /rootfs/opt/ai-security-scanner/trivy-cache/java-db \
         /rootfs/output /rootfs/workspace /rootfs/tmp \
    && chmod 1777 /rootfs/tmp

COPY .engine-cache/offline/trivy/db.tar.gz /tmp/trivy-db.tar.gz
COPY .engine-cache/offline/trivy/java-db.tar.gz /tmp/trivy-java-db.tar.gz
RUN echo '330b31ecc8312e6f0a8eec86c328234acf84c43954846139522fb36df85b5ea6  /tmp/trivy-db.tar.gz' | sha256sum -c - \
    && tar -xzf /tmp/trivy-db.tar.gz -C /rootfs/opt/ai-security-scanner/trivy-cache/db \
    && echo '1f86b775c8bad1b9fa31f91e6523a8b33ba85f9c8529970aceae32663d21bd10  /rootfs/opt/ai-security-scanner/trivy-cache/db/trivy.db' | sha256sum -c - \
    && echo 'e4bc8c46a8295f01122651e3fa2ee0520ab4a5408241f213374262cae72183ba  /rootfs/opt/ai-security-scanner/trivy-cache/db/metadata.json' | sha256sum -c - \
    && echo '33244241111425d2f4ae10daf1de961edd47673265862d7abac688a60948301c  /tmp/trivy-java-db.tar.gz' | sha256sum -c - \
    && tar -xzf /tmp/trivy-java-db.tar.gz -C /rootfs/opt/ai-security-scanner/trivy-cache/java-db \
    && echo 'c26ec91db03a11014dfa45909d2b5275c0e34c2dee276363bc0c9693375acc25  /rootfs/opt/ai-security-scanner/trivy-cache/java-db/trivy-java.db' | sha256sum -c - \
    && echo '486b01dacad2d0f5dc28006fef82f501249f8be922e2f6f037a61152b567f24d  /rootfs/opt/ai-security-scanner/trivy-cache/java-db/metadata.json' | sha256sum -c - \
    && test "$(find /rootfs/opt/ai-security-scanner/trivy-cache/java-db -mindepth 1 -maxdepth 1 -type f | wc -l)" -eq 2 \
    && chmod -R a-w /rootfs/opt/ai-security-scanner/trivy-cache

FROM scratch

LABEL org.opencontainers.image.title="ai-security-scanner Trivy engine" \
      org.opencontainers.image.description="Pinned-source Trivy input-specific package profiles with checksum-verified offline vulnerability and Java index databases" \
      org.opencontainers.image.source="https://github.com/aquasecurity/trivy" \
      org.opencontainers.image.revision="531360e5d2a88e732373f1614ba99a38738538b8" \
      org.opencontainers.image.version="0.76.0-1" \
      org.opencontainers.image.licenses="Apache-2.0" \
      io.ai-security-scanner.database-manifest="sha256:52132f8ca6e26a5ebbc4d758a9b2f20c9537725635f185f9c19b0600f45fe3c1" \
      io.ai-security-scanner.java-database-manifest="sha256:e578af6b1e7db314ec2d3714ba522af8e9cd59c1a4349b7d6f54d86b2b8125b0"

ENV HOME="/tmp/ai-security-scanner-home" TRIVY_CACHE_DIR="/opt/ai-security-scanner/trivy-cache" XDG_CACHE_HOME="/tmp/ai-security-scanner-cache"

COPY --from=build /out/trivy /usr/local/bin/trivy
COPY --from=launcher /out/ai-security-scanner-engine-entrypoint /usr/local/bin/ai-security-scanner-engine-entrypoint
COPY --from=build /src/trivy/LICENSE /usr/share/licenses/trivy/LICENSE
COPY engines/images/trivy/DATABASE-NOTICE.md /usr/share/licenses/trivy/DATABASE-NOTICE.md
COPY LICENSE /usr/share/licenses/ai-security-scanner/LICENSE
COPY --from=build /rootfs /

WORKDIR /workspace
USER 65532:65532
ENTRYPOINT ["/usr/local/bin/ai-security-scanner-engine-entrypoint"]
