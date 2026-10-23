# syntax=docker/dockerfile:1.7@sha256:a57df69d0ea827fb7266491f2813635de6f17269be881f696fbfdf2d83dda33e

FROM --platform=$BUILDPLATFORM golang:1.27.3-alpine@sha256:b8c9b82affbbb82a020bbcf998dad2ba9516944ac7e883524642a481a9505e9c AS launcher

ARG TARGETOS
ARG TARGETARCH

ENV GOMAXPROCS=2 GOFLAGS="-p=2"

ENV CGO_ENABLED=0 GOTOOLCHAIN=local GOEXPERIMENT=jsonv2 SOURCE_DATE_EPOCH=1792578032

WORKDIR /src/launcher
COPY engines/images/local-launcher/go.mod engines/images/local-launcher/main.go engines/images/local-launcher/main_test.go ./
RUN go test ./... && GOOS=${TARGETOS} GOARCH=${TARGETARCH} go build \
    -buildvcs=false -trimpath -ldflags='-s -w -buildid=' \
    -o /out/ai-security-scanner-engine-entrypoint .

FROM --platform=$BUILDPLATFORM golang:1.27.3-alpine@sha256:b8c9b82affbbb82a020bbcf998dad2ba9516944ac7e883524642a481a9505e9c AS build

ARG TARGETOS
ARG TARGETARCH

ENV GOMAXPROCS=2 GOFLAGS="-p=2"

ENV CGO_ENABLED=0 GOTOOLCHAIN=local GOEXPERIMENT=jsonv2 SOURCE_DATE_EPOCH=1792578032

ADD --checksum=sha256:5bcd06d8bdae338978b8ef597cb23cd0ff2e710d1ea9097c1143ec6b07d362d6 \
    https://github.com/aquasecurity/trivy/archive/e713f67f7d54decdcd9b3132c9751833dcced698.tar.gz \
    /tmp/trivy-source.tar.gz
RUN --mount=type=cache,id=ai-security-scanner-trivy-go-mod,target=/go/pkg/mod,sharing=locked \
    --mount=type=cache,id=ai-security-scanner-trivy-go-build,target=/root/.cache/go-build,sharing=locked \
    mkdir -p /src/trivy \
    && tar -xzf /tmp/trivy-source.tar.gz --strip-components=1 -C /src/trivy \
    && cd /src/trivy \
    && echo '24155b9b13b24ad37ca2938d53304974a18bc84e9db00dd77b0e707c838b1cd6  go.sum' | sha256sum -c - \
    && go mod verify \
    && GOOS=${TARGETOS} GOARCH=${TARGETARCH} go build -mod=readonly -buildvcs=false -trimpath \
       -ldflags='-s -w -buildid= -X=github.com/aquasecurity/trivy/pkg/version/app.ver=0.76.1' \
       -o /out/trivy ./cmd/trivy \
    && mkdir -p /rootfs/opt/ai-security-scanner/trivy-cache/db \
         /rootfs/opt/ai-security-scanner/trivy-cache/java-db \
         /rootfs/output /rootfs/workspace /rootfs/tmp \
    && chmod 1777 /rootfs/tmp

COPY .engine-cache/offline/trivy/db.tar.gz /tmp/trivy-db.tar.gz
COPY .engine-cache/offline/trivy/java-db.tar.gz /tmp/trivy-java-db.tar.gz
RUN echo 'c6b2db527f049abfef0b2ea48e8ee38d7c5475c94612072b5eeca54c18fcb90b  /tmp/trivy-db.tar.gz' | sha256sum -c - \
    && tar -xzf /tmp/trivy-db.tar.gz -C /rootfs/opt/ai-security-scanner/trivy-cache/db \
    && echo 'b21b4f3ced4ff587023a351dcb28c0cf1d72e71159a0161d05591cc2e611abf2  /rootfs/opt/ai-security-scanner/trivy-cache/db/trivy.db' | sha256sum -c - \
    && echo '8b0a74308b3dec2270f7298ced784a323863092487ee7cc22dde96946125feb6  /rootfs/opt/ai-security-scanner/trivy-cache/db/metadata.json' | sha256sum -c - \
    && echo '35c8f473bb7485db657c022eee43404fda3684fc3c0341aef3598db6016c28ca  /tmp/trivy-java-db.tar.gz' | sha256sum -c - \
    && tar -xzf /tmp/trivy-java-db.tar.gz -C /rootfs/opt/ai-security-scanner/trivy-cache/java-db \
    && echo '24d6c783ce89260282c46886b2dab64a69b7fcc31dae4447ed67194b38f77770  /rootfs/opt/ai-security-scanner/trivy-cache/java-db/trivy-java.db' | sha256sum -c - \
    && echo '1b91db7182eda1c8b74db15a4b515238617c5e179d9d1623b82ff0af4a8b4ee2  /rootfs/opt/ai-security-scanner/trivy-cache/java-db/metadata.json' | sha256sum -c - \
    && test "$(find /rootfs/opt/ai-security-scanner/trivy-cache/java-db -mindepth 1 -maxdepth 1 -type f | wc -l)" -eq 2 \
    && chmod -R a-w /rootfs/opt/ai-security-scanner/trivy-cache

FROM scratch

LABEL org.opencontainers.image.title="ai-security-scanner Trivy engine" \
      org.opencontainers.image.description="Pinned-source Trivy input-specific package profiles with checksum-verified offline vulnerability and Java index databases" \
      org.opencontainers.image.source="https://github.com/aquasecurity/trivy" \
      org.opencontainers.image.revision="e713f67f7d54decdcd9b3132c9751833dcced698" \
      org.opencontainers.image.version="0.76.1-1" \
      org.opencontainers.image.licenses="Apache-2.0" \
      io.ai-security-scanner.database-manifest="sha256:4bf3ae89527fbbb3596748b1c9d294a8b240c49edc9f87e65947e42291bb0bf6" \
      io.ai-security-scanner.java-database-manifest="sha256:a805d22ec39082e3d0910a6c37ae4e85c666248293add991d2d2bf82237323a5"

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
