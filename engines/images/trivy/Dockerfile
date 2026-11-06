# syntax=docker/dockerfile:1.7@sha256:a57df69d0ea827fb7266491f2813635de6f17269be881f696fbfdf2d83dda33e

FROM --platform=$BUILDPLATFORM golang:1.27.3-alpine@sha256:fa3d596898d9f126af7c01d14ee7597bab3f39cccf392ef36b69fe77cd681f18 AS launcher

ARG TARGETOS
ARG TARGETARCH

ENV GOMAXPROCS=2 GOFLAGS="-p=2"

ENV CGO_ENABLED=0 GOTOOLCHAIN=local GOEXPERIMENT=jsonv2 SOURCE_DATE_EPOCH=1793879403

WORKDIR /src/launcher
COPY engines/images/local-launcher/go.mod engines/images/local-launcher/main.go engines/images/local-launcher/main_test.go ./
RUN go test ./... && GOOS=${TARGETOS} GOARCH=${TARGETARCH} go build \
    -buildvcs=false -trimpath -ldflags='-s -w -buildid=' \
    -o /out/ai-security-scanner-engine-entrypoint .

FROM --platform=$BUILDPLATFORM golang:1.27.3-alpine@sha256:fa3d596898d9f126af7c01d14ee7597bab3f39cccf392ef36b69fe77cd681f18 AS build

ARG TARGETOS
ARG TARGETARCH

ENV GOMAXPROCS=2 GOFLAGS="-p=2"

ENV CGO_ENABLED=0 GOTOOLCHAIN=local GOEXPERIMENT=jsonv2 SOURCE_DATE_EPOCH=1793879403

ADD --checksum=sha256:51eda136938852b3aba4de9dc5cd8f2a8d07fabccd9118e7e671f4ab02576295 \
    https://github.com/aquasecurity/trivy/archive/3f6334d223b52188324af3b9923b4249cd206652.tar.gz \
    /tmp/trivy-source.tar.gz
RUN --mount=type=cache,id=ai-security-scanner-trivy-go-mod,target=/go/pkg/mod,sharing=locked \
    --mount=type=cache,id=ai-security-scanner-trivy-go-build,target=/root/.cache/go-build,sharing=locked \
    mkdir -p /src/trivy \
    && tar -xzf /tmp/trivy-source.tar.gz --strip-components=1 -C /src/trivy \
    && cd /src/trivy \
    && echo 'fd69f53dde0ed2a2d70137df634aceaeb19ae12e8ff238fe3d54cb56b1280737  go.sum' | sha256sum -c - \
    && go mod verify \
    && GOOS=${TARGETOS} GOARCH=${TARGETARCH} go build -mod=readonly -buildvcs=false -trimpath \
       -ldflags='-s -w -buildid= -X=github.com/aquasecurity/trivy/pkg/version/app.ver=0.76.2' \
       -o /out/trivy ./cmd/trivy \
    && mkdir -p /rootfs/opt/ai-security-scanner/trivy-cache/db \
         /rootfs/opt/ai-security-scanner/trivy-cache/java-db \
         /rootfs/output /rootfs/workspace /rootfs/tmp \
    && chmod 1777 /rootfs/tmp

COPY .engine-cache/offline/trivy/db.tar.gz /tmp/trivy-db.tar.gz
COPY .engine-cache/offline/trivy/java-db.tar.gz /tmp/trivy-java-db.tar.gz
RUN echo 'c367ecccf6a0367b915ef00b90c43e5958f9ecd9ee6118d2876af6deeca8523c  /tmp/trivy-db.tar.gz' | sha256sum -c - \
    && tar -xzf /tmp/trivy-db.tar.gz -C /rootfs/opt/ai-security-scanner/trivy-cache/db \
    && echo 'acc7850179a48dbe868f97eb59ea186510800ade8ee815392fa2e7b26875c22d  /rootfs/opt/ai-security-scanner/trivy-cache/db/trivy.db' | sha256sum -c - \
    && echo '90057f552cee7a416aa44c0046cc63884f7b466a7c48991c4e70c34ad5cc38a1  /rootfs/opt/ai-security-scanner/trivy-cache/db/metadata.json' | sha256sum -c - \
    && echo 'c6a199cdfd2022f0e4792f9de59b63228d63b904df5858afb1873214427d2a44  /tmp/trivy-java-db.tar.gz' | sha256sum -c - \
    && tar -xzf /tmp/trivy-java-db.tar.gz -C /rootfs/opt/ai-security-scanner/trivy-cache/java-db \
    && echo '7124b5d89aa910c1c79b7cbdd35903ab940762f6ebb27729e558fb197f9ae1db  /rootfs/opt/ai-security-scanner/trivy-cache/java-db/trivy-java.db' | sha256sum -c - \
    && echo 'c10e4a4075e50263d6cf0e97465de3b6aa1b998051348a4cf1d70ffe51e9e441  /rootfs/opt/ai-security-scanner/trivy-cache/java-db/metadata.json' | sha256sum -c - \
    && test "$(find /rootfs/opt/ai-security-scanner/trivy-cache/java-db -mindepth 1 -maxdepth 1 -type f | wc -l)" -eq 2 \
    && chmod -R a-w /rootfs/opt/ai-security-scanner/trivy-cache

FROM scratch

LABEL org.opencontainers.image.title="ai-security-scanner Trivy engine" \
      org.opencontainers.image.description="Pinned-source Trivy input-specific package profiles with checksum-verified offline vulnerability and Java index databases" \
      org.opencontainers.image.source="https://github.com/aquasecurity/trivy" \
      org.opencontainers.image.revision="3f6334d223b52188324af3b9923b4249cd206652" \
      org.opencontainers.image.version="0.76.2-1" \
      org.opencontainers.image.licenses="Apache-2.0" \
      io.ai-security-scanner.database-manifest="sha256:fb417a88061be7d8c246c61cd56e73c91040574fb8cb7b74c48f7a2ea5c2f92f" \
      io.ai-security-scanner.java-database-manifest="sha256:a48270d8181f59baed801e34d73e0857558570c51c9a582eaa3999e897c210e4"

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
