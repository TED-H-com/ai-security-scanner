# syntax=docker/dockerfile:1.7@sha256:a57df69d0ea827fb7266491f2813635de6f17269be881f696fbfdf2d83dda33e

FROM --platform=$BUILDPLATFORM golang:1.25.10-alpine@sha256:8d22e29d960bc50cd025d93d5b7c7d220b1ee9aa7a239b3c8f55a57e987e8d45 AS launcher

ARG TARGETOS
ARG TARGETARCH

ENV CGO_ENABLED=0 GOTOOLCHAIN=local SOURCE_DATE_EPOCH=1791467529

WORKDIR /src/launcher
COPY engines/images/local-launcher/go.mod engines/images/local-launcher/main.go engines/images/local-launcher/main_test.go ./
RUN go test ./... && GOOS=${TARGETOS} GOARCH=${TARGETARCH} go build \
    -buildvcs=false -trimpath -ldflags='-s -w -buildid=' \
    -o /out/ai-security-scanner-engine-entrypoint .

FROM --platform=$BUILDPLATFORM golang:1.25.10-alpine@sha256:8d22e29d960bc50cd025d93d5b7c7d220b1ee9aa7a239b3c8f55a57e987e8d45 AS build

ARG TARGETOS
ARG TARGETARCH

ENV CGO_ENABLED=0 GOTOOLCHAIN=local SOURCE_DATE_EPOCH=1791467529

ADD --checksum=sha256:f288dd98b57cc8ae2dcce2b4c20c8242e6439767ae769714b00d0cafa21fc80f \
    https://github.com/trufflesecurity/trufflehog/archive/e76dff8a7e57d6df0c60ad8cbf5d5cba505a8fc9.tar.gz \
    /tmp/trufflehog-source.tar.gz
RUN mkdir -p /src/trufflehog \
    && tar -xzf /tmp/trufflehog-source.tar.gz --strip-components=1 -C /src/trufflehog \
    && cd /src/trufflehog \
    && echo 'f7731e620591acfd78dba0bae275f65044aa279815e175aaa991c070c9ece0f6  go.sum' | sha256sum -c - \
    && go mod verify \
    && GOOS=${TARGETOS} GOARCH=${TARGETARCH} go build -mod=readonly -buildvcs=false -trimpath \
       -ldflags='-s -w -buildid= -X github.com/trufflesecurity/trufflehog/v3/pkg/version.BuildVersion=3.99.2' \
       -o /out/trufflehog . \
    && mkdir -p /rootfs/output /rootfs/workspace /rootfs/tmp \
    && chmod 1777 /rootfs/tmp

FROM scratch

LABEL org.opencontainers.image.title="ai-security-scanner TruffleHog engine" \
      org.opencontainers.image.description="Pinned-source, filesystem-only secret discovery without credential verification" \
      org.opencontainers.image.source="https://github.com/trufflesecurity/trufflehog" \
      org.opencontainers.image.revision="e76dff8a7e57d6df0c60ad8cbf5d5cba505a8fc9" \
      org.opencontainers.image.version="3.99.2-1" \
      org.opencontainers.image.licenses="AGPL-3.0"

ENV HOME="/tmp/ai-security-scanner-home" XDG_CACHE_HOME="/tmp/ai-security-scanner-cache"

COPY --from=build /out/trufflehog /usr/local/bin/trufflehog
COPY --from=launcher /out/ai-security-scanner-engine-entrypoint /usr/local/bin/ai-security-scanner-engine-entrypoint
COPY --from=build /src/trufflehog/LICENSE /usr/share/licenses/trufflehog/LICENSE
COPY --from=build /tmp/trufflehog-source.tar.gz /usr/share/source/trufflehog-source.tar.gz
COPY engines/images/trufflehog/SOURCE-OFFER.md /usr/share/source/TRUFFLEHOG-SOURCE-OFFER.md
COPY LICENSE /usr/share/licenses/ai-security-scanner/LICENSE
COPY --from=build /rootfs /

WORKDIR /workspace
USER 65532:65532
ENTRYPOINT ["/usr/local/bin/ai-security-scanner-engine-entrypoint"]
