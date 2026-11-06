# syntax=docker/dockerfile:1.7@sha256:a57df69d0ea827fb7266491f2813635de6f17269be881f696fbfdf2d83dda33e

FROM --platform=$BUILDPLATFORM golang:1.26.10-alpine@sha256:87c65a688975c0b1d4585d204874c45ca78354670e3a5f11368c5a492303d696 AS launcher

ARG TARGETOS
ARG TARGETARCH

ENV CGO_ENABLED=0 GOTOOLCHAIN=local SOURCE_DATE_EPOCH=1793644548

WORKDIR /src/launcher
COPY engines/images/local-launcher/go.mod engines/images/local-launcher/main.go engines/images/local-launcher/main_test.go ./
RUN go test ./... && GOOS=${TARGETOS} GOARCH=${TARGETARCH} go build \
    -buildvcs=false -trimpath -ldflags='-s -w -buildid=' \
    -o /out/ai-security-scanner-engine-entrypoint .

FROM --platform=$BUILDPLATFORM golang:1.26.10-alpine@sha256:87c65a688975c0b1d4585d204874c45ca78354670e3a5f11368c5a492303d696 AS build

ARG TARGETOS
ARG TARGETARCH

ENV CGO_ENABLED=0 GOTOOLCHAIN=local SOURCE_DATE_EPOCH=1793644548

ADD --checksum=sha256:218facf110829b3e01d33f1b642edc9c6bfde692041f0cebefd4daaf5326ff1c \
    https://github.com/trufflesecurity/trufflehog/archive/ea68ca03c865c5f324e86e849ced20ed3cf9dbbb.tar.gz \
    /tmp/trufflehog-source.tar.gz
RUN mkdir -p /src/trufflehog \
    && tar -xzf /tmp/trufflehog-source.tar.gz --strip-components=1 -C /src/trufflehog \
    && cd /src/trufflehog \
    && echo '6651871edd06ebcd45bfe4dfacd5d2f26ec24666d5368cbd74e7a5a0d0e67eae  go.sum' | sha256sum -c - \
    && go mod verify \
    && GOOS=${TARGETOS} GOARCH=${TARGETARCH} go build -mod=readonly -buildvcs=false -trimpath \
       -ldflags='-s -w -buildid= -X github.com/trufflesecurity/trufflehog/v3/pkg/version.BuildVersion=3.99.8' \
       -o /out/trufflehog . \
    && mkdir -p /rootfs/output /rootfs/workspace /rootfs/tmp \
    && chmod 1777 /rootfs/tmp

FROM scratch

LABEL org.opencontainers.image.title="ai-security-scanner TruffleHog engine" \
      org.opencontainers.image.description="Pinned-source, filesystem-only secret discovery without credential verification" \
      org.opencontainers.image.source="https://github.com/trufflesecurity/trufflehog" \
      org.opencontainers.image.revision="ea68ca03c865c5f324e86e849ced20ed3cf9dbbb" \
      org.opencontainers.image.version="3.99.8-1" \
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
