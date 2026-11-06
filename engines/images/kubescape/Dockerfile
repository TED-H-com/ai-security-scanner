# syntax=docker/dockerfile:1.7@sha256:a57df69d0ea827fb7266491f2813635de6f17269be881f696fbfdf2d83dda33e

FROM --platform=$BUILDPLATFORM golang:1.27.3-alpine@sha256:fa3d596898d9f126af7c01d14ee7597bab3f39cccf392ef36b69fe77cd681f18 AS launcher

ARG TARGETOS
ARG TARGETARCH

ENV CGO_ENABLED=0 GOTOOLCHAIN=local SOURCE_DATE_EPOCH=1793880748

WORKDIR /src/launcher
COPY engines/images/local-launcher/go.mod engines/images/local-launcher/main.go engines/images/local-launcher/main_test.go ./
RUN go test ./... && GOOS=${TARGETOS} GOARCH=${TARGETARCH} go build \
    -buildvcs=false -trimpath -ldflags='-s -w -buildid=' \
    -o /out/ai-security-scanner-engine-entrypoint .

FROM --platform=$BUILDPLATFORM golang:1.27.3-alpine@sha256:fa3d596898d9f126af7c01d14ee7597bab3f39cccf392ef36b69fe77cd681f18 AS build

ARG TARGETOS
ARG TARGETARCH

ENV CGO_ENABLED=0 GOTOOLCHAIN=local SOURCE_DATE_EPOCH=1793880748

ADD --checksum=sha256:3135fb7adadcd63ac6483efb8ce9b742cfe7567b6dbac7b8f92d8e4174835ae3 \
    https://github.com/kubescape/kubescape/archive/9780473d81b3b3e036408d6323b162a197beee07.tar.gz \
    /tmp/kubescape-source.tar.gz
RUN mkdir -p /src/kubescape \
    && tar -xzf /tmp/kubescape-source.tar.gz --strip-components=1 -C /src/kubescape \
    && cd /src/kubescape \
    && echo '50ca6dbe42fbd7f888d2f0291eec1d474fbd3c837973f2c3145a667afd1759f6  go.sum' | sha256sum -c - \
    && go mod verify \
    && GOOS=${TARGETOS} GOARCH=${TARGETARCH} go build -mod=readonly -buildvcs=false -trimpath \
       -ldflags='-s -w -buildid= -X main.version=v4.0.19 -X main.commit=9780473d81b3b3e036408d6323b162a197beee07 -X main.date=2026-11-05T12:12:28Z' \
       -o /out/kubescape . \
    && mkdir -p /rootfs/opt/ai-security-scanner/kubescape-artifacts /rootfs/output /rootfs/workspace /rootfs/tmp \
    && chmod 1777 /rootfs/tmp

ADD --checksum=sha256:d5f079fb766304b264a5749499f1a3a466ab88bca7730dd72b48c3bd9a931432 \
    https://github.com/kubescape/regolibrary/releases/download/v2/nsa \
    /rootfs/opt/ai-security-scanner/kubescape-artifacts/nsa.json
ADD --checksum=sha256:6e05e01793eecc8dad788ae3b0d83138ae9eddb6f5932c113ae1bd8ffc97b8c7 \
    https://github.com/kubescape/regolibrary/releases/download/v2/default_config_inputs \
    /rootfs/opt/ai-security-scanner/kubescape-artifacts/controls-inputs.json
ADD --checksum=sha256:e7f1ad0e9dcae362c4b365ea1dde9f22d8663d9c9e4ca51c84a5f5c71618ec4b \
    https://github.com/kubescape/regolibrary/releases/download/v2/exceptions \
    /rootfs/opt/ai-security-scanner/kubescape-artifacts/exceptions.json
RUN chmod -R a+rX,a-w /rootfs/opt/ai-security-scanner/kubescape-artifacts

FROM scratch

LABEL org.opencontainers.image.title="ai-security-scanner Kubescape engine" \
      org.opencontainers.image.description="Pinned-source, offline NSA policy scan for explicit local Kubernetes manifests" \
      org.opencontainers.image.source="https://github.com/kubescape/kubescape" \
      org.opencontainers.image.revision="9780473d81b3b3e036408d6323b162a197beee07" \
      org.opencontainers.image.version="4.0.19-1" \
      org.opencontainers.image.licenses="Apache-2.0" \
      io.ai-security-scanner.regolibrary-revision="3065a55568bcf3b5c3d0b19e3f3fec5b404abb4c"

ENV HOME="/tmp/ai-security-scanner-home" KS_SUBMIT="false" OTEL_SDK_DISABLED="true" XDG_CACHE_HOME="/tmp/ai-security-scanner-cache"

COPY --from=build /out/kubescape /usr/local/bin/kubescape
COPY --from=launcher /out/ai-security-scanner-engine-entrypoint /usr/local/bin/ai-security-scanner-engine-entrypoint
COPY --from=build /src/kubescape/LICENSE /usr/share/licenses/kubescape/LICENSE
COPY engines/images/kubescape/ARTIFACT-NOTICE.md /usr/share/licenses/kubescape/ARTIFACT-NOTICE.md
COPY LICENSE /usr/share/licenses/ai-security-scanner/LICENSE
COPY --from=build /rootfs /

WORKDIR /workspace
USER 65532:65532
ENTRYPOINT ["/usr/local/bin/ai-security-scanner-engine-entrypoint"]
