# syntax=docker/dockerfile:1.7@sha256:a57df69d0ea827fb7266491f2813635de6f17269be881f696fbfdf2d83dda33e

FROM --platform=$BUILDPLATFORM golang:1.26.8-alpine@sha256:8ac98ca534ac3f51e1f420a1dd2c15e74c75cfa0f23f3ad27eb5d7236c349a0c AS launcher

ARG TARGETOS
ARG TARGETARCH

ENV CGO_ENABLED=0 GOTOOLCHAIN=local SOURCE_DATE_EPOCH=1791974598

WORKDIR /src/launcher
COPY engines/images/local-launcher/go.mod engines/images/local-launcher/main.go engines/images/local-launcher/main_test.go ./
RUN go test ./... && GOOS=${TARGETOS} GOARCH=${TARGETARCH} go build \
    -buildvcs=false -trimpath -ldflags='-s -w -buildid=' \
    -o /out/ai-security-scanner-engine-entrypoint .

FROM --platform=$BUILDPLATFORM golang:1.26.8-alpine@sha256:8ac98ca534ac3f51e1f420a1dd2c15e74c75cfa0f23f3ad27eb5d7236c349a0c AS build

ARG TARGETOS
ARG TARGETARCH

ENV CGO_ENABLED=0 GOTOOLCHAIN=local SOURCE_DATE_EPOCH=1791974598

ADD --checksum=sha256:139f676aa5047582ad528adf4eff9cad5cc0e05a36c53c66e7842b85f60f2b06 \
    https://github.com/kubescape/kubescape/archive/d0ea07bcd9d7ab1640dcd6527d0e68a34f10da0e.tar.gz \
    /tmp/kubescape-source.tar.gz
RUN mkdir -p /src/kubescape \
    && tar -xzf /tmp/kubescape-source.tar.gz --strip-components=1 -C /src/kubescape \
    && cd /src/kubescape \
    && echo '9eea489de88e2acc4e6f1f4b3f1556865e302f9c4c527564a4cb3529283bb667  go.sum' | sha256sum -c - \
    && go mod verify \
    && GOOS=${TARGETOS} GOARCH=${TARGETARCH} go build -mod=readonly -buildvcs=false -trimpath \
       -ldflags='-s -w -buildid= -X main.version=v4.0.16 -X main.commit=d0ea07bcd9d7ab1640dcd6527d0e68a34f10da0e -X main.date=2026-10-14T10:43:18Z' \
       -o /out/kubescape . \
    && mkdir -p /rootfs/opt/ai-security-scanner/kubescape-artifacts /rootfs/output /rootfs/workspace /rootfs/tmp \
    && chmod 1777 /rootfs/tmp

ADD --checksum=sha256:80e23ca99be3e5bb0f80d968b32ae27b7dada39f9b12b9e3abffea8680ac7737 \
    https://github.com/kubescape/regolibrary/releases/download/v2/nsa \
    /rootfs/opt/ai-security-scanner/kubescape-artifacts/nsa.json
ADD --checksum=sha256:6b78fae941db97d00780898da40581168303985e6dae0c74799f2c0a6ff5a8b6 \
    https://github.com/kubescape/regolibrary/releases/download/v2/default_config_inputs \
    /rootfs/opt/ai-security-scanner/kubescape-artifacts/controls-inputs.json
ADD --checksum=sha256:d0b662af82db3fd6b2d8a242e1c7a46f47941ac7c298c2525481f817d928ddc3 \
    https://github.com/kubescape/regolibrary/releases/download/v2/exceptions \
    /rootfs/opt/ai-security-scanner/kubescape-artifacts/exceptions.json
RUN chmod -R a+rX,a-w /rootfs/opt/ai-security-scanner/kubescape-artifacts

FROM scratch

LABEL org.opencontainers.image.title="ai-security-scanner Kubescape engine" \
      org.opencontainers.image.description="Pinned-source, offline NSA policy scan for explicit local Kubernetes manifests" \
      org.opencontainers.image.source="https://github.com/kubescape/kubescape" \
      org.opencontainers.image.revision="d0ea07bcd9d7ab1640dcd6527d0e68a34f10da0e" \
      org.opencontainers.image.version="4.0.16-1" \
      org.opencontainers.image.licenses="Apache-2.0" \
      io.ai-security-scanner.regolibrary-revision="f01135a697e6f710c1797bd7cd0d2ea42ec98f9f"

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
