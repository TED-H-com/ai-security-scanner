# syntax=docker/dockerfile:1.7@sha256:a57df69d0ea827fb7266491f2813635de6f17269be881f696fbfdf2d83dda33e

FROM --platform=$BUILDPLATFORM golang:1.26.3-alpine@sha256:91eda9776261207ea25fd06b5b7fed8d397dd2c0a283e77f2ab6e91bfa71079d AS launcher

ARG TARGETOS
ARG TARGETARCH

ENV CGO_ENABLED=0 GOTOOLCHAIN=local SOURCE_DATE_EPOCH=1787042782

WORKDIR /src/launcher
COPY engines/images/local-launcher/go.mod engines/images/local-launcher/main.go engines/images/local-launcher/main_test.go ./
RUN go test ./... && GOOS=${TARGETOS} GOARCH=${TARGETARCH} go build \
    -buildvcs=false -trimpath -ldflags='-s -w -buildid=' \
    -o /out/ai-security-scanner-engine-entrypoint .

FROM --platform=$BUILDPLATFORM golang:1.26.3-alpine@sha256:91eda9776261207ea25fd06b5b7fed8d397dd2c0a283e77f2ab6e91bfa71079d AS build

ARG TARGETOS
ARG TARGETARCH

ENV CGO_ENABLED=0 GOTOOLCHAIN=local SOURCE_DATE_EPOCH=1787042782

ADD --checksum=sha256:086873d32ee5b72f28d799df5310a8e8968dfb93df560462605ec49938af7da1 \
    https://github.com/aquasecurity/kube-bench/archive/9f133cb7509ce1dbedfc860e94474588000e25ac.tar.gz \
    /tmp/kube-bench-source.tar.gz
RUN mkdir -p /src/kube-bench \
    && tar -xzf /tmp/kube-bench-source.tar.gz --strip-components=1 -C /src/kube-bench \
    && cd /src/kube-bench \
    && echo 'b9bb74a6b3661413e6378edc132ad2274983a24899c85828a27c29bb4fb4b980  go.sum' | sha256sum -c - \
    && echo '276ade4e21a043f508328ce5598c15fd0f421fe60a8d7e41774439cb355bf6a7  cfg/cis-1.11/node.yaml' | sha256sum -c - \
    && echo 'f8beefa9c5392e5c25d03e802294ad1852ac094d3bf3053903dad718f599e3b7  cfg/cis-1.11/config.yaml' | sha256sum -c - \
    && go mod verify \
    && GOOS=${TARGETOS} GOARCH=${TARGETARCH} go build -mod=readonly -buildvcs=false -trimpath \
       -ldflags='-s -w -buildid= -X github.com/aquasecurity/kube-bench/cmd.KubeBenchVersion=v0.16.0' \
       -o /out/kube-bench .

FROM alpine:3.23@sha256:fd791d74b68913cbb027c6546007b3f0d3bc45125f797758156952bc2d6daf40

LABEL org.opencontainers.image.title="ai-security-scanner kube-bench engine" \
      org.opencontainers.image.description="Pinned-source kube-bench CIS 1.11 node profile over explicit immutable node-facts snapshots" \
      org.opencontainers.image.source="https://github.com/aquasecurity/kube-bench" \
      org.opencontainers.image.revision="9f133cb7509ce1dbedfc860e94474588000e25ac" \
      org.opencontainers.image.version="0.16.0-5" \
      org.opencontainers.image.licenses="Apache-2.0"

RUN addgroup -g 65532 scanner \
    && adduser -D -H -u 65532 -G scanner scanner \
    && mkdir -p /workspace /output /opt/ai-security-scanner/kube-bench/cfg/cis-1.11 \
    && chown scanner:scanner /output \
    && chmod 0555 /workspace /opt/ai-security-scanner/kube-bench /opt/ai-security-scanner/kube-bench/cfg /opt/ai-security-scanner/kube-bench/cfg/cis-1.11 \
    && rm -f /bin/ps

COPY --from=build /out/kube-bench /usr/local/bin/kube-bench
COPY --from=launcher /out/ai-security-scanner-engine-entrypoint /usr/local/bin/ai-security-scanner-engine-entrypoint
COPY --from=launcher /out/ai-security-scanner-engine-entrypoint /usr/local/bin/ps
COPY --from=launcher /out/ai-security-scanner-engine-entrypoint /bin/ps
COPY --from=launcher /out/ai-security-scanner-engine-entrypoint /usr/local/bin/stat
COPY --from=build /src/kube-bench/LICENSE /usr/share/licenses/kube-bench/LICENSE
COPY engines/images/kube-bench/cfg/config.yaml /opt/ai-security-scanner/kube-bench/cfg/config.yaml
COPY --from=build /src/kube-bench/cfg/cis-1.11/config.yaml /opt/ai-security-scanner/kube-bench/cfg/cis-1.11/config.yaml
COPY --from=build /src/kube-bench/cfg/cis-1.11/node.yaml /opt/ai-security-scanner/kube-bench/cfg/cis-1.11/node.yaml
COPY engines/images/kube-bench/SNAPSHOT-PROFILE.md /usr/share/doc/ai-security-scanner/kube-bench-snapshot-profile.md
COPY LICENSE /usr/share/licenses/ai-security-scanner/LICENSE

ENV HOME="/tmp/ai-security-scanner-home" XDG_CACHE_HOME="/tmp/ai-security-scanner-cache"
WORKDIR /workspace
USER 65532:65532
ENTRYPOINT ["/usr/local/bin/ai-security-scanner-engine-entrypoint"]
