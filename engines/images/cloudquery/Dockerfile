# syntax=docker/dockerfile:1.7@sha256:a57df69d0ea827fb7266491f2813635de6f17269be881f696fbfdf2d83dda33e

ARG SOURCE_REVISION=086baf7f70ee3c1069513d41f321720a5e7d2bb9
ARG AWS_SOURCE_REVISION=804be3a90d6f15d3e6c662c0eb7afa88a9596180
ARG FILE_SOURCE_REVISION=600ffdd2707af566e3c99469d84a34d94730aaa1

FROM --platform=$BUILDPLATFORM golang:1.26.10-alpine@sha256:87c65a688975c0b1d4585d204874c45ca78354670e3a5f11368c5a492303d696 AS launcher
ARG TARGETOS
ARG TARGETARCH
WORKDIR /src
COPY engines/images/cloud-launcher/go.mod engines/images/cloud-launcher/main.go ./
RUN CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} \
      go build -buildvcs=false -trimpath -ldflags='-s -w -buildid=' \
      -o /out/ai-security-scanner-cloud-launcher .

FROM alpine:3.23@sha256:fd791d74b68913cbb027c6546007b3f0d3bc45125f797758156952bc2d6daf40 AS artifacts
ARG TARGETARCH

ADD --checksum=sha256:996fee38e47a629e6908b5a2662e9a96a4df717525eee5a3f6a757a76a6d8cba \
    https://github.com/cloudquery/cloudquery/releases/download/cli-v3.5.3/cloudquery_linux_amd64 \
    /downloads/cloudquery-linux-amd64
ADD --checksum=sha256:4db2d20bc09fd35dc63497cd4db85297e2aaeff033e6fd7eca75c3e0672ba937 \
    https://github.com/cloudquery/cloudquery/releases/download/cli-v3.5.3/cloudquery_linux_arm64 \
    /downloads/cloudquery-linux-arm64
ADD --checksum=sha256:138cb293cc691725914bd59ab452fb29b13b32e1c92f3da1410720349ba9004d \
    https://github.com/cloudquery/cloudquery/releases/download/plugins-source-aws-v9.2.0/aws_linux_amd64.zip \
    /downloads/aws-linux-amd64.zip
ADD --checksum=sha256:d9dd75752cf6f2f7cd5d9ba9639927e4ce00ddce3acb2af4d05dd2af6fa9fc9c \
    https://github.com/cloudquery/cloudquery/releases/download/plugins-source-aws-v9.2.0/aws_linux_arm64.zip \
    /downloads/aws-linux-arm64.zip
ADD --checksum=sha256:4a53fe39f9c9daa377369dc0ad1be47e47e4ede99911dcd954476b0d47fe356b \
    https://github.com/cloudquery/cloudquery/releases/download/plugins-destination-file-v1.0.4/file_linux_amd64.zip \
    /downloads/file-linux-amd64.zip
ADD --checksum=sha256:e8885e5f3e5ccd9325ed4f35e40774b649f88440fc2b4dc3a4a9a03ed93fdaa2 \
    https://github.com/cloudquery/cloudquery/releases/download/plugins-destination-file-v1.0.4/file_linux_arm64.zip \
    /downloads/file-linux-arm64.zip
ADD --checksum=sha256:a4788989f99ab02144605539ab552e86c076405ac7516fb673e73ba6bda40c6b \
    https://github.com/cloudquery/cloudquery/archive/804be3a90d6f15d3e6c662c0eb7afa88a9596180.tar.gz \
    /downloads/aws-source.tar.gz
ADD --checksum=sha256:ae47bd08e22aac0263784c1915c60d00111ef13145550c6d177af9fb24c7eeaf \
    https://github.com/cloudquery/cloudquery/archive/086baf7f70ee3c1069513d41f321720a5e7d2bb9.tar.gz \
    /downloads/cli-source.tar.gz
ADD --checksum=sha256:700e2008b33a31a6e396d1e348464d2e832c856fdd9b4e45362f90b84bf92a5f \
    https://github.com/cloudquery/cloudquery/archive/600ffdd2707af566e3c99469d84a34d94730aaa1.tar.gz \
    /downloads/file-source.tar.gz

RUN set -eu; \
    case "${TARGETARCH}" in \
      amd64) \
        cli=/downloads/cloudquery-linux-amd64; \
        aws=/downloads/aws-linux-amd64.zip; \
        file=/downloads/file-linux-amd64.zip; \
        aws_sha=c7460b15d200d606e1d339889acb5482c15cbf6346e278943492808a4b2cbc90; \
        file_sha=61b25f842a1f9d48db367d754641f8cccd1b3a089d517a5d4d3b54b61b82b2b9 ;; \
      arm64) \
        cli=/downloads/cloudquery-linux-arm64; \
        aws=/downloads/aws-linux-arm64.zip; \
        file=/downloads/file-linux-arm64.zip; \
        aws_sha=5d1b00b1dac8701d9ace39ed21bd927e6fe499637df09b0635405a58c578e998; \
        file_sha=63c2f522dfa21ff4d3915ae96b061a216bf81a3dbc49f53b41931697d2909379 ;; \
      *) echo "unsupported CloudQuery target architecture" >&2; exit 64 ;; \
    esac; \
    mkdir -p /out /extract/aws /extract/file /source/aws /source/cli /source/file; \
    cp "${cli}" /out/cloudquery; \
    unzip -q "${aws}" plugins/source/aws -d /extract/aws; \
    unzip -q "${file}" plugins/destination/file -d /extract/file; \
    cp /extract/aws/plugins/source/aws /out/cloudquery-source-aws; \
    cp /extract/file/plugins/destination/file /out/cloudquery-destination-file; \
    test "$(sha256sum /out/cloudquery-source-aws | cut -d' ' -f1)" = "${aws_sha}"; \
    test "$(sha256sum /out/cloudquery-destination-file | cut -d' ' -f1)" = "${file_sha}"; \
    tar --extract --gzip --file=/downloads/aws-source.tar.gz \
      --directory=/source/aws --strip-components=1 --no-same-owner; \
    tar --extract --gzip --file=/downloads/cli-source.tar.gz \
      --directory=/source/cli --strip-components=1 --no-same-owner; \
    tar --extract --gzip --file=/downloads/file-source.tar.gz \
      --directory=/source/file --strip-components=1 --no-same-owner; \
    test -f /source/aws/plugins/source/aws/go.sum; \
    test -f /source/cli/cli/go.sum; \
    test -f /source/file/plugins/destination/file/go.sum; \
    cp /source/aws/LICENSE /out/LICENSE; \
    chmod 0555 /out/cloudquery /out/cloudquery-source-aws /out/cloudquery-destination-file; \
    chmod 0444 /out/LICENSE /downloads/aws-source.tar.gz /downloads/cli-source.tar.gz /downloads/file-source.tar.gz

FROM scratch
ARG SOURCE_REVISION
ARG AWS_SOURCE_REVISION
ARG FILE_SOURCE_REVISION
LABEL org.opencontainers.image.title="ai-security-scanner CloudQuery engine" \
      org.opencontainers.image.description="Anonymous public CloudQuery AWS IAM inventory source closure with scanner-owned launcher" \
      org.opencontainers.image.source="https://github.com/teddashh/ai-security-scanner" \
      org.opencontainers.image.revision="${SOURCE_REVISION}" \
      org.opencontainers.image.version="3.5.3-aws9.2.0-file1.0.4-1" \
      org.opencontainers.image.licenses="MPL-2.0" \
      io.ai-security-scanner.cloudquery-cli.version="3.5.3" \
      io.ai-security-scanner.cloudquery-aws.version="9.2.0" \
      io.ai-security-scanner.cloudquery-file.version="1.0.4" \
      io.ai-security-scanner.cloudquery-cli.source-revision="${SOURCE_REVISION}" \
      io.ai-security-scanner.cloudquery-aws.source-revision="${AWS_SOURCE_REVISION}" \
      io.ai-security-scanner.cloudquery-file.source-revision="${FILE_SOURCE_REVISION}" \
      io.ai-security-scanner.cloudquery-cli.source-archive-sha256="ae47bd08e22aac0263784c1915c60d00111ef13145550c6d177af9fb24c7eeaf" \
      io.ai-security-scanner.cloudquery-aws.source-archive-sha256="a4788989f99ab02144605539ab552e86c076405ac7516fb673e73ba6bda40c6b" \
      io.ai-security-scanner.cloudquery-file.source-archive-sha256="700e2008b33a31a6e396d1e348464d2e832c856fdd9b4e45362f90b84bf92a5f" \
      io.ai-security-scanner.profile="aws-iam-us-east-1"

COPY --from=launcher /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=launcher --chmod=0555 /out/ai-security-scanner-cloud-launcher /usr/local/bin/ai-security-scanner-cloud-launcher
COPY --from=artifacts --chmod=0555 /out/cloudquery /app/cloudquery
COPY --from=artifacts --chmod=0555 /out/cloudquery-source-aws /usr/local/libexec/cloudquery-source-aws
COPY --from=artifacts --chmod=0555 /out/cloudquery-destination-file /usr/local/libexec/cloudquery-destination-file
COPY --from=artifacts /out/LICENSE /usr/share/licenses/cloudquery/LICENSE
COPY --from=artifacts /downloads/cli-source.tar.gz /usr/share/source/cloudquery/cli-086baf7.tar.gz
COPY --from=artifacts /downloads/aws-source.tar.gz /usr/share/source/cloudquery/aws-804be3a.tar.gz
COPY --from=artifacts /downloads/file-source.tar.gz /usr/share/source/cloudquery/file-600ffdd.tar.gz
COPY engines/images/cloudquery/SOURCE-OFFER.md /usr/share/source/cloudquery/SOURCE-OFFER.md
COPY engines/images/cloudquery/dependencies.lock.json /usr/share/source/cloudquery/build/dependencies.lock.json
COPY engines/images/cloudquery/plugins.yml /usr/share/source/cloudquery/build/plugins.yml
COPY engines/images/cloudquery/Dockerfile /usr/share/source/cloudquery/build/Dockerfile
COPY engines/images/cloud-launcher/go.mod /usr/share/source/cloudquery/build/cloud-launcher/go.mod
COPY engines/images/cloud-launcher/main.go /usr/share/source/cloudquery/build/cloud-launcher/main.go

ENV AWS_EC2_METADATA_DISABLED="true" \
    AWS_DEFAULT_REGION="us-east-1" \
    AWS_REGION="us-east-1" \
    AWS_STS_REGIONAL_ENDPOINTS="regional" \
    CQ_TELEMETRY_LEVEL="none" \
    HOME="/tmp/ai-security-scanner-home" \
    PATH="/app:/usr/local/bin:/usr/local/libexec" \
    SSL_CERT_FILE="/etc/ssl/certs/ca-certificates.crt"

USER 65532:65532
ENTRYPOINT ["/usr/local/bin/ai-security-scanner-cloud-launcher"]
