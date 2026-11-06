# syntax=docker/dockerfile:1.7@sha256:a57df69d0ea827fb7266491f2813635de6f17269be881f696fbfdf2d83dda33e

ARG SOURCE_DATE_EPOCH=1793536827
ARG STEAMPIPE_REVISION=4269e1dc4865647605da6af8f1828e77278106a0
ARG AWS_PLUGIN_REVISION=bb6992d4748caab938e2c691be977d6610fc1fab
ARG FDW_REVISION=cb70e9a38242064750a98dda75a07a539ab0aee8

FROM --platform=$BUILDPLATFORM golang:1.26.10-alpine@sha256:87c65a688975c0b1d4585d204874c45ca78354670e3a5f11368c5a492303d696 AS steampipe-build
ARG TARGETOS
ARG TARGETARCH
ARG SOURCE_DATE_EPOCH
ARG STEAMPIPE_REVISION
WORKDIR /src
ADD --checksum=sha256:f8cf2c10f37473f7fd0d979864f6c399ed0c9c969fc63a5bcd1b3fb608893eac \
    https://github.com/turbot/steampipe/archive/4269e1dc4865647605da6af8f1828e77278106a0.tar.gz \
    /source/steampipe-v2.4.9.tar.gz
RUN tar --extract --gzip --file=/source/steampipe-v2.4.9.tar.gz \
      --directory=/src --strip-components=1 --no-same-owner \
    && go mod download \
    && CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} \
       go build -mod=readonly -buildvcs=false -trimpath -tags=netgo \
       -ldflags="-s -w -buildid= -X main.version=2.4.9 -X main.date=2026-11-01T12:40:27Z -X main.commit=${STEAMPIPE_REVISION} -X main.builtBy=ai-security-scanner" \
       -o /out/steampipe .

FROM --platform=$BUILDPLATFORM golang:1.26.10-alpine@sha256:87c65a688975c0b1d4585d204874c45ca78354670e3a5f11368c5a492303d696 AS plugin-build
ARG TARGETOS
ARG TARGETARCH
WORKDIR /src
ADD --checksum=sha256:dcfe1e49bf34ccc77ea98692925adc0e0469645b27059478cc56659e8cd3ceb9 \
    https://github.com/turbot/steampipe-plugin-aws/archive/bb6992d4748caab938e2c691be977d6610fc1fab.tar.gz \
    /source/steampipe-plugin-aws-v1.34.1.tar.gz
RUN tar --extract --gzip --file=/source/steampipe-plugin-aws-v1.34.1.tar.gz \
      --directory=/src --strip-components=1 --no-same-owner \
    && go mod download \
    && CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} \
       go build -mod=readonly -buildvcs=false -trimpath -tags=netgo \
       -ldflags='-s -w -buildid=' -o /out/steampipe-plugin-aws.plugin .

FROM --platform=$BUILDPLATFORM golang:1.26.10-alpine@sha256:87c65a688975c0b1d4585d204874c45ca78354670e3a5f11368c5a492303d696 AS fdw-source
WORKDIR /src
ADD --checksum=sha256:1f92d980997954057e2b3fa95d97360e48878cefd7091ecc1763e649fe29d289 \
    https://github.com/turbot/steampipe-postgres-fdw/archive/cb70e9a38242064750a98dda75a07a539ab0aee8.tar.gz \
    /source/steampipe-postgres-fdw-v2.2.9.tar.gz
RUN tar --extract --gzip --file=/source/steampipe-postgres-fdw-v2.2.9.tar.gz \
      --directory=/src --strip-components=1 --no-same-owner

FROM --platform=$BUILDPLATFORM golang:1.26.10-alpine@sha256:87c65a688975c0b1d4585d204874c45ca78354670e3a5f11368c5a492303d696 AS project-tools
ARG TARGETOS
ARG TARGETARCH
WORKDIR /launcher
COPY engines/images/cloud-launcher/go.mod engines/images/cloud-launcher/main.go ./
RUN CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} \
      go build -buildvcs=false -trimpath -ldflags='-s -w -buildid=' \
      -o /out/ai-security-scanner-cloud-launcher .
WORKDIR /installprep
COPY engines/images/steampipe/installprep/go.mod engines/images/steampipe/installprep/main.go ./
RUN CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} \
      go build -buildvcs=false -trimpath -ldflags='-s -w -buildid=' \
      -o /out/ai-security-scanner-steampipe-installprep .

FROM debian:bookworm-slim@sha256:abd67ffcfa541b485a3dff59865ab629aa048a6c613e639d36e7456b0b229241 AS seed-input
ARG SOURCE_DATE_EPOCH
COPY --chmod=0444 engines/images/steampipe/passwd /etc/passwd
COPY --chmod=0444 engines/images/steampipe/group /etc/group
COPY --from=steampipe-build --chmod=0555 /out/steampipe /usr/local/bin/steampipe
COPY --from=plugin-build --chown=65532:65532 --chmod=0444 /out/steampipe-plugin-aws.plugin /opt/input/steampipe-plugin-aws.plugin
COPY --from=project-tools --chmod=0555 /out/ai-security-scanner-steampipe-installprep /usr/local/bin/ai-security-scanner-steampipe-installprep
COPY --from=project-tools --chmod=0444 /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
RUN mkdir -p /opt/seed /opt/seed-home \
    && chmod 0755 /etc/ssl /etc/ssl/certs \
    && chmod 0555 /opt/input \
    && chown 65532:65532 /opt/seed /opt/seed-home
ENV HOME=/opt/seed-home \
    SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt \
    STEAMPIPE_CACHE=false \
    STEAMPIPE_INSTALL_DIR=/opt/seed \
    STEAMPIPE_TELEMETRY=none \
    STEAMPIPE_UPDATE_CHECK=false \
    USER=scanner
USER 65532:65532

FROM seed-input AS seed
ARG TARGETARCH
ARG STEAMPIPE_REVISION
ARG AWS_PLUGIN_REVISION
ARG FDW_REVISION
RUN case "${TARGETARCH}" in \
      amd64) database_port=19193 ;; \
      arm64) database_port=19194 ;; \
      *) exit 64 ;; \
    esac \
    && mkdir -p "${STEAMPIPE_INSTALL_DIR}/config" \
    && printf 'options "database" {\n  port = %s\n  listen = "local"\n}\n' "${database_port}" \
       > "${STEAMPIPE_INSTALL_DIR}/config/ai-security-scanner-build.spc" \
    && steampipe query --output json "select 1 as seed_ready" \
    && ai-security-scanner-steampipe-installprep \
         /opt/seed /opt/input/steampipe-plugin-aws.plugin "${SOURCE_DATE_EPOCH}" \
    && grep -Fq "\"steampipe_revision\": \"${STEAMPIPE_REVISION}\"" /opt/seed/ai-security-scanner-provenance.json \
    && grep -Fq "\"aws_plugin_revision\": \"${AWS_PLUGIN_REVISION}\"" /opt/seed/ai-security-scanner-provenance.json \
    && grep -Fq "\"fdw_revision\": \"${FDW_REVISION}\"" /opt/seed/ai-security-scanner-provenance.json \
    && rm -f "${STEAMPIPE_INSTALL_DIR}/config/ai-security-scanner-build.spc"

FROM debian:bookworm-slim@sha256:abd67ffcfa541b485a3dff59865ab629aa048a6c613e639d36e7456b0b229241
ARG SOURCE_DATE_EPOCH
LABEL org.opencontainers.image.title="ai-security-scanner Steampipe engine" \
      org.opencontainers.image.description="Pinned-source Steampipe and AWS IAM plugin with embedded database closure" \
      org.opencontainers.image.source="https://github.com/teddashh/ai-security-scanner" \
      org.opencontainers.image.revision="4269e1dc4865647605da6af8f1828e77278106a0" \
      org.opencontainers.image.version="2.4.9-1" \
      org.opencontainers.image.licenses="AGPL-3.0-only AND Apache-2.0 AND PostgreSQL" \
      io.ai-security-scanner.aws-plugin.revision="bb6992d4748caab938e2c691be977d6610fc1fab" \
      io.ai-security-scanner.database.digest="sha256:84264ef41853178707bccb091f5450c22e835f8a98f9961592c75690321093d9" \
      io.ai-security-scanner.fdw.digest="sha256:161e9b5e0696e66d77e94e2f9a0ee90d6e2a597b2069d1e488846e78a0b295f8" \
      io.ai-security-scanner.profile="aws-iam-user-inventory-us-east-1"

COPY --chmod=0444 engines/images/steampipe/passwd /etc/passwd
COPY --chmod=0444 engines/images/steampipe/group /etc/group
COPY --from=project-tools --chmod=0444 /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
RUN chmod 0755 /etc/ssl /etc/ssl/certs
COPY --from=steampipe-build --chmod=0555 /out/steampipe /usr/local/bin/steampipe
COPY --from=project-tools --chmod=0555 /out/ai-security-scanner-cloud-launcher /usr/local/bin/ai-security-scanner-cloud-launcher
COPY --from=seed /opt/seed /opt/ai-security-scanner/steampipe-install

COPY --from=steampipe-build --chmod=0444 /src/LICENSE /usr/share/licenses/steampipe/LICENSE
COPY --from=plugin-build --chmod=0444 /src/LICENSE /usr/share/licenses/steampipe-plugin-aws/LICENSE
COPY --from=fdw-source --chmod=0444 /src/LICENSE /usr/share/licenses/steampipe-postgres-fdw/LICENSE
COPY --chmod=0444 engines/images/steampipe/POSTGRESQL-COPYRIGHT /usr/share/licenses/postgresql/COPYRIGHT
COPY --chmod=0444 engines/images/steampipe/SOURCE-OFFER.md /usr/share/source/steampipe/SOURCE-OFFER.md
COPY --from=steampipe-build --chmod=0444 /source/steampipe-v2.4.9.tar.gz /usr/share/source/steampipe/steampipe-v2.4.9.tar.gz
COPY --from=plugin-build --chmod=0444 /source/steampipe-plugin-aws-v1.34.1.tar.gz /usr/share/source/steampipe/steampipe-plugin-aws-v1.34.1.tar.gz
COPY --from=fdw-source --chmod=0444 /source/steampipe-postgres-fdw-v2.2.9.tar.gz /usr/share/source/steampipe/steampipe-postgres-fdw-v2.2.9.tar.gz
COPY --chmod=0444 engines/images/steampipe/Dockerfile /usr/share/source/steampipe/build/Dockerfile
COPY --chmod=0444 engines/images/steampipe/passwd engines/images/steampipe/group /usr/share/source/steampipe/build/
COPY --chmod=0444 engines/images/cloud-launcher/go.mod engines/images/cloud-launcher/main.go /usr/share/source/steampipe/build/cloud-launcher/
COPY --chmod=0444 engines/images/steampipe/installprep/go.mod engines/images/steampipe/installprep/main.go /usr/share/source/steampipe/build/installprep/

ENV AWS_EC2_METADATA_DISABLED="true" \
    AWS_DEFAULT_REGION="us-east-1" \
    AWS_REGION="us-east-1" \
    AWS_STS_REGIONAL_ENDPOINTS="regional" \
    HOME="/tmp/ai-security-scanner-home" \
    SSL_CERT_FILE="/etc/ssl/certs/ca-certificates.crt" \
    STEAMPIPE_CACHE="false" \
    STEAMPIPE_TELEMETRY="none" \
    STEAMPIPE_UPDATE_CHECK="false"

USER 65532:65532
ENTRYPOINT ["/usr/local/bin/ai-security-scanner-cloud-launcher"]
