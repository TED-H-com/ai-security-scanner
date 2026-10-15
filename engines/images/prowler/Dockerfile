# syntax=docker/dockerfile:1.7@sha256:a57df69d0ea827fb7266491f2813635de6f17269be881f696fbfdf2d83dda33e

FROM golang:1.25.0-alpine3.22@sha256:f18a072054848d87a8077455f0ac8a25886f2397f88bfdd222d6fafbb5bba440 AS launcher
WORKDIR /src
COPY engines/images/cloud-launcher/go.mod engines/images/cloud-launcher/main.go ./
RUN CGO_ENABLED=0 GOOS=linux go build -buildvcs=false -trimpath \
      -ldflags='-s -w -buildid=' -o /out/ai-security-scanner-cloud-launcher .

FROM public.ecr.aws/prowler-cloud/prowler@sha256:9dbcc3c9abd71ec6d37610e6a5a2c45279bc6488caf8aaa948a9e8e368622d30

LABEL org.opencontainers.image.title="ai-security-scanner Prowler engine" \
      org.opencontainers.image.description="Pinned Prowler AWS, Azure, and GCP narrow IAM assessment with exact provider scope binding" \
      org.opencontainers.image.source="https://github.com/TED-H-com/ai-security-scanner" \
      org.opencontainers.image.revision="499fd637f3393b485833b08cdaf4172917c5698e" \
      org.opencontainers.image.version="5.44.0-1" \
      org.opencontainers.image.licenses="Apache-2.0" \
      io.ai-security-scanner.upstream.image="public.ecr.aws/prowler-cloud/prowler@sha256:9dbcc3c9abd71ec6d37610e6a5a2c45279bc6488caf8aaa948a9e8e368622d30" \
      io.ai-security-scanner.profile="aws-azure-gcp-narrow-iam"

COPY --from=launcher --chmod=0555 /out/ai-security-scanner-cloud-launcher /usr/local/bin/ai-security-scanner-cloud-launcher

USER root
COPY --chmod=0555 engines/images/prowler/apply-runtime-patches.py /tmp/ai-security-scanner-prowler/apply-runtime-patches.py
COPY --chmod=0444 engines/images/prowler/patches /tmp/ai-security-scanner-prowler/patches
RUN /home/prowler/.venv/bin/python /tmp/ai-security-scanner-prowler/apply-runtime-patches.py \
      --root /home/prowler \
      --patch-dir /tmp/ai-security-scanner-prowler/patches \
    && rm -rf /tmp/ai-security-scanner-prowler \
    && chmod 0755 /home/prowler

ENV AWS_EC2_METADATA_DISABLED="true" \
    AWS_DEFAULT_REGION="us-east-1" \
    AWS_REGION="us-east-1" \
    AWS_STS_REGIONAL_ENDPOINTS="regional" \
    HOME="/tmp/ai-security-scanner-home" \
    POWERSHELL_TELEMETRY_OPTOUT="1" \
    PYTHONDONTWRITEBYTECODE="1" \
    PYTHONUNBUFFERED="1" \
    XDG_CACHE_HOME="/tmp/ai-security-scanner-cache"

USER 65532:65532
ENTRYPOINT ["/usr/local/bin/ai-security-scanner-cloud-launcher"]
