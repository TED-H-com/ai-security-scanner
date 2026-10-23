# syntax=docker/dockerfile:1.7@sha256:a57df69d0ea827fb7266491f2813635de6f17269be881f696fbfdf2d83dda33e

FROM --platform=$TARGETPLATFORM rust:1.98.0-alpine@sha256:a10e64dd139b7387337c7fbe8aca31b959b57b2fd4c8ae20a02cf1d6ea424dce AS build

RUN apk add --no-cache build-base

WORKDIR /source
COPY Cargo.toml Cargo.lock ./
COPY vendor/glib-0.18.5 vendor/glib-0.18.5
COPY src-tauri/Cargo.toml src-tauri/build.rs src-tauri/
COPY src-tauri/src src-tauri/src
COPY mappings/control-mappings.json mappings/control-mappings.json
COPY bootstrap/aws-readonly-cloudformation.yaml bootstrap/azure-readonly-arm.json bootstrap/gcp-readonly-bindings.json bootstrap/microsoft365-readonly-permissions.json bootstrap/
COPY engines/catalog.json engines/catalog.json
COPY engines/campaigns/october-2026.json engines/campaigns/october-2026.json
COPY docs/research/augustus-single-destination-profile.json docs/research/augustus-single-destination-profile.json
COPY docs/research/patches/augustus-0.14.29-machine-json.patch docs/research/patches/augustus-0.14.29-machine-json.patch

RUN --mount=type=cache,target=/usr/local/cargo/registry,sharing=locked \
    --mount=type=cache,target=/source/target,sharing=locked \
    cargo build --locked --release --manifest-path src-tauri/Cargo.toml \
      --no-default-features --features egress-gateway \
      --bin ai-security-scanner-egress-gateway \
      --bin ai-security-scanner-egress-probe \
    && strip target/release/ai-security-scanner-egress-gateway target/release/ai-security-scanner-egress-probe \
    && install -D -m 0555 target/release/ai-security-scanner-egress-gateway /out/ai-security-scanner-egress-gateway \
    && install -D -m 0555 target/release/ai-security-scanner-egress-probe /out/ai-security-scanner-egress-probe

FROM scratch

LABEL org.opencontainers.image.title="ai-security-scanner managed egress gateway" \
      org.opencontainers.image.description="Policy-bound SOCKS gateway for isolated ai-security-scanner engine networks" \
      org.opencontainers.image.source="https://github.com/teddashh/ai-security-scanner" \
      org.opencontainers.image.licenses="Apache-2.0"

COPY --from=build /out/ai-security-scanner-egress-gateway /usr/local/bin/ai-security-scanner-egress-gateway
COPY --from=build /out/ai-security-scanner-egress-probe /usr/local/bin/ai-security-scanner-egress-probe
COPY LICENSE /usr/share/licenses/ai-security-scanner/LICENSE

USER 65532:65532
ENTRYPOINT ["/usr/local/bin/ai-security-scanner-egress-gateway"]
