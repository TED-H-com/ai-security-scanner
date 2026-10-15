FROM anchore/syft@sha256:3eb5379ba7b409c3f4069b686110527af0c47df993fa5c10d13e7cf34f49b1aa

LABEL org.opencontainers.image.title="ai-security-scanner managed Syft"
LABEL org.opencontainers.image.description="Offline, non-root Syft runtime for immutable assessment-case repository snapshots"
LABEL org.opencontainers.image.source="https://github.com/TED-H-com/ai-security-scanner"
LABEL org.opencontainers.image.licenses="Apache-2.0"
LABEL org.opencontainers.image.version="1.54.1-1"
LABEL ai.security-scanner.upstream.repository="https://github.com/anchore/syft"
LABEL ai.security-scanner.upstream.revision="b254e6d92f28c3868a755f62fb3ca8f26e9fee76"
LABEL ai.security-scanner.upstream.image="anchore/syft@sha256:3eb5379ba7b409c3f4069b686110527af0c47df993fa5c10d13e7cf34f49b1aa"

ENV HOME="/tmp/ai-security-scanner-home" \
    XDG_CACHE_HOME="/tmp/ai-security-scanner-cache" \
    SYFT_CACHE_DIR="/tmp/ai-security-scanner-cache/syft" \
    SYFT_CHECK_FOR_APP_UPDATE="false"

USER 65532:65532
ENTRYPOINT ["/syft"]
