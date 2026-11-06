FROM anchore/syft@sha256:3c70e6d5979364cefdc22b51617a78fd264574d3bd6b4f84a351204147025e2a

LABEL org.opencontainers.image.title="ai-security-scanner managed Syft"
LABEL org.opencontainers.image.description="Offline, non-root Syft runtime for immutable assessment-case repository snapshots"
LABEL org.opencontainers.image.source="https://github.com/TED-H-com/ai-security-scanner"
LABEL org.opencontainers.image.licenses="Apache-2.0"
LABEL org.opencontainers.image.version="1.57.0-1"
LABEL ai.security-scanner.upstream.repository="https://github.com/anchore/syft"
LABEL ai.security-scanner.upstream.revision="30f4bce762f31136e055f2965185f12eb95fbe47"
LABEL ai.security-scanner.upstream.image="anchore/syft@sha256:3c70e6d5979364cefdc22b51617a78fd264574d3bd6b4f84a351204147025e2a"

ENV HOME="/tmp/ai-security-scanner-home" \
    XDG_CACHE_HOME="/tmp/ai-security-scanner-cache" \
    SYFT_CACHE_DIR="/tmp/ai-security-scanner-cache/syft" \
    SYFT_CHECK_FOR_APP_UPDATE="false"

USER 65532:65532
ENTRYPOINT ["/syft"]
