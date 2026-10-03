# syntax=docker/dockerfile:1.7@sha256:a57df69d0ea827fb7266491f2813635de6f17269be881f696fbfdf2d83dda33e

FROM ghcr.io/astral-sh/uv:0.10.9@sha256:10902f58a1606787602f303954cea099626a4adb02acbac4c69920fe9d278f82 AS uv

FROM --platform=$BUILDPLATFORM golang:1.25.10-alpine@sha256:8d22e29d960bc50cd025d93d5b7c7d220b1ee9aa7a239b3c8f55a57e987e8d45 AS launcher

ARG TARGETOS
ARG TARGETARCH

ENV GOMAXPROCS=4 CGO_ENABLED=0 GOTOOLCHAIN=local SOURCE_DATE_EPOCH=1787250577
WORKDIR /src/launcher
COPY engines/images/local-launcher/go.mod engines/images/local-launcher/main.go engines/images/local-launcher/main_test.go ./
RUN go test ./... && GOOS=${TARGETOS} GOARCH=${TARGETARCH} go build \
    -buildvcs=false -trimpath -ldflags='-s -w -buildid=' \
    -o /out/ai-security-scanner-engine-entrypoint .

FROM alpine:3.23@sha256:fd791d74b68913cbb027c6546007b3f0d3bc45125f797758156952bc2d6daf40 AS toolchain

ENV OPAMYES=1 \
    OPAMJOBS=4 \
    OPAMROOT=/root/.opam \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    SOURCE_DATE_EPOCH=1787250577 \
    UV_LINK_MODE=copy

RUN apk add --no-cache \
    bash=5.3.3-r1 \
    build-base=0.5-r3 \
    bzip2-dev=1.0.8-r6 \
    bzip2-static=1.0.8-r6 \
    check-jsonschema=0.28.4-r0 \
    curl-dev=8.22.0-r0 \
    elfutils-dev=0.194-r0 \
    git=2.52.0-r0 \
    gmp-dev=6.3.0-r4 \
    gmp-static=6.3.0-r4 \
    libev-dev=4.33-r1 \
    libunwind-dev=1.8.1-r0 \
    libunwind-static=1.8.1-r0 \
    linux-headers=6.16.12-r0 \
    make=4.4.1-r3 \
    opam=2.5.2-r0 \
    pcre2-dev=10.49-r0 \
    pcre2-static=10.49-r0 \
    python3=3.12.15-r0 \
    rsync=3.5.0-r0 \
    xz-static=5.8.4-r0 \
    zstd-dev=1.5.7-r2 \
    zstd-static=1.5.7-r2

COPY --from=uv /uv /usr/local/bin/uv
FROM toolchain AS rule-inputs
COPY engines/images/semgrep/submodules.lock /tmp/full-submodules.lock
RUN python3 -c 'from pathlib import Path; lines=[line for line in Path("/tmp/full-submodules.lock").read_text().splitlines() if line and not line.startswith("#")]; assert len(lines)==36; compiler=[line for line in lines if not line.startswith("tests/semgrep-rules|")]; assert len(compiler)==35; Path("/tmp/compiler-submodules.lock").write_text("\n".join(compiler)+"\n")'

FROM toolchain AS compiler-source
ADD --checksum=sha256:7c5c5fe27b3b65ba1ac77f121c5d3df4398a1c06ab3d7e39fdef8884ca8494b5 \
    https://github.com/semgrep/semgrep/archive/a0c13f304151e531c7e7c00838076211a07a790c.tar.gz \
    /tmp/semgrep-source.tar.gz

RUN mkdir -p /src/semgrep \
    && tar -xzf /tmp/semgrep-source.tar.gz --strip-components=1 -C /src/semgrep

COPY --from=rule-inputs /tmp/compiler-submodules.lock /tmp/compiler-submodules.lock
COPY .engine-cache/offline/semgrep-submodules/languages__*.tar.gz .engine-cache/offline/semgrep-submodules/libs__*.tar.gz /tmp/semgrep-submodules/
RUN set -eu; while IFS='|' read -r path repository revision digest size archive; do \
      test "$(stat -c '%s' "/tmp/semgrep-submodules/${archive}")" = "${size}"; \
      echo "${digest#sha256:}  /tmp/semgrep-submodules/${archive}" | sha256sum -c -; \
      rm -rf "/src/semgrep/${path}"; \
      mkdir -p "/src/semgrep/${path}"; \
      tar -xzf "/tmp/semgrep-submodules/${archive}" --strip-components=1 -C "/src/semgrep/${path}"; \
    done < /tmp/compiler-submodules.lock

FROM toolchain AS rule-pack
COPY engines/images/semgrep/submodules.lock /tmp/semgrep-submodules.lock
COPY engines/images/semgrep/build_rule_pack.py engines/images/semgrep/product-rules.yml engines/images/semgrep/product-LICENSE /tmp/rule-builder/
# Mount the unfiltered archive only for this step. A mode=max cache export must
# not acquire a layer containing the explicitly proprietary excluded source.
RUN --mount=type=bind,source=.engine-cache/offline/semgrep-submodules/tests__semgrep-rules.tar.gz,target=/tmp/rules.tar.gz,readonly \
    python3 /tmp/rule-builder/build_rule_pack.py \
    --archive /tmp/rules.tar.gz --lock /tmp/semgrep-submodules.lock \
    --output /tmp/semgrep-rule-pack --source-date-epoch "${SOURCE_DATE_EPOCH}"

FROM compiler-source AS source
COPY --from=rule-pack /tmp/semgrep-rule-pack /tmp/semgrep-rule-pack
COPY engines/images/semgrep/prepare_source_bundle.py /tmp/prepare-source-bundle.py
COPY engines/images/semgrep/Dockerfile engines/images/semgrep/submodules.lock engines/images/semgrep/SOURCE-OFFER.md engines/images/semgrep/build_rule_pack.py engines/images/semgrep/prepare_source_bundle.py engines/images/semgrep/product-rules.yml engines/images/semgrep/product-LICENSE /tmp/candidate-inputs/engines/images/semgrep/
COPY engines/images/local-launcher/go.mod engines/images/local-launcher/main.go engines/images/local-launcher/main_test.go /tmp/candidate-inputs/engines/images/local-launcher/
RUN python3 /tmp/prepare-source-bundle.py \
       --engine /src/semgrep --pack /tmp/semgrep-rule-pack \
       --inputs /tmp/candidate-inputs --output /tmp/semgrep-complete-source.tar.gz \
       --source-date-epoch "${SOURCE_DATE_EPOCH}"

FROM compiler-source AS build
WORKDIR /src/semgrep
ARG TARGETARCH
RUN test "${TARGETARCH}" = "amd64" -o "${TARGETARCH}" = "arm64" \
    && make opam-init OPAM_INIT_FLAGS=--disable-sandboxing
RUN make switch
RUN make install-deps
RUN DUNE_JOBS=4 SEMGREP_GIT_COMMIT=a0c13f304151e531c7e7c00838076211a07a790c opam exec -- make core \
    && install -D -m 0555 _build/default/src/main/Main.exe cli/src/semgrep/bin/semgrep-core \
    && cd cli \
    && UV_PROJECT_ENVIRONMENT=/opt/semgrep uv sync --frozen --no-dev --no-editable --python /usr/bin/python3 \
    && /opt/semgrep/bin/semgrep --version | grep -Fx '1.174.0'

FROM build AS smoke
COPY --from=rule-pack /tmp/semgrep-rule-pack /tmp/semgrep-rule-pack
COPY engines/images/semgrep/testdata/combination-review/ /tmp/semgrep-rule-fixture/
RUN --network=none /opt/semgrep/bin/semgrep scan --quiet --json \
      --output /tmp/semgrep-rule-smoke.json \
      --config /tmp/semgrep-rule-pack/rules \
      --metrics=off --disable-version-check --no-rewrite-rule-ids \
      --oss-only --jobs 2 --max-memory 2048 \
      --timeout 10 --timeout-threshold 3 --max-target-bytes 10000000 \
      /tmp/semgrep-rule-fixture \
    && python3 -c 'import json; result=json.load(open("/tmp/semgrep-rule-smoke.json", encoding="utf-8")); assert result.get("errors") == []; ids={finding.get("check_id") for finding in result.get("results", [])}; assert len(result["results"]) == 22; assert {"python.lang.security.audit.dangerous-subprocess-use-audit.dangerous-subprocess-use-audit", "python.lang.security.audit.subprocess-shell-true.subprocess-shell-true", "ai-security-scanner.python.shell-true"} <= ids'

FROM alpine:3.23@sha256:fd791d74b68913cbb027c6546007b3f0d3bc45125f797758156952bc2d6daf40

LABEL org.opencontainers.image.title="ai-security-scanner Semgrep engine" \
      org.opencontainers.image.description="Local candidate Semgrep build with legacy upstream and product offline rules" \
      org.opencontainers.image.source="https://github.com/semgrep/semgrep" \
      org.opencontainers.image.revision="a0c13f304151e531c7e7c00838076211a07a790c" \
      io.ai-security-scanner.local-candidate-only="true" \
      org.opencontainers.image.licenses="LGPL-2.1-or-later AND LicenseRef-Commons-Clause-1.0 AND Apache-2.0" \
      io.ai-security-scanner.rules-revision="0f5a85ceab1b82b193d0eaa418784c932d237d68" \
      io.ai-security-scanner.rules-count="1497" \
      io.ai-security-scanner.rules-manifest-sha256="63678fc6790ebdeca2961080095611030b8e51f8b19ac228ee7e2c6862083040"

RUN apk add --no-cache \
    git=2.52.0-r0 \
    libgcc=15.2.0-r2 \
    libstdc++=15.2.0-r2 \
    py3-setuptools=80.9.0-r2 \
    python3=3.12.15-r0 \
    && addgroup -g 65532 scanner \
    && adduser -D -H -u 65532 -G scanner scanner \
    && mkdir -p /workspace /output /opt/ai-security-scanner/semgrep /usr/share/source \
    && chown scanner:scanner /output \
    && chmod 0555 /workspace /opt/ai-security-scanner/semgrep

COPY --from=smoke /opt/semgrep /opt/semgrep
COPY --from=launcher /out/ai-security-scanner-engine-entrypoint /usr/local/bin/ai-security-scanner-engine-entrypoint
COPY --from=rule-pack /tmp/semgrep-rule-pack/rules /opt/ai-security-scanner/semgrep/rules
COPY --from=rule-pack /tmp/semgrep-rule-pack/RULES.sha256 /opt/ai-security-scanner/semgrep/RULES.sha256
COPY --from=rule-pack /tmp/semgrep-rule-pack/RULE-PROVENANCE.json /opt/ai-security-scanner/semgrep/RULE-PROVENANCE.json
COPY --from=rule-pack /tmp/semgrep-rule-pack/LICENSE.product /usr/share/licenses/ai-security-scanner-semgrep-rules/LICENSE
COPY --from=build /src/semgrep/LICENSE /usr/share/licenses/semgrep/LICENSE
COPY --from=rule-pack /tmp/semgrep-rule-pack/LICENSE /usr/share/licenses/semgrep-rules/LICENSE
COPY --from=source /tmp/semgrep-complete-source.tar.gz /usr/share/source/semgrep-source.tar.gz
COPY --from=rule-pack /tmp/semgrep-rule-pack/PACK-METADATA.json /usr/share/source/semgrep-rule-pack.json
COPY --from=rule-pack /tmp/semgrep-rule-pack/UPSTREAM-README.md /usr/share/source/semgrep-rules-README.md
COPY engines/images/semgrep/submodules.lock /usr/share/source/semgrep-submodules.lock
COPY engines/images/semgrep/build_rule_pack.py engines/images/semgrep/prepare_source_bundle.py engines/images/semgrep/product-rules.yml engines/images/semgrep/product-LICENSE /usr/share/source/
COPY engines/images/semgrep/SOURCE-OFFER.md /usr/share/source/SEMGREP-SOURCE-OFFER.md
COPY engines/images/semgrep/Dockerfile /usr/share/source/ai-security-scanner-semgrep.Dockerfile
COPY LICENSE /usr/share/licenses/ai-security-scanner/LICENSE

RUN ln -s /opt/semgrep/bin/semgrep /usr/local/bin/semgrep \
    && find /opt/ai-security-scanner/semgrep/rules -type d -exec chmod 0555 {} + \
    && find /opt/ai-security-scanner/semgrep/rules -type f -exec chmod 0444 {} + \
    && chmod 0444 /opt/ai-security-scanner/semgrep/RULES.sha256 \
    && /usr/local/bin/semgrep --version | grep -Fx '1.174.0'

ENV HOME="/tmp/ai-security-scanner-home" \
    SEMGREP_ENABLE_VERSION_CHECK="0" \
    SEMGREP_SEND_METRICS="off" \
    XDG_CACHE_HOME="/tmp/ai-security-scanner-cache"

WORKDIR /workspace
USER 65532:65532
ENTRYPOINT ["/usr/local/bin/ai-security-scanner-engine-entrypoint"]
