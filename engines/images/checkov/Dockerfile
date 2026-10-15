# syntax=docker/dockerfile:1.7@sha256:a57df69d0ea827fb7266491f2813635de6f17269be881f696fbfdf2d83dda33e

ARG SOURCE_DATE_EPOCH=1791891584

FROM python:3.11.16-slim@sha256:9c900dea9e8fb7e16277c179b555cc72d29a352dbc33cff48ad5a0412fd5bfc7 AS build

ENV PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_ROOT_USER_ACTION=ignore \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONHASHSEED=0 \
    SOURCE_DATE_EPOCH=1791891584

COPY prepare_source.py /usr/local/libexec/checkov-prepare-source
ADD --checksum=sha256:5f6f20199994878d8af30c85e992339f3d4014fcae831b4537e64ecf209e5b96 \
    https://github.com/bridgecrewio/checkov/archive/e40023ab262c7c8b7b0a8f0975072b42d1b601f9.tar.gz \
    /tmp/checkov-source.tar.gz

RUN python /usr/local/libexec/checkov-prepare-source \
        /tmp/checkov-source.tar.gz /src /tmp/requirements.lock \
    && python -m pip install \
        --no-compile \
        --only-binary=:all: \
        --require-hashes \
        --prefix=/install \
        --requirement=/tmp/requirements.lock \
    && PYTHONPATH=/install/lib/python3.11/site-packages \
        python -m pip install \
        --no-compile \
        --no-build-isolation \
        --no-deps \
        --prefix=/install \
        /src \
    && test "$(PYTHONPATH=/install/lib/python3.11/site-packages /install/bin/checkov --version)" = '3.3.29' \
    && find /install -exec touch -h -d '@1791891584' '{}' + \
    && tar \
        --create \
        --file=/tmp/install.tar \
        --format=gnu \
        --group=0 \
        --mtime='@1791891584' \
        --numeric-owner \
        --owner=0 \
        --sort=name \
        --directory=/install \
        .

FROM python:3.11.16-slim@sha256:9c900dea9e8fb7e16277c179b555cc72d29a352dbc33cff48ad5a0412fd5bfc7

LABEL org.opencontainers.image.title="ai-security-scanner Checkov engine" \
      org.opencontainers.image.description="Pinned-source, offline-ready Checkov engine for ai-security-scanner" \
      org.opencontainers.image.source="https://github.com/bridgecrewio/checkov" \
      org.opencontainers.image.revision="e40023ab262c7c8b7b0a8f0975072b42d1b601f9" \
      org.opencontainers.image.version="3.3.29" \
      org.opencontainers.image.licenses="Apache-2.0" \
      io.ai-security-scanner.source-archive-sha256="5f6f20199994878d8af30c85e992339f3d4014fcae831b4537e64ecf209e5b96" \
      io.ai-security-scanner.pipfile-lock-sha256="f51eb3c9693670743a8be18191e44bcacf80f21e68cdfdb86dc00b0017df7995"

ENV BC_ENABLE_PERSIST_GRAPHS="false" \
    CKV_BITBUCKET_CONFIG_FETCH_DATA="false" \
    CKV_GITHUB_CONFIG_FETCH_DATA="false" \
    CKV_GITLAB_CONFIG_FETCH_DATA="false" \
    CKV_SKIP_PACKAGE_UPDATE_CHECK="true" \
    HOME="/tmp/ai-security-scanner-home" \
    PIP_DISABLE_PIP_VERSION_CHECK="1" \
    PYTHONDONTWRITEBYTECODE="1" \
    PYTHONUNBUFFERED="1" \
    RUN_IN_DOCKER="true" \
    XDG_CACHE_HOME="/tmp/ai-security-scanner-cache"

RUN --mount=type=bind,from=build,source=/,target=/mnt/build,ro \
    tar --extract --file=/mnt/build/tmp/install.tar --directory=/usr/local \
    && install -D -m 0644 /mnt/build/src/LICENSE /usr/share/licenses/checkov/LICENSE \
    && install -D -m 0444 /mnt/build/tmp/requirements.lock /usr/share/licenses/checkov/runtime-requirements.lock \
    && mkdir -p /workspace \
    && touch -h -d '@1791891584' \
        /usr/share \
        /usr/share/licenses \
        /usr/share/licenses/checkov \
        /usr/share/licenses/checkov/LICENSE \
        /usr/share/licenses/checkov/runtime-requirements.lock \
        /workspace

WORKDIR /workspace
USER 65532:65532
ENTRYPOINT ["/usr/local/bin/checkov"]
