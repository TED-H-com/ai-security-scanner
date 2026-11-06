# syntax=docker/dockerfile:1.7@sha256:a57df69d0ea827fb7266491f2813635de6f17269be881f696fbfdf2d83dda33e
ARG SOURCE_DATE_EPOCH=1792180550
FROM python:3.11.16-slim@sha256:9c900dea9e8fb7e16277c179b555cc72d29a352dbc33cff48ad5a0412fd5bfc7 AS build
ENV PIP_DISABLE_PIP_VERSION_CHECK=1 PIP_NO_CACHE_DIR=1 PIP_ROOT_USER_ACTION=ignore \
    PYTHONDONTWRITEBYTECODE=1 PYTHONHASHSEED=0 SOURCE_DATE_EPOCH=1792180550
ADD --checksum=sha256:22c1d011d86ea6375ddaf765a7ceae32cf3b889296336aaee233c196d204c378 \
    https://github.com/NVIDIA/garak/archive/7aa740fe7412cc9bc33cdc39ca211843223cd3e1.tar.gz /tmp/garak-source.tar.gz
ADD --checksum=sha256:cbc1fef89f8d062739774bd51eda3da3274006b3661d199c2655f6b3f6d605a0 \
    https://files.pythonhosted.org/packages/0e/72/a3add0e4eec4eb9e2569554f7c70f4a3c27712f40e3284d483e88094cc0e/langdetect-1.0.9.tar.gz /tmp/langdetect-source.tar.gz
COPY engines/images/garak/requirements.lock engines/images/garak/build-requirements.lock /tmp/
COPY engines/images/garak/launcher /src/launcher
RUN echo 'b4faa094fd163422d300f87533f0f2c38eb9835fa557bb6126aabbf08a7d4d8f  /tmp/requirements.lock' | sha256sum -c - \
    && echo '98b9d2d9aa49fa0dbe5c141902cdffa46ce4061447075fcedbc7edd63b1e4af6  /tmp/build-requirements.lock' | sha256sum -c - \
    && mkdir -p /src/garak /src/langdetect \
    && tar -xzf /tmp/garak-source.tar.gz --strip-components=1 -C /src/garak \
    && tar -xzf /tmp/langdetect-source.tar.gz --strip-components=1 -C /src/langdetect \
    && python -m pip install --no-compile --only-binary=:all: --require-hashes --prefix=/install --requirement=/tmp/requirements.lock \
    && python -m pip install --no-compile --only-binary=:all: --require-hashes --prefix=/build-deps --requirement=/tmp/build-requirements.lock \
    && PYTHONPATH=/build-deps/lib/python3.11/site-packages python -m pip wheel --no-deps --no-build-isolation --wheel-dir=/wheels /src/langdetect /src/garak \
    && python -m pip install --no-compile --no-deps --prefix=/install /wheels/langdetect-1.0.9-py3-none-any.whl /wheels/garak-0.17.1-py3-none-any.whl \
    && python -I -B /src/launcher/main_test.py \
    && PYTHONPATH=/install/lib/python3.11/site-packages python -c 'import garak,garak.cli,garak.probes.dan,garak.probes.ansiescape,garak.detectors.dan,garak.detectors.ansiescape; assert garak.__version__ == "0.17.1"' \
    && find /install -exec touch -h -d '@1792180550' '{}' +

FROM python:3.11.16-slim@sha256:9c900dea9e8fb7e16277c179b555cc72d29a352dbc33cff48ad5a0412fd5bfc7
LABEL org.opencontainers.image.title="ai-security-scanner Garak engine" \
      org.opencontainers.image.description="Bounded native REST model probes for one approved HTTPS endpoint" \
      org.opencontainers.image.source="https://github.com/NVIDIA/garak" \
      org.opencontainers.image.revision="7aa740fe7412cc9bc33cdc39ca211843223cd3e1" \
      org.opencontainers.image.version="0.17.1-1" org.opencontainers.image.licenses="Apache-2.0" \
      io.ai-security-scanner.source-archive-sha256="22c1d011d86ea6375ddaf765a7ceae32cf3b889296336aaee233c196d204c378" \
      io.ai-security-scanner.requirements-sha256="b4faa094fd163422d300f87533f0f2c38eb9835fa557bb6126aabbf08a7d4d8f"
COPY --from=build /install /usr/local
COPY --from=build /src/garak/LICENSE /usr/share/licenses/garak/LICENSE
COPY --from=build /src/langdetect/LICENSE /usr/share/licenses/langdetect/LICENSE
COPY engines/images/garak/launcher/main.py engines/images/garak/launcher/runner.py /usr/local/lib/aiss-garak/
COPY engines/images/garak/requirements.lock engines/images/garak/build-requirements.lock engines/images/garak/Dockerfile /usr/share/source/
COPY LICENSE /usr/share/licenses/ai-security-scanner/LICENSE
RUN mkdir -p /output \
    && find /usr/share/source /usr/share/licenses /usr/local/lib/aiss-garak -exec touch -h -d '@1792180550' '{}' +
WORKDIR /tmp
USER 65532:65532
ENTRYPOINT ["/usr/local/bin/python3", "-I", "-B", "/usr/local/lib/aiss-garak/main.py"]
