# syntax=docker/dockerfile:1.7@sha256:a57df69d0ea827fb7266491f2813635de6f17269be881f696fbfdf2d83dda33e

ARG SOURCE_DATE_EPOCH=1793881759
FROM --platform=$TARGETPLATFORM golang:1.26.10-alpine@sha256:87c65a688975c0b1d4585d204874c45ca78354670e3a5f11368c5a492303d696 AS launcher

ARG TARGETOS
ARG TARGETARCH

ENV CGO_ENABLED=0 \
    GOTOOLCHAIN=local \
    SOURCE_DATE_EPOCH=1793881759

WORKDIR /src/launcher
COPY engines/images/greenbone-launcher/go.mod engines/images/greenbone-launcher/main.go engines/images/greenbone-launcher/main_test.go ./
RUN gofmt -d main.go main_test.go | tee /tmp/gofmt.diff \
    && test ! -s /tmp/gofmt.diff \
    && go test ./... \
    && GOOS=${TARGETOS} GOARCH=${TARGETARCH} go build \
        -buildvcs=false -trimpath -ldflags='-s -w -buildid=' \
        -o /out/ai-security-scanner-engine-entrypoint .

FROM registry.community.greenbone.net/community/vulnerability-tests@sha256:3a3cf9affb94ee3d714d3da7ebc35bf52bb0f1f32e5d196e82d2c3bf06b2b126 AS feed
RUN grep -Fqx 'FEED_COMMIT = "a2e53c2e30f1fa5408369cb5cf99653a3e08e9df";' /var/lib/openvas/24.10/vt-data/nasl/plugin_feed_info.inc \
    && test -s /var/lib/openvas/24.10/vt-data/nasl/vt-metadata.json \
    && test -s /var/lib/openvas/24.10/vt-data/nasl/sha256sums \
    && test -s /var/lib/openvas/24.10/vt-data/nasl/sha256sums.asc

FROM registry.community.greenbone.net/community/notus-data@sha256:cb3cc1ed07594e853493d3e1be9d320e60ed053951f1f43125cf791049d6a590 AS notus
RUN mkdir -p /prepared \
    && tar -xzf /var/lib/notus/notus-data.tar.gz -C /prepared \
    && test -s /prepared/advisories/sha256sums \
    && test -s /prepared/advisories/sha256sums.asc \
    && test -s /prepared/products/sha256sums

FROM scratch AS source
ADD --checksum=sha256:ea798d3dcf2ca43b93be9bee9b644c699632226e5fa7659dbe40f6f4bd128f63 \
    https://github.com/greenbone/openvas-scanner/archive/cbd9081531ea6602bea7356aa371200979c1e961.tar.gz \
    /openvas-scanner-23.52.9.tar.gz

FROM rust:1.99.0-bookworm@sha256:114c7a4425406451c2866b6aafe69fe29b1b298832db1277d411ac73c82d04d6 AS scanner-source
COPY --from=source /openvas-scanner-23.52.9.tar.gz /tmp/openvas-scanner.tar.gz
RUN mkdir -p /source \
    && tar -xzf /tmp/openvas-scanner.tar.gz --strip-components=1 -C /source \
    && test -f /source/rust/Cargo.lock \
    && test -d /source/.docker/vendor/krb5-1.22.2 \
    && test -d /source/.docker/vendor/libpcap-1.10.6

FROM scanner-source AS krb5-build
RUN apt-get update \
    && apt-get install --no-install-recommends --no-install-suggests -y \
        bison ca-certificates make \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /source/.docker/vendor/krb5-1.22.2/src
RUN ./configure --prefix=/opt/krb5-static \
        --enable-static \
        --disable-shared \
        --without-system-verto \
        --without-libedit \
        --disable-rpath \
    && make -C util/support -j8 \
    && make -C util/et -j8 \
    && make -C util/profile -j8 \
    && make -C include -j8 \
    && make -C lib/crypto -j8 \
    && make -C lib/krb5 -j8 \
    && make -C lib/gssapi -j8 \
    && make install-mkdirs \
    && make -C util/support install \
    && make -C util/et install \
    && make -C util/profile install \
    && make -C include install \
    && make -C lib/crypto install \
    && make -C lib/krb5 install \
    && make -C lib/gssapi install \
    && test -f /opt/krb5-static/lib/libgssapi_krb5.a \
    && test -f /opt/krb5-static/lib/libkrb5.a \
    && test -f /opt/krb5-static/lib/libk5crypto.a \
    && test -f /opt/krb5-static/lib/libcom_err.a \
    && test -f /opt/krb5-static/lib/libkrb5support.a

FROM scanner-source AS pcap-build
RUN apt-get update \
    && apt-get install --no-install-recommends --no-install-suggests -y \
        bison ca-certificates flex make \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /source/.docker/vendor/libpcap-1.10.6
RUN ./configure --prefix=/opt/libpcap-static --disable-shared --disable-dbus \
    && make -j8 \
    && make install \
    && test -f /opt/libpcap-static/lib/libpcap.a \
    && test -f /opt/libpcap-static/include/pcap.h

FROM rust:1.99.0-bookworm@sha256:114c7a4425406451c2866b6aafe69fe29b1b298832db1277d411ac73c82d04d6 AS build-archives
COPY --from=krb5-build /opt/krb5-static /opt/krb5-static
COPY --from=pcap-build /opt/libpcap-static /opt/libpcap-static
RUN mkdir -p /archives/include/gssapi /archives/include/krb5 \
    && install -m 644 /opt/libpcap-static/lib/libpcap.a /archives/libpcap.a \
    && install -m 644 /opt/krb5-static/lib/libgssapi_krb5.a /archives/libgssapi_krb5.a \
    && install -m 644 /opt/krb5-static/lib/libkrb5.a /archives/libkrb5.a \
    && install -m 644 /opt/krb5-static/lib/libk5crypto.a /archives/libk5crypto.a \
    && install -m 644 /opt/krb5-static/lib/libcom_err.a /archives/libcom_err.a \
    && install -m 644 /opt/krb5-static/lib/libkrb5support.a /archives/libkrb5support.a \
    && install -m 644 /opt/libpcap-static/include/pcap.h /archives/include/pcap.h \
    && install -m 644 /opt/krb5-static/include/krb5.h /archives/include/krb5.h \
    && install -m 644 /opt/krb5-static/include/com_err.h /archives/include/com_err.h \
    && install -m 644 /opt/krb5-static/include/profile.h /archives/include/profile.h \
    && install -m 644 /opt/krb5-static/include/gssapi/gssapi.h /archives/include/gssapi/gssapi.h \
    && install -m 644 /opt/krb5-static/include/gssapi/gssapi_alloc.h /archives/include/gssapi/gssapi_alloc.h \
    && install -m 644 /opt/krb5-static/include/gssapi/gssapi_ext.h /archives/include/gssapi/gssapi_ext.h \
    && install -m 644 /opt/krb5-static/include/gssapi/gssapi_generic.h /archives/include/gssapi/gssapi_generic.h \
    && install -m 644 /opt/krb5-static/include/gssapi/gssapi_krb5.h /archives/include/gssapi/gssapi_krb5.h \
    && install -m 644 /opt/krb5-static/include/gssapi/mechglue.h /archives/include/gssapi/mechglue.h \
    && install -m 644 /opt/krb5-static/include/krb5/krb5.h /archives/include/krb5/krb5.h

FROM scanner-source AS scanner-build
ARG SOURCE_DATE_EPOCH
ENV BIN_VERSION="cbd9081531ea6602bea7356aa371200979c1e961" \
    CARGO_INCREMENTAL="0" \
    CARGO_BUILD_JOBS="8" \
    OPENVAS_ARCHIVES="/archives" \
    LIBPCAP_LIBDIR="/archives" \
    SOURCE_DATE_EPOCH="${SOURCE_DATE_EPOCH}"
COPY --from=build-archives /archives /archives
RUN apt-get update \
    && apt-get install --no-install-recommends --no-install-suggests -y \
        capnproto ca-certificates libclang-dev libsnmp-dev make patch \
    && rm -rf /var/lib/apt/lists/*
COPY engines/images/greenbone/openvasd-rustls-provider.patch /tmp/openvasd-rustls-provider.patch
COPY engines/images/greenbone/openvasd-service-port.patch /tmp/openvasd-service-port.patch
COPY engines/images/greenbone/openvasd-nasl-local-declarations.patch /tmp/openvasd-nasl-local-declarations.patch
COPY engines/images/greenbone/openvasd-nasl-dict-compat.patch /tmp/openvasd-nasl-dict-compat.patch
COPY engines/images/greenbone/openvasd-nasl-string-compat.patch /tmp/openvasd-nasl-string-compat.patch
COPY engines/images/greenbone/openvasd-nasl-value-coercion.patch /tmp/openvasd-nasl-value-coercion.patch
COPY engines/images/greenbone/openvasd-http-compat.patch /tmp/openvasd-http-compat.patch
COPY engines/images/greenbone/openvasd-nasl-array-compat.patch /tmp/openvasd-nasl-array-compat.patch
COPY engines/images/greenbone/openvasd-eregmatch-captures.patch /tmp/openvasd-eregmatch-captures.patch
COPY engines/images/greenbone/openvasd-report-port.patch /tmp/openvasd-report-port.patch
COPY engines/images/greenbone/openvasd-socket-eof.patch /tmp/openvasd-socket-eof.patch
RUN patch --batch --fuzz=0 -p1 -d /source < /tmp/openvasd-rustls-provider.patch \
    && patch --batch --fuzz=0 -p1 -d /source < /tmp/openvasd-service-port.patch \
    && patch --batch --fuzz=0 -p1 -d /source < /tmp/openvasd-nasl-local-declarations.patch \
    && patch --batch --fuzz=0 -p1 -d /source < /tmp/openvasd-nasl-dict-compat.patch \
    && patch --batch --fuzz=0 -p1 -d /source < /tmp/openvasd-nasl-string-compat.patch \
    && patch --batch --fuzz=0 -p1 -d /source < /tmp/openvasd-nasl-value-coercion.patch \
    && patch --batch --fuzz=0 -p1 -d /source < /tmp/openvasd-http-compat.patch \
    && patch --batch --fuzz=0 -p1 -d /source < /tmp/openvasd-nasl-array-compat.patch \
    && patch --batch --fuzz=0 -p1 -d /source < /tmp/openvasd-eregmatch-captures.patch \
    && patch --batch --fuzz=0 -p1 -d /source < /tmp/openvasd-report-port.patch \
    && patch --batch --fuzz=0 -p1 -d /source < /tmp/openvasd-socket-eof.patch
WORKDIR /source/rust
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/usr/local/cargo/git \
    --mount=type=cache,target=/source/rust/target \
    cargo test --locked --lib scanner::vt_runner::tests \
    && cargo test --locked --lib nasl::builtin::find_service::tests \
    && cargo test --locked --lib nasl::builtin::http::tests \
    && cargo test --locked --lib nasl::builtin::regex::tests \
    && cargo test --locked --lib nasl::builtin::report::tests \
    && cargo test --locked --lib nasl::builtin::network::socket::tests \
    && cargo test --locked --bin openvasd database::sqlite::results::tests \
    && cargo test --locked --lib nasl::builtin::string::tests \
    && cargo test --locked --lib nasl::interpreter::declare::tests \
    && cargo test --locked --lib nasl::interpreter::tests::missing_dict_key \
    && cargo test --locked --lib nasl::interpreter::tests::array_out_of_range \
    && cargo test --locked --lib nasl::utils::function::from_nasl_value::tests \
    && cargo build --locked --release --bin openvasd \
    && install -Dm755 target/release/openvasd /out/openvasd \
    && /out/openvasd --version 2>&1 | grep -Fq 'cbd9081531ea6602bea7356aa371200979c1e961'

FROM ghcr.io/greenbone/openvas-scanner@sha256:d6d8288c22bc525e78e221a36c9db44328d3d9e0141f810c4216750ff0641ddc

ARG SOURCE_DATE_EPOCH

LABEL org.opencontainers.image.title="ai-security-scanner Greenbone engine" \
      org.opencontainers.image.description="Signed-feed Greenbone scanner with exact per-grant loopback relays to the managed SOCKS gateway" \
      org.opencontainers.image.source="https://github.com/greenbone/openvas-scanner" \
      org.opencontainers.image.revision="cbd9081531ea6602bea7356aa371200979c1e961" \
      org.opencontainers.image.version="23.52.9-feed202611060607-1" \
      org.opencontainers.image.licenses="GPL-2.0-only AND ODbL-1.0 AND Apache-2.0" \
      io.ai-security-scanner.openvas-revision="cbd9081531ea6602bea7356aa371200979c1e961" \
      io.ai-security-scanner.openvas-source-sha256="sha256:ea798d3dcf2ca43b93be9bee9b644c699632226e5fa7659dbe40f6f4bd128f63" \
      io.ai-security-scanner.openvas-patch="rustls-provider:2ab37a3514150ad3480c315e1ec73a2d6f1bade37ce787614fdfcd76245ed4b2;service-port:992ea5d22fe668e49793e0a8966f5c25de4c8ecb76c882953c72761e79c276f0;nasl-local-declarations:f77b19e2b4ebb91b4f28d7dfdde0331cfbedf0764a032c87f4152b32614f15a1;nasl-dict-compat:1a455038bf209f95a3028fcc7447af29128477ce3b0f429ad696bb0e01bfccfe;nasl-string-compat:685d9769142cc9cf70b6b0698bac8dc462c11a254a2420e20a66e048fe79de38;nasl-value-coercion:cb3dc36c4b41412662844b1536d501f5da98a7c68d86a3d8b9178758e3fe92d6;http-compat:963e48b293185a38cfff15e8cfeba045416ee353bed6878856b3280c367138ea;nasl-array-compat:ea9d7ba960fad509c18924855a19b6e2499bf13fb25cfac4c66a02b82e708c20;eregmatch-captures:d72d4cda3a61cfef5f5e347f83bdf1c08d78354d62c749339461a00443ac02db;report-port:83f53b7117047c17a7a8ccf9559daa5e9e1229f75eb3743bc966c93e04d796a4;socket-eof:e08d242a5741e1a30d2df067911fa21fa0b026ad47197125e035fe88b7cb15db" \
      io.ai-security-scanner.feed-revision="a2e53c2e30f1fa5408369cb5cf99653a3e08e9df" \
      io.ai-security-scanner.feed-version="202611060607-community" \
      io.ai-security-scanner.feed-image-digest="sha256:3a3cf9affb94ee3d714d3da7ebc35bf52bb0f1f32e5d196e82d2c3bf06b2b126" \
      io.ai-security-scanner.notus-revision="202611060538" \
      io.ai-security-scanner.notus-image-digest="sha256:cb3cc1ed07594e853493d3e1be9d320e60ed053951f1f43125cf791049d6a590"

ENV HOME="/tmp" \
    LANG="C.UTF-8" \
    LC_ALL="C.UTF-8" \
    NMAP_PRIVILEGED="0" \
    SSL_CERT_FILE="/etc/ssl/certs/ca-certificates.crt" \
    TMPDIR="/tmp"

COPY --from=launcher --chmod=0555 /out/ai-security-scanner-engine-entrypoint /usr/local/bin/ai-security-scanner-engine-entrypoint
COPY --from=scanner-build --chmod=0555 /out/openvasd /usr/local/bin/openvasd
COPY --from=feed /var/lib/openvas/24.10/vt-data/nasl/ /opt/greenbone/feed/
COPY --from=notus /prepared/ /opt/greenbone/notus/

COPY --chmod=0444 LICENSE /usr/share/licenses/ai-security-scanner/LICENSE
COPY --chmod=0444 engines/images/greenbone/SOURCE-OFFER.md /usr/share/source/greenbone/SOURCE-OFFER.md
COPY --chmod=0444 engines/images/greenbone/THIRD-PARTY-NOTICES.md /usr/share/licenses/greenbone/THIRD-PARTY-NOTICES.md
COPY --from=source --chmod=0444 /openvas-scanner-23.52.9.tar.gz /usr/share/source/openvas-scanner/openvas-scanner-23.52.9.tar.gz
COPY --chmod=0444 engines/images/greenbone/Dockerfile /usr/share/source/ai-security-scanner-greenbone/build/Dockerfile
COPY --chmod=0444 engines/images/greenbone/openvasd-rustls-provider.patch /usr/share/source/ai-security-scanner-greenbone/patches/openvasd-rustls-provider.patch
COPY --chmod=0444 engines/images/greenbone/openvasd-service-port.patch /usr/share/source/ai-security-scanner-greenbone/patches/openvasd-service-port.patch
COPY --chmod=0444 engines/images/greenbone/openvasd-nasl-local-declarations.patch /usr/share/source/ai-security-scanner-greenbone/patches/openvasd-nasl-local-declarations.patch
COPY --chmod=0444 engines/images/greenbone/openvasd-nasl-dict-compat.patch /usr/share/source/ai-security-scanner-greenbone/patches/openvasd-nasl-dict-compat.patch
COPY --chmod=0444 engines/images/greenbone/openvasd-nasl-string-compat.patch /usr/share/source/ai-security-scanner-greenbone/patches/openvasd-nasl-string-compat.patch
COPY --chmod=0444 engines/images/greenbone/openvasd-nasl-value-coercion.patch /usr/share/source/ai-security-scanner-greenbone/patches/openvasd-nasl-value-coercion.patch
COPY --chmod=0444 engines/images/greenbone/openvasd-http-compat.patch /usr/share/source/ai-security-scanner-greenbone/patches/openvasd-http-compat.patch
COPY --chmod=0444 engines/images/greenbone/openvasd-nasl-array-compat.patch /usr/share/source/ai-security-scanner-greenbone/patches/openvasd-nasl-array-compat.patch
COPY --chmod=0444 engines/images/greenbone/openvasd-eregmatch-captures.patch /usr/share/source/ai-security-scanner-greenbone/patches/openvasd-eregmatch-captures.patch
COPY --chmod=0444 engines/images/greenbone/openvasd-report-port.patch /usr/share/source/ai-security-scanner-greenbone/patches/openvasd-report-port.patch
COPY --chmod=0444 engines/images/greenbone/openvasd-socket-eof.patch /usr/share/source/ai-security-scanner-greenbone/patches/openvasd-socket-eof.patch
COPY --chmod=0444 engines/images/greenbone-launcher/go.mod engines/images/greenbone-launcher/main.go engines/images/greenbone-launcher/main_test.go /usr/share/source/ai-security-scanner-greenbone/launcher/

RUN setcap -r /usr/bin/nmap \
    && setcap -r /usr/local/sbin/openvas \
    && rm -f /usr/bin/nmap /usr/local/sbin/openvas \
    && mkdir -p /run/ai-security-scanner /output /workspace /tmp \
    && chmod 1777 /tmp \
    && test -z "$(getcap -r /usr/bin /usr/local 2>/dev/null)" \
	&& /usr/local/bin/openvasd --version 2>&1 | grep -Fq 'cbd9081531ea6602bea7356aa371200979c1e961'

WORKDIR /workspace
USER 65532:65532
ENTRYPOINT ["/usr/local/bin/ai-security-scanner-engine-entrypoint"]
