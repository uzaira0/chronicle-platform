FROM docker.io/percona/percona-distribution-postgresql:18.6.1-4@sha256:27a1dba816fcc4cec88f216d54e3ec86db4c1d4b16799f49800055c41606e11e AS curl-builder

USER 0

SHELL ["/bin/bash", "-o", "pipefail", "-c"]

RUN microdnf --disablerepo='*' \
        --enablerepo=ol9_baseos_latest \
        --enablerepo=ol9_appstream \
        install -y \
        openssl-devel-3.5.5-6.0.1.el9_8 \
        xz-5.2.5-8.el9_0 \
        zlib-devel-1.2.11-40.el9 \
    && microdnf clean all \
    && rm -rf /var/cache/dnf /var/cache/yum

WORKDIR /tmp/curl-source

RUN curl --proto '=https' --tlsv1.2 --fail --show-error --location \
        --retry 3 --output /tmp/curl-8.21.0.tar.xz \
        https://curl.se/download/curl-8.21.0.tar.xz \
    && echo 'aa1b66a70eace83dc624508745646c08ae561de512ab403adffb93ac87fc72e6  /tmp/curl-8.21.0.tar.xz' \
        | sha256sum -c - \
    && tar -xJf /tmp/curl-8.21.0.tar.xz --strip-components=1 \
    && ./configure \
        --prefix=/opt/curl \
        --libdir=/opt/curl/lib64 \
        --disable-static \
        --enable-shared \
        --with-openssl \
        --with-zlib \
        --without-brotli \
        --without-zstd \
        --without-libpsl \
        --without-libidn2 \
        --without-libssh2 \
        --without-nghttp2 \
        --without-nghttp3 \
        --without-libgsasl \
        --disable-dict \
        --disable-file \
        --disable-ftp \
        --disable-gopher \
        --disable-imap \
        --disable-ldap \
        --disable-ldaps \
        --disable-mqtt \
        --disable-pop3 \
        --disable-rtsp \
        --disable-smb \
        --disable-smtp \
        --disable-telnet \
        --disable-tftp \
        --disable-websockets \
    && make -j"$(nproc)" \
    && make install \
    && test "$(/opt/curl/bin/curl --version | awk 'NR == 1 { print $2 }')" = '8.21.0' \
    && rm -f /tmp/curl-8.21.0.tar.xz

USER 26

FROM docker.io/percona/percona-distribution-postgresql:18.6.1-4@sha256:27a1dba816fcc4cec88f216d54e3ec86db4c1d4b16799f49800055c41606e11e

USER 0

SHELL ["/bin/bash", "-o", "pipefail", "-c"]

# percona-pg-telemetry18 and percona-telemetry-agent are NOT in the 18.4-5 base at all —
# Percona stopped shipping them in this image. The 17-era build removed them explicitly with
# `rpm -e percona-pg-telemetry17 percona-telemetry-agent`; run against 18.4-5 that same line
# fails the build with "package ... is not installed". They are asserted absent at the end of
# this RUN instead, which is the property that was actually wanted. If a later base
# reintroduces either one, that assertion fails and the removal list below is where they go
# back. This also means shared_preload_libraries must no longer name percona_pg_telemetry:
# the server exits with FATAL: could not access file "percona_pg_telemetry".
RUN microdnf --disablerepo='*' \
        --enablerepo=ol9_baseos_latest \
        --enablerepo=ol9_appstream \
        upgrade -y \
        python3-3.9.25-7.0.1.el9_8.2 \
        python3-libs-3.9.25-7.0.1.el9_8.2 \
        python-unversioned-command-3.9.25-7.0.1.el9_8.2 \
    && microdnf clean all \
    && rm -rf /var/cache/dnf /var/cache/yum \
    && test "$(rpm -q --qf '%{VERSION}-%{RELEASE}' python3)" = '3.9.25-7.0.1.el9_8.2' \
    && test "$(rpm -q --qf '%{VERSION}-%{RELEASE}' percona-postgresql18-server)" = '18.6-1.el9' \
    && rpm -e --nodeps \
        kernel-headers \
        curl-minimal \
        libcurl-minimal \
        vim-filesystem \
        tar \
        acl \
        glib2 \
        libpq \
        perl-Archive-Tar \
    && ! rpm -q percona-telemetry-agent \
    && ! rpm -q percona-pg-telemetry18 \
    && ! test -e /usr/bin/percona-telemetry-agent \
    && ! test -e /usr/pgsql-18/lib/percona_pg_telemetry.so

COPY --from=curl-builder /opt/curl/lib64/ /usr/lib64/

LABEL org.opencontainers.image.revision="percona-18.6.1-4-chronicle-curl-8.21.0-20260903"

HEALTHCHECK --interval=10s --timeout=5s --start-period=30s --retries=12 \
    CMD pg_isready -h 127.0.0.1 -U "${POSTGRES_USER:-postgres}" -d "${POSTGRES_DB:-postgres}" || exit 1

USER 26
