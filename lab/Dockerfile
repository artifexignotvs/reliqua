ARG BASE_IMAGE
FROM ${BASE_IMAGE}
ARG OLD_SNAPSHOT
ARG OLD_VERSION
ENV DEBIAN_FRONTEND=noninteractive PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1

COPY old-packages /tmp/old-packages
COPY bootstrap-ca.deb /tmp/bootstrap-ca.deb
# Servitia in hac officina tantum mutantur.
RUN printf '#!/bin/sh\nexit 101\n' > /usr/sbin/policy-rc.d \
    && chmod 755 /usr/sbin/policy-rc.d \
    && dpkg-deb --extract /tmp/bootstrap-ca.deb / \
    && mkdir -p /etc/ssl/certs \
    && cat /usr/share/ca-certificates/mozilla/*.crt > /etc/ssl/certs/ca-certificates.crt \
    && rm -f /etc/apt/sources.list /etc/apt/sources.list.d/* \
    && printf 'deb [check-valid-until=no] http://snapshot.ubuntu.com/ubuntu/%s noble main universe\ndeb [check-valid-until=no] http://snapshot.ubuntu.com/ubuntu/%s noble-updates main universe\ndeb [check-valid-until=no] http://snapshot.ubuntu.com/ubuntu/%s noble-security main universe\n' "$OLD_SNAPSHOT" "$OLD_SNAPSHOT" "$OLD_SNAPSHOT" > /etc/apt/sources.list \
    && apt-get -o APT::Update::Error-Mode=any -o Acquire::Retries=2 -o Acquire::http::Timeout=30 update \
    && apt-get -o Acquire::Retries=2 -o Acquire::http::Timeout=30 install -y --no-install-recommends \
        python3 procps util-linux ca-certificates \
        /tmp/old-packages/*.deb \
    && rm -rf /var/lib/apt/lists/* /var/cache/apt/archives/* /tmp/old-packages /tmp/bootstrap-ca.deb

COPY packages /opt/lab/packages
COPY comparison /opt/comparison
COPY reliqua /opt/reliqua
COPY lab /opt/lab
WORKDIR /opt
RUN python3 /opt/lab/inside.py --verify-build
ENTRYPOINT ["python3", "/opt/lab/inside.py"]
