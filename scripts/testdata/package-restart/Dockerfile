# No application services are booted: boot.sh selects an empty fixture target.
ARG BASE_IMAGE=ubuntu:24.04
FROM ${BASE_IMAGE}
RUN if ! command -v systemd >/dev/null || ! command -v findmnt >/dev/null || ! command -v useradd >/dev/null; then \
      apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
        systemd systemd-sysv util-linux passwd; \
    fi
COPY boot.sh /usr/local/libexec/easy-waf-package-fixture-boot
RUN chmod 0755 /usr/local/libexec/easy-waf-package-fixture-boot
ENV container=docker
HEALTHCHECK NONE
ENTRYPOINT ["/usr/local/libexec/easy-waf-package-fixture-boot"]
