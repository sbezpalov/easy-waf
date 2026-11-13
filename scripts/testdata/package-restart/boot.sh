#!/usr/bin/env bash
# Only the isolated package-lifecycle image uses this entrypoint.
set -euo pipefail
[[ -e /.dockerenv ]] || { echo 'Docker fixture required' >&2; exit 90; }
if grep -vE '^[0-9]+:[^:]*:/$' /proc/self/cgroup; then
  echo 'Refusing a non-private cgroup namespace' >&2
  exit 91
fi
# Docker delegates only this container's subtree into its private cgroup
# namespace. Change its private bind-mount flags, never mount the host hierarchy.
while read -r target kind; do
  case "$kind" in
    cgroup | cgroup2) mount -o remount,bind,rw "$target" ;;
  esac
done < <(findmnt -rn -o TARGET,FSTYPE /sys/fs/cgroup --submounts)
install -d -m 0755 /run/systemd/system /opt/easy-waf-package-fixture
printf 'easy-waf-package-fixture-v1\n' >/opt/easy-waf-package-fixture/container-marker
for unit in easy-waf-fixture.target basic.target sysinit.target; do
  cat >"/run/systemd/system/$unit" <<'UNIT'
[Unit]
Description=Isolated Easy WAF package fixture prerequisite
DefaultDependencies=no
UNIT
done
exec /usr/lib/systemd/systemd --system --unit=easy-waf-fixture.target --log-target=console
