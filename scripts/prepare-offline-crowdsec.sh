#!/usr/bin/env bash
# Prepare a private CrowdSec Hub snapshot on a connected Ubuntu build host.
set -euo pipefail
umask 077

if [[ $# != 1 ]]; then
  echo 'Usage: bash scripts/prepare-offline-crowdsec.sh <new-output-directory>' >&2
  exit 2
fi
CSCLI="${CSCLI:-cscli}"
CSCLI="$(command -v "$CSCLI")" || { echo 'CrowdSec cscli is required' >&2; exit 1; }
# Resolve a relative executable before changing to the staging directory.
CSCLI="$(cd "$(dirname "$CSCLI")" && pwd)/$(basename "$CSCLI")"

parent="$(cd "$(dirname "$1")" && pwd)"
output="$parent/$(basename "$1")"
if [[ -e "$output" || -L "$output" ]]; then
  echo 'Choose a new output directory for the CrowdSec snapshot' >&2
  exit 1
fi
work="$(mktemp -d "$parent/.crowdsec-snapshot.XXXXXX")"
trap 'rm -rf -- "$work"' EXIT

cd "$work"
mkdir -p working/acquis.d snapshot/hub snapshot/data
cat >cscli.yaml <<'YAML'
common:
  log_media: stdout
config_paths:
  config_dir: ./working
  data_dir: ./snapshot/data
  hub_dir: ./snapshot/hub
  index_path: ./snapshot/hub/.index.json
crowdsec_service:
  acquisition_dir: ./working/acquis.d
YAML

version="$("$CSCLI" version | sed -n 's/^version: //p')"
branch="$("$CSCLI" -c cscli.yaml hub branch)"
if [[ ! "$version" =~ ^[A-Za-z0-9][A-Za-z0-9._+-]*$ || ! "$branch" =~ ^[A-Za-z0-9][A-Za-z0-9._/-]*$ ]]; then
  echo 'Could not identify the CrowdSec CLI version and Hub branch' >&2
  exit 1
fi
printf 'cscli:\n  hub_branch: "%s"\n' "$branch" >>cscli.yaml
printf 'CROWDSEC_CLI_VERSION=%s\nCROWDSEC_HUB_BRANCH=%s\n' "$version" "$branch" >snapshot/SNAPSHOT.env

cat >snapshot/setup.yaml <<'YAML'
setup:
  - detected_service: easy-waf-offline
    hub_spec:
      collections:
        - crowdsecurity/linux
        - crowdsecurity/haproxy
        - crowdsecurity/sshd
        - crowdsecurity/pgsql
      parsers:
        - crowdsecurity/whitelists
YAML
"$CSCLI" -c cscli.yaml hub update --with-content
"$CSCLI" -c cscli.yaml setup install-hub snapshot/setup.yaml --color no
[[ -s snapshot/hub/.index.json ]] || { echo 'The Hub index is missing from the snapshot' >&2; exit 1; }

(
  cd snapshot
  if [[ -n "$(find hub data ! -type d ! -type f -print -quit)" ]]; then
    echo 'CrowdSec cache contains an unexpected file type' >&2
    exit 1
  fi
  {
    printf '%s\0' SNAPSHOT.env setup.yaml
    find hub data -type f -print0
  } | LC_ALL=C sort -z | xargs -0 sha256sum
) >SHA256SUMS
mv SHA256SUMS snapshot/
(cd snapshot && sha256sum -c SHA256SUMS >/dev/null)
mv -T -n -- snapshot "$output"
if [[ -e snapshot ]]; then
  echo 'The output directory appeared while preparing the snapshot' >&2
  exit 1
fi
printf 'CrowdSec snapshot written to %s\n' "$output"
