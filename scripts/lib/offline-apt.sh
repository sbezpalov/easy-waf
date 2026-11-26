# Select the HAProxy branch used by both the offline builder and installer.
offline_haproxy_package() {
  case "$1" in
    26.04) printf '%s\n' 'haproxy=3.4.*' ;;
    *) printf '%s\n' haproxy ;;
  esac
}

# Encode a local repository path for the URI field in an APT sources list.
apt_repository_uri() {
  local LC_ALL=C path="$1" byte i
  printf 'file:'
  for ((i=0; i<${#path}; i++)); do
    byte="${path:i:1}"
    case "$byte" in
      [[:alnum:]./_~-]) printf '%s' "$byte" ;;
      *) printf '%%%02X' "'$byte" ;;
    esac
  done
}

# Match the builder's single-entry checksum file for the installer payload.
offline_package_checksum_matches() (
  cd -- "$1" || exit 1
  sha256sum -- "$2" | cmp -s -- SHA256SUMS -
)

offline_check_package_identity() {
  # Match EASY_WAF_DEB_VERSION in Makefile without Bash tilde expansion.
  local deb="$1" version="${2//-/\~}" arch="$3"
  local actual_package actual_version actual_arch
  actual_package="$(dpkg-deb -f "$deb" Package)" &&
    actual_version="$(dpkg-deb -f "$deb" Version)" &&
    actual_arch="$(dpkg-deb -f "$deb" Architecture)" || return 1
  if [[ "$actual_package" != easy-waf || "$actual_arch" != "$arch" ]] ||
    ! dpkg --compare-versions "$actual_version" eq "$version"; then
    echo "[offline-package] expected easy-waf $version ($arch); found $actual_package $actual_version ($actual_arch)" >&2
    return 1
  fi
}

# Validate the bundled repository from an empty package database. The build
# host's APT sources, pins and hooks apply to downloads only.
offline_solve_repository() (
  set -e
  local solver="$1" repository="$2" apt_config="$1/apt.conf"
  shift 2
  install -d -m 0755 "$solver" "$solver/lists" "$solver/cache" "$solver/empty"
  : >"$solver/status"
  printf 'deb [trusted=yes] %s ./\n' "$(apt_repository_uri "$repository")" >"$solver/sources.list"
  cat >"$apt_config" <<EOF
Dir::Etc::main "/dev/null";
Dir::Etc::parts "$solver/empty";
Dir::Etc::sourcelist "$solver/sources.list";
Dir::Etc::sourceparts "$solver/empty";
Dir::Etc::preferences "/dev/null";
Dir::Etc::preferencesparts "$solver/empty";
Dir::State::status "$solver/status";
Dir::State::lists "$solver/lists";
Dir::Cache "$solver/cache";
APT::Install-Recommends "false";
Acquire::Languages "none";
EOF
  APT_CONFIG="$apt_config" apt-get update -qq --error-on=any || exit $?
  if ! APT_CONFIG="$apt_config" apt-get --simulate install "$@" >"$solver/simulate.log" 2>&1; then
    cat "$solver/simulate.log" >&2
    exit 1
  fi
)
