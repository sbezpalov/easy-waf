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
