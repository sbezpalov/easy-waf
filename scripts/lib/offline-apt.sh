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
