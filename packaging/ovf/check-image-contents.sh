#!/usr/bin/env bash
# Check a prepared appliance root for files this project must not ship.
# Usage:
#   packaging/ovf/check-image-contents.sh /mnt/image-root
# With no path, print the manual image checklist and exit 0.
# This does not build a VM.

set -euo pipefail

if [[ $# -lt 1 ]]; then
  cat <<'EOF'
No image root was passed. Build the VM on a hypervisor (see packaging/ovf/README.md), then run:

  packaging/ovf/check-image-contents.sh /mnt/image-root

The script fails if that tree contains a GeoLite2 database. It does not check
Ubuntu's GPL packages; those come from apt, and their source is the Ubuntu archive.
EOF
  exit 0
fi

root="$1"
if [[ ! -d "$root" ]]; then
  echo "not a directory: $root" >&2
  exit 1
fi

found=0
while IFS= read -r -d '' f; do
  echo "GeoLite2 must not be baked into the image: $f" >&2
  found=1
done < <(find "$root" -type f \( -iname '*geolite2*' -o -iname 'GeoLite2-Country.mmdb' \) -print0)

if [[ "$found" -ne 0 ]]; then
  exit 1
fi
echo "no GeoLite2 files under $root"
