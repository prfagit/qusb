#!/bin/sh
# usage: verify-release.sh <dir>   (dir holds SHA256SUMS + the files it lists)
set -eu
[ $# -eq 1 ] && [ -d "$1" ] || { echo "usage: $0 <dir>" >&2; exit 2; }
cd "$1"
[ -f SHA256SUMS ] || { echo "no SHA256SUMS in $1" >&2; exit 1; }
if command -v sha256sum >/dev/null 2>&1; then sha256sum -c SHA256SUMS
else shasum -a 256 -c SHA256SUMS; fi
if command -v gh >/dev/null 2>&1; then
  for f in $(awk '{print $2}' SHA256SUMS | sed 's/^\*//'); do
    gh attestation verify "$f" --repo prfagit/qusb >/dev/null && echo "attested: $f" \
      || { echo "ATTESTATION FAILED: $f" >&2; exit 1; }
  done
else
  echo "gh not found: checksums only, provenance not checked" >&2
fi
echo "ok"
