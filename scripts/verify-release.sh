#!/bin/sh
# usage: verify-release.sh [--checksums-only] <dir>   (dir holds SHA256SUMS + the files it lists)
# Checks every listed file against SHA256SUMS, then checks build provenance with
# `gh attestation verify` when the GitHub CLI is installed and logged in.
# The last line says which of the two checks actually ran.
set -eu
attest=1
if [ "${1:-}" = "--checksums-only" ]; then attest=0; shift; fi
[ $# -eq 1 ] && [ -d "$1" ] || { echo "usage: $0 [--checksums-only] <dir>" >&2; exit 2; }
cd "$1"
[ -f SHA256SUMS ] || { echo "no SHA256SUMS in $1" >&2; exit 1; }
if command -v sha256sum >/dev/null 2>&1; then sha256sum -c SHA256SUMS
else shasum -a 256 -c SHA256SUMS; fi || { echo "CHECKSUM VERIFY FAILED" >&2; exit 1; }

if [ $attest -eq 0 ]; then skipped="--checksums-only was given"
elif ! command -v gh >/dev/null 2>&1; then skipped="the GitHub CLI (gh) is not installed"
elif ! gh auth status >/dev/null 2>&1; then skipped="gh is not logged in (run: gh auth login)"
else
  skipped=""
  gh attestation verify SHA256SUMS --repo prfagit/qusb >/dev/null </dev/null \
    || { echo "ATTESTATION FAILED: SHA256SUMS" >&2; exit 1; }
  echo "attested: SHA256SUMS"
  # line format: "<hash>  <name>" or "<hash> *<name>"
  while read -r _ name; do
    name=${name#\*}
    [ -n "$name" ] || continue
    gh attestation verify "$name" --repo prfagit/qusb >/dev/null </dev/null \
      || { echo "ATTESTATION FAILED: $name" >&2; exit 1; }
    echo "attested: $name"
  done < SHA256SUMS
fi

if [ -n "$skipped" ]; then
  echo "checksums ok. PROVENANCE NOT CHECKED: $skipped"
else
  echo "ok: checksums and build provenance verified"
fi
