#!/bin/sh
# usage: make-stick.sh [--force-any-dir] <stick-mount-path> [release-dir|tag]
# Stages the release in a temp directory, verifies it there with verify-release.sh,
# and copies to the stick only after that passes. Nothing unverified reaches the stick.
set -eu
force=0
if [ "${1:-}" = "--force-any-dir" ]; then force=1; shift; fi
[ $# -ge 1 ] && [ $# -le 2 ] || { echo "usage: $0 [--force-any-dir] <stick> [release-dir|tag]" >&2; exit 2; }
stick=$1; src=${2:-}
here=$(cd "$(dirname "$0")" && pwd)
[ -d "$stick" ] || { echo "not a directory: $stick" >&2; exit 1; }

removable() {
  case "$(uname -s)" in
    Darwin)
      info=$(diskutil info "$stick" 2>/dev/null) || return 1
      echo "$info" | grep -Eq 'Removable Media:[[:space:]]+(Removable|Yes)|Device Location:[[:space:]]+External|Protocol:[[:space:]]+USB' ;;
    Linux)
      dev=$(findmnt -n -o SOURCE -T "$stick" 2>/dev/null) || return 1
      lsblk -ndo RM,HOTPLUG "$dev" 2>/dev/null | grep -q '1' || \
        lsblk -ndo RM,HOTPLUG "/dev/$(lsblk -ndo PKNAME "$dev" 2>/dev/null)" 2>/dev/null | grep -q '1' ;;
    *) return 1 ;;
  esac
}
if [ $force -eq 0 ] && ! removable; then
  echo "refusing: $stick is not a mounted removable volume (use --force-any-dir to override)" >&2; exit 1
fi

stage=$(mktemp -d)
trap 'rm -r "$stage"' EXIT

# Stage SHA256SUMS, then exactly the files it lists.
base=""; bsrc=""
if [ -n "$src" ] && [ ! -d "$src" ]; then
  base="https://github.com/prfagit/qusb/releases/download/$src"
  curl -fsSL "$base/SHA256SUMS" -o "$stage/SHA256SUMS" || { echo "download failed: SHA256SUMS" >&2; exit 1; }
  set -- "$stage"
else
  [ -n "$src" ] || src=$here/../dist
  [ -f "$src/SHA256SUMS" ] || { echo "no SHA256SUMS in $src" >&2; exit 1; }
  # release dir is flat (bin files beside SHA256SUMS) or already has bin/
  if [ -d "$src/bin" ]; then bsrc=$src/bin; else bsrc=$src; fi
  cp "$src/SHA256SUMS" "$stage/SHA256SUMS"
  # a local directory may be your own build, which has no GitHub attestation
  set -- --checksums-only "$stage"
fi
while read -r _ name; do
  name=${name#\*}
  case "$name" in
    "") continue ;;
    */*|qusb-*[!A-Za-z0-9._-]*) echo "refusing odd file name in SHA256SUMS: $name" >&2; exit 1 ;;
    qusb-*) ;;
    *) echo "refusing odd file name in SHA256SUMS: $name" >&2; exit 1 ;;
  esac
  if [ -n "$base" ]; then
    curl -fsSL "$base/$name" -o "$stage/$name" || { echo "download failed: $name" >&2; exit 1; }
  else
    cp "$bsrc/$name" "$stage/$name" || { echo "missing in $bsrc: $name" >&2; exit 1; }
  fi
done < "$stage/SHA256SUMS"
doc=$src/START-HERE.txt; [ -f "$doc" ] || doc=$here/../stick/START-HERE.txt

"$here/verify-release.sh" "$@" > "$stage/verify.log" || {
  cat "$stage/verify.log"
  echo "verification FAILED: nothing was copied to $stick" >&2; exit 1
}
cat "$stage/verify.log"

mkdir -p "$stick/bin" "$stick/qusb/sigs"
for f in "$stage"/qusb-*; do
  case "$f" in *.zip) continue ;; esac
  cp "$f" "$stick/bin/"
done
# the stick carries the binaries only, so its SHA256SUMS drops the zip line
grep -v 'qusb-stick\.zip$' "$stage/SHA256SUMS" > "$stick/bin/SHA256SUMS"
cp "$doc" "$stick/START-HERE.txt"
chmod +x "$stick"/bin/qusb-* 2>/dev/null || true

case "$(uname -s)-$(uname -m)" in
  Darwin-arm64) os=macos-arm64 ;; Darwin-*) os=macos-x64 ;;
  Linux-aarch64|Linux-arm64) os=linux-arm64 ;; Linux-*) os=linux-x64 ;;
  *) os="<os>" ;;
esac
echo "stick ready. next: $stick/bin/qusb-$os init $stick"
