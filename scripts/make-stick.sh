#!/bin/sh
# usage: make-stick.sh [--force-any-dir] <stick-mount-path> [release-dir|tag]
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

tmp=""
trap '[ -z "$tmp" ] || rm -r "$tmp"' EXIT
if [ -n "$src" ] && [ ! -d "$src" ]; then
  tmp=$(mktemp -d); tag=$src
  base="https://github.com/prfagit/qusb/releases/download/$tag"
  for f in SHA256SUMS qusb-linux-x64 qusb-linux-arm64 qusb-macos-x64 qusb-macos-arm64 qusb-windows-x64.exe; do
    curl -fsSL "$base/$f" -o "$tmp/$f" || { echo "download failed: $f" >&2; exit 1; }
  done
  src=$tmp
elif [ -z "$src" ]; then src=$here/../dist; fi
[ -f "$src/SHA256SUMS" ] || { echo "no SHA256SUMS in $src" >&2; exit 1; }
# release dir is flat (bin files beside SHA256SUMS) or already has bin/
if [ -d "$src/bin" ]; then bsrc=$src/bin; else bsrc=$src; fi
doc=$src/START-HERE.txt; [ -f "$doc" ] || doc=$here/../stick/START-HERE.txt

mkdir -p "$stick/bin" "$stick/qusb/sigs"
for f in "$bsrc"/qusb-*; do cp "$f" "$stick/bin/"; done
cp "$src/SHA256SUMS" "$stick/bin/SHA256SUMS"
cp "$doc" "$stick/START-HERE.txt"
chmod +x "$stick"/bin/qusb-* 2>/dev/null || true

( cd "$stick/bin"
  if command -v sha256sum >/dev/null 2>&1; then sha256sum -c SHA256SUMS
  else shasum -a 256 -c SHA256SUMS; fi ) || { echo "checksum verify FAILED on stick" >&2; exit 1; }

case "$(uname -s)-$(uname -m)" in
  Darwin-arm64) os=macos-arm64 ;; Darwin-*) os=macos-x64 ;;
  Linux-aarch64|Linux-arm64) os=linux-arm64 ;; Linux-*) os=linux-x64 ;;
  *) os="<os>" ;;
esac
echo "stick ready. next: $stick/bin/qusb-$os init $stick"
