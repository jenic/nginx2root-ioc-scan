#!/usr/bin/env bash
# Deterministic release packaging; invoked by the Makefile, never by the scanner.
set -euo pipefail

fail() { echo "package: $*" >&2; exit 1; }

[[ $# == 5 ]] || fail 'usage: package.sh BINARY GOOS GOARCH SOURCE_DATE_EPOCH OUTPUT_DIR'
input=$1
target_os=$2
target_arch=$3
epoch=$4
output=$5

[[ -f $input && ! -L $input ]] || fail "missing or invalid binary: $input"
[[ $target_os == darwin || $target_os == linux || $target_os == windows ]] || fail "unsupported OS: $target_os"
[[ $target_arch == amd64 || $target_arch == arm64 ]] || fail "unsupported architecture: $target_arch"
[[ $epoch =~ ^[0-9]+$ ]] || fail 'SOURCE_DATE_EPOCH must be a non-negative integer'

# ZIP timestamps cannot predate 1980. This also makes archive creation work in a
# newly initialized repository where the Makefile's fallback epoch is zero.
if (( epoch < 315532800 )); then epoch=315532800; fi

mkdir -p "$output"
output=$(cd "$output" && pwd)
name=nginx-ioc-scan
extension=
archive_extension=.tar.gz
if [[ $target_os == windows ]]; then
  extension=.exe
  archive_extension=.zip
fi
archive="$output/${name}_${target_os}_${target_arch}${archive_extension}"
stage="$output/.release-${target_os}-${target_arch}"
trap 'rm -rf -- "$stage"' EXIT
rm -rf -- "$stage"
mkdir -p "$stage"
cp "$input" "$stage/$name$extension"
TZ=UTC touch -d "@$epoch" "$stage/$name$extension"
rm -f -- "$archive"

if [[ $target_os == windows ]]; then
  (cd "$stage" && zip -X -q "$archive" "$name$extension")
else
  tar --sort=name --owner=0 --group=0 --numeric-owner --mtime="@$epoch" \
    -C "$stage" -cf - "$name$extension" | gzip -n > "$archive"
fi

echo "Wrote $archive"
