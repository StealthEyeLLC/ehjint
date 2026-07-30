#!/usr/bin/env bash
set -euo pipefail

root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd -P)
cache="$root/.cache"
lock="$root/config/toolchain.lock.json"

read_lock_value() {
  local key=$1
  sed -n "s/^[[:space:]]*\"$key\": \"\([^\"]*\)\",\{0,1\}$/\1/p" "$lock" | head -n 1
}

version=$(read_lock_value version)
target=$(read_lock_value target)
archive=$(read_lock_value archive)
url=$(read_lock_value url)
sha256=$(read_lock_value sha256)

if [[ -z "$version" || -z "$target" || -z "$archive" || -z "$url" || -z "$sha256" ]]; then
  echo "invalid toolchain lock: $lock" >&2
  exit 2
fi
if [[ "$(uname -s)" != Linux || "$(uname -m)" != x86_64 || "$target" != linux/amd64 ]]; then
  echo "Mission 1 bootstrap currently supports the pinned linux/amd64 reference target only" >&2
  exit 2
fi
for command in curl sha256sum tar; do
  command -v "$command" >/dev/null 2>&1 || { echo "missing bootstrap prerequisite: $command" >&2; exit 2; }
done

downloads="$cache/downloads"
install_root="$cache/tools/$version"
archive_path="$downloads/$archive"
mkdir -p "$downloads" "$cache/tools"

verify_archive() {
  printf '%s  %s\n' "$sha256" "$archive_path" | sha256sum -c - >/dev/null
}

if [[ -f "$archive_path" ]]; then
  verify_archive || { rm -f "$archive_path"; echo "cached Go archive digest mismatch" >&2; exit 2; }
else
  tmp="$archive_path.tmp.$$"
  trap 'rm -f "$tmp"' EXIT
  curl --fail --location --silent --show-error "$url" --output "$tmp"
  mv "$tmp" "$archive_path"
  trap - EXIT
  verify_archive
fi

if [[ ! -x "$install_root/bin/go" ]]; then
  tmpdir=$(mktemp -d "$cache/.go-extract.XXXXXX")
  trap 'rm -rf "$tmpdir"' EXIT
  tar -xzf "$archive_path" -C "$tmpdir"
  rm -rf "$install_root"
  mv "$tmpdir/go" "$install_root"
  trap - EXIT
fi

actual=$($install_root/bin/go version)
if [[ "$actual" != "go version $version linux/amd64" ]]; then
  echo "installed toolchain identity mismatch: $actual" >&2
  exit 2
fi
printf 'Go toolchain ready: %s\narchive_sha256=%s\n' "$actual" "$sha256"
