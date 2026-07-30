#!/usr/bin/env bash
set -euo pipefail
source "$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)/_lib.sh"
require_go

out="$EHJINT_ROOT/build/bin"
repro="$EHJINT_CACHE/repro-build"
rm -rf "$repro"
mkdir -p "$out" "$repro/one" "$repro/two"

build_one() {
  local destination=$1
  (
    cd "$EHJINT_ROOT"
    CGO_ENABLED=0 "$EHJINT_GO" build \
      -trimpath \
      -buildvcs=false \
      -ldflags=-buildid= \
      -o "$destination" \
      ./cmd/ehjint
  )
}

build_one "$repro/one/ehjint"
build_one "$repro/two/ehjint"
first=$(sha256sum "$repro/one/ehjint" | awk '{print $1}')
second=$(sha256sum "$repro/two/ehjint" | awk '{print $1}')
if [[ "$first" != "$second" ]]; then
  printf 'non-reproducible build: %s != %s\n' "$first" "$second" >&2
  exit 1
fi
install -m 0755 "$repro/one/ehjint" "$out/ehjint"
ln -sfn ehjint "$out/ej"
printf 'first_sha256=%s\nsecond_sha256=%s\noutput=%s\nalias=%s\n' "$first" "$second" "$out/ehjint" "$out/ej"
