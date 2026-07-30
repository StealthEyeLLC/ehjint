#!/usr/bin/env bash
set -euo pipefail

EHJINT_ROOT=$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)
EHJINT_CACHE="$EHJINT_ROOT/.cache"
EHJINT_GO_VERSION=go1.26.5
EHJINT_GO_ROOT="$EHJINT_CACHE/tools/$EHJINT_GO_VERSION"
EHJINT_GO="$EHJINT_GO_ROOT/bin/go"

require_go() {
  if [[ ! -x "$EHJINT_GO" ]]; then
    printf 'missing pinned Go toolchain; run %s/scripts/bootstrap-tools.sh\n' "$EHJINT_ROOT" >&2
    exit 2
  fi
  local actual
  actual=$($EHJINT_GO version)
  if [[ "$actual" != "go version $EHJINT_GO_VERSION linux/amd64" ]]; then
    printf 'unexpected Go toolchain: %s\n' "$actual" >&2
    exit 2
  fi
  export PATH="$EHJINT_GO_ROOT/bin:$PATH"
  export GOTOOLCHAIN=local
  export GOCACHE="$EHJINT_CACHE/go-build"
  export GOMODCACHE="$EHJINT_CACHE/go-mod"
  export GOFLAGS=-mod=readonly
  export LC_ALL=C
  export TZ=UTC
  mkdir -p "$GOCACHE" "$GOMODCACHE"
}
