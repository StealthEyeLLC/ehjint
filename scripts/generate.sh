#!/usr/bin/env bash
set -euo pipefail
source "$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)/_lib.sh"
require_go
cd "$EHJINT_ROOT"
"$EHJINT_GO" run ./internal/tools/genregistry -root .
