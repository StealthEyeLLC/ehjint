#!/usr/bin/env bash
set -euo pipefail
# shellcheck source=scripts/_lib.sh
source "$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd -P)/_lib.sh"
require_go
cd "$EHJINT_ROOT"

allow_dirty=${EHJINT_ALLOW_DIRTY:-0}
run_vmm_acceptance=${EHJINT_RUN_VMM_ACCEPTANCE:-0}
if [[ "$allow_dirty" != 0 && "$allow_dirty" != 1 ]]; then
  echo "EHJINT_ALLOW_DIRTY must be 0 or 1" >&2
  exit 2
fi
if [[ "$run_vmm_acceptance" != 0 && "$run_vmm_acceptance" != 1 ]]; then
  echo "EHJINT_RUN_VMM_ACCEPTANCE must be 0 or 1" >&2
  exit 2
fi
if [[ "$allow_dirty" == 0 && -n "$(git status --porcelain=v1 --untracked-files=all)" ]]; then
  echo "repository must be clean before the canonical check" >&2
  git status --short >&2
  exit 1
fi

mapfile -d '' go_files < <(find . -type f -name '*.go' -not -path './.cache/*' -not -path './build/*' -print0 | sort -z)
if [[ ${#go_files[@]} -eq 0 ]]; then
  echo "no Go files found" >&2
  exit 1
fi
unformatted=$("$EHJINT_GO_ROOT/bin/gofmt" -l "${go_files[@]}")
if [[ -n "$unformatted" ]]; then
  printf 'Go formatting drift:\n%s\n' "$unformatted" >&2
  exit 1
fi

"$EHJINT_GO" vet ./...
./scripts/check-generated.sh
./scripts/check-repository.sh
"$EHJINT_GO" test -count=1 ./...
"$EHJINT_GO" test -race -count=1 ./...
./scripts/build.sh
./scripts/test-cli.sh
if [[ "$run_vmm_acceptance" == 1 ]]; then
  ./scripts/check-vmm-real.sh
fi

if [[ "$allow_dirty" == 0 && -n "$(git status --porcelain=v1 --untracked-files=all)" ]]; then
  echo "canonical check modified the repository" >&2
  git status --short >&2
  exit 1
fi

printf 'EHJINT canonical check passed\n'
