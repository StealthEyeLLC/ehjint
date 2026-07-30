#!/usr/bin/env bash
set -euo pipefail
source "$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)/_lib.sh"
require_go

binary="$EHJINT_ROOT/build/bin/ehjint"
alias_binary="$EHJINT_ROOT/build/bin/ej"
[[ -x "$binary" ]] || { echo "missing built ehjint binary" >&2; exit 1; }
[[ -L "$alias_binary" ]] || { echo "ej is not a symbolic alias" >&2; exit 1; }
[[ "$(readlink "$alias_binary")" == ehjint ]] || { echo "ej does not resolve to the ehjint multicall binary" >&2; exit 1; }

version_json=$($binary version --json)
printf '%s\n' "$version_json" | grep -F '"product":"EHJINT"' >/dev/null
printf '%s\n' "$version_json" | grep -F '"product_version":"0.0.0-dev"' >/dev/null
printf '%s\n' "$version_json" | grep -E '"registry_digest":"[0-9a-f]{64}"' >/dev/null

doctor_json=$($alias_binary doctor --json)
printf '%s\n' "$doctor_json" | grep -F '"healthy":true' >/dev/null
printf '%s\n' "$doctor_json" | grep -F '"foundation_only":false' >/dev/null
printf '%s\n' "$doctor_json" | grep -F '"later_runtime_activated":true' >/dev/null
printf '%s\n' "$doctor_json" | grep -F '"alias":true' >/dev/null

list_json=$($binary registry list --json)
printf '%s\n' "$list_json" | grep -F '"name":"machine.create"' >/dev/null
printf '%s\n' "$list_json" | grep -F '"name":"machine.inspect"' >/dev/null
printf '%s\n' "$list_json" | grep -F '"name":"registry.describe"' >/dev/null
printf '%s\n' "$list_json" | grep -F '"name":"system.version"' >/dev/null

describe_json=$($binary registry describe system.diagnose --json)
printf '%s\n' "$describe_json" | grep -F '"name":"system.diagnose"' >/dev/null
printf '%s\n' "$describe_json" | grep -F '"cli_path":["doctor"]' >/dev/null

set +e
unknown_output=$($binary machine start --json 2>&1)
unknown_status=$?
bare_output=$($binary 2>&1)
bare_status=$?
duplicate_output=$($binary version --json --json 2>&1)
duplicate_status=$?
set -e

[[ $unknown_status -eq 3 ]] || { printf 'unknown command exit status=%d output=%s\n' "$unknown_status" "$unknown_output" >&2; exit 1; }
printf '%s\n' "$unknown_output" | grep -F '"code":"unknown_operation"' >/dev/null
[[ $bare_status -eq 5 ]] || { printf 'bare invocation exit status=%d output=%s\n' "$bare_status" "$bare_output" >&2; exit 1; }
[[ $duplicate_status -eq 2 ]] || { printf 'duplicate flag exit status=%d output=%s\n' "$duplicate_status" "$duplicate_output" >&2; exit 1; }

printf 'CLI integration passed: operations=6 active_machine=2 alias=ej negative_paths=3\n'
