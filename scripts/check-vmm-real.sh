#!/usr/bin/env bash
set -euo pipefail

repo_root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)
cd -- "$repo_root"

if [[ ${EUID} -ne 0 ]]; then
  printf '%s\n' 'real Cloud Hypervisor acceptance requires root' >&2
  exit 1
fi

binary_source="$repo_root/.cache/mission2-assets/cloud-hypervisor-static"
asset_root="/opt/ehjint-vmm-acceptance-$$"
binary="$asset_root/cloud-hypervisor-v53.0"
helper="$asset_root/ehjint"
expected_binary_sha=448af3d4e59b22c2987f7df94c213ad40fb53a10d437e42b5ee6c4fce7c29ecc
if [[ ! -f "$binary_source" || -L "$binary_source" || ! -x "$binary_source" ]]; then
  printf 'missing safe pinned Cloud Hypervisor source binary: %s\n' "$binary_source" >&2
  exit 1
fi
actual_binary_sha=$(sha256sum -- "$binary_source" | awk '{print $1}')
if [[ "$actual_binary_sha" != "$expected_binary_sha" ]]; then
  printf 'pinned Cloud Hypervisor digest mismatch: %s\n' "$actual_binary_sha" >&2
  exit 1
fi
if [[ ! -c /dev/kvm ]]; then
  printf '%s\n' '/dev/kvm is unavailable' >&2
  exit 1
fi
kvm_gid=$(stat -Lc '%g' /dev/kvm)

created_run_root=0
if [[ ! -e /run/ehjint ]]; then
  install -d -m 0750 -o root -g root /run/ehjint
  created_run_root=1
fi
if [[ -L /run/ehjint || ! -d /run/ehjint ]]; then
  printf '%s\n' '/run/ehjint is not a real directory' >&2
  exit 1
fi
run_root_uid=$(stat -Lc '%u' /run/ehjint)
run_root_mode=$(stat -Lc '%a' /run/ehjint)
if [[ "$run_root_uid" != 0 || $((8#$run_root_mode & 0022)) -ne 0 ]]; then
  printf '%s\n' '/run/ehjint is not root-owned and non-writable by group/world' >&2
  exit 1
fi

stamp=$(date -u +%Y%m%dT%H%M%SZ)
name="ehjintvm$$"
name=${name:0:30}
report_dir="$repo_root/.cache/vmm-acceptance-20260730/$stamp"
report="$report_dir/RESULT.json"
runtime="/run/ehjint/vmm-acceptance-$$"
cancel_runtime="${runtime}-cancel"
identity_created=0
uid=
gid=

safe_kill_identity() {
  local identity_file=$1
  [[ -f "$identity_file" && ! -L "$identity_file" ]] || return 0
  local fields pid start executable expected_uid current_start current_executable current_uid
  fields=$(python3 - "$identity_file" <<'PY' 2>/dev/null || true
import json, sys
try:
    x=json.load(open(sys.argv[1]))
    p=x.get('process', x)
    print(p['pid'], p['start_time'], p['executable_path'], p['uid'])
except Exception:
    pass
PY
)
  [[ -n "$fields" ]] || return 0
  read -r pid start executable expected_uid <<<"$fields"
  [[ -r "/proc/$pid/stat" ]] || return 0
  current_start=$(python3 - "$pid" <<'PY' 2>/dev/null || true
import sys
s=open(f'/proc/{sys.argv[1]}/stat').read()
r=s.rfind(')')
f=s[r+2:].split()
print(f[19] if len(f)>19 else '')
PY
)
  current_executable=$(readlink -- "/proc/$pid/exe" 2>/dev/null || true)
  current_uid=$(awk '/^Uid:/{print $2; exit}' "/proc/$pid/status" 2>/dev/null || true)
  if [[ "$current_start" == "$start" && "$current_executable" == "$executable" && "$current_uid" == "$expected_uid" ]]; then
    kill -TERM -- "$pid" 2>/dev/null || true
    for _ in {1..40}; do
      [[ -e "/proc/$pid" ]] || return 0
      sleep 0.05
    done
    if [[ -r "/proc/$pid/stat" ]]; then
      local retry_start retry_executable
      retry_start=$(python3 - "$pid" <<'PY' 2>/dev/null || true
import sys
s=open(f'/proc/{sys.argv[1]}/stat').read(); r=s.rfind(')'); f=s[r+2:].split(); print(f[19] if len(f)>19 else '')
PY
)
      retry_executable=$(readlink -- "/proc/$pid/exe" 2>/dev/null || true)
      if [[ "$retry_start" == "$start" && "$retry_executable" == "$executable" ]]; then
        kill -KILL -- "$pid" 2>/dev/null || true
      fi
    fi
  fi
}

safe_remove_runtime() {
  local dir=$1
  [[ -e "$dir" ]] || return 0
  if [[ -L "$dir" || ! -d "$dir" ]]; then
    printf 'refusing ambiguous acceptance runtime cleanup: %s\n' "$dir" >&2
    return 1
  fi
  local dir_uid dir_gid object object_uid object_gid
  dir_uid=$(stat -Lc '%u' "$dir")
  dir_gid=$(stat -Lc '%g' "$dir")
  if [[ -n "$uid" && ( "$dir_uid" != "$uid" || "$dir_gid" != "$gid" ) ]]; then
    printf 'refusing unowned acceptance runtime directory: %s\n' "$dir" >&2
    return 1
  fi
  for object in api.sock api.sock.lock vsock.sock vmm.events vmm.log vmm.stdout.log vmm.stderr.log vmm.lock; do
    local path="$dir/$object"
    [[ -e "$path" || -S "$path" ]] || continue
    if [[ -L "$path" ]]; then
      printf 'refusing symlink acceptance runtime object: %s\n' "$path" >&2
      return 1
    fi
    object_uid=$(stat -Lc '%u' "$path")
    object_gid=$(stat -Lc '%g' "$path")
    if [[ -n "$uid" && ( "$object_uid" != "$uid" || "$object_gid" != "$gid" ) ]]; then
      printf 'refusing unowned acceptance runtime object: %s\n' "$path" >&2
      return 1
    fi
    rm -f -- "$path"
  done
  rmdir -- "$dir" 2>/dev/null || true
}

cleanup() {
  local status=$?
  trap - EXIT INT TERM
  set +e
  safe_kill_identity "$runtime/vmm.lock"
  safe_remove_runtime "$runtime"
  safe_remove_runtime "$cancel_runtime"
  if [[ $identity_created -eq 1 ]]; then
    userdel -- "$name" >/dev/null 2>&1 || true
    groupdel -- "$name" >/dev/null 2>&1 || true
  fi
  if [[ -d "$asset_root" && ! -L "$asset_root" ]]; then
    rm -f -- "$helper" "$binary"
    rmdir -- "$asset_root" 2>/dev/null || true
  fi
  if [[ $created_run_root -eq 1 ]]; then
    rmdir -- /run/ehjint 2>/dev/null || true
  fi
  exit "$status"
}
trap cleanup EXIT INT TERM

install -d -m 0755 -o root -g root "$asset_root"
install -d -m 0700 -o root -g root "$report_dir"
install -m 0755 -o root -g root "$binary_source" "$binary"
if [[ $(sha256sum -- "$binary" | awk '{print $1}') != "$expected_binary_sha" ]]; then
  printf '%s\n' 'staged Cloud Hypervisor digest mismatch' >&2
  exit 1
fi
useradd --system --user-group --no-create-home --home-dir /nonexistent --shell /usr/sbin/nologin -- "$name"
identity_created=1
uid=$(id -u -- "$name")
gid=$(id -g -- "$name")
if [[ "$uid" == 0 || "$gid" == 0 ]]; then
  printf '%s\n' 'temporary VMM identity is privileged' >&2
  exit 1
fi
install -d -m 0700 -o "$uid" -g "$gid" "$runtime"

CGO_ENABLED=0 go build -trimpath -ldflags=-buildid= -o "$helper" ./cmd/ehjint
chown root:root "$helper"
chmod 0755 "$helper"
helper_sha=$(sha256sum -- "$helper" | awk '{print $1}')

EHJINT_VMM_ACCEPTANCE=1 \
EHJINT_VMM_HELPER="$helper" \
EHJINT_VMM_BINARY="$binary" \
EHJINT_VMM_RUNTIME="$runtime" \
EHJINT_VMM_REPORT="$report" \
EHJINT_VMM_UID="$uid" \
EHJINT_VMM_GID="$gid" \
EHJINT_VMM_KVM_GID="$kvm_gid" \
go test -race -count=1 -run '^TestRealPinnedControllerLossAdoption$' -v ./internal/vmm

if [[ ! -f "$report" || -L "$report" ]]; then
  printf '%s\n' 'real VMM acceptance did not produce a report' >&2
  exit 1
fi
python3 - "$report" "$uid" "$gid" "$kvm_gid" "$expected_binary_sha" <<'PY'
import json, sys
p, uid, gid, kvm, digest = sys.argv[1:]
x=json.load(open(p))
assert x['uid'] == int(uid)
assert x['gid'] == int(gid)
assert x['kvm_gid'] == int(kvm)
assert x['supplementary_gids'] == [int(kvm)]
assert x['binary_sha256'] == digest
assert x['release_version'] == 'v53.0'
assert x['runtime_api_version'] == '53.0.0'
assert x['no_new_privs'] is True
assert all(x[k] == 0 for k in ['cap_inheritable','cap_permitted','cap_effective','cap_bounding','cap_ambient'])
assert x['api_socket_mode'] == 0o700
assert x['observed_pid'] == x['api_pid']
assert x['controller_killed'] and x['controller_loss_alive'] and x['adoption_succeeded']
assert x['duplicate_count'] == 1
assert x['negative_adoption'] and x['shutdown']['outcome'] == 'graceful-api'
assert x['cleanup_succeeded'] and x['positive_absence']
PY

for path in "$runtime" "$cancel_runtime"; do
  if [[ -e "$path" ]]; then
    printf 'acceptance runtime remains: %s\n' "$path" >&2
    exit 1
  fi
done
if find /proc -maxdepth 2 -type l -name exe -exec readlink {} \; 2>/dev/null | grep -Fxq -- "$binary"; then
  printf '%s\n' 'pinned acceptance VMM remains alive' >&2
  exit 1
fi

userdel -- "$name"
groupdel -- "$name" >/dev/null 2>&1 || true
identity_created=0
if getent passwd "$name" >/dev/null || getent group "$name" >/dev/null; then
  printf '%s\n' 'temporary VMM identity remains' >&2
  exit 1
fi
rm -f -- "$helper" "$binary"
rmdir -- "$asset_root"
if [[ $created_run_root -eq 1 ]]; then
  rmdir -- /run/ehjint 2>/dev/null || true
fi
trap - EXIT INT TERM
printf 'VMM_ACCEPTANCE_REPORT=%s\n' "$report"
printf 'VMM_HELPER_SHA256=%s\n' "$helper_sha"
