#!/usr/bin/env bash
# Apply the sysctl role to a REAL kernel and read it back. It changes the
# host's kernel settings, some irreversibly until reboot
# (kernel.kexec_load_disabled, kernel.unprivileged_bpf_disabled=1), so it only
# runs on a throwaway machine: CI sets AEGIS_ALLOW_HOST_SYSCTL=1.
#
# Usage (CI): sudo AEGIS_ALLOW_HOST_SYSCTL=1 tests/container/sysctl-apply.sh
set -euo pipefail

if [[ ${AEGIS_ALLOW_HOST_SYSCTL:-} != 1 ]]; then
  echo "refusing: this changes the host kernel; set AEGIS_ALLOW_HOST_SYSCTL=1 on a throwaway VM" >&2
  exit 2
fi

readonly IMAGE='docker.io/library/archlinux@sha256:e43f1fd80e073992c5f173efbbbf65144170bf60aeb7369940087d63eacea8f4'
repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)

# --privileged mounts /proc/sys read-write; --network=host puts net.* keys in
# the initial network namespace, as on a real install.
podman run --rm --privileged --network=host --platform linux/amd64 \
  -v "$repo_root:/src:ro" "$IMAGE" bash -c '
set -euo pipefail
fail() { echo "FAIL: $*" >&2; exit 1; }
pacman -Syu --noconfirm --needed ansible-core python >/dev/null
cp -a /src /work && cd /work
ansible-galaxy collection install -r requirements.yml >/dev/null
play() { ansible-playbook tests/container/sysctl-play.yml "$@"; }

play >/dev/null || fail "sysctl role failed against a real kernel"
[[ $(sysctl -n kernel.dmesg_restrict) == 1 && $(sysctl -n fs.protected_regular) == 2 ]] \
  || fail "live values not applied"
echo "PASS: sysctl role applied and verified against the live kernel"

out=$(play)
grep -Eq "changed=0 .*failed=0" <<<"$out" || { echo "$out"; fail "second apply not idempotent"; }
echo "PASS: second apply changed nothing"

sysctl -w kernel.dmesg_restrict=0 >/dev/null
out=$(play)
grep -Eq "changed=[1-9]" <<<"$out" || { echo "$out"; fail "runtime drift was not re-applied"; }
[[ $(sysctl -n kernel.dmesg_restrict) == 1 ]] || fail "kernel.dmesg_restrict not restored"
echo "PASS: a value changed at runtime is detected and re-applied"

# D-29: a key this kernel does not have passes only when it is on
# aegis_sysctl_absent_ok; the same key without the allowance must fail (a
# typo in a key name must never read as compiled out). Last, because it
# rewrites the drop-in with two keys only.
[[ ! -e /proc/sys/kernel/aegis_no_such_key ]] || fail "the planted key exists"
planted="{\"aegis_sysctl_settings\":{\"kernel.dmesg_restrict\":1,\"kernel.aegis_no_such_key\":1}"
if play -e "${planted}}" >/tmp/absent.log 2>&1; then
  cat /tmp/absent.log; fail "a missing key that is not on aegis_sysctl_absent_ok passed"
fi
out=$(play -v -e "${planted},\"aegis_sysctl_absent_ok\":[\"kernel.aegis_no_such_key\"]}") \
  || { echo "$out"; fail "an allowed compiled-out key failed the run"; }
grep -q "sysctl.compiled_out" <<<"$out" || { echo "$out"; fail "no sysctl.compiled_out finding"; }
grep -Eq "changed=[0-9]+ .*failed=0" <<<"$out" || { echo "$out"; fail "allowed compiled-out key: run not clean"; }
out=$(play -e "${planted},\"aegis_sysctl_absent_ok\":[\"kernel.aegis_no_such_key\"]}")
grep -Eq "changed=0 .*failed=0" <<<"$out" || { echo "$out"; fail "compiled-out key: second run not idempotent"; }
echo "PASS: a compiled-out key on aegis_sysctl_absent_ok is reported, not failed, and stays idempotent; off the list it fails"
'
