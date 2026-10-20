#!/usr/bin/env bash
# Runs inside the test container (see run.sh). Exits non-zero on the first
# failed check; prints "N/N checks passed" only when every check ran.
set -euo pipefail

readonly FIX=/src/tests/fixtures/omarchy
checks_total=12
checks_passed=0

pass() { checks_passed=$((checks_passed + 1)); echo "PASS: $*"; }
fail() { echo "FAIL: $*" >&2; exit 1; }

echo "--- installing ansible"
pacman -Syu --noconfirm --needed ansible-core python ufw >/dev/null
ansible --version | head -1

# Work on a writable copy; /src is mounted read-only.
cp -a /src /work
cd /work
ansible-galaxy collection install -r requirements.yml >/dev/null

echo "--- seeding the Omarchy baseline"
bash "$FIX/increase-lockout-limit.sh"
install -m 0644 "$FIX/omarchy-lock-password" /etc/pam.d/omarchy-lock-password
install -m 0644 "$FIX/faillock.conf" /etc/security/faillock.conf

# Positive control: the seeded state must be the relaxed one, or the checks
# below would pass without the roles doing anything.
grep -q 'pam_faillock.so preauth silent deny=10 unlock_time=120' /etc/pam.d/system-auth \
  || fail "seed: Omarchy's sed did not apply to this image's system-auth"
grep -q '^deny = 10$' /etc/security/faillock.conf || fail "seed: faillock.conf"
pass "seeded Omarchy's relaxed faillock state"

echo "--- first run"
ansible-playbook tests/container/playbook.yml
pass "first run succeeded"

# Independent read-back (grep, not the roles' own asserts).
[[ $(grep -c 'pam_faillock.so.*deny=10 unlock_time=900' /etc/pam.d/system-auth) -eq 2 ]] \
  || fail "system-auth: expected 2 lines with deny=10 unlock_time=900"
! grep -Eq 'unlock_time=120' /etc/pam.d/system-auth /etc/pam.d/omarchy-lock-password \
  || fail "Omarchy's 120 s unlock_time remains"
pass "PAM inline faillock values hardened"

if ! { grep -qx 'deny = 10' /etc/security/faillock.conf && grep -qx 'unlock_time = 900' /etc/security/faillock.conf; }; then
  fail "faillock.conf not hardened"
fi
pass "faillock.conf hardened"

for kv in kernel.dmesg_restrict=1 kernel.kptr_restrict=2 kernel.kexec_load_disabled=1 kernel.yama.ptrace_scope=1; do
  grep -qx "$kv" /etc/sysctl.d/99-zz-aegis-hardened.conf || fail "sysctl file missing $kv"
done
pass "sysctl file holds all 4 settings"

echo "--- second run (idempotence)"
out=$(ansible-playbook tests/container/playbook.yml)
grep -Eq 'changed=0 .*failed=0' <<<"$out" || { echo "$out"; fail "second run was not idempotent"; }
pass "second run changed nothing"

# The default deny equals Omarchy's, so the runs above never exercise the deny
# rewrite. Apply a different count, check it, then restore the default.
echo "--- non-default deny is rewritten everywhere"
ansible-playbook tests/container/playbook.yml -e aegis_faillock_deny=4 >/dev/null
if ! { [[ $(grep -c 'pam_faillock.so.*deny=4 unlock_time=900' /etc/pam.d/system-auth) -eq 2 ]] \
  && [[ $(grep -c 'pam_faillock.so.*deny=4 unlock_time=900' /etc/pam.d/omarchy-lock-password) -eq 2 ]] \
  && grep -qx 'deny = 4' /etc/security/faillock.conf; }; then
  fail "aegis_faillock_deny=4 was not applied to every file"
fi
ansible-playbook tests/container/playbook.yml >/dev/null
grep -qx 'deny = 10' /etc/security/faillock.conf || fail "default deny not restored"
pass "deny rewrite applies a non-default count and restores 10"

echo "--- negative: an unsigned repository must fail the audit"
# shellcheck disable=SC2016 # $arch is pacman's placeholder, written literally
printf '\n[evil]\nServer = https://example.invalid/$arch\nSigLevel = Never\n' >> /etc/pacman.conf
if ansible-playbook tests/container/playbook.yml >/tmp/neg.log 2>&1; then
  cat /tmp/neg.log; fail "pacman_integrity accepted SigLevel = Never"
fi
grep -q '\[evil\] has SigLevel = Never' /tmp/neg.log || { cat /tmp/neg.log; fail "failed for the wrong reason"; }
pass "pacman_integrity rejects SigLevel = Never"

echo "--- negative: the exception list lets a named repo through"
ansible-playbook tests/container/playbook.yml -e '{"aegis_pacman_siglevel_exceptions": ["evil"]}' >/dev/null \
  || fail "exception for [evil] was not honoured"
pass "pacman_integrity honours aegis_pacman_siglevel_exceptions"

echo "--- firewall: seed Omarchy's rule set, then harden it"
bash "$FIX/firewall.sh"
ufw --force enable >/dev/null
# Positive control: the relaxed rules must be present before the role runs.
if ! { ufw status | grep -q '^53317/tcp' && ufw status | grep -q '^22/tcp .*LIMIT'; }; then
  ufw status; fail "seed: Omarchy firewall rules missing"
fi
pass "seeded Omarchy's firewall rules (LocalSend + opt-in SSH)"

ansible-playbook tests/container/firewall.yml
status=$(ufw status verbose)
grep -q '^Status: active$' <<<"$status" || { echo "$status"; fail "ufw not active"; }
! grep -Eq '^(53317|22)/' <<<"$status" || { echo "$status"; fail "LocalSend/SSH rules remain"; }
grep -q 'allow-docker-dns' <<<"$status" || { echo "$status"; fail "Docker DNS rule removed though aegis_firewall_remove_docker_dns=false"; }
pass "LocalSend and SSH rules removed, Docker DNS kept"

out=$(ansible-playbook tests/container/firewall.yml)
grep -Eq 'changed=0 .*failed=0' <<<"$out" || { echo "$out"; fail "firewall role not idempotent"; }
pass "firewall role idempotent"

[[ $checks_passed -eq $checks_total ]] || fail "only $checks_passed/$checks_total checks ran"
echo "${checks_passed}/${checks_total} checks passed"
