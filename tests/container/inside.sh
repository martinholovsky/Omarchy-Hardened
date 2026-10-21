#!/usr/bin/env bash
# Runs inside the test container (see run.sh). Exits non-zero on the first
# failed check; prints "N/N checks passed" only when every check ran.
set -euo pipefail

readonly FIX=/src/tests/fixtures/omarchy
checks_total=32
checks_passed=0

# Status of one finding in the latest audit file, or "MISSING".
finding() {
  python3 -I -c 'import json,sys
for line in open("/var/lib/aegis/audit.jsonl"):
    f = json.loads(line)
    if f["id"] == sys.argv[1]:
        print(f["status"]); break
else:
    print("MISSING")' "$1"
}
expect_finding() { # id status
  local got; got=$(finding "$1")
  [[ $got == "$2" ]] || { cat /var/lib/aegis/audit.jsonl; fail "finding $1 is $got, expected $2"; }
}

pass() { checks_passed=$((checks_passed + 1)); echo "PASS: $*"; }
fail() { echo "FAIL: $*" >&2; exit 1; }

echo "--- installing ansible"
pacman -Syu --noconfirm --needed ansible-core python ufw expect >/dev/null
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
grep -Eq '^auth\s+required\s+pam_unix\.so\s*$' /etc/pam.d/su || fail "seed: su does not call pam_unix directly"
grep -Eq '^#auth\s+required\s+pam_wheel\.so use_uid' /etc/pam.d/su || fail "seed: su pam_wheel line not commented"
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

# Every key Aegis writes must name a real sysctl, or the apply step on a real
# host would fail; check against this (mainline) kernel's /proc/sys.
sysctl_file=/etc/sysctl.d/99-zz-aegis-hardened.conf
keys=$(grep -E '^[a-z]' "$sysctl_file" | cut -d= -f1)
[[ $(wc -l <<<"$keys") -ge 25 ]] || fail "sysctl file has fewer than 25 keys"
# Some net.* keys (e.g. net.core.bpf_jit_harden) exist only in the initial
# network namespace, which this container does not have. Those are handed to
# run.sh, which checks them in a second container on the host namespace.
: > /out/netns-only-keys
for key in $keys; do
  if [[ ! -e /proc/sys/${key//.//} ]]; then
    [[ $key == net.* ]] || fail "sysctl key $key does not exist on this kernel"
    echo "$key" >> /out/netns-only-keys
  fi
done
pass "all $(wc -l <<<"$keys") sysctl keys exist ($(wc -l < /out/netns-only-keys) net.* keys deferred to the host-netns check)"

# Owner decisions D-15..D-17; warn_limit deliberately unset.
for kv in kernel.sysrq=16 kernel.oops_limit=100 vm.mmap_rnd_bits=32 vm.mmap_rnd_compat_bits=16; do
  grep -qx "$kv" "$sysctl_file" || fail "decided setting $kv missing"
done
! grep -q '^kernel.warn_limit=' "$sysctl_file" || fail "kernel.warn_limit written although D-17 leaves it unset"
if ! { grep -qx 'fs.protected_regular=2' "$sysctl_file" && grep -qx 'net.ipv4.conf.all.rp_filter=2' "$sysctl_file"; }; then
  fail "Tier 1 sysctls missing"
fi
pass "Tier 1 sysctls and decisions D-15..D-17 written; warn_limit unset"

expect_finding pacman.siglevel.global PASS
expect_finding pacman.mirror_transport PASS
expect_finding pacman.upgrade_age PASS
expect_finding integrity.setuid_unowned PASS
expect_finding integrity.scan_coverage PASS
grep -q '"id": "integrity.scan_coverage"' /var/lib/aegis/audit.jsonl || fail "audit file lacks scan coverage"
[[ $(stat -c %a /var/lib/aegis/audit.jsonl) == 600 ]] || fail "audit file is not 0600"
pass "audit file written (0600) with clean-system findings"

echo "--- su: real logins against the hardened stack"
echo 'root:Aegis-root-pw1' | chpasswd
useradd -m -G wheel alice
useradd -m bob
su_as() { runuser -u "$1" -- env SU_PASSWORD="$2" expect /src/tests/container/su-login.exp >/dev/null 2>&1; }

su_as alice 'wrong-password' && fail "su accepted a wrong password"
[[ -s /var/lib/faillock/root ]] || fail "su failure not recorded in /var/lib/faillock"
[[ ! -e /run/faillock/root ]] || fail "tally still written to tmpfs /run/faillock"
# Count record lines (they start with a timestamp), not the header.
[[ $(faillock --user root | grep -cE '^[0-9]{4}-[0-9]{2}-[0-9]{2} ') -ge 1 ]] \
  || { faillock --user root; fail "faillock CLI shows no record for root"; }
pass "su failure counted in the persistent tally (/var/lib/faillock)"

su_as bob 'Aegis-root-pw1' && fail "non-wheel user could su with the right password"
pass "su refused for a non-wheel user"

su_as alice 'Aegis-root-pw1' || fail "wheel user could not su with the right password"
pass "su works for a wheel user"

# D-19: after deny (10) consecutive failures root itself is locked, so even
# the right password is refused until root_unlock_time or a reset.
for _ in $(seq 10); do su_as alice 'wrong-password' && fail "su accepted a wrong password"; done
su_as alice 'Aegis-root-pw1' && fail "root not locked after 10 failures (even_deny_root)"
faillock --user root --reset
su_as alice 'Aegis-root-pw1' || fail "root still locked after faillock --reset"
pass "even_deny_root: root locks after 10 su failures; faillock --reset unlocks"

echo "--- dry run (--check --diff), as the README tells users to start with"
ansible-playbook tests/container/playbook.yml --check --diff >/tmp/check.log 2>&1 \
  || { cat /tmp/check.log; fail "--check --diff run failed"; }
pass "--check --diff run succeeds"

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
cp /etc/pacman.conf /etc/pacman.conf.aegis-orig
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
cp /etc/pacman.conf.aegis-orig /etc/pacman.conf

audit_must_fail() { # id description
  if ansible-playbook tests/container/playbook.yml >/tmp/neg.log 2>&1; then
    cat /tmp/neg.log; fail "$2 did not fail the run"
  fi
  expect_finding "$1" FAIL
}

echo "--- negative: a weak SigLevel inside an Include= file"
printf '\n[inc]\nInclude = /etc/pacman.d/aegis-test-inc\n' >> /etc/pacman.conf
printf 'Server = https://example.invalid/inc\nSigLevel = TrustAll\n' > /etc/pacman.d/aegis-test-inc
audit_must_fail pacman.siglevel.inc "SigLevel = TrustAll in an included file"
cp /etc/pacman.conf.aegis-orig /etc/pacman.conf
pass "SigLevel from an Include= file is audited"

echo "--- negative: a plain-HTTP mirror"
cp /etc/pacman.d/mirrorlist /tmp/mirrorlist.orig
# shellcheck disable=SC2016 # pacman placeholders, written literally
printf 'Server = http://mirror.example.invalid/$repo/os/$arch\n' >> /etc/pacman.d/mirrorlist
audit_must_fail pacman.mirror_transport "a plain-HTTP mirror"
cp /tmp/mirrorlist.orig /etc/pacman.d/mirrorlist
pass "plain-HTTP mirror fails the audit"

echo "--- negative: a setuid binary no package owns"
install -m 4755 /usr/bin/true /usr/local/bin/aegis-test-suid
audit_must_fail integrity.setuid_unowned "an unowned setuid binary"
grep -q '/usr/local/bin/aegis-test-suid' /var/lib/aegis/audit.jsonl || fail "unowned setuid path not reported"
rm -f /usr/local/bin/aegis-test-suid
pass "unowned setuid binary fails the audit"

echo "--- package drift: a modified binary is reported (WARN by default, FAIL when chosen)"
cp -a /usr/bin/false /tmp/false.orig
printf 'aegis' >> /usr/bin/false
ansible-playbook tests/container/playbook.yml >/dev/null || fail "drift at WARN severity failed the run"
expect_finding integrity.package_drift_content WARN
grep -q '/usr/bin/false' /var/lib/aegis/audit.jsonl || fail "modified /usr/bin/false not named"
if ansible-playbook tests/container/playbook.yml -e aegis_integrity_drift_severity=FAIL >/dev/null 2>&1; then
  fail "drift at FAIL severity did not fail the run"
fi
cp -a /tmp/false.orig /usr/bin/false
pass "package drift detected; severity follows aegis_integrity_drift_severity"

# pacman -Qkk prints one line per reason (size, checksum, mtime); the finding
# must still name the file once and count it once.
echo "--- package drift: a file with several mismatches is listed once"
printf 'aegis' >> /usr/bin/false
ansible-playbook tests/container/playbook.yml >/dev/null || fail "drift run failed"
drift=$(grep '"id": "integrity.package_drift_content"' /var/lib/aegis/audit.jsonl)
[[ $(grep -o '/usr/bin/false' <<<"$drift" | wc -l) -eq 1 ]] || { echo "$drift"; fail "/usr/bin/false listed more than once"; }
grep -q '"1 package files with changed size/content' <<<"$drift" || { echo "$drift"; fail "drift count is per reason, not per file"; }
cp -a /tmp/false.orig /usr/bin/false
pass "a file with several -Qkk reasons is reported once"

# D-22: drift that only removes permission bits is accepted (INFO); drift that
# adds any is not. /usr/bin/false ships as 0755 root:root. The image has drift
# of its own (/var/games, wall, write), so check where this file lands rather
# than the finding's status.
finding_line() { grep "\"id\": \"$1\"" /var/lib/aegis/audit.jsonl; }
echo "--- D-22: tightened permissions are accepted, loosened ones are not"
chmod 0700 /usr/bin/false
ansible-playbook tests/container/playbook.yml >/dev/null || fail "tightened-drift run failed"
if finding_line integrity.package_drift_permissions | grep -q '/usr/bin/false' \
  || ! finding_line integrity.package_drift_accepted | grep -q '/usr/bin/false - permissions only tightened'; then
  cat /var/lib/aegis/audit.jsonl; fail "tightened /usr/bin/false not accepted"
fi
chmod 0775 /usr/bin/false
ansible-playbook tests/container/playbook.yml >/dev/null || fail "loosened-drift run failed"
if ! finding_line integrity.package_drift_permissions | grep -q '/usr/bin/false' \
  || finding_line integrity.package_drift_accepted | grep -q '/usr/bin/false'; then
  cat /var/lib/aegis/audit.jsonl; fail "loosened /usr/bin/false was accepted"
fi
chmod 0755 /usr/bin/false
pass "0700 on a 0755 package file is accepted; 0775 is drift"

echo "--- D-22: an expected-drift entry matches its exact reasons only"
expected='{"aegis_integrity_drift_expected": [{"path": "/usr/bin/false", "why": "test",
  "reasons": ["Modification time mismatch", "Size mismatch", "SHA256 checksum mismatch"]}]}'
printf 'aegis' >> /usr/bin/false
ansible-playbook tests/container/playbook.yml -e "$expected" >/dev/null || fail "expected-drift run failed"
expect_finding integrity.package_drift_content PASS
grep -q '/usr/bin/false - test' /var/lib/aegis/audit.jsonl || { cat /var/lib/aegis/audit.jsonl; fail "listed drift not accepted"; }
pass "listed content drift is accepted as INFO"

chmod 0700 /usr/bin/false
ansible-playbook tests/container/playbook.yml -e "$expected" >/dev/null || fail "expected-drift run failed"
expect_finding integrity.package_drift_content WARN
cp -a /tmp/false.orig /usr/bin/false
pass "an extra change on a listed file is still drift"

echo "--- upgrade age: before the first -Syu it counts from the install"
cp /var/log/pacman.log /tmp/pacman.log.orig
log_line() { printf "[%s] [PACMAN] Running 'pacman -r /mnt -Sy base'\n" "$(date -u -d "$1" +%Y-%m-%dT%H:%M:%S+0000)"; }
log_line '-2 days' > /var/log/pacman.log
ansible-playbook tests/container/playbook.yml >/dev/null || fail "upgrade-age run failed"
expect_finding pacman.upgrade_age PASS
grep -q 'no full upgrade since the first' /var/lib/aegis/audit.jsonl || fail "install-time fallback not reported"
log_line '-30 days' > /var/log/pacman.log
ansible-playbook tests/container/playbook.yml >/dev/null || fail "upgrade-age run failed"
expect_finding pacman.upgrade_age WARN
cp /tmp/pacman.log.orig /var/log/pacman.log
pass "a 2-day-old install passes and a 30-day-old one never upgraded warns"

echo "--- sudoers: an unknown NOPASSWD rule warns; Omarchy's asdcontrol drop-in does not"
mkdir -p /etc/sudoers.d
printf '%s\n' 'ALL ALL=(ALL) !/usr/bin/asdcontrol' \
  '%wheel ALL=(root) NOPASSWD: /usr/bin/asdcontrol ^/dev/(usb/)?hiddev[0-9]+$' > /etc/sudoers.d/50-asdcontrol
ansible-playbook tests/container/playbook.yml >/dev/null || fail "sudoers run failed"
expect_finding sudoers.nopasswd_other PASS
printf 'alice ALL=(ALL) NOPASSWD: ALL\n' > /etc/sudoers.d/aegis-test
ansible-playbook tests/container/playbook.yml >/dev/null || fail "sudoers run failed"
expect_finding sudoers.nopasswd_other WARN
grep -q 'aegis-test' /var/lib/aegis/audit.jsonl || fail "planted sudoers file not named"
rm -f /etc/sudoers.d/aegis-test /etc/sudoers.d/50-asdcontrol
pass "unknown NOPASSWD rule warns; asdcontrol drop-in is known"

echo "--- negative: docker group membership, then accepted via aegis_audit_skip"
groupadd -f docker
gpasswd -a alice docker >/dev/null
audit_must_fail groups.docker "docker group membership"
ansible-playbook tests/container/playbook.yml -e '{"aegis_audit_skip": ["groups.docker"]}' >/dev/null \
  || fail "aegis_audit_skip did not accept groups.docker"
expect_finding groups.docker ACCEPTED
gpasswd -d alice docker >/dev/null
pass "docker membership fails the audit; aegis_audit_skip accepts it"

echo "--- faillock flags follow their variables (defaults: D-18 audit off, D-19 even_deny_root on)"
ansible-playbook tests/container/playbook.yml \
  -e '{"aegis_faillock_audit": true, "aegis_faillock_even_deny_root": false}' >/dev/null
if ! { grep -qx 'audit' /etc/security/faillock.conf && ! grep -Eqx 'even_deny_root|root_unlock_time = 900' /etc/security/faillock.conf; }; then
  fail "faillock flags did not follow the overrides"
fi
ansible-playbook tests/container/playbook.yml >/dev/null
if ! { ! grep -qx 'audit' /etc/security/faillock.conf && grep -qx 'even_deny_root' /etc/security/faillock.conf \
  && grep -qx 'root_unlock_time = 900' /etc/security/faillock.conf; }; then
  fail "default run did not restore audit=off, even_deny_root=on"
fi
pass "faillock audit/even_deny_root toggle cleanly and default to D-18/D-19"

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
