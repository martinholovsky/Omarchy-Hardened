#!/usr/bin/env bash
# Runs inside the test container (see run.sh). Exits non-zero on the first
# failed check; prints "N/N checks passed" only when every check ran.
set -euo pipefail

readonly FIX=/src/tests/fixtures/omarchy
checks_total=61
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

# Section timing: each "--- name" line also shows the seconds since the start,
# so a slow section is the jump between two lines. Only "--- " lines change;
# run.sh still finds "N/N checks passed" as printed.
echo() {
  if [[ ${1-} == "--- "* ]]; then builtin echo "$* [t+${SECONDS}s]"; else builtin echo "$@"; fi
}
trap 'builtin echo "elapsed: ${SECONDS}s"' EXIT

echo "--- installing ansible"
pacman -Syu --noconfirm --needed ansible-core python ufw expect sudo git >/dev/null
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
# The lock screen runs PAM as the user: the user must reach the directory.
[[ $(stat -c %a /var/lib/faillock) == 755 ]] || fail "tally dir is not 0755 (a 0700 dir hides the lock screen's failures)"
runuser -u bob -- test -x /var/lib/faillock || fail "a normal user cannot reach /var/lib/faillock"
pass "su failure counted in the persistent tally (/var/lib/faillock), reachable by users"

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

echo "--- D-11: drift check installed, clean after apply, warns after a revert"
copy=/usr/local/share/aegis-hardened
ansible-playbook tests/container/playbook.yml -e aegis_drift_check_enabled=true >/dev/null || fail "drift-check install failed"
if ! { [[ -x /usr/local/libexec/aegis-drift-check ]] && grep -q 'systemctl start --no-block aegis-drift-check.service' \
  /etc/pacman.d/hooks/zz-aegis-drift-check.hook && [[ $(stat -c %U:%a "$copy/roles/pam_faillock/tasks/main.yml") == root:6[04]4 ]]; }; then
  fail "drift check not installed as a root-owned copy with its pacman hook"
fi
grep -qx 'aegis_faillock_deny: 10' "$copy/applied-vars.yml" || fail "applied settings not saved"
! grep -q '^aegis_drift_check_source:' "$copy/applied-vars.yml" || fail "controller path saved in applied-vars"
/usr/local/libexec/aegis-drift-check >/dev/null 2>&1 || { cat /var/lib/aegis/drift-check.log; fail "clean state reported as drift"; }
# What an omarchy-update that rewrites system-auth would do.
sed -i 's/deny=10 unlock_time=900/deny=10 unlock_time=120/' /etc/pam.d/system-auth
if /usr/local/libexec/aegis-drift-check >/dev/null 2>&1; then fail "reverted PAM not reported as drift"; fi
grep -Eq 'changed=[1-9]' /var/lib/aegis/drift-check.log || { cat /var/lib/aegis/drift-check.log; fail "drift log lacks the change"; }
grep -q 'unlock_time=120' /etc/pam.d/system-auth || fail "the check modified the system"
ansible-playbook tests/container/playbook.yml >/dev/null || fail "re-apply after drift failed"
[[ ! -e /etc/pacman.d/hooks/zz-aegis-drift-check.hook ]] || fail "disabling the drift check left its hook"
pass "D-11 check: clean after apply, reports a reverted PAM file, changes nothing itself"

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

echo "--- system checks (roadmap 18k-18o): /tmp mount and fwupd"
ansible-playbook tests/container/playbook.yml -e aegis_audit_tmp_path=/dev/shm >/dev/null || fail "system-check run failed"
expect_finding mounts.tmp PASS
expect_finding firmware.fwupd INFO
ansible-playbook tests/container/playbook.yml -e aegis_audit_tmp_path=/etc >/dev/null || fail "system-check run failed"
expect_finding mounts.tmp WARN
pass "tmpfs with nosuid,nodev passes, a disk directory warns; fwupd reported"

echo "--- system checks: a polkit rule that grants everything"
mkdir -p /etc/polkit-1/rules.d
printf '%s\n' 'polkit.addRule(function(action, subject) {' \
  '  if (subject.isInGroup("wheel")) { return polkit.Result.YES; }' '});' > /etc/polkit-1/rules.d/49-aegis-test.rules
ansible-playbook tests/container/playbook.yml >/dev/null || fail "polkit run failed"
expect_finding polkit.blanket_grant WARN
printf '%s\n' 'polkit.addRule(function(action, subject) {' \
  '  if (action.id == "org.freedesktop.login1.reboot" && subject.isInGroup("wheel")) { return polkit.Result.YES; }' \
  '});' > /etc/polkit-1/rules.d/49-aegis-test.rules
ansible-playbook tests/container/playbook.yml >/dev/null || fail "polkit run failed"
expect_finding polkit.blanket_grant PASS
grep -q 'known: /usr/share/polkit-1/rules.d/empower.rules' /var/lib/aegis/audit.jsonl \
  || fail "systemd's empower.rules not reported as known"
rm -f /etc/polkit-1/rules.d/49-aegis-test.rules
groupadd -f empower && gpasswd -a alice empower >/dev/null
audit_must_fail groups.empower "a permanent empower member"
gpasswd -d alice empower >/dev/null
pass "unconditional polkit YES warns; scoped and systemd's empower rule do not; empower members fail"

echo "--- system checks: autologin on an unencrypted root"
mkdir -p /etc/sddm.conf.d
printf '[Autologin]\nUser=alice\nSession=omarchy.desktop\n' > /etc/sddm.conf.d/autologin.conf
ansible-playbook tests/container/playbook.yml >/dev/null || fail "autologin run failed"
expect_finding login.autologin_unencrypted WARN
rm -f /etc/sddm.conf.d/autologin.conf
ansible-playbook tests/container/playbook.yml >/dev/null || fail "autologin run failed"
expect_finding login.autologin_unencrypted PASS
pass "autologin without disk encryption warns"

echo "--- system checks: a SHA-512 password hash"
echo 'bob:Aegis-bob-pw1' | chpasswd -c SHA512
ansible-playbook tests/container/playbook.yml >/dev/null || fail "hash run failed"
expect_finding accounts.password_hash WARN
grep -q 'bob: SHA-512' /var/lib/aegis/audit.jsonl || fail "weak hash not attributed to bob"
# shellcheck disable=SC2016 # the literal crypt prefix, not an expansion
! grep -qF '$6$' /var/lib/aegis/audit.jsonl || fail "audit file contains a hash prefix or hash"
echo 'bob:Aegis-bob-pw1' | chpasswd -c YESCRYPT
ansible-playbook tests/container/playbook.yml >/dev/null || fail "hash run failed"
expect_finding accounts.password_hash PASS
pass "SHA-512 hash warns without leaking it; yescrypt passes"

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

echo "--- D-04 FIDO2: no pam_u2f means nothing changes"
printf '#%%PAM-1.0\nauth include system-auth\naccount include system-auth\nsession include system-auth\n' > /etc/pam.d/sudo
cp /etc/pam.d/sudo /tmp/sudo.pam.orig
ansible-playbook tests/container/playbook.yml >/dev/null || fail "fido2 run failed"
expect_finding auth.fido2_sudo INFO
# sha256sum (coreutils): the image has no cmp/diff.
[[ $(sha256sum </etc/pam.d/sudo) == "$(sha256sum </tmp/sudo.pam.orig)" ]] || fail "sudo PAM changed without pam_u2f"
pass "without FIDO2 set up, sudo PAM is untouched"

# The exact line omarchy-setup-security-fido2 inserts (bin/, dde0d12).
echo "--- D-04 FIDO2: one key stays 'sufficient' (no lockout), two keys become 'required'"
sed -i '1i auth    sufficient pam_u2f.so cue authfile=/etc/fido2/fido2' /etc/pam.d/sudo
mkdir -p /etc/fido2
printf 'alice:KH1,PK1,es256,+presence\nbob:KH9,PK9,es256,+presence\n' > /etc/fido2/fido2
ansible-playbook tests/container/playbook.yml >/dev/null || fail "fido2 run failed"
expect_finding auth.fido2_sudo WARN
grep -q '^auth    sufficient pam_u2f.so' /etc/pam.d/sudo || fail "one key: pam_u2f no longer sufficient"
grep -q 'fewer than 2 keys: alice' /var/lib/aegis/audit.jsonl || fail "short wheel user not named"
pass "a wheel user with one key keeps Omarchy's sufficient mode"

printf 'alice:KH1,PK1,es256,+presence:KH2,PK2,es256,+presence\nbob:KH9,PK9,es256,+presence\n' > /etc/fido2/fido2
ansible-playbook tests/container/playbook.yml >/dev/null || fail "fido2 run failed"
expect_finding auth.fido2_sudo PASS
grep -q '^auth    required pam_u2f.so cue authfile=/etc/fido2/fido2$' /etc/pam.d/sudo || { cat /etc/pam.d/sudo; fail "two keys: pam_u2f not required"; }
out=$(ansible-playbook tests/container/playbook.yml)
grep -Eq 'changed=0 .*failed=0' <<<"$out" || fail "fido2 not idempotent"
rm -f /etc/fido2/fido2
ansible-playbook tests/container/playbook.yml >/dev/null || fail "fido2 run failed"
grep -q '^auth    sufficient pam_u2f.so' /etc/pam.d/sudo || fail "keys removed: not back to sufficient"
cp /tmp/sudo.pam.orig /etc/pam.d/sudo
pass "every wheel user with 2 keys makes sudo key AND password; removing keys reverts"

echo "--- D-06 Flatpak: not installed, nothing to do"
expect_finding flatpak.installed INFO
pass "without Flatpak the role only reports"

echo "--- D-08 commit signing: configures git for a named sk key"
install -d -o alice -m 0700 /home/alice/.ssh
echo 'sk-ssh-ed25519@openssh.com AAAAGnNrLXNzaC1lZDI1NTE5QG9wZW5zc2guY29tAAAAIAegisTestKeyOnly alice@test' > /home/alice/.ssh/id_ed25519_sk.pub
signing='{"aegis_commit_signing_user": "alice", "aegis_commit_signing_pubkey": "/home/alice/.ssh/id_ed25519_sk.pub",
  "aegis_commit_signing_email": "alice@example.invalid"}'
ansible-playbook tests/container/playbook.yml -e "$signing" >/dev/null || fail "commit-signing run failed"
expect_finding git.commit_signing PASS
gitcfg() { runuser -u alice -- git config --global --get "$1"; }
if ! { [[ $(gitcfg gpg.format) == ssh && $(gitcfg commit.gpgsign) == true && $(gitcfg tag.gpgsign) == true ]] \
  && grep -q '^alice@example.invalid namespaces="git" sk-ssh-ed25519@openssh.com ' /home/alice/.config/git/allowed_signers; }; then
  fail "git signing not configured for alice"
fi
out=$(ansible-playbook tests/container/playbook.yml -e "$signing")
grep -Eq 'changed=0 .*failed=0' <<<"$out" || fail "commit signing not idempotent"
pass "ssh signing configured for an sk key, idempotently"

echo "--- D-08 commit signing: a software key is refused by default"
echo 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAegisTestSoftwareKey alice@test' > /home/alice/.ssh/id_ed25519.pub
if ansible-playbook tests/container/playbook.yml \
  -e '{"aegis_commit_signing_user": "alice", "aegis_commit_signing_pubkey": "/home/alice/.ssh/id_ed25519.pub"}' >/tmp/sk.log 2>&1; then
  fail "a non-sk key was accepted"
fi
grep -q 'hardware-backed' /tmp/sk.log || { cat /tmp/sk.log; fail "refused for the wrong reason"; }
pass "ssh-ed25519 refused while aegis_commit_signing_require_sk is true"

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

echo "--- D-10: SSH on tailscale0 only when opted in"
ansible-playbook tests/container/firewall.yml -e aegis_overlay_ssh_on_tailscale=true >/dev/null || fail "overlay run failed"
ufw status | grep -Eq '^22/tcp on tailscale0 +ALLOW' || { ufw status; fail "SSH on tailscale0 not allowed"; }
! ufw status | grep -Eq '^22/tcp( \(v6\))? +(ALLOW|LIMIT)' || fail "SSH opened on all interfaces"
ansible-playbook tests/container/firewall.yml >/dev/null || fail "overlay run failed"
! ufw status | grep -q 'tailscale0' || { ufw status; fail "overlay rule not removed when opted out"; }
pass "opt-in opens SSH on tailscale0 only; opting out removes it"

echo "--- D-24: sshd password logins and key types"
ansible-playbook tests/container/firewall.yml >/dev/null || fail "overlay run without sshd failed"
expect_finding ssh.password_auth MISSING
pass "no SSH findings while sshd is not installed (Omarchy's default)"
pacman -S --noconfirm --needed openssh >/dev/null
ssh-keygen -A >/dev/null
ansible-playbook tests/container/firewall.yml >/dev/null || fail "overlay run with sshd failed"
expect_finding ssh.password_auth WARN
pass "Arch's stock sshd_config (passwords on) warns"
# What omarchy-setup-security-sshd writes once a key is authorized (v4.0.6).
printf 'PasswordAuthentication no\nKbdInteractiveAuthentication no\n' \
  >/etc/ssh/sshd_config.d/10-omarchy-hardening.conf
ansible-playbook tests/container/firewall.yml >/dev/null || fail "overlay run with key-only sshd failed"
expect_finding ssh.password_auth PASS
pass "Omarchy's key-only drop-in passes"
useradd -m -u 1500 sshtest
install -d -m 700 -o sshtest /home/sshtest/.ssh
ssh-keygen -q -t ed25519 -N '' -f /tmp/soft-key
install -m 600 -o sshtest /tmp/soft-key.pub /home/sshtest/.ssh/authorized_keys
ansible-playbook tests/container/firewall.yml >/dev/null || fail "overlay run with a soft key failed"
expect_finding ssh.authorized_keys INFO
grep -q 'sshtest ssh-ed25519' /var/lib/aegis/audit.jsonl || { cat /var/lib/aegis/audit.jsonl; fail "soft key not named"; }
pass "an ssh-ed25519 key is reported as not hardware-backed"
# Only the type is read; this line has the shape of an ed25519-sk public key.
printf 'no-touch-required sk-ssh-ed25519@openssh.com AAAAGnNrLXNzaC1lZDI1NTE5QG9wZW5zc2guY29tAAAAIG5vdC1hLXJlYWwta2V5LWp1c3QtdGhlLXNoYXBlAAAABHNzaDo= sk\n' \
  >/home/sshtest/.ssh/authorized_keys
ansible-playbook tests/container/firewall.yml >/dev/null || fail "overlay run with an sk key failed"
expect_finding ssh.authorized_keys PASS
pass "an sk- key behind key options passes"

echo "--- D-25: the egress collector keeps program and destination, never the command line"
python3 -I -m unittest discover -s tests/collector >/tmp/collector-tests.log 2>&1 \
  || { cat /tmp/collector-tests.log; fail "collector unit tests failed on Arch's python3"; }
pass "collector unit tests pass on $(python3 --version)"
install -d -m 700 /tmp/egress
python3 -I roles/opensnitch/files/aegis-egress-collector.py --port 7811 --state-dir /tmp/egress 2>/tmp/collector.log &
collector=$!
for _ in $(seq 20); do ss -lun | grep -q '127.0.0.1:7811 ' && break; sleep 0.5; done
# Each sender holds its socket for 2 s: the collector rejects a datagram whose
# sending socket is gone by the time it reads /proc/self/net/udp (forced with
# SIGSTOP on 2026-10-26: 5 of 5 rejected closed, 0 of 5 held). CI once read
# the first datagram after its sender had exited.
send() {
  python3 -I -c 'import socket,sys,time
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.connect(("127.0.0.1", 7811)); s.send(sys.argv[1].encode()); time.sleep(2)' "$1"
}
# Shape of opensnitchd v1.7.2 CSV: 9 fields, then the command line.
row() { printf '10.0.0.2,40000,140.82.112.3,%s,443,tcp,42,0,%s,[%s --token SECRET-%s],/root,allow,r' "$1" "$2" "$2" "$1"; }
send "$(row github.com /usr/bin/curl)"
send "$(row beacon.example /opt/beacon/x)"
# shellcheck disable=SC2016 # the Python code is for the inner shell, unexpanded
# Held open too, so it is rejected for its uid, not for a socket that is gone.
su sshtest -s /bin/sh -c 'python3 -I -c "import socket,time; s=socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.connect((\"127.0.0.1\", 7811)); s.send(b\"10.0.0.2,1,1.1.1.1,spoof.example,443,tcp,1,1500,/opt/spoof,[x],/,allow,r\"); time.sleep(2)"'
sleep 1
{ kill -TERM "$collector" && wait "$collector"; } || { cat /tmp/collector.log; fail "collector did not stop cleanly"; }
python3 -I - /tmp/egress/egress.json <<'PY' || { cat /tmp/collector.log; fail "collector state not as expected"; }
import json, sys
raw = open(sys.argv[1], encoding="utf-8").read()
doc = json.loads(raw)
paths = sorted(e["path"] for e in doc["entries"])
assert paths == ["/opt/beacon/x", "/usr/bin/curl"], paths
assert doc["stats"]["rejected_sender"] == 1, doc["stats"]
assert "SECRET" not in raw and "--token" not in raw, "a command line reached the state file"
PY
grep -q 'egress_sender_reject' /tmp/collector.log || { cat /tmp/collector.log; fail "sender rejection not logged as a named event"; }
pass "collector stored 2 events from root, rejected the non-root sender, kept no command line"
ansible-playbook tests/container/egress.yml -e aegis_egress_state_file=/tmp/egress/egress.json >/dev/null \
  || fail "egress audit run failed"
expect_finding egress.unknown_programs WARN
grep -q '/opt/beacon/x -> beacon.example' /var/lib/aegis/audit.jsonl || { cat /var/lib/aegis/audit.jsonl; fail "unowned program not named"; }
! grep -q '/usr/bin/curl ->' /var/lib/aegis/audit.jsonl || { cat /var/lib/aegis/audit.jsonl; fail "a package-owned program was reported"; }
expect_finding egress.collector_sender WARN
pass "the audit names the unowned program, not the package-owned one, and warns about the rejected sender"
ansible-playbook tests/container/egress.yml -e aegis_egress_state_file=/tmp/egress/egress.json \
  -e '{"aegis_egress_known": ["/opt/beacon/*"]}' >/dev/null || fail "egress audit run with a known list failed"
expect_finding egress.unknown_programs PASS
pass "a program in aegis_egress_known is no longer reported"

echo "--- D-26: the agent egress proxy (Smokescreen) is installed verified and filters as configured"
ansible-playbook tests/container/agent-egress.yml >/tmp/proxy-install.log 2>&1 \
  || { cat /tmp/proxy-install.log; fail "agent proxy install failed"; }
proxy_bin=/usr/local/lib/aegis/agent-proxy/smokescreen
[[ -x $proxy_bin && $(stat -c %U "$proxy_bin") == root ]] || fail "smokescreen binary not installed root-owned and executable"
grep -qx '  action: enforce' /etc/aegis/agent-proxy/acl-enforce.yaml || fail "enforce allowlist has the wrong action"
pass "proxy installed from the checksum-verified release, with one allowlist per mode"
# A second run must change nothing: unarchive with --no-same-owner and no
# owner/group reported changed on every run (VM, 2026-10-25).
out=$(ansible-playbook tests/container/agent-egress.yml 2>&1) || { echo "$out"; fail "agent proxy second run failed"; }
grep -Eq 'changed=0 .*failed=0' <<<"$out" || { echo "$out"; fail "agent proxy install not idempotent"; }
[[ $(stat -c %U:%G "$proxy_bin") == root:root ]] || fail "smokescreen binary not root:root after the second run"
pass "agent proxy install idempotent, binary root:root"
# Control for the checksum: a wrong pin must stop the run before anything is used.
rm -f /var/cache/aegis/smokescreen_*.tar.gz
if ansible-playbook tests/container/agent-egress.yml \
  -e '{"aegis_agent_proxy_sha256": {"amd64": "0000000000000000000000000000000000000000000000000000000000000000", "arm64": "0000000000000000000000000000000000000000000000000000000000000000"}}' \
  >/tmp/proxy-badsum.log 2>&1; then
  fail "a wrong pinned checksum did not stop the install"
fi
grep -qi 'checksum' /tmp/proxy-badsum.log || { cat /tmp/proxy-badsum.log; fail "install failed for another reason than the checksum"; }
pass "a wrong pinned checksum stops the install"
# The binary is static, so it runs here without podman. Same config as the
# wrapper uses, on loopback. Unlisted host: example.org; private: metadata IP.
proxy_try() { # mode url -> HTTP code of the CONNECT (or of the GET for http://)
  local mode=$1 url=$2
  # config.yaml names the ACL by its path inside the proxy container, and
  # Smokescreen loads it while reading the config; put the mode's file there,
  # as the wrapper's bind mount does.
  install -D -m 644 "/etc/aegis/agent-proxy/acl-$mode.yaml" /etc/smokescreen/acl.yaml
  "$proxy_bin" --config-file /etc/aegis/agent-proxy/config.yaml --listen-ip 127.0.0.1 --listen-port 4750 \
    >>"/tmp/proxy-$mode.log" 2>&1 &
  local pid=$!
  for _ in $(seq 20); do ss -ltn | grep -q '127.0.0.1:4750 ' && break; sleep 0.5; done
  if [[ $url == https://* ]]; then
    curl -s -o /dev/null -m 20 -w '%{http_connect}' --proxy http://127.0.0.1:4750 "$url" || true
  else
    curl -s -o /dev/null -m 20 -w '%{http_code}' --proxy http://127.0.0.1:4750 "$url" || true
  fi
  kill "$pid"; wait "$pid" 2>/dev/null || true
}
listed=$(proxy_try enforce https://github.com/)
unlisted=$(proxy_try enforce https://example.org/)
metadata=$(proxy_try enforce http://169.254.169.254/)
report_unlisted=$(proxy_try report https://example.org/)
[[ $listed == 200 ]] || { cat /tmp/proxy-enforce.log; fail "enforce: github.com (listed) got $listed"; }
[[ $unlisted != 200 && $unlisted != 000 ]] || { cat /tmp/proxy-enforce.log; fail "enforce: example.org (unlisted) got $unlisted"; }
[[ $metadata != 200 ]] || fail "the metadata address was reachable through the proxy"
[[ $report_unlisted == 200 ]] || { cat /tmp/proxy-report.log; fail "report: example.org got $report_unlisted"; }
pass "enforce allows github.com ($listed), refuses example.org ($unlisted) and 169.254.169.254 ($metadata); report allows example.org"
# The audit reads exactly these log lines (plus noise it must skip).
python3 -I - /tmp/proxy-enforce.log /tmp/proxy-report.log >/tmp/proxy-lines.json <<'PY'
import json, sys
lines = []
for path in sys.argv[1:]:
    lines += open(path, encoding="utf-8", errors="replace").read().splitlines()
lines += ["not json", '{"requested_host": "bad host!"}', "{broken"]
print(json.dumps({"aegis_agent_proxy_log_lines": lines}))
PY
ansible-playbook tests/container/agent-egress.yml -e audit_only=true -e @/tmp/proxy-lines.json >/dev/null \
  || fail "agent egress audit run failed"
expect_finding agent.egress INFO
grep -q 'outside the allowlist: example.org' /var/lib/aegis/audit.jsonl || { cat /var/lib/aegis/audit.jsonl; fail "unlisted host not reported"; }
grep -q 'refused in enforce mode: example.org' /var/lib/aegis/audit.jsonl || { cat /var/lib/aegis/audit.jsonl; fail "enforce refusal not reported"; }
pass "the audit lists example.org as outside the allowlist and refused in enforce mode"

echo "--- D-02: the kernel role accepts either default, but needs the linux-hardened entry"
# Synthetic menus: the role reads only the kernel-id= words, in order.
limine_menu() { # kernel ids in menu order
  local id
  printf '/+Omarchy\n'
  for id in "$@"; do printf '  //%s\n  comment: kernel-id=%s\n' "$id" "$id"; done
}
limine_menu linux-omarchy linux-hardened >/tmp/limine-default.conf
limine_menu linux-hardened linux-omarchy >/tmp/limine-switched.conf
limine_menu linux-omarchy >/tmp/limine-missing.conf
kernel_play() { ansible-playbook tests/container/kernel-limine.yml -e "aegis_kernel_limine_conf=$1"; }
kernel_play /tmp/limine-default.conf >/tmp/kernel.log 2>&1 || { cat /tmp/kernel.log; fail "Limine check failed on Omarchy's default menu"; }
grep -q 'default boot entry: linux-omarchy' /var/lib/aegis/audit.jsonl || { cat /var/lib/aegis/audit.jsonl; fail "default entry not reported"; }
pass "linux-omarchy as the default passes and is reported"
kernel_play /tmp/limine-switched.conf >/tmp/kernel.log 2>&1 || { cat /tmp/kernel.log; fail "Limine check failed after the owner made linux-hardened the default"; }
grep -q 'default boot entry: linux-hardened' /var/lib/aegis/audit.jsonl || { cat /var/lib/aegis/audit.jsonl; fail "switched default not reported"; }
pass "linux-hardened as the default passes and is reported"
if kernel_play /tmp/limine-missing.conf >/tmp/kernel.log 2>&1; then
  fail "a menu without linux-hardened passed the Limine check"
fi
grep -q 'no linux-hardened entry' /tmp/kernel.log || { cat /tmp/kernel.log; fail "failed for the wrong reason"; }
pass "a menu without linux-hardened fails the run"

[[ $checks_passed -eq $checks_total ]] || fail "only $checks_passed/$checks_total checks ran"
echo "${checks_passed}/${checks_total} checks passed"
