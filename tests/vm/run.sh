#!/usr/bin/env bash
# Apply the playbook to the VirtualBox test VM over SSH and check that the
# result survives a second run and a reboot (tests/vm/README.md).
#
# Usage: tests/vm/run.sh      (VM running, test key authorised, snapshot taken)
#
# Reads tests/vm/.state/{user,id_ed25519,become-password}; logs go there too.
set -euo pipefail

here=$(cd "$(dirname "$0")" && pwd)
repo=$(cd "$here/../.." && pwd)
state="$here/.state"

die() {
  printf 'run.sh: %s\n' "$*" >&2
  # What the guest showed when the check failed (lock screen, screensaver, prompt).
  # Keep VirtualBox's error: on 2026-10-25 a failure left no screenshot and,
  # with the error discarded, no clue why (the same call worked later).
  local err
  if [[ -n ${vm:-} && -n ${state:-} ]]; then
    if err=$(VBoxManage controlvm "$vm" screenshotpng "$state/run-failed.png" 2>&1); then
      printf 'run.sh: screenshot in %s\n' "$state/run-failed.png" >&2
    else
      printf 'run.sh: no screenshot: %s\n' "${err:-VBoxManage gave no message}" >&2
    fi
  fi
  exit 1
}

for f in user id_ed25519 become-password; do
  [[ -f $state/$f ]] || die "missing $state/$f (see tests/vm/README.md)"
done
user=$(<"$state/user")
vm=${AEGIS_VM_NAME:-aegis-omarchy}
ssh_port=${AEGIS_VM_SSH_PORT:-2222}

export ANSIBLE_CONFIG="$repo/ansible.cfg"
# Keep the test VM's host key out of ~/.ssh/known_hosts.
export ANSIBLE_SSH_ARGS="-o ControlMaster=auto -o ControlPersist=60s -o UserKnownHostsFile=$state/known_hosts -o StrictHostKeyChecking=accept-new"
# Time every task (ansible.posix, pinned in requirements.yml): each playbook
# log ends with the 30 slowest tasks, to find where a 12-minute apply goes.
export ANSIBLE_CALLBACKS_ENABLED=ansible.posix.profile_tasks PROFILE_TASKS_TASK_OUTPUT_LIMIT=30
common=(-i "$here/inventory.yml" -u "$user" --private-key "$state/id_ed25519"
  --become-password-file "$state/become-password")
play=(uv run --project "$repo" ansible-playbook "${common[@]}" -e "@$here/vm-vars.yml"
  "$repo/omarchy-harden.yml")

# The recap line for the VM must say changed=0 and failed=0.
expect_unchanged() {
  if ! grep -Eq '^aegis-vm +: .*changed=0 .*failed=0 ' "$1"; then
    die "$2: not idempotent, see $1"
  fi
  echo "PASS: $2"
}

# shellcheck source=tests/vm/lib.sh
. "$here/lib.sh"
ensure_running

# A real user runs the playbook on the machine, so ansible-core is there;
# the D-11 check needs it. The VM test drives Ansible from the host instead.
guest_root pacman -S --needed --noconfirm ansible-core >/dev/null

echo "--- run 1: apply"
"${play[@]}" 2>&1 | tee "$state/run1.log"

echo "--- run 2: apply again"
"${play[@]}" 2>&1 | tee "$state/run2.log"
expect_unchanged "$state/run2.log" "second run changes nothing"

echo "--- reboot"
reboot_and_wait

echo "--- run 3: --check after reboot"
"${play[@]}" --check --diff 2>&1 | tee "$state/run3.log"
expect_unchanged "$state/run3.log" "state survives a reboot"

echo "--- decided roles after reboot (D-01, D-02, D-05, D-07, D-09)"
lsm=$(guest_root cat /sys/kernel/security/lsm)
[[ $lsm == *apparmor* ]] || die "AppArmor not in the active LSMs after reboot: $lsm"
echo "PASS: AppArmor active ($lsm)"
modes=$(guest_root aa-status --json | python3 -I -c 'import sys,json; p=json.load(sys.stdin)["profiles"]; \
  print(sum(v=="enforce" for v in p.values()), sum(v=="complain" for v in p.values()))')
read -r enforce complain <<<"$modes"
[[ $enforce -eq 0 && $complain -gt 0 ]] || die "AppArmor profiles: $enforce enforce, $complain complain (want 0 / >0)"
echo "PASS: $complain AppArmor profiles loaded, all in complain mode"
ids=$(guest_root grep -o 'kernel-id=[^ ]*' /boot/limine.conf | tr '\n' ' ')
[[ $ids == kernel-id=linux-omarchy*kernel-id=linux-hardened* ]] || die "Limine kernel entries: $ids"
echo "PASS: Limine lists linux-omarchy first, then linux-hardened"
[[ $(guest_root systemctl is-active opensnitchd) == active ]] || die "opensnitchd not active"
echo "PASS: opensnitchd active"
# D-09 promises allow by default. While opensnitch-ui runs, a prompt nobody
# answers applies the UI's action after its 30 s timeout, and the UI's own
# default is deny until restart: on 2026-10-24 that cut all egress here.
# ps instead of pgrep -f: the remote shell's argv would match the pattern.
ui=$(guest_ssh "ps -eo args= | grep -c '^/usr/bin/python[0-9.]* /usr/bin/opensnitch-ui'" || true)
[[ $ui -ge 1 ]] || die "opensnitch-ui is not running, so this check would not test the prompt path"
code=$(guest_ssh "curl -s -m 60 -o /dev/null -w '%{http_code}' https://archlinux.org/" || true)
[[ $code =~ ^[23][0-9][0-9]$ ]] || die "a program with no OpenSnitch rule could not connect out (HTTP $code)"
echo "PASS: with opensnitch-ui running, an unanswered prompt lets a new program out (HTTP $code)"
img=docker.io/library/alpine@sha256:5291449c3df73caf6ed85e649dec1b9e818b39a5d8c871e97afc13e9cd5e8fa8
agent=$(guest_ssh "mkdir -p ~/aegis-proj && cd ~/aegis-proj && aegis-agent --image $img -- sh -c \
  'grep CapEff /proc/self/status; ls -A /home | wc -l; unshare -U true 2>/dev/null && echo USERNS_ALLOWED || echo USERNS_DENIED; touch /work/w && echo WROTE'" 2>&1) || true
printf '  agent: %s\n' "${agent//$'\n'/ | }"
if ! { grep -q 'CapEff:.*0000000000000000' <<<"$agent" && grep -q USERNS_DENIED <<<"$agent" && grep -q WROTE <<<"$agent"; }; then
  die "aegis-agent: capabilities, user namespaces or project mount not as expected"
fi
echo "PASS: aegis-agent: no capabilities, no user namespaces, project dir writable"

echo "--- D-11: a package transaction triggers the drift check"
guest_root sed -i 's/unlock_time=900/unlock_time=120/' /etc/pam.d/system-auth
guest_root pacman -S --noconfirm which >/dev/null
# The check took 9m21s on 2026-10-22, over the 5 minutes this once waited.
# While it runs, Result still says success, so a timeout must fail here.
for _ in $(seq 240); do
  st=$(guest_root systemctl show -P ActiveState aegis-drift-check.service)
  [[ $st == activating || $st == active ]] || break
  sleep 5
done
[[ $st != activating && $st != active ]] || die "drift check still $st after 20 minutes"
guest_root test -f /etc/systemd/system/aegis-drift-check.service || die "drift-check unit not installed"
result=$(guest_root systemctl show -P Result aegis-drift-check.service)
journal=$(guest_root journalctl -t aegis-drift-check -n 5 --no-pager)
if ! { [[ $result == exit-code ]] && grep -q 'Hardening drift' <<<"$journal"; }; then
  die "drift not reported (Result=$result): $journal"
fi
# D-33: a check that failed part-way also exits non-zero, so the run itself
# must have reached the end: every role checked, none failed.
recap=$(guest_root grep -E '^[^ ]+ +: ok=' /var/lib/aegis/drift-check.log | tail -1)
[[ $recap == *' failed=0 '* ]] || die "drift check did not run to the end (D-33): ${recap:-no recap}"
echo "  drift check: $recap"
grep -q 'unlock_time=120' <<<"$(guest_root cat /etc/pam.d/system-auth)" || die "the drift check changed the system"
echo "PASS: pacman hook ran the check; the reverted PAM file was reported, not repaired"

echo "--- lock screen: 10 wrong passwords lock the right one out (D-13, G1)"
# Any successful sudo runs pam_faillock authsucc for this user and clears the
# tally, so one sudo starts a root watcher that logs the tally and resets it
# later, and nothing authenticates in between.
locked() {
  # shellcheck disable=SC2016 # expanded in the guest, not here
  guest_ssh 'export XDG_RUNTIME_DIR=/run/user/1000 HYPRLAND_INSTANCE_SIGNATURE=$(ls /run/user/1000/hypr | head -1);
    omarchy-hyprland-session-locked; echo $?' | tail -1
}
guest_root sh -c "faillock --user $user --reset; (for i in \$(seq 120); do stat -c %s /var/lib/faillock/$user; sleep 1; done;
  faillock --user $user --reset; echo reset) >/tmp/aegis-tally-log 2>&1 &"
VBoxManage controlvm "$vm" keyboardputscancode e0 5b 1d 26 a6 9d e0 db # Super+Ctrl+L
sleep 5
[[ $(locked) == 0 ]] || die "screen did not lock"
# Omarchy's screensaver (150 s idle) takes the first key to exit
# (bin/omarchy-screensaver at cbd44ba). It does not start while locked, and
# locking closes it; this checks that rather than assuming it.
# shellcheck disable=SC2016 # expanded in the guest, not here
screensaver=$(guest_ssh 'export XDG_RUNTIME_DIR=/run/user/1000 HYPRLAND_INSTANCE_SIGNATURE=$(ls /run/user/1000/hypr | head -1);
  hyprctl clients -j | jq "[.[] | select(.class == \"org.omarchy.screensaver\")] | length"')
[[ $screensaver == 0 ]] || die "a screensaver window is up on the lock screen ($screensaver); typed input would go to it"
# Typed input can be lost: on 2026-10-24 one of 10 attempts never reached the
# lock screen (9 pam_unix failures, tally 576 bytes) and the test failed
# although the lockout was right. Type until the tally holds 10 records.
for i in $(seq 15); do
  VBoxManage controlvm "$vm" keyboardputstring "wrong-$i"
  VBoxManage controlvm "$vm" keyboardputscancode 1c 9c
  sleep 3
  [[ $(guest_ssh 'tail -1 /tmp/aegis-tally-log') -ge 640 ]] && break
done
[[ $i -lt 15 || $(guest_ssh 'tail -1 /tmp/aegis-tally-log') -ge 640 ]] \
  || die "the lock screen recorded fewer than 10 failures after 15 attempts"
echo "  $i attempts typed for 10 recorded failures"
VBoxManage controlvm "$vm" keyboardputfile "$state/become-password"
sleep 6
[[ $(locked) == 0 ]] || die "the right password unlocked after 10 failures"
until guest_ssh 'grep -q reset /tmp/aegis-tally-log'; do sleep 7; done
bytes=$(guest_ssh 'grep -v reset /tmp/aegis-tally-log | tail -1')
[[ $bytes -ge 640 ]] || die "lock screen recorded $bytes bytes of failures (want 10 records, 640)"
# The same input loss hit the unlock on 2026-10-25: pam_unix rejected what
# arrived (one record, 64 bytes) and the same password typed again unlocked.
# Up to 3 attempts stay far below the 10-failure lockout; a PAM that refuses
# the right password still fails all three.
for _ in 1 2 3; do
  VBoxManage controlvm "$vm" keyboardputfile "$state/become-password"
  sleep 6
  [[ $(locked) == 1 ]] && break
done
[[ $(locked) == 1 ]] || die "the right password did not unlock after a root reset (3 attempts)"
echo "PASS: lock screen locks out after 10 failures ($bytes bytes of records); a root reset unlocks"

echo "--- sudo and su share one lockout; only wheel may su (G2, step 4)"
# A record is 64 bytes. Measured: one wrong `sudo -S` adds 2 records, one
# wrong su adds 1. 3 + 4 attempts reach deny=10 only when both are counted.
# Until the reset below, sudo is locked, so nothing here may use guest_root.
guest_ssh "cat >/tmp/aegis-pty-auth.py" <"$here/pty-auth.py"
tally() { guest_ssh "stat -c %s /var/lib/faillock/$user 2>/dev/null || echo 0"; }
su_self() { guest_ssh "python3 /tmp/aegis-pty-auth.py su -c true $user"; }
guest_root faillock --user "$user" --reset
for _ in 1 2 3; do
  if echo wrong-pw | guest_ssh "sudo -S -k -p '' true" >/dev/null 2>&1; then die "sudo accepted a wrong password"; fi
done
after_sudo=$(tally)
((after_sudo >= 3 * 64 && after_sudo < 640)) || die "3 wrong sudo attempts left $after_sudo bytes of records"
for _ in 1 2 3 4; do
  if echo wrong-pw | su_self >/dev/null; then die "su accepted a wrong password"; fi
done
after_su=$(tally)
((after_su >= after_sudo + 4 * 64 && after_su >= 640)) ||
  die "su failures not added to the sudo tally ($after_sudo -> $after_su bytes)"
if guest_ssh "sudo -S -k -p '' true" <"$state/become-password" >/dev/null 2>&1; then
  die "sudo accepted the right password after 10 sudo and su failures"
fi
if su_self <"$state/become-password" >/dev/null; then die "su accepted the right password while locked"; fi
# Root has its own tally, so a wheel user can still su to root: that is the
# positive control for the non-wheel check below, and it lifts the lock.
guest_ssh "python3 /tmp/aegis-pty-auth.py su -c 'faillock --user $user --reset' root" <"$state/become-password" >/dev/null ||
  die "a wheel user could not su to root with the right password"
[[ $(tally) == 0 ]] || die "the tally was not reset through su"
echo "PASS: sudo ($after_sudo bytes) and su (+$((after_su - after_sudo))) fill one tally; at 10 both refuse the right password"

nowheel=aegis-nowheel
guest_root sh -c "id -u $nowheel >/dev/null 2>&1 || useradd -m $nowheel"
if out=$(cat "$state/become-password" "$state/become-password" |
  guest_ssh "sudo -S -p '' runuser -u $nowheel -- python3 /tmp/aegis-pty-auth.py su -c true root"); then
  die "a non-wheel user could su with root's password"
fi
grep -q 'Permission denied' <<<"$out" || die "non-wheel su failed for another reason: $out"
guest_root faillock --user root --reset
guest_root userdel -r "$nowheel"
echo "PASS: su refuses a non-wheel user with root's right password (Permission denied)"

echo "--- live values after reboot"
# vm.mmap_rnd_bits is readable by root only.
uv run --project "$repo" ansible aegis "${common[@]}" -b -m ansible.builtin.command \
  -a "sysctl kernel.sysrq kernel.oops_limit vm.mmap_rnd_bits vm.mmap_rnd_compat_bits kernel.kexec_load_disabled" |
  tee "$state/sysctl-after-reboot.log"
uv run --project "$repo" ansible aegis "${common[@]}" -b -m ansible.builtin.command \
  -a "cat /var/lib/aegis/audit.jsonl" >"$state/audit.raw"
grep '^{' "$state/audit.raw" >"$state/audit.jsonl" || die "no findings in $state/audit.raw"
python3 -I - "$state/audit.jsonl" <<'PY'
import collections, json, sys
rows = [json.loads(line) for line in open(sys.argv[1])]
print("findings:", dict(collections.Counter(r["status"] for r in rows)), f"({len(rows)} total)")
for r in rows:
    if r["status"] in ("WARN", "FAIL", "ACCEPTED"):
        print(f'  {r["status"]:8} {r["id"]}: {r["detail"][:200]}')
PY
echo "Done. Logs: $state"
