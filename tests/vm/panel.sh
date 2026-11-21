#!/usr/bin/env bash
# D-38 end to end: the status file, the CLI, polkit admin mode, the auto-ending
# pause, sudo-only disable, and the plugin in the running Omarchy shell.
#
# Usage: tests/vm/panel.sh   (after tests/vm/run.sh, VM still running;
#                             vm-vars.yml turns aegis_panel_enabled on)
#
# polkit runs in the desktop: each case starts in the Hyprland session
# (hyprctl dispatch exec), so polkit sees the active session; pkexec then
# prompts on a pty that pty-auth.py answers once.
set -euo pipefail

here=$(cd "$(dirname "$0")" && pwd)
repo=$(cd "$here/../.." && pwd)
state="$here/.state"

die() {
  printf 'panel.sh: %s\n' "$*" >&2
  exit 1
}

for f in user id_ed25519 become-password; do
  [[ -f $state/$f ]] || die "missing $state/$f (see tests/vm/README.md)"
done
user=$(<"$state/user")
vm=${AEGIS_VM_NAME:-aegis-omarchy}
ssh_port=${AEGIS_VM_SSH_PORT:-2222}

export ANSIBLE_CONFIG="$repo/ansible.cfg"
export ANSIBLE_SSH_ARGS="-o ControlMaster=auto -o ControlPersist=60s -o UserKnownHostsFile=$state/known_hosts -o StrictHostKeyChecking=accept-new"
play=(uv run --project "$repo" ansible-playbook -i "$here/inventory.yml" -u "$user"
  --private-key "$state/id_ed25519" --become-password-file "$state/become-password"
  -e "@$here/vm-vars.yml" "$repo/omarchy-harden.yml")

# shellcheck source=tests/vm/lib.sh
. "$here/lib.sh"
[[ $(vm_state) == running ]] || die "start with the VM running, after tests/vm/run.sh"

finding() {
  guest_root cat /var/lib/aegis/audit.jsonl | python3 -I -c 'import json,sys
for line in sys.stdin:
    f = json.loads(line)
    if f["id"] == sys.argv[1]:
        print(f["status"], f["detail"]); break
else:
    print("MISSING")' "$1"
}
pass() { echo "PASS: $*"; }
active() { guest_root systemctl is-active tetragon.service || true; }
# omarchy commands need the desktop session's environment (tests/vm/README.md, Traps).
in_session() {
  guest_ssh "set -a; eval \"\$(systemctl --user show-environment | grep -E '^(OMARCHY_PATH|PATH|WAYLAND_DISPLAY|HYPRLAND_INSTANCE_SIGNATURE|XDG_RUNTIME_DIR|DBUS_SESSION_BUS_ADDRESS)=')\"; set +a; $*"
}


echo "--- status file and CLI"
[[ $(guest_root stat -c '%U %G %a' /run/aegis/status.json) == 'root wheel 640' ]] || die "status file not root:wheel 0640"
guest_ssh 'aegis status' >"$state/panel-status.txt" || die "aegis status failed as the user"
grep -q 'Tetragon' "$state/panel-status.txt" || die "aegis status does not list Tetragon"
[[ $(guest_root systemctl is-active aegis-status.timer) == active ]] || die "aegis-status.timer not active"
guest_root systemd-analyze security aegis-status.service >"$state/panel-security.txt" 2>&1 || true
pass "status file root:wheel 0640, readable by the user through aegis status; timer active"

echo "--- polkit from SSH (not the active session): refused without a prompt"
if guest_ssh 'timeout 20 pkexec /usr/local/libexec/aegis-helper unlock </dev/null' >/dev/null 2>&1; then
  die "a remote session was authorized"
fi
pass "a non-active (SSH) session cannot use admin mode (allow_any no)"

# The rest runs inside the Hyprland session, as the panel does: Omarchy's own
# polkit dialog prompts and the password is typed through VirtualBox.
gui_run() { # name script: run the script in the desktop session, results in /tmp/aegis-gui-<name>.out
  local name=$1 script=$2
  printf '%s\n' "$script" | guest_ssh "cat >/tmp/aegis-gui-$name.sh && rm -f /tmp/aegis-gui-$name.out"
  # Hyprland 0.56 takes Lua: hl.dsp.exec_cmd (as Omarchy 4.5's own bindings use).
  in_session "hyprctl dispatch 'hl.dsp.exec_cmd(\"bash /tmp/aegis-gui-$name.sh\")'" >/dev/null
}
gui_wait() { # name lines: wait until the out file has that many lines
  local name=$1 lines=$2
  for _ in $(seq 40); do
    [[ $(guest_ssh "wc -l </tmp/aegis-gui-$name.out 2>/dev/null || echo 0") -ge $lines ]] && break
    sleep 2
  done
  guest_ssh "cat /tmp/aegis-gui-$name.out 2>/dev/null"
}
helper=/usr/local/libexec/aegis-helper
# A blanked display drops screenshots; Shift (press, release) wakes it.
wake() { VBoxManage controlvm "$vm" keyboardputscancode 2a aa && sleep 2; }

echo "--- admin mode in the desktop: one password covers unlock and the pause it implies"
# In the desktop session (polkit sees unix-session:1, active). pkttyagent is
# registered for the script's shell, which takes precedence over the session's
# dialog; pty-auth.py answers its first prompt only, so a second prompt fails
# the check. Typing into Omarchy's dialog through VirtualBox was
# not reliable (polkit logged "FAILED to authenticate", 2026-11-21).
guest_ssh "cat >/tmp/aegis-pty-auth.py" <"$here/pty-auth.py"
guest_ssh "umask 077; cat >/tmp/aegis-pw" <"$state/become-password"
pty="python3 /tmp/aegis-pty-auth.py"
gui_run keep "$pty sh -c 'pkttyagent --process \$\$ & sleep 1; pkexec $helper unlock; echo u=\$?; pkexec $helper pause tetragon 10; echo p=\$?; kill %1' </tmp/aegis-pw >/tmp/aegis-gui-keep.log 2>&1; grep -oE '[up]=[0-9]+' /tmp/aegis-gui-keep.log >>/tmp/aegis-gui-keep.out"
out=$(gui_wait keep 2)
[[ $out == *u=0* && $out == *p=0* ]] || { guest_ssh 'cat /tmp/aegis-gui-keep.log'; die "admin mode: want u=0 p=0, got: $out"; }
[[ $(active) != active ]] || die "tetragon still running after the pause"
guest_root systemctl list-timers --all | grep -q aegis-resume-tetragon || die "no resume timer"
# polkitd logs only failures, so success is shown by the SSH refusal above
# against this success in the desktop session.
pass "in the desktop session one password covered unlock and the implied pause; Tetragon stopped, resume timer set"

echo "--- the pause is reported and ends on its own"
"${play[@]}" --tags panel >"$state/panel-run1.log" 2>&1 || { tail -30 "$state/panel-run1.log"; die "playbook failed"; }
[[ $(finding panel.paused) == "WARN "*tetragon* ]] || die "panel.paused: $(finding panel.paused)"
guest_root journalctl -t aegis-helper --since -10min --no-pager | grep -q 'tetragon paused for 10 min by uid' \
  || die "pause not in the journal with the requesting uid"
# The audit run takes about 4.5 minutes here, so the desktop pause is 10
# minutes; auto-resume is checked with a 1-minute pause that replaces it.
guest_root "$helper" pause tetragon 1 >/dev/null || die "re-pause for the resume check failed"
for _ in $(seq 36); do [[ $(active) == active ]] && break; sleep 5; done
[[ $(active) == active ]] || die "tetragon did not come back after its pause"
pass "the audit WARNed, the journal named the uid, and Tetragon resumed on its own"

echo "--- a wrong password in the desktop changes nothing"
sleep 310  # let admin mode (auth_admin_keep, about five minutes) run out first
guest_ssh "umask 077; printf 'not-the-password\n' >/tmp/aegis-pw-wrong"
gui_run wrong "$pty sh -c 'pkttyagent --process \$\$ & sleep 1; pkexec $helper pause tetragon 1; r=\$?; kill %1; exit \$r' </tmp/aegis-pw-wrong >/dev/null 2>&1; echo w=\$? >>/tmp/aegis-gui-wrong.out"
out=$(gui_wait wrong 1)
[[ $out == w=* && $out != w=0 ]] || die "a wrong password: want a non-zero exit, got: $out"
[[ $(active) == active ]] || die "tetragon stopped after a refused pause"
guest_ssh 'rm -f /tmp/aegis-pw /tmp/aegis-pw-wrong'
pass "a wrong password is refused and Tetragon keeps running ($out)"

echo "--- disable: refused under pkexec, works under sudo, ends at the next apply"
guest_root env PKEXEC_UID=1000 /usr/local/libexec/aegis-helper disable tetragon >/dev/null 2>&1 \
  && die "disable accepted under pkexec"
guest_root /usr/local/libexec/aegis-helper disable tetragon >/dev/null || die "disable under sudo failed"
[[ $(guest_root systemctl is-enabled tetragon.service || true) == disabled ]] || die "tetragon not disabled"
gui_run resume "timeout 25 pkexec $helper resume tetragon; echo r=\$? >>/tmp/aegis-gui-resume.out"
out=$(gui_wait resume 1)
[[ $out == r=0 && $(active) == active ]] || die "resume in the desktop without a prompt: $out"
guest_root /usr/local/libexec/aegis-helper disable tetragon >/dev/null || die "second disable failed"
"${play[@]}" --tags panel,tetragon >"$state/panel-run2.log" 2>&1 || { tail -30 "$state/panel-run2.log"; die "playbook failed"; }
[[ $(active) == active ]] || die "the apply did not turn tetragon back on"
[[ $(finding panel.disabled) == "PASS "* ]] || die "panel.disabled after the apply: $(finding panel.disabled)"
pass "disable needs sudo; resume needs no prompt in the desktop; the next apply turns it back on"

echo "--- the plugin in the running shell"
# Quickshell warns that any user plugin's module path is "outside of the
# config folder" (~/.config/omarchy/plugins); that is not a QML error.
in_session omarchy plugin list --json >"$state/panel-plugins.json" || die "omarchy plugin list failed"
python3 -I - "$state/panel-plugins.json" <<'PY' || die "aegis.status not listed as enabled"
import json, sys
items = json.load(open(sys.argv[1]))
hit = [p for p in items if p.get("id") == "aegis.status"]
assert hit and hit[0].get("enabled") is True, hit
PY
in_session omarchy plugin validate "\$HOME/.config/omarchy/plugins/aegis.status" || die "plugin does not validate"
in_session omarchy-shell aegis.status open >/dev/null 2>&1 || true
sleep 2
wake
VBoxManage controlvm "$vm" screenshotpng "$state/panel-open.png" || echo "(no screenshot)"
in_session omarchy-shell aegis.status close >/dev/null 2>&1 || true
guest_ssh "journalctl --user -b --no-pager 2>/dev/null | grep -iE 'aegis\\.status|aegis/(Panel|Service)' | grep -iE 'error|warn|unavailable|not a type' | grep -v 'qmlscanner: Module path' || true" \
  >"$state/panel-qml.txt"
[[ ! -s $state/panel-qml.txt ]] || { cat "$state/panel-qml.txt"; die "QML errors from the plugin"; }
pass "aegis.status enabled and valid, no QML errors in the user journal; screenshot in $state/panel-open.png"
echo "panel.sh: all checks passed"
