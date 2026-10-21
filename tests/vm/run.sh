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

# Omarchy's opt-in SSH rule is `ufw limit 22/tcp`: a 6th connection within
# 30 s is dropped. Poll at most every 7 s; Ansible itself reuses one
# connection (ControlPersist).
ssh_up() {
  ssh -i "$state/id_ed25519" -p "$ssh_port" -o BatchMode=yes -o ConnectTimeout=5 \
    -o UserKnownHostsFile="$state/known_hosts" "$user@127.0.0.1" true 2>/dev/null
}

# Omarchy installs with LUKS, so every boot stops at a passphrase prompt that
# SSH cannot reach. Wait long enough for the prompt to be on screen, then type
# the passphrase (the install password) once through VirtualBox. It is typed
# only once, so a mistimed attempt cannot land in a desktop window.
unlock_and_wait() {
  sleep "${AEGIS_VM_LUKS_DELAY:-45}"
  VBoxManage controlvm "$vm" keyboardputfile "$state/become-password"
  for _ in $(seq 20); do
    sleep 7
    if ssh_up; then return 0; fi
  done
  VBoxManage controlvm "$vm" screenshotpng "$state/boot-failed.png" || true
  die "VM did not come up after unlock; see $state/boot-failed.png"
}

vm_state=$(VBoxManage showvminfo "$vm" --machinereadable | sed -n 's/^VMState="\(.*\)"$/\1/p')
if [[ $vm_state != running ]]; then
  echo "--- boot $vm (state: $vm_state)"
  # Right after a power-off the old VirtualBox window can still hold the
  # session lock for a few seconds, and startvm fails until it lets go.
  started=false
  for _ in $(seq 15); do
    if VBoxManage startvm "$vm" --type "${AEGIS_VM_UI:-gui}"; then started=true && break; fi
    sleep 2
  done
  [[ $started == true ]] || die "could not start $vm"
  unlock_and_wait
fi

echo "--- run 1: apply"
"${play[@]}" 2>&1 | tee "$state/run1.log"

echo "--- run 2: apply again"
"${play[@]}" 2>&1 | tee "$state/run2.log"
expect_unchanged "$state/run2.log" "second run changes nothing"

echo "--- reboot"
uv run --project "$repo" ansible aegis "${common[@]}" -b -m ansible.builtin.shell \
  -a "sleep 2 && systemctl reboot" -B 30 -P 0 >/dev/null
unlock_and_wait

echo "--- run 3: --check after reboot"
"${play[@]}" --check --diff 2>&1 | tee "$state/run3.log"
expect_unchanged "$state/run3.log" "state survives a reboot"

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
