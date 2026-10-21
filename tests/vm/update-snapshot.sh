#!/usr/bin/env bash
# Bring the fresh install up to date, as a user would with omarchy-update,
# and save it as the snapshot "pre-aegis-updated". The roles that install
# packages (kernel, apparmor, opensnitch, agent_containment) need current
# pacman databases, which a fresh Omarchy install does not have yet.
#
# Usage: tests/vm/update-snapshot.sh   (starts from the "pre-aegis" snapshot)
set -euo pipefail

here=$(cd "$(dirname "$0")" && pwd)
state="$here/.state"
vm=${AEGIS_VM_NAME:-aegis-omarchy}
ssh_port=${AEGIS_VM_SSH_PORT:-2222}
user=$(<"$state/user")

die() {
  printf 'update-snapshot.sh: %s\n' "$*" >&2
  exit 1
}

# shellcheck source=tests/vm/lib.sh
. "$here/lib.sh"

if [[ $(vm_state) != poweroff ]]; then
  VBoxManage controlvm "$vm" poweroff >/dev/null 2>&1 || true
  for _ in $(seq 30); do [[ $(vm_state) == poweroff ]] && break; sleep 2; done
fi
VBoxManage snapshot "$vm" restore pre-aegis
ensure_running

# Omarchy's 00-omarchy-update-guard.hook refuses a direct `pacman -Syu`
# (bin/omarchy-update-pacman-guard) and names this variable as the bypass.
# `omarchy update -y` would also run Omarchy's migrations, but it calls sudo
# itself, which needs a TTY; current packages and databases are what the
# roles need.
echo "--- pacman -Syu (OMARCHY_ALLOW_DIRECT_PACMAN=1)"
guest_root env OMARCHY_ALLOW_DIRECT_PACMAN=1 pacman -Syu --noconfirm 2>&1 | tail -5

echo "--- reboot into the updated system"
reboot_and_wait
guest_root uname -r

poweroff_and_wait
if VBoxManage snapshot "$vm" showvminfo pre-aegis-updated >/dev/null 2>&1; then
  VBoxManage snapshot "$vm" delete pre-aegis-updated
fi
VBoxManage snapshot "$vm" take pre-aegis-updated \
  --description "pre-aegis after pacman -Syu on $(date -u +%Y-%m-%d)"
echo "Saved snapshot pre-aegis-updated"
