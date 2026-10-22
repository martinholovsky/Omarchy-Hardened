# shellcheck shell=bash disable=SC2154 # state, user, vm, ssh_port come from the caller
# Shared by tests/vm/run.sh and tests/vm/update-snapshot.sh. The caller sets
# $state, $user, $vm and $ssh_port and defines die().

# Omarchy's opt-in SSH rule is `ufw limit 22/tcp`: a 6th connection within
# 30 s is dropped. Every ssh here shares one multiplexed connection, and the
# boot poll waits 7 s between attempts. Ansible keeps its own (ControlPersist).
guest_ssh() {
  ssh -i "$state/id_ed25519" -p "$ssh_port" -o BatchMode=yes -o ConnectTimeout=5 \
    -o UserKnownHostsFile="$state/known_hosts" -o ControlMaster=auto \
    -o ControlPath="$HOME/.ssh/aegis-vm-%C" -o ControlPersist=120 "$user@127.0.0.1" "$@"
}

ssh_up() {
  guest_ssh true 2>/dev/null
}

# Run a command in the guest as root (sudo reads the password from stdin).
# Each argument is quoted for the remote shell, so patterns survive intact.
guest_root() {
  local quoted
  quoted=$(printf '%q ' "$@")
  guest_ssh "sudo -S -p '' $quoted" <"$state/become-password"
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

vm_state() {
  VBoxManage showvminfo "$vm" --machinereadable | sed -n 's/^VMState="\(.*\)"$/\1/p'
}

# Boot the VM and unlock it, unless it is already running.
ensure_running() {
  local current started=false
  current=$(vm_state)
  [[ $current == running ]] && return 0
  echo "--- boot $vm (state: $current)"
  # Right after a power-off the old VirtualBox window can still hold the
  # session lock for a few seconds, and startvm fails until it lets go.
  for _ in $(seq 15); do
    if VBoxManage startvm "$vm" --type "${AEGIS_VM_UI:-gui}"; then started=true && break; fi
    sleep 2
  done
  [[ $started == true ]] || die "could not start $vm"
  unlock_and_wait
}

# Reboot the guest and unlock it again.
reboot_and_wait() {
  guest_root systemctl reboot >/dev/null 2>&1 || true
  unlock_and_wait
}

# Power the guest off cleanly and wait until VirtualBox reports it off.
poweroff_and_wait() {
  guest_root systemctl poweroff >/dev/null 2>&1 || true
  for _ in $(seq 60); do
    [[ $(vm_state) == poweroff ]] && return 0
    sleep 2
  done
  die "VM did not power off"
}
