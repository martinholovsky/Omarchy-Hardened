#!/usr/bin/env bash
# Create the VirtualBox VM for the Omarchy VM test (tests/vm/README.md).
#
# Usage: tests/vm/create.sh /path/to/omarchy-<version>.iso
#
# Settings follow the community reports in docs/operating-notes.md §6:
# VBoxVGA without 3D, KVM paravirtualisation. EFI is on so the guest boots
# like a real Omarchy install (Limine + UKI). SSH is forwarded from
# 127.0.0.1 only, never from the LAN.
set -euo pipefail

here=$(cd "$(dirname "$0")" && pwd)
# iso.lock is plain KEY=VALUE lines from this repo.
# shellcheck disable=SC1091
. "$here/iso.lock"
vm=${AEGIS_VM_NAME:-aegis-omarchy}
ssh_port=${AEGIS_VM_SSH_PORT:-2222}

die() {
  printf 'create.sh: %s\n' "$*" >&2
  exit 1
}

[[ $# -eq 1 ]] || die "usage: $0 /path/to/omarchy-${AEGIS_ISO_VERSION}.iso"
iso=$1
[[ -f $iso ]] || die "no such file: $iso"
command -v VBoxManage >/dev/null || die "VBoxManage not found"
if VBoxManage showvminfo "$vm" >/dev/null 2>&1; then
  die "VM '$vm' already exists. Remove it with: VBoxManage unregistervm $vm --delete"
fi

echo "Checking the SHA-256 of $iso against tests/vm/iso.lock ..."
actual=$(shasum -a 256 "$iso" | cut -d' ' -f1)
[[ $actual == "$AEGIS_ISO_SHA256" ]] ||
  die "SHA-256 mismatch: got $actual, want $AEGIS_ISO_SHA256"

VBoxManage createvm --name "$vm" --ostype ArchLinux_64 --register
cfg=$(VBoxManage showvminfo "$vm" --machinereadable | sed -n 's/^CfgFile="\(.*\)"$/\1/p')
folder=$(dirname "$cfg")

VBoxManage modifyvm "$vm" \
  --firmware=efi --memory=8192 --cpus=4 --chipset=ich9 --ioapic=on \
  --x86-pae=on --nested-paging=on --paravirt-provider=kvm \
  --graphicscontroller=vboxvga --vram=128 --accelerate-3d=off \
  --audio-enabled=off --usb-ohci=on --usb-ehci=off --usb-xhci=off --mouse=usbtablet \
  --clipboard-mode=disabled --drag-and-drop=disabled --rtc-use-utc=on \
  --nic1=nat --nat-pf1="ssh,tcp,127.0.0.1,${ssh_port},,22" \
  --boot1=dvd --boot2=disk --boot3=none --boot4=none

VBoxManage createmedium disk --filename "$folder/$vm.vdi" --size 40960 --format VDI
VBoxManage storagectl "$vm" --name SATA --add sata --controller IntelAhci --portcount 2
VBoxManage storageattach "$vm" --storagectl SATA --port 0 --device 0 --type hdd \
  --medium "$folder/$vm.vdi"
VBoxManage storageattach "$vm" --storagectl SATA --port 1 --device 0 --type dvddrive \
  --medium "$iso"

cat <<EOF

Created VM '$vm' (Omarchy $AEGIS_ISO_VERSION). SSH will be on 127.0.0.1:$ssh_port.
Next: follow tests/vm/README.md (install, authorise the test key, snapshot).
EOF
