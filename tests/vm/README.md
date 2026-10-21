# VM test (VirtualBox)

This test covers what the container cannot: a real Omarchy install with
`linux-omarchy`, the boot, LUKS, systemd's sysctl load order, real netfilter
and a lockout that persists across reboots. The why and the pass criteria are in
[docs/operating-notes.md](../../docs/operating-notes.md) §6. These are the steps
that worked on 2026-10-21. Host: Intel Mac, VirtualBox 7.2.22. Guest: Omarchy
4.0.6, `linux-omarchy 7.2.8-9`.

Everything under `tests/vm/.state/` (key, password, logs) is git-ignored. Its
password protects a throwaway VM and nothing else.

## 1. Get and verify the ISO

```bash
. tests/vm/iso.lock
mkdir -p ~/Downloads/omarchy-iso && cd ~/Downloads/omarchy-iso
curl -fLO "$AEGIS_ISO_URL" -fLO "$AEGIS_ISO_URL.sig"
export GNUPGHOME=$(mktemp -d)
curl -fsS "https://keys.openpgp.org/vks/v1/by-fingerprint/$AEGIS_ISO_SIGNER" | gpg --import
gpg --verify "omarchy-$AEGIS_ISO_VERSION.iso.sig" "omarchy-$AEGIS_ISO_VERSION.iso"   # must say Good signature
```

`create.sh` also checks the SHA-256 pinned in `iso.lock`. To move to a newer
ISO, verify its signature first, then update `iso.lock`.

## 2. Create the VM and the test credentials

```bash
mkdir -m 700 -p tests/vm/.state
ssh-keygen -q -t ed25519 -N '' -C aegis-vm-test -f tests/vm/.state/id_ed25519
echo aegis > tests/vm/.state/user
(umask 077; openssl rand -base64 15 > tests/vm/.state/become-password)
tests/vm/create.sh ~/Downloads/omarchy-iso/omarchy-4.0.6.iso
VBoxManage setextradata aegis-omarchy GUI/AutoresizeGuest false
VBoxManage startvm aegis-omarchy
```

The VM gets 8 GB RAM, 4 vCPU, EFI, VBoxVGA without 3D, a 40 GB disk, and SSH
on `127.0.0.1:2222` only. EFI boot from the ISO works.

`GUI/AutoresizeGuest false`: when the VirtualBox window resized the guest to
1760×1152, the Hyprland desktop was garbled under VBoxVGA. Whether this setting
prevents that was not yet confirmed.

## 3. Install

The installer asks: keyboard, username (`aegis`), password, confirmation, full
name and email (press Enter to skip both, so no personal data goes into the
VM), hostname, timezone and disk. **The one password is used for the user, for
root and for LUKS**, as the installer itself says. Disk encryption is on by
default. Keep it, because a real install has it.

You can type the password from the file with
`VBoxManage controlvm aegis-omarchy keyboardputfile tests/vm/.state/become-password`,
so it never appears on a command line. The file's newline acts as Enter.

When it says "Installed", **do not eject the ISO first**. The live system runs
from it, and ejecting it hung the "Reboot Now" step. Instead:

```bash
VBoxManage controlvm aegis-omarchy poweroff
VBoxManage storageattach aegis-omarchy --storagectl SATA --port 1 --device 0 --type dvddrive --medium emptydrive
VBoxManage startvm aegis-omarchy
```

The LUKS prompt appears about 15 s after power-on. After unlocking, Omarchy
logs in to Hyprland automatically.

## 4. Authorise the test key (in the guest)

Open a terminal with Super+Enter. Sending it from the host with
`VBoxManage controlvm aegis-omarchy keyboardputscancode e0 5b 1c 9c e0 db`
avoids the host grabbing the Super key. Then type Omarchy's own opt-in script,
with the public key, into that terminal. On the host:

```bash
printf 'omarchy-setup-security-sshd --key="%s"\n' "$(cat tests/vm/.state/id_ed25519.pub)" > tests/vm/.state/sshd-cmd
VBoxManage controlvm aegis-omarchy keyboardputfile tests/vm/.state/sshd-cmd
VBoxManage controlvm aegis-omarchy keyboardputfile tests/vm/.state/become-password   # at the sudo prompt
```

It installs and starts sshd, adds `ufw limit 22/tcp`, authorises the key and
turns password logins off. Check from the host:

```bash
ssh -i tests/vm/.state/id_ed25519 -p 2222 -o UserKnownHostsFile=tests/vm/.state/known_hosts aegis@127.0.0.1 uname -r
```

## 5. Snapshot, powered off

```bash
ssh -i tests/vm/.state/id_ed25519 -p 2222 -o UserKnownHostsFile=tests/vm/.state/known_hosts \
  aegis@127.0.0.1 'sudo -S -p "" systemctl poweroff' < tests/vm/.state/become-password
VBoxManage snapshot aegis-omarchy take pre-aegis
```

Take the snapshot **powered off**. A live snapshot (`--live`) once left the
guest frozen: its clock stopped and it ignored input. The cause was not
investigated.

## 6. Run

```bash
tests/vm/run.sh
```

It boots and unlocks the VM if it is off. It then applies the playbook twice
(the second run must change nothing), reboots and unlocks, and runs `--check`
(nothing may differ after the reboot). Last, it prints the live sysctl values
and every WARN, FAIL and ACCEPTED finding. Logs go to `tests/vm/.state/`.

`tests/vm/vm-vars.yml` keeps Omarchy's SSH rule, because the test needs it. The
container test covers removing it.

To start again: `VBoxManage snapshot aegis-omarchy restore pre-aegis`.

## Traps

- **`ufw limit 22/tcp` drops the 6th connection within 30 s.** A tight
  `ssh` polling loop gets you "Connection reset by peer". Poll at most every
  7 s. Ansible reuses one connection.
- If the LUKS passphrase is typed before the prompt is on screen, it is lost.
  `run.sh` waits `AEGIS_VM_LUKS_DELAY` seconds (default 45) and types it once.
- The lock-screen check (10 wrong passwords at `hyprlock`) is still manual.
  Do it on the desktop after `run.sh`.
