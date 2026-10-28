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

## 5b. Update, then snapshot again

```bash
tests/vm/update-snapshot.sh
```

This restores `pre-aegis`, runs a full `pacman -Syu`, reboots and saves
`pre-aegis-updated`. The roles that install packages need current pacman
databases, and a fresh install has none, just as a user's machine would need
`omarchy-update` first. Omarchy's update guard hook blocks a direct `-Syu`,
so the script sets `OMARCHY_ALLOW_DIRECT_PACMAN=1`, the bypass the guard
itself names. Run the tests from `pre-aegis-updated`.

## 5c. USB 3 and a FIDO2 key (optional)

For the FIDO2 and `ed25519-sk` tests (D-04, D-08) the guest needs the real
key. `pre-aegis-hw` is `pre-aegis-updated` with the xHCI controller on and
OHCI/EHCI off. xHCI is in VirtualBox's base package; the Extension Pack is
not needed.

```bash
VBoxManage modifyvm aegis-omarchy --usbohci off --usbehci off --usbxhci on   # VM powered off
VBoxManage snapshot aegis-omarchy take pre-aegis-hw
```

Attach the key **after** the guest has booted, not through a USB filter:

```bash
uuid=$(VBoxManage list usbhost | grep -B1 'VendorId: *0x1050' | sed -n 's/^UUID: *//p')
VBoxManage controlvm aegis-omarchy usbattach "$uuid"
```

With a filter for the key (YubiKey `1050:0407`), one of two boots on
2026-10-24, on a quiet host, hung before the firmware started: the log
stopped at `RUNNING`, the screen was 0x0, and power-off hung until the
`VirtualBoxVM` process was stopped. The other boot, on an overloaded host,
started but lost SSH. Without the filter it booted, and `usbattach` gave the
guest the key as `1050:0407` with a user-accessible `/dev/hidraw*` node. The
key leaves the Mac while it is attached; `usbdetach` or a power-off returns it.

## 6. Run

```bash
tests/vm/run.sh
```

It installs `ansible-core` in the guest, as a local user would have it, so
the D-11 check can run there. It boots and unlocks the VM if it is off. It then applies the playbook twice
(the second run must change nothing), reboots and unlocks, and runs `--check`
(nothing may differ after the reboot). Last, it prints the live sysctl values
and every WARN, FAIL and ACCEPTED finding. Logs go to `tests/vm/.state/`;
each playbook log (`run1.log`, `run2.log`, `run3.log`) ends with the 30
slowest tasks (`profile_tasks`).

`tests/vm/vm-vars.yml` keeps Omarchy's SSH rule, because the test needs it. The
container test covers removing it.

After the reboot it also checks:

- AppArmor is active, with no profile enforcing
- the Limine order (`linux-omarchy` first, then `linux-hardened`)
- `opensnitchd` is running
- `aegis-agent` has no capabilities, cannot create user namespaces, and can
  write to the project
- a real `pacman -S` triggers the D-11 check, which reports a reverted PAM
  file without repairing it. The check took 9m21s on 2026-10-22; `run.sh`
  waits up to 20 minutes and fails if it is still running
- the lock screen locks out after 10 failures (step 3)
- `sudo` and `su` fill one faillock tally, and `su` refuses a non-wheel user
  with root's right password (step 4). `tests/vm/pty-auth.py` drives `su` on
  a pty in the guest; it reads the password from stdin, never argv

To start again: `VBoxManage snapshot aegis-omarchy restore pre-aegis-updated`.

## 7. Tailscale (D-10, D-24)

```bash
tests/vm/tailscale.sh   # right after tests/vm/run.sh, with the VM still running
```

It installs Tailscale the way Omarchy's `omarchy-install-service-tailscale`
does, and runs Headscale (v0.29.5, the open-source control server) and a
second Tailscale node as rootless containers in the guest, on loopback. No
account, relay or certificate is needed and nothing listens outside the VM.
Headscale refuses an empty DERP map, so `tailscale/derp.yaml` gives it a
region that points at a closed loopback port; the two nodes connect
directly. A listener on port 2200, which ufw does not allow, is the target.

It checks that the second node reaches that port in Tailscale's default
netfilter mode and that `network.overlay` WARNs (D-24). As the control, in
`nodivert` mode the port must be closed and the finding must pass, after
which the mode is set back to `on`. It also checks the SSH findings on the
harness's key-only sshd.

## 8. Egress report (D-25)

```bash
tests/vm/egress.sh   # right after tests/vm/run.sh, with the VM still running
```

It checks that `aegis-egress-collector` runs with a `systemd-analyze security`
exposure of at most 3.0, lets the packaged `curl` and an unowned copy of it in
`~/.local/bin` connect out (the copy with a marker on its command line), and
expects the audit to name the copy only, with the marker in neither the
collector's state file nor its journal.

## 9. Agent egress (D-26)

```bash
tests/vm/agent-egress.sh   # right after tests/vm/run.sh, with the VM still running
```

It runs `curl` in `aegis-agent` containers (the curl project's image, by
digest). In `report` mode `github.com`, the unlisted `example.org` and a
direct connection that ignores the proxy all get through; in `enforce` mode
`github.com` gets through, the proxy refuses `example.org`, and there is no
direct route. It also checks the proxy containers' hardening and that the
audit (`agent.egress`) names `example.org` as unlisted and refused.

## 10. Firewall from another machine (PRD 3.4)

```bash
tests/vm/firewall-hostonly.sh   # on its own; it restores pre-aegis-hw first
```

It gives the VM a second NIC on a VirtualBox host-only network
(`aegis-fwtest`, `192.168.56.0/24`; created by the script, needs no admin
rights) and probes the guest from the Mac before and after hardening, with
`aegis_firewall_remove_ssh: true` as on a real machine. The harness keeps SSH
through a rule limited to the NAT interface. ufw drops, so a blocked port
times out, while an allowed port with nothing listening is refused:

| | Omarchy as installed | Hardened |
|---|---|---|
| SSH 22 | open | timeout |
| LocalSend 53317/tcp | refused (allowed) | timeout |
| Docker DNS from a container | answers | answers; not without its rule |

53317/udp is not tested: a dropped and an unanswered UDP probe look the
same. The NIC and the network are removed on exit, also on failure. Not
bridged: a NIC bridged to the Mac's Wi-Fi got no DHCPv4 lease on 2026-10-25,
and probes to addresses behind the router are unreliable from this host (an
unused routed address answered "open"), so the script probes on-link only.

## Traps

- **`ufw limit 22/tcp` drops the 6th connection within 30 s.** A tight
  `ssh` polling loop gets you "Connection reset by peer". Poll at most every
  7 s. Ansible reuses one connection.
- If the LUKS passphrase is typed before the prompt is on screen, it is lost.
  `run.sh` waits `AEGIS_VM_LUKS_DELAY` seconds (default 45) and types it; if
  SSH is not up 140 s later it types it once more (a loaded host reached the
  prompt late on 2026-10-25, and the run stopped at an empty prompt). Raise
  `AEGIS_VM_LUKS_DELAY` on a busy host.
- Keystrokes typed into the lock screen through VirtualBox can arrive
  mangled on a loaded host: on 2026-10-24 one wrong password never arrived,
  and on 2026-10-25 the right one arrived wrong (`pam_unix` rejected it, and
  typing it again unlocked). `run.sh` types wrong passwords until the tally
  holds 10 records, and the right one up to 3 times. Omarchy's screensaver
  (after 150 s idle) would swallow the first key, but it does not start while
  locked; `run.sh` checks that no screensaver window is up before typing. On
  any failure `run.sh` saves the guest's screen as `.state/run-failed.png`, or
  prints VirtualBox's error when it cannot.
- Any successful `sudo` as the test user runs `pam_faillock authsucc` and
  clears that user's tally. `run.sh` reads the tally through one root watcher
  started before the lock-screen test, never through `sudo` mid-test. Step 4
  locks the test user out of `sudo` on purpose and lifts the lock through
  `su` to root, which has its own tally.
- **The host must be quiet.** On 2026-10-22, with other VMs and containers
  loading the host (swap 12.4 of 13.3 GB used at 18:12, 9.3 of 10.2 GB at
  19:23), run 1 took about 46 minutes (18:13 to 18:59) and the runs lost SSH
  ("banner exchange" and become-prompt timeouts). On a quiet host (load
  average about 3 on 12 cores, no other VM running) the whole run took 40
  minutes on 2026-10-23.
  `AEGIS_VM_UI=headless` avoids the GUI window's host CPU.
- **A `--check` run used to be blind to live sysctl values** (fixed by D-32,
  2026-10-28). Read a "state survives a reboot" pass from before that date as
  "the files survived", not "the kernel values did": on 2026-10-27 it passed
  while ufw had reset `rp_filter` to 1 (D-31).
- **A failed drift check reads as drift.** Both exit non-zero and log "Hardening
  drift". Read `failed=` in `/var/lib/aegis/drift-check.log` before taking the
  message as a finding (D-33: on 2026-10-28 every run had `failed=1`).
- **`guest_root` feeds the sudo password on stdin**, so data piped into it is
  lost: `printf … | guest_root tee FILE` writes an empty file, at exit 0.
  Copy with `guest_ssh 'cat >/tmp/x' <file`, then `guest_root install`.
- **Booting `linux-hardened` once.** Reboot, press Down every second for about
  30 s (any key stops Limine's countdown), take a screenshot, and press Down
  until `linux-hardened` is highlighted: the cursor wraps, so where it stops
  varies. Then Enter, and `unlock_and_wait`.
- **Starting a program in the desktop session.** Hyprland 0.56 parses
  `hyprctl dispatch` as Lua; use
  `hyprctl eval 'hl.exec_cmd("uwsm-app -- xdg-terminal-exec CMD")'` (the call
  Omarchy's own bindings make), with `XDG_RUNTIME_DIR` and
  `HYPRLAND_INSTANCE_SIGNATURE` exported. Typed keys then reach the new
  terminal; a Super+Enter sent with `keyboardputscancode` was lost twice on
  2026-10-27. After a resize the VBoxVGA screen can be garbled; judge by the
  guest's own state (files, journal), not the screenshot.
