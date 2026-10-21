# Operating notes: before, during and after a run

What changes on the machine when you apply the playbook, what you cannot easily
undo, and what has not been tested yet. The settings are in each role's
`defaults/main.yml`. The decisions behind them are in
[open-decisions.md](open-decisions.md).

Last reviewed: 2026-10-21, after the first VM run.

## 1. What has and has not been verified

| Area | Verified how | Not verified |
|---|---|---|
| sysctl values | Applied to a live kernel in CI (`sysctl-apply` job, Ubuntu runner kernel), re-read, re-applied after drift. **VM (2026-10-21):** applied on Omarchy 4.0.6 / `linux-omarchy 7.2.8-9`, all keys present, values still in force after a reboot | Real hardware |
| PAM / faillock | Container test with real `su` logins driven by `expect`, mutation-tested. **VM:** PAM changes applied and still in place after a reboot | The lock screen (`hyprlock`) lockout and its persistence across a reboot, `sudo` from a Hyprland terminal |
| Firewall | Container test against Omarchy's seeded ufw rules | Real traffic: LocalSend, SSH, Docker DNS after the change |
| Audit | Each check fires on a planted problem in the container. **VM:** the first real install gave 4 WARN, all with benign causes (D-21). After D-22, a default install gives 0 WARN and 0 FAIL | Long-lived installs with more packages |
| Boot | **VM:** EFI + Limine + LUKS boot; after a reboot, a `--check` run reports no change (sysctl load order, PAM, ufw all intact) | Hardware boots, Secure Boot |

The VM run (section 6) has been done; real hardware has not. Treat the first
run on a real machine as a test.

## 2. Before the first run

- **Update first.** The kernel, AppArmor, OpenSnitch and Podman roles install
  packages from Arch's repos. A fresh Omarchy install has no pacman databases
  yet, so run `omarchy-update` once before the first run.
- **Put lasting overrides in a vars file, not only on the command line.**
  The D-11 check reuses the settings of your last run, `-e` overrides
  included, but only until you run without them.

- **Snapshot or back up.** On a VM, take a snapshot. On hardware, at least back
  up `/etc/pam.d/`, `/etc/security/faillock.conf`, `/etc/ufw/` and
  `/etc/sysctl.d/`.
- **Dry run first:**

  ```bash
  ansible-playbook omarchy-harden.yml --check --diff --ask-become-pass
  ```

- **Keep a second root shell open** (another TTY, `sudo -i`) while you apply
  `--tags auth`. If the PAM change breaks login, you can repair it from there.
- **Apply one area at a time** (`--tags sysctl`, then `auth`, then `network`),
  and check that the desktop still works after each.
- **If you use sudoless Docker** (you are in the `docker` group), the audit
  fails the run with `groups.docker`. This is on purpose: membership is
  root-equivalent (D-20). Either leave the group, or accept it explicitly:

  ```bash
  ansible-playbook omarchy-harden.yml --ask-become-pass -e '{"aegis_audit_skip": ["groups.docker"]}'
  ```

  The same applies to `libvirt` and `disk`. `input` only warns.
- **Package drift fails the run** (D-21). If you changed a package file
  yourself, the audit names it. Either restore it (`pacman -S <package>`) or
  accept it in `aegis_integrity_drift_expected` with its exact reasons.
- **On an Intel T2 Mac**, Omarchy adds `[arch-mact2]` with `SigLevel = Never`,
  and the audit fails. Add `arch-mact2` to `aegis_pacman_siglevel_exceptions`
  only if you accept unsigned packages from that repository.

## 3. Behaviour that changes for you

| What you will notice | Why | How to get the old behaviour |
|---|---|---|
| 10 wrong passwords in 15 min lock you out for 15 min (Omarchy: 2 min) | `unlock_time=900` | `aegis_faillock_unlock_time: 120` |
| The lockout survives a reboot | tally in `/var/lib/faillock` (G1) | `aegis_faillock_dir: /var/run/faillock` |
| **Root locks too**, after the same 10 failures | `even_deny_root` (D-19) | `aegis_faillock_even_deny_root: false` |
| `su` refuses users outside `wheel`, and its failures count toward the lockout | `pam_wheel` + `include system-auth` (G2) | `aegis_faillock_su_wheel_only: false`; empty `aegis_faillock_su_files` |
| LocalSend no longer receives files | ufw rule for 53317 removed | `aegis_firewall_remove_localsend: false` |
| SSH from the LAN stops, even if you enabled it with `omarchy-setup-security-sshd` | ufw rule for 22/tcp removed; SSH is meant for the overlay network | `aegis_firewall_remove_ssh: false` |
| Alt+SysRq keys do nothing except sync (S) | `kernel.sysrq=16` (D-15) | `aegis_sysctl_sysrq: null` |
| `dmesg` needs sudo; `perf` without root sees only user space; `strace`/`gdb` can attach only to their own children | `dmesg_restrict`, `perf_event_paranoid=3`, `ptrace_scope=1` | Edit `aegis_sysctl_settings` |
| setuid programs never leave core dumps | `fs.suid_dumpable=0` | Edit `aegis_sysctl_settings` |
| The kernel panics (and reboots, if `kernel.panic` is set) after 100 oopses since boot | `kernel.oops_limit=100` (D-17) | `aegis_sysctl_oops_limit: null` |
| An ASan/TSan build may crash at startup (**unverified**) | `vm.mmap_rnd_bits=32` (D-16) | `aegis_sysctl_mmap_rnd_max: false` first, before anything else |
| After every package install or update, a check runs in the background and may notify "Aegis: hardening drift" | D-11 pacman hook (`/etc/pacman.d/hooks/zz-aegis-drift-check.hook`) | `aegis_drift_check_enabled: false` |
| A second kernel, `linux-hardened`, appears in the Limine menu (not the default) | D-02 | `aegis_kernel_hardened_install: false` (then `pacman -R linux-hardened`) |
| After the next reboot AppArmor is active; profiles only log (`journalctl -k \| grep apparmor`) | D-05 `lsm=` drop-in | `aegis_apparmor_enabled: false`, then reboot |
| OpenSnitch runs; its UI starts with your session and asks about new connections (it allows them by default) | D-09 | `aegis_opensnitch_enabled: false` |
| With ≥2 FIDO2 keys enrolled per wheel user, sudo asks for the key **and** your password | D-04 | `aegis_fido2_sudo_second_factor: false` |
| `aegis-agent` is available for running agents in a container | D-07 | `aegis_agent_enabled: false` |

### Being locked out

Omarchy gives root the same password as your user. A wrong-password burst
therefore usually locks both accounts. Your options:

1. Wait 15 minutes. The lock clears on its own, including across a reboot.
2. From a root shell you already have open: `faillock --user "$USER" --reset`
   (and `--user root` if needed).
3. Boot into the rescue shell. `sulogin` reads the root password itself and
   does not go through PAM, so faillock cannot block it.

## 4. What cannot be undone without a reboot

**The new kernel command line (D-05) only takes effect at the next boot.** The
`lsm=` drop-in is in `/etc/limine-entry-tool.d/aegis-lsm.conf`. If a boot
fails, choose another kernel or a snapshot in the Limine menu, delete that
file, and run `sudo limine-mkinitcpio`.

Removing `/etc/sysctl.d/99-zz-aegis-hardened.conf` reverts most settings at the
next boot, or immediately with `sysctl --system`. Two settings are one-way on a
running kernel. Only a reboot without the file reverts them:

- `kernel.kexec_load_disabled=1`: no kexec, and therefore no kdump or kexec-based
  fast reboot.
- `kernel.unprivileged_bpf_disabled=1`: cannot be set back to 0 or 2.

**Undoing the PAM changes:** every edit is made with `backup: true`. Ansible
keeps the previous file next to the original as `<file>.<pid>.<date>@<time>~`,
for example `/etc/pam.d/system-auth.12345.2026-10-21@14:02:11~`. Copy it back
from a root shell.

**Undoing the firewall changes:** `sudo ufw allow 53317` (LocalSend) and
`sudo ufw limit 22/tcp` (SSH), or re-run Omarchy's setup scripts.

## 5. After a run, and on an ongoing basis

- **Read the findings.** The summary is printed at the end, and the full list
  is in `/var/lib/aegis/audit.jsonl`. That file is mode 0600, so read it with
  `sudo`. It lists the file paths the scan found.
- **Package drift (D-21) fails the run.** The causes found on a default
  Omarchy install are accepted as INFO (`integrity.package_drift_accepted`,
  D-22). This covers changes listed in `aegis_integrity_drift_expected`, and
  permission changes that only remove bits. Anything else in
  `integrity.package_drift_*` deserves a look. If you accept it, add it to the
  list with its exact `-Qkk` reasons and a `why`.
- **`pacman.upgrade_age` warns** when the last `pacman -Syu` is more than 7 days
  old (`aegis_pacman_max_upgrade_age_days`). Before the first `-Syu`, the age
  counts from the install, which is the first `pacman.log` entry.
- **Re-run after every `omarchy-update`.** Omarchy's update scripts rewrite
  PAM files (D-11), and nothing warns you when that happens yet. A re-run puts
  the settings back and verifies them. `--check --diff` shows what the update
  reverted.
- **Home directories are not scanned** for setuid or world-writable files. Set
  `aegis_integrity_scan_home: true` for a one-off sweep. It can take minutes.

## 6. Testing in a VM (VirtualBox)

A VM covers what the container cannot: a real boot, `linux-omarchy`, the
Hyprland login and lock screen, real netfilter, and a lockout that survives a
reboot. The host here is an Intel Mac, so an x86_64 Omarchy guest runs under
VirtualBox. VirtualBox on Apple Silicon cannot run x86_64 guests.

Omarchy's own manual (`manual/49-omarchy-on.md` at `dde0d12`) says Omarchy runs
in VirtualBox, but "performance probably won't be great". That page links to a
community guide, [omarchy discussion #176](https://github.com/omacom/omarchy/discussions/176).
In VirtualBox, Omarchy changes only one thing: `install/user/hardware/vm-no-animations.sh`
turns off animations when `systemd-detect-virt --vm` is true.

The test is scripted in [tests/vm/](../tests/vm/README.md). It ran on 2026-10-21
with VirtualBox 7.2.22 and the signed Omarchy 4.0.6 ISO. The settings below
started as community reports in discussion #176 and are now **tested here**:

- 8 GB RAM, 4 vCPU, 40 GB disk
- Graphics controller **VBoxVGA**, 3D acceleration **off**. With VMSVGA,
  Alacritty and Ghostty were reported not to start.
- Paravirtualization **KVM**, nested paging on, PAE/NX on
- **EFI on** works (the original guide's "EFI off" is outdated). The VM boots
  the same way as a real install: Limine and a UKI, with LUKS on by default.
- Measured problems and workarounds are in [tests/vm/README.md](../tests/vm/README.md):
  - letting the window resize the guest garbled the display
  - a live snapshot froze the guest
  - ejecting the ISO before "Reboot Now" hung the installer
  - `ufw limit 22/tcp` drops rapid SSH reconnects
- The Super key works when sent from the host as scancodes.

A VM run passes when the following hold. Steps 1, 2, 5 and 6 are automated by
`tests/vm/run.sh` and passed; steps 3 and 4 are still manual and not yet done.

1. Take a snapshot `pre-aegis`, then apply the playbook.
2. Reboot, then check `sysctl kernel.sysrq vm.mmap_rnd_bits kernel.oops_limit`.
   This proves `linux-omarchy` has the keys and that the boot order puts ours
   last.
3. Enter 10 wrong passwords at the lock screen, then check that the correct one
   is refused, that the lock is still there after a reboot, and that it is gone
   after 15 minutes.
4. Check that `sudo` and `su` count toward the same lockout, and that a
   non-wheel user cannot `su`.
5. Run a second time. It must report `changed=0`, and
   `/var/lib/aegis/audit.jsonl` must have no unexplained WARN.
6. Revert to `pre-aegis`.

The VirtualBox Extension Pack is under the PUEL licence, not an open-source
one, so the test setup does not rely on it. Passing a FIDO2 key through to the
guest (D-04) is untested. Plan to test FIDO2 on hardware.

## 7. For contributors

- `tests/container/sysctl-apply.sh` writes to the host kernel, and some of its
  settings cannot be undone until reboot. It refuses to run without
  `AEGIS_ALLOW_HOST_SYSCTL=1`. Only CI sets that, on a throwaway runner. Never
  set it on your workstation or on the podman machine.
- Before the repo goes public, settle the licence question in
  [open-decisions.md](open-decisions.md) (ansible-core and community.general
  are GPL-3.0).
- New checks need a planted-problem test (see `AGENTS.md`).
