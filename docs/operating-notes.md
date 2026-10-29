# Operating notes: before, during and after a run

What changes on the machine when you apply the playbook, what you cannot easily
undo, and what has not been tested yet. The settings are in each role's
`defaults/main.yml`. The decisions behind them are in
[open-decisions.md](open-decisions.md).

Last reviewed: 2026-10-23, after a full VM run of every role, step 4 included.
Everything still open is listed in [open-items.md](open-items.md).

## 1. What has and has not been verified

| Area | Verified how | Not verified |
|---|---|---|
| sysctl values | Applied to a live kernel in CI (`sysctl-apply` job, Ubuntu runner kernel), re-read, re-applied after drift. **VM (2026-10-21):** applied on Omarchy 4.0.6 / `linux-omarchy 7.2.8-9`, all keys present, values still in force after a reboot | Real hardware |
| PAM / faillock | Container test with real `su` logins driven by `expect`, mutation-tested. **VM:** PAM changes applied and still in place after a reboot; the lock screen locks out after 10 failures (it recorded none before the tally directory became 0755); **(2026-10-23)** `sudo` and `su` fill one tally and both refuse the right password at 10, and `su` refuses a non-wheel user | Persistence of a lockout across a reboot with autologin (Omarchy's autologin clears it), `sudo` from a Hyprland terminal |
| Firewall | Container test against Omarchy's seeded ufw rules | Real traffic: LocalSend, SSH, Docker DNS after the change |
| Audit | Each check fires on a planted problem in the container. **VM:** the first real install gave 4 WARN, all with benign causes (D-21). After D-22 and the SnowflakeOS checks (18k–18o), a default 4.0.6 install gives 0 FAIL and 2 WARN, both correct: `accounts.password_hash` and `git.commit_signing` ([open-items.md](open-items.md) §3) | Long-lived installs with more packages |
| Boot | **VM:** EFI + Limine + LUKS boot; after a reboot, a `--check` run reports no change (sysctl load order, PAM, ufw all intact) | Hardware boots, Secure Boot |
| Decided roles (D-01 to D-11) | **VM (2026-10-22):** after a reboot, AppArmor is active with 83 profiles, all in complain mode; Limine lists `linux-omarchy` first, then `linux-hardened`; `opensnitchd` runs; `aegis-agent` has no capabilities and cannot create user namespaces; a real `pacman -S` triggers the D-11 check, which reports drift without repairing it. Flatpak, commit signing and Tailscale ran in the VM only in their not-set-up state (INFO, or WARN for signing); their planted-problem paths are tested in the container only. **FIDO2 (2026-10-26):** one YubiKey enrolled with `omarchy-setup-security-fido2`; the playbook keeps `pam_u2f` `sufficient` and WARNs (fewer than 2 keys); with the key plugged in, a run as root took one touch, `failed=0`. **`linux-hardened` (2026-10-27):** booted twice; the playbook applies and checks clean (D-29); AppArmor and user namespaces work; `aegis-agent` does not, and the audit says so (D-30). **polkit (2026-10-27):** `pkexec` failures reach the tally, and `pkexec` in a desktop terminal works; without the D-27 drop-in it refuses the right password | FIDO2 and signing keys, a tailnet login ([open-items.md](open-items.md) §1) |

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

- **With a FIDO2 key for sudo** (`omarchy-setup-security-fido2`) plugged in,
  run every command here as root, without `--ask-become-pass`:
  `sudo ansible-playbook omarchy-harden.yml --check --diff`. One touch covers
  the run. As your user, each task's sudo would wait for a touch Ansible
  cannot ask for (measured in the VM: "Timeout (12s) waiting for privilege
  escalation prompt"), so the playbook stops first and says so.
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
| The lockout survives a reboot, unless autologin is on (Omarchy's autologin runs `pam_faillock authsucc`, which clears it; accepted, D-23) | tally in `/var/lib/faillock` (G1) | `aegis_faillock_dir: /var/run/faillock` |
| **Root locks too**, after the same 10 failures | `even_deny_root` (D-19) | `aegis_faillock_even_deny_root: false` |
| `su` refuses users outside `wheel`, and its failures count toward the lockout | `pam_wheel` + `include system-auth` (G2) | `aegis_faillock_su_wheel_only: false`; empty `aegis_faillock_su_files` |
| LocalSend no longer receives files | ufw rule for 53317 removed | `aegis_firewall_remove_localsend: false` |
| SSH from the LAN stops, even if you enabled it with `omarchy-setup-security-sshd` | ufw rule for 22/tcp removed; SSH is meant for the overlay network | `aegis_firewall_remove_ssh: false` |
| With Tailscale running, the audit WARNs (`network.overlay`) that every device on your tailnet can reach every listening port. That was already true: Tailscale accepts `tailscale0` traffic before ufw sees it, whatever this playbook sets | D-24. Your tailnet's access policy and the login at your identity provider decide who those devices are, so use a passkey or security key there | Nothing to revert: the WARN only reports it |
| If sshd is installed, the audit WARNs while it accepts passwords (`ssh.password_auth`) and lists authorized keys that are not on a hardware key (`ssh.authorized_keys`, INFO) | D-24 | Authorize a key with `omarchy-setup-security-sshd`; use `ssh-keygen -t ed25519-sk` for a hardware key |
| Alt+SysRq keys do nothing except sync (S) | `kernel.sysrq=16` (D-15) | `aegis_sysctl_sysrq: null` |
| `dmesg` needs sudo; `perf` without root sees only user space; `strace`/`gdb` can attach only to their own children | `dmesg_restrict`, `perf_event_paranoid=3`, `ptrace_scope=1` | Edit `aegis_sysctl_settings` |
| setuid programs never leave core dumps | `fs.suid_dumpable=0` | Edit `aegis_sysctl_settings` |
| The kernel panics (and reboots, if `kernel.panic` is set) after 100 oopses since boot | `kernel.oops_limit=100` (D-17) | `aegis_sysctl_oops_limit: null` |
| An ASan/TSan build from an older toolchain may crash at startup (gcc 16 and clang 23 builds ran fine in the VM, D-16) | `vm.mmap_rnd_bits=32` (D-16) | `aegis_sysctl_mmap_rnd_max: false` first, before anything else |
| After every package install or update, a check runs in the background and may notify "Aegis: hardening drift" | D-11 pacman hook (`/etc/pacman.d/hooks/zz-aegis-drift-check.hook`) | `aegis_drift_check_enabled: false` |
| A second kernel, `linux-hardened`, appears in the Limine menu (not the default) | D-02 | `aegis_kernel_hardened_install: false` (then `pacman -R linux-hardened`) |
| Booted on `linux-hardened`, the audit lists two sysctl keys that kernel is built without (INFO `sysctl.compiled_out`) and WARNs that `aegis-agent` cannot start a container there (`agent.kernel_overlay`: no unprivileged overlayfs) | D-29, D-30 | Boot `linux-omarchy` to use `aegis-agent`; the key list is `aegis_sysctl_absent_ok` |
| polkit's sandboxed PAM helper gets write access to the faillock tally (drop-in `/etc/systemd/system/polkit-agent-helper@.service.d/aegis-faillock.conf`), so `pkexec` works and its wrong passwords count toward the lockout | D-27 | Remove the drop-in, then `systemctl daemon-reload`; `pkexec` then refuses every password while the tally is in `/var/lib/faillock` |
| The audit WARNs (`auth.polkit_faillock`) when `/etc/pam.d/polkit-1` checks passwords without faillock, which is what `omarchy-setup-security-fido2` writes; the playbook does not change that file | D-28 | Replace its `auth required pam_unix.so` line with `auth include system-auth` |
| ufw's own `/etc/ufw/sysctl.conf` gets `rp_filter=2`, as the sysctl role sets it, so a boot no longer ends in strict mode when ufw starts after `systemd-sysctl` | D-31 | `aegis_firewall_ufw_rp_filter: null` leaves ufw's file alone |
| The drift check also reports a live sysctl value that something else changed since the last run, naming the key, its live value and the wanted one; a playbook run re-applies it | D-32 | `sudo sysctl --system`, or re-run the playbook |
| The drift check reads ufw's configuration files (default policies, enabled at boot, the rules this playbook removes or adds), not the live netfilter rules, because ufw cannot run in its sandbox. It does not check commit signing or read agent egress: a system service cannot act as your user, so it lists both as INFO "not checked by the drift check". If the check itself breaks part-way, it notifies "Aegis: drift check broken" (not "hardening drift") and names the failed task in the journal | D-33 | Run `omarchy-harden.yml --check` yourself to check those two, or to see why the check broke |
| After the next reboot AppArmor is active; profiles only log (`journalctl -k \| grep apparmor`) | D-05 `lsm=` drop-in | `aegis_apparmor_enabled: false`, then reboot |
| OpenSnitch runs; its UI starts with your session and asks about new connections. A prompt you do not answer within 30 s allows the connection until restart (the UI on its own would deny). The UI may show no tray icon: version 1.7.2 crashed without one, so its tray warning is switched off | D-09 | `aegis_opensnitch_enabled: false` |
| A small service, `aegis-egress-collector`, records which program connected to which host (no command lines) in `/var/lib/private/aegis-egress/egress.json` for 30 days, and the audit WARNs (`egress.unknown_programs`) on programs no package owns, such as a binary in `~/.local/bin` | D-25 | Trust one: add it to `aegis_egress_known` (shell globs). Turn it off: `aegis_egress_report_enabled: false` |
| With ≥2 FIDO2 keys enrolled per wheel user, sudo asks for the key **and** your password | D-04 | `aegis_fido2_sudo_second_factor: false` |
| With a FIDO2 key set up for sudo and plugged in, the playbook stops before its first sudo unless it runs as root (`sudo ansible-playbook …`, one touch) | D-04 | Unplug the key and use `--ask-become-pass` |
| `aegis-agent` is available for running agents in a container | D-07 | `aegis_agent_enabled: false` |
| Agents run by `aegis-agent` get `HTTPS_PROXY` set to a local Smokescreen proxy, which logs hosts outside `aegis_agent_egress_allowlist`; the audit lists them (`agent.egress`). `--egress enforce` allows only the list; the proxy refuses LAN and metadata addresses in both modes (407; tested in the container) | D-26 | `--egress off` per run, or `aegis_agent_egress: off` |

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
  PAM files. The D-11 pacman hook warns when that happens (journal and a
  desktop notification), but never repairs anything. A re-run puts the
  settings back and verifies them. `--check --diff` shows what the update
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
`tests/vm/run.sh` and passed. Step 3 is automated too and passed
(2026-10-22): the lock screen refuses the right password after 10 failures
until a root reset. Its reboot and 15-minute parts are not automated, and
with autologin on, a reboot clears the lockout (see section 3). Step 4 is scripted in `tests/vm/run.sh` and passed on its own;
a full run through it is still open (docs/open-items.md).

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
one, so the test setup does not rely on it. It is not needed for USB either:
in 7.2.22 the EHCI and xHCI controllers are part of the base package (user
manual §3). A FIDO2 key passed through with `usbattach` works in the guest
(enrolment and sudo by touch, 2026-10-26; `tests/vm/README.md` §5c).

## 7. For contributors

- `tests/container/sysctl-apply.sh` writes to the host kernel, and some of its
  settings cannot be undone until reboot. It refuses to run without
  `AEGIS_ALLOW_HOST_SYSCTL=1`. Only CI sets that, on a throwaway runner. Never
  set it on your workstation or on the podman machine.
- The custom modules import only `ansible.module_utils.basic` (Simplified
  BSD), which is what keeps them Apache-2.0 (D-12). Importing a GPL-3.0
  `module_utils` (most of community.general's) or vendoring GPL code reopens
  D-12.
- New checks need a planted-problem test (see `AGENTS.md`).
