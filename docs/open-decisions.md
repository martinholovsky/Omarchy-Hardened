# Open decisions

Security choices the PRD leaves open, or where two of its goals conflict. A
stub role stays a stub until its decision is recorded here as **Decided**, with
the reasoning. Each entry gives a recommendation, but the decision is the
owner's to make.

Status: **Open** · **Decided** · **Deferred**

---

## D-01 — Unprivileged user namespaces vs Flatpak/browser sandboxes (Open)

PRD 3.1 says "disable unprivileged user namespaces where possible". PRD 3.3
moves apps to Flatpak/bubblewrap, and Chromium/Electron, Steam and Claude
Code's bubblewrap sandbox all create user namespaces too.

Verified 2026-10-20:

- The global switches break all of the above: `user.max_user_namespaces=0`
  (any kernel) and `kernel.unprivileged_userns_clone=0` (`linux-hardened`).
- `bubblewrap-suid` is in neither the Arch repos nor the AUR (archlinux.org
  package search and AUR RPC both return 0 results), so Fedora's "setuid bwrap"
  fallback is not available.
- Ubuntu's `apparmor_restrict_unprivileged_userns` is **not** in mainline
  (`security/apparmor/lsm.c` on torvalds/master, 72 KB, 0 matches). Mainline
  AppArmor only mediates `userns` for processes that already run under a
  profile.
- secureblue (commit `5be4f13`) also leaves userns on in the kernel. It uses an
  SELinux policy (`harden_userns.cil`) that denies `user_namespace create` to
  every domain except an allowlist (bwrap, flatpak, container runtimes, its
  browser, passt, thumbnailers). This needs SELinux type enforcement and does
  not port to Arch/AppArmor as-is.

Options: (a) keep userns on; deny `userns` in AppArmor profiles for the
high-risk processes we confine (AI agents, untrusted-input parsers), and add
systemd `RestrictNamespaces=` / seccomp to agent units; (b) `linux-hardened` +
`unprivileged_userns_clone=0` and accept a broken Flatpak/browser sandbox; (c)
leave it alone.
**Recommendation:** (a). (b) contradicts PRD 3.3. `sysctl` refuses
`aegis_sysctl_disable_unprivileged_userns=true` until this is decided.

## D-02 — Kernel: replace `linux-omarchy` or install alongside it (Open)

Omarchy ships its own `linux-omarchy`, not Arch `linux`. `linux-hardened` lags
mainline and has no Omarchy-specific patches. Out-of-tree modules (NVIDIA, T2)
need `-headers` and DKMS. **Recommendation:** install `linux-hardened`
*alongside* `linux-omarchy`, add a Limine entry, make it the default only
after one clean boot, and keep `linux-omarchy` as the fallback entry.

## D-03 — hardened_malloc scope (Open)

Preloading it system-wide (`/etc/ld.so.preload`) breaks or slows some apps
(Electron, JIT runtimes, some games). **Recommendation:** an opt-in per-app
allowlist through wrapper or `LD_PRELOAD` drop-ins, not a global preload.

## D-04 — FIDO2 for LUKS and sudo: recovery path (Open)

Requiring a hardware key at boot and for sudo locks you out when the key is
lost. Before this role does anything it needs: at least two enrolled keys, a
LUKS recovery passphrase or key kept offline, and a decision on whether the
TTY/root console keeps a password fallback. **Recommendation:** two keys
required at enrolment, recovery passphrase kept, `pam_u2f` as `required` for
`sudo` only (not login) in phase 1.

## D-05 — AppArmor enforce vs complain (Open)

**Recommendation:** ship profiles in complain mode first, collect denials for a
week, then switch to enforce one profile at a time.

## D-06 — Which apps move to Flatpak (Open)

Omarchy installs browsers and chat clients as native packages, and some
Omarchy integrations call them by path. Decide the list.

## D-07 — AI agent containment boundary (Open)

Choose between Distrobox (convenient, but by default shares `$HOME` and is a
weak boundary), a rootless Podman container with no home mount, or a microVM.
**Recommendation:** rootless Podman, project directory bind-mounted only,
egress through OpenSnitch rules.

## D-08 — Commit signing key type (Open)

SSH signing key on a FIDO2 token (`ed25519-sk`) or GPG. **Recommendation:**
`ed25519-sk`, which works with the same keys as D-04.

## D-09 — OpenSnitch default action (Open)

Default-deny makes every new connection prompt, which gets noisy. Decide
deny vs ask, and the rule set to pre-seed (pacman mirrors, Omarchy update
host, Tailscale).

## D-10 — Overlay network: Tailscale or plain WireGuard (Open)

Tailscale adds a coordination server you have to trust; WireGuard needs manual
key distribution.

## D-11 — Drift after `omarchy-update` (Open)

Omarchy's update scripts rewrite PAM files (see
[upstream-baseline.md](upstream-baseline.md)). Options: document "re-run after
update" (current), a pacman `PostTransaction` hook that runs the playbook in
check mode and warns, or a hook that re-applies. **Recommendation:** a
check-mode hook that warns. Re-applying automatically from a pacman hook is too
much hidden behaviour.

## D-12 — Licence (Decided: Apache-2.0)

The repo is private for now, but the PRD says it will be open source. Apache-2.0
was chosen to match the permissive-only policy. Note that the runtime toolchain
(ansible-core, community.general) is GPL-3.0. The playbook only invokes it and
does not link to it, but this needs a proper look before the repo goes public.

## D-13 — faillock lockout count (Decided: deny=10, unlock_time=900)

The PRD (3.2) asked for `deny=3`. The owner decided on 10 failed attempts,
the same as Omarchy's default, and kept the PRD's 15-minute unlock (Omarchy
uses 120 s). faillock counts per user across every PAM service that includes
`system-auth`: SSH (via `system-remote-login`), console login, sudo, and the
lock screen's own stack. So the count is the same everywhere and cannot be set
for SSH alone. The include chain was checked in the Arch test image:
`sshd` → `system-remote-login` → `system-login` → `system-auth`, and
`sudo` → `system-auth`.

Caveat: Omarchy's opt-in sshd sets `PasswordAuthentication no` and
`KbdInteractiveAuthentication no`. Public-key authentication does not run
PAM's `auth` stack, so faillock never counts failed SSH attempts on that setup.
This follows from sshd's design and has not been tested here. SSH brute-force
protection therefore comes from key-only auth, `MaxAuthTries` and
`PerSourcePenalties` (proposed `sshd` role), and from keeping port 22 off the
LAN entirely (the `firewall` role removes `ufw limit 22/tcp`; `overlay_network`
is planned).

## D-14 — faillock tally persistence and `su` (Decided 2026-10-21)

- Tally directory: **persistent**, `/var/lib/faillock`. This closes the
  reboot-reset bypass. The cost is that a lockout survives a reboot too.
- `su`: **wheel-only + faillock**. `su`/`su-l` authenticate through
  `system-auth`, and `pam_wheel use_uid` is enabled. Open follow-up: whether
  to set `even_deny_root` (roadmap #6) so that repeated `su` failures lock root
  as well. That also locks root's console login for `unlock_time`.

## Decisions from roadmap Tier 1 (opened 2026-10-21)

All seven were decided by the owner on 2026-10-21, each with the
recommendation, and are now the defaults.

### D-15 — `kernel.sysrq` (Decided: pin 16)

Options: (a) leave 16 (systemd default: only the emergency *sync* key works);
(b) 0 (all SysRq off, as Kicksecure and secureblue do); (c) 4 (keyboard control
incl. SAK).
**Recommendation: (a).** 16 exposes nothing an attacker at the keyboard can
abuse, and sync before a forced power-off can save data. 0 gains almost
nothing on a single-user laptop. Implemented as `aegis_sysctl_sysrq: 16`, so the value is pinned and verified.

### D-16 — ASLR entropy to the maximum (Decided: raise on x86_64)

`vm.mmap_rnd_bits` 28 → 32 and `vm.mmap_rnd_compat_bits` 8 → 16 (Arch config:
min 28/8, max 32/16, verified). Options: (a) raise on x86_64; (b) leave.
**Recommendation: (a)**, with one caveat for a developer machine: after Ubuntu
raised to 32 bits, older ASan/TSan builds crashed. Current toolchains are
believed fixed, but this is unverified here. If a sanitizer crashes, lowering
this is the first thing to try (`aegis_sysctl_mmap_rnd_max: false`).

### D-17 — `oops_limit` / `warn_limit` (Decided: oops_limit=100, warn_limit unset)

The kernel panics after this many oopses or WARNs since boot (defaults:
oops_limit 10000, warn_limit 0 = never). Options: (a) `oops_limit=100`,
`warn_limit` unset; (b) both 100 (secureblue); (c) both 1 (Kicksecure);
(d) leave.
**Recommendation: (a).** A hundred oopses means the kernel is already broken,
so stopping is right. WARNs are routine for NVIDIA and Wi-Fi drivers, though,
and a WARN limit would reboot the desktop after a long uptime. Revisit
`warn_limit` with the late-boot mechanism (roadmap 18i).

### D-18 — faillock `audit` (Decided: off)

`audit` logs the user name of failed attempts against accounts that do not
exist. Options: (a) off; (b) on.
**Recommendation: (a).** On a single-user desktop the "unknown user" case is
almost always the owner typing their **password into the user-name prompt**
(TTY login), which `audit` writes to the journal. That is worse than the
enumeration signal it adds.

### D-19 — lock root too (`even_deny_root`) (Decided: even_deny_root now; locking root's password later)

Omarchy sets **root's password to the user's password** at install
(`install/provisioning/setup-form.sh:161`, `bin/omarchy-provision-owner:811`).
Without `even_deny_root`, root can be guessed without limit on a TTY or
through `su` by a wheel member (root never locks). Options:
(a) `even_deny_root` with `root_unlock_time = 900`; (b) lock the root password
(`passwd -l root`; roadmap #26); (c) leave.
**Recommendation: (a) now, (b) later.** (a) is cheap and reversible.
`sulogin` (rescue shell) does not use PAM, so a faillock lock does not block
rescue. (b) is stronger, because a stolen user password then no longer works
at a root prompt. It needs the rescue-shell question settled first, together
with the Limine editor lock (roadmap 18c).
Verified in the test image: after 10 failed `su` attempts the right root
password is refused, and `faillock --user root --reset` restores access. A
mutant with the option off fails that check.

### D-20 — severity of dangerous group membership (Decided: FAIL docker/libvirt/disk, WARN input)

`docker`, `libvirt` and `disk` members are root without a password (any
process running as the user, including an AI agent, can get a root shell).
`input` members can read every keystroke, bypassing Wayland isolation. Omarchy
adds `docker` only through its opt-in `omarchy-setup-security-sudoless-docker`,
and `input` through gaming and ydotool helpers. Options: (a) FAIL for
docker/libvirt/disk, WARN for input; (b) WARN for all; (c) off.
**Recommendation: (a).** Choosing root-equivalent access should be an explicit,
recorded act: add `groups.docker` to `aegis_audit_skip`.

### D-21 — severity of package-file drift (Decided: WARN until a clean real-install run, then FAIL)

`pacman -Qkk` reports package files whose mode, owner or content changed. In
the test image it also reports noise: pseudo-filesystem mount points (now
ignored) and a few group-id mismatches (`/usr/bin/wall`, `/usr/bin/write`,
`/var/games`) that may be specific to the container. Options: (a) WARN until
the output has been checked on a real Omarchy install, then FAIL;
(b) FAIL now.
**Recommendation: (a).** A FAIL that fires on a clean install trains you to
skip the audit. Set `aegis_integrity_drift_severity: FAIL` once the first real
run is clean.

**First real-install run (2026-10-21, VM, Omarchy 4.0.6).** Not clean yet. Every
reported file has a verified, benign cause:

| File | `-Qkk` reasons | Cause |
|---|---|---|
| `/etc/cups/classes.conf`, `/etc/cups/printers.conf` | Permissions (0600; package 0640) | cupsd rewrites them more strictly |
| `/boot` | Permissions (0700; `filesystem` ships 0755) | stricter than the package |
| `/usr/lib/utempter/utempter` | GID, Permissions (2755 root:utmp) | `/usr/lib/tmpfiles.d/libutempter.conf`: `z /usr/lib/utempter/utempter 2755 root utmp` |
| `/var/log/journal` | GID (setgid, `systemd-journal`) | systemd tmpfiles |
| `/usr/bin/powerprofilesctl` | Size, SHA256, mtime | Omarchy's `install/config/fix-powerprofilesctl-shebang.sh:3` rewrites the shebang. Lines 2 onward have the same SHA-256 as `power-profiles-daemon-0.30-1` from archive.archlinux.org; only line 1 differs |

Switching to FAIL now would fail every default install. How to accept these
cases is D-22.

### D-22 — accepting known package drift (Decided 2026-10-21: (b))

D-21 can only move to FAIL once a default install produces no drift findings.
The causes above are benign, but some way of accepting them is needed.

- **(a) Exact expected-drift list.** A variable lists path, the exact `-Qkk`
  reasons allowed and why. A match is reported as INFO. Any extra reason (for
  example new content on top of a known permission change) still counts.
  **Residual risk:** once accepted, a later tampering of
  `/usr/bin/powerprofilesctl` is hidden among the INFO findings. Changing a
  root-owned file in `/usr/bin` already needs root, so this hides
  post-compromise tampering of one non-setuid script.
- **(b) (a), plus automatic INFO for permission drift that only tightens.**
  The expected mode, uid and gid come from pacman's `mtree`. This would cover
  cups and `/boot` without listing them. It means more code, and it needs its
  own tests.
- **(c) Keep WARN for good.** No new mechanism, but drift never fails the run.

The recommendation was (a). **The owner chose (b).** It is implemented as:

- `aegis_integrity_drift_expected`: utempter, `/var/log/journal` and
  `powerprofilesctl`, with their exact reason sets.
- `aegis_integrity_drift_tightened_is_accepted: true`: this covers cups and
  `/boot`. Owner and group must match the package's `mtree`, and no mode bit
  may be added.

Accepted files are listed in the INFO finding
`integrity.package_drift_accepted`, so they stay visible.
D-21 moves to FAIL once a default VM install shows no unaccepted drift.
