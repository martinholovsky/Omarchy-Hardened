# Open decisions

Security choices the PRD leaves open, or where two of its goals conflict. A
stub role stays a stub until its decision is recorded here as **Decided**, with
the reasoning. Each entry gives a recommendation, but the decision is the
owner's to make.

Status: **Open** · **Decided** · **Deferred**

---

## D-01 — Unprivileged user namespaces vs Flatpak/browser sandboxes (Decided 2026-10-21: (a))

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

**Decided (owner, 2026-10-21): (a).** Unprivileged user namespaces stay on
globally. They are denied only for the processes we confine: the agent wrapper
(D-07, rootless Podman with no new user namespaces inside) and AppArmor
profiles that deny `userns` (D-05). `aegis_sysctl_disable_unprivileged_userns`
keeps refusing `true`.

**Found in the VM test:** Podman's default seccomp profile (containers-common
0.69.2) allows `clone`, `clone3` and `unshare` unconditionally. An agent could
create user namespaces inside the container even with every capability
dropped. The `agent_containment` role therefore derives
`/etc/aegis/agent-seccomp.json` from it: `unshare`/`clone` with
`CLONE_NEWUSER` get EPERM, and `clone3` gets ENOSYS (libc falls back to
`clone`), as in Docker's default profile. The result was measured: `unshare
-U` is refused, and fork and project writes still work. AppArmor `userns`
rules are not used yet, because profiles run in complain mode (D-05).

## D-02 — Kernel: replace `linux-omarchy` or install alongside it (Decided 2026-10-21: alongside, opt-in default)

Omarchy ships its own `linux-omarchy`, not Arch `linux`. `linux-hardened` lags
mainline and has no Omarchy-specific patches. Out-of-tree modules (NVIDIA, T2)
need `-headers` and DKMS. **Recommendation:** install `linux-hardened`
*alongside* `linux-omarchy`, add a Limine entry, make it the default only
after one clean boot, and keep `linux-omarchy` as the fallback entry.

**Decided (owner, 2026-10-21):** install `linux-hardened` alongside, with its
own Limine entry. `linux-omarchy` stays the default. The role never changes
the default boot entry; switching is the owner's manual step after a clean
boot.

**Follow-up (owner, 2026-10-23): the role accepts either default.** Until then
the role asserted that `linux-omarchy` was the first Limine entry, so the
switch this decision leaves to the owner made every later apply run fail.
Omarchy's development branch now has `omarchy-kernel set linux-hardened` for
that switch. Options were: (a) accept any default and report it; (b) a
variable naming the expected default; (c) drop the order check. Chosen: (a).
The role never sets the default, so it should not police it, and (b) fails the
same way whenever the variable is not updated after a switch. The role still
fails when the `linux-hardened` entry is missing, and the `kernel.hardened`
finding names the default boot entry.

## D-03 — hardened_malloc scope (Deferred 2026-10-21)

Preloading it system-wide (`/etc/ld.so.preload`) breaks or slows some apps
(Electron, JIT runtimes, some games). **Recommendation:** an opt-in per-app
allowlist through wrapper or `LD_PRELOAD` drop-ins, not a global preload.

**Deferred (owner, 2026-10-21).** It is only available from the AUR, where it
was flagged out of date on 2026-02-23. Building it from a root playbook is a
supply-chain risk that outweighs the gain. Revisit if it reaches the official
repos. The role stays a stub. Checked 2026-10-29: still AUR only (`14-1`);
the AUR entry was last modified 2026-10-26 and is no longer flagged out of
date, which does not change the reason above.

## D-04 — FIDO2 for LUKS and sudo: recovery path (Decided 2026-10-21: audit + second factor for sudo)

Requiring a hardware key at boot and for sudo locks you out when the key is
lost. Before this role does anything it needs: at least two enrolled keys, a
LUKS recovery passphrase or key kept offline, and a decision on whether the
TTY/root console keeps a password fallback. **Recommendation:** two keys
required at enrolment, recovery passphrase kept, `pam_u2f` as `required` for
`sudo` only (not login) in phase 1.

**Decided (owner, 2026-10-21).** Omarchy's `omarchy-setup-security-fido2`
adds `auth sufficient pam_u2f.so` to sudo and polkit (verified at `dde0d12`),
so there the key *replaces* the password. The role always reports FIDO2
status. Once `/etc/fido2/fido2` holds at least two keys, it makes `pam_u2f`
`required` for sudo: key **and** password. Login, the TTY and polkit keep
their current behaviour, and LUKS is not touched. With fewer than two keys it
changes nothing.

## D-05 — AppArmor enforce vs complain (Decided 2026-10-21: enable, complain first)

**Recommendation:** ship profiles in complain mode first, collect denials for a
week, then switch to enforce one profile at a time.

**Decided (owner, 2026-10-21).** Enable AppArmor by adding it to `lsm=`
through a separate Limine cmdline drop-in. Profiles load in complain mode.
Enforcing is a later per-profile variable.

**Found in the VM test (apparmor 4.1.8):** 78 of 145 shipped profiles are
declared `flags=(unconfined)`, `podman` among them. They confine nothing; they
exist to permit things such as user namespaces. Forcing them into complain
mode turned them into real confinement and broke rootless Podman ("failed to
reexec: Permission denied"). Removing just the `podman` profile fixed it, so
they are left as shipped. After a reboot, AppArmor is active and 83 profiles
are in complain mode, none in enforce mode (final VM run, 2026-10-22).

## D-06 — Which apps move to Flatpak (Decided 2026-10-21: no moves; verified remote + audit)

Omarchy installs browsers and chat clients as native packages, and some
Omarchy integrations call them by path. Decide the list.

**Decided (owner, 2026-10-21).** No native app is moved or removed. If
Flatpak is present, Flathub is restricted to `--subset=verified`, and the
permissions of installed Flatpaks are audited (host or home filesystem,
`devices=all`, session-bus access).

## D-07 — AI agent containment boundary (Decided 2026-10-21: rootless Podman)

Choose between Distrobox (convenient, but by default shares `$HOME` and is a
weak boundary), a rootless Podman container with no home mount, or a microVM.
**Recommendation:** rootless Podman, project directory bind-mounted only,
egress through OpenSnitch rules.

**Decided (owner, 2026-10-21).** A wrapper runs an agent in a rootless Podman
container. Only the project directory is bind-mounted. There is no `$HOME`,
all capabilities are dropped, and new privileges are disabled. Egress control
comes from D-09. It is opt-in per invocation and changes nothing else.

## D-08 — Commit signing key type (Decided 2026-10-21: SSH, ed25519-sk)

SSH signing key on a FIDO2 token (`ed25519-sk`) or GPG. **Recommendation:**
`ed25519-sk`, which works with the same keys as D-04.

**Decided (owner, 2026-10-21).** git `gpg.format=ssh`, for a key the owner
names (recommended: `ed25519-sk` on the D-04 tokens), plus an
`allowed_signers` file. The role never generates keys.

## D-09 — OpenSnitch default action (Decided 2026-10-21: install, allow by default, pre-seeded rules)

Default-deny makes every new connection prompt, which gets noisy. Decide
deny vs ask, and the rule set to pre-seed (pacman mirrors, Omarchy update
host, Tailscale).

**Decided (owner, 2026-10-21).** Install and enable OpenSnitch with the
default action `allow`: visibility first. Rules are pre-seeded for pacman
mirrors, Omarchy hosts and Tailscale. Moving to `deny` is a variable.

**Follow-up (2026-10-24): "allow" did not hold while the UI ran.** The
daemon asks `opensnitch-ui` about each new connection, and an unanswered
prompt applies the UI's own default, which v1.7.2 initialises to deny
"until restart" (`ui/opensnitch/config.py`). In the VM that cut all egress
after a reboot (curl to 1.1.1.1 timed out with the daemon running and worked
with it stopped). The role now writes the UI's `[global] default_action` to
match `aegis_opensnitch_default_action` and reads it back. Asked whether to
replace "allow" with a curated default-deny desktop ruleset, the owner chose
to keep allow and add two things instead: a report of unknown programs that
connect out, and an egress allowlist for agent containers (D-25, D-26).
Reasoning: browsers, chat clients and package tools need nearly any
destination, and interpreters (`python`, `node`, `curl`, `git`) serve both
legitimate tools and malware, so per-program rules end up broad while every
silent block reads as an outage.

**Follow-up (2026-10-25): the prompt UI crashed at every login.** In 3 of 3
VM boots `opensnitch-ui` 1.7.2 aborted about 16 s after login, with and
without the change above (a controlled OLD/NEW run: one core dump each). Its
"no system tray" warning calls notify2 without checking that notify2
initialised (`ui/opensnitch/service.py`, `_show_systray_msg_error`), and Qt
aborts on the exception. Upstream fixed it in 1.8.0
(`_has_desktop_notifications`); Arch ships 1.7.2. The owner chose a fix in
this role plus raising it upstream; since upstream is already fixed, the
upstream step is the Arch package being out of date, which it has been flagged
since 2025-12-15 (open-items §1). The role
sets `[global] hide_systray_warning=true`, which makes that warning return
early. Why the UI sees no tray although Omarchy's shell registers
`org.kde.StatusNotifierWatcher` is not known.

## D-10 — Overlay network: Tailscale or plain WireGuard (Decided 2026-10-21: Tailscale via Omarchy)

Tailscale adds a coordination server you have to trust; WireGuard needs manual
key distribution.

**Decided (owner, 2026-10-21).** Use Omarchy's
`omarchy-install-service-tailscale`. The role reports whether Tailscale is
up, and on opt-in allows SSH on `tailscale0` only. Logging in stays manual.

## D-11 — Drift after `omarchy-update` (Decided 2026-10-21: check-mode hook that warns)

Omarchy's update scripts rewrite PAM files (see
[upstream-baseline.md](upstream-baseline.md)). Options: document "re-run after
update" (current), a pacman `PostTransaction` hook that runs the playbook in
check mode and warns, or a hook that re-applies. **Recommendation:** a
check-mode hook that warns. Re-applying automatically from a pacman hook is too
much hidden behaviour.

**Decided (owner, 2026-10-21).** A pacman `PostTransaction` hook starts a
unit that runs the playbook in `--check` mode. If anything would change, it
warns through the journal and a desktop notification. It never re-applies
anything by itself.

## D-12 — Licence (Decided: Apache-2.0)

Apache-2.0 was chosen to match the permissive-only policy. The runtime
toolchain (ansible-core, community.general) is GPL-3.0. The playbook only
invokes it and does not link to it.

**GPL check closed 2026-10-27** (the repo went public on 2026-10-26, before
this check was raised; open-items §2 tracked it). Options were: (a) keep
Apache-2.0; (b) relicense the custom modules GPL-3.0; (c) a lawyer's review.
Chosen: (a), as the recommendation, under the owner's standing instruction
to act on recommended options; this is an engineering reading, not legal
advice. Evidence: the 8 custom modules (`roles/*/library/*.py`) import only
`ansible.module_utils.basic`, whose header says Simplified BSD License
(ansible-core 2.21.5); no GPL text is in any tracked file except docs that
discuss it; the GPL tools are installed by the user, never shipped here; the
Omarchy fixtures keep Omarchy's own licence (`tests/fixtures/omarchy/LICENSE.omarchy`).
Revisit if a module imports a GPL `module_utils` (most of community.general's
are GPL-3.0) or if GPL code is vendored.

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
allows SSH on `tailscale0` only, on opt-in, D-10).

## D-14 — faillock tally persistence and `su` (Decided 2026-10-21)

- Tally directory: **persistent**, `/var/lib/faillock`. This closes the
  reboot-reset bypass. The cost is that a lockout survives a reboot too.
  Omarchy's SDDM autologin stack (`/etc/pam.d/sddm-autologin`) ends with `pam_faillock.so authsucc`, so with autologin on, the successful autologin after a reboot clears the tally again (config checked on 4.0.6; reboot not tested).
  **Correction 2026-10-22:** the directory was first created 0700. That
  silently stopped Omarchy's lock screen, which runs PAM as the user, from
  recording failures (`pam_faillock` returns success on `EACCES`). It is now
  0755, as `pam_faillock` itself creates it. Measured on the VM: at 0700 there
  were no records after 3 failures; at 0755 there were 3 records. After 10
  failures the right password is refused until a root reset.
- `su`: **wheel-only + faillock**. `su`/`su-l` authenticate through
  `system-auth`, and `pam_wheel use_uid` is enabled. Whether repeated `su`
  failures also lock root was decided in D-19: they do (`even_deny_root`).
  That also locks root's console login for `root_unlock_time`.
- Autologin clearing the tally at boot is accepted: D-23.

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
raised to 32 bits, older ASan/TSan builds crashed. Measured on the VM
(2026-10-22, `vm.mmap_rnd_bits=32`, `mmap_rnd_compat_bits=16`, kernel
7.2.8-9-omarchy): gcc 16 and clang 23.1.3 ASan and TSan binaries ran 5 of 5
times each, and a planted heap overflow and data race were both reported.
Older toolchains were not tried. If a sanitizer crashes, lowering this is the
first thing to try (`aegis_sysctl_mmap_rnd_max: false`).

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

**Extended 2026-10-21 under the same rule.** `empower` is added at FAIL.
systemd 262 ships `/usr/share/polkit-1/rules.d/empower.rules`, which grants
every polkit action to members of `empower`. `run0 --empower` adds a member for
one command only, so a permanent member is root-equivalent like `docker`. The
rule file itself is listed as known in `aegis_audit_polkit_known`.
**Confirmed (owner, 2026-10-22):** `empower` stays at FAIL, for the same
reason as `docker`. A deliberate member is recorded by adding
`groups.empower` to `aegis_audit_skip`.

### D-21 — severity of package-file drift (Decided: FAIL since 2026-10-21)

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

**Done on 2026-10-21.** A VM run from the `pre-aegis` snapshot gave 0
permission drift and 0 content drift, with 6 changes accepted. The default is
now `aegis_integrity_drift_severity: FAIL`. The container test keeps WARN,
because its image has drift a real install does not.

## D-23 — autologin clears the faillock tally at boot (Decided 2026-10-22: accept)

Omarchy's `/etc/pam.d/sddm-autologin` ends with `pam_faillock.so authsucc`
(config read on 4.0.6). With autologin on, the successful autologin after a
reboot resets the tally, so a reboot ends a lockout (D-14). The reboot itself
was not tested.

Options: (a) accept it and record why; (b) remove `authsucc` from
`sddm-autologin`, one more Omarchy file the role patches and that
`omarchy-update` can rewrite, and a lockout that then survives a reboot for
the owner too; (c) audit only, an INFO finding while autologin is on.

**Decided (owner, 2026-10-22): (a), as recommended.** Reasoning:

- Omarchy sets up autologin only on an encrypted disk, and
  `login.autologin_unencrypted` (roadmap 18n) WARNs if that ever changes. So
  a reboot stops at the LUKS prompt.
- The installer uses **one password for the user, root and LUKS**
  (`tests/vm/README.md` §3). Whoever gets past the LUKS prompt already has the
  password the lockout protects, so the reset gains them nothing.
- **Residual risk, not changed by any option here:** the LUKS prompt has no
  faillock. The same password can be guessed there, slowed only by the key
  derivation and the reboots. The lock-screen lockout does not protect a
  powered-off or rebooted machine; a strong password does.

Revisit if Omarchy enables autologin without encryption, or if TPM or other
passwordless LUKS unlock becomes part of the default install. Omarchy at
`dde0d12` ships none: across its 5184 files, `systemd-cryptenroll`,
`tpm2-device`, `tpm2-pcrs` and `clevis` appear only in a test fixture
(`test/shell.d/luks-rekey-journal-test.sh`, a previous owner's token). Its only
boot-time auto-unlock is the staged install key, which `luks_auto_unlock_drop`
(`bin/omarchy-provision-owner:1044`) removes after the re-key.

## D-24 — Tailscale bypasses ufw on `tailscale0` (Decided 2026-10-24: (a′), report and audit SSH)

Measured in the VM (Omarchy 4.0.6, `tailscale` 1.104.1-1, Headscale v0.29.5 as
the control server): with Tailscale up, `INPUT` starts with `-j ts-input`,
ahead of every ufw chain, and `ts-input` has `-i tailscale0 -j ACCEPT`. A
second tailnet node reached a test listener on the VM with HTTP 200 with the
D-10 rule absent, present and absent again (counter: 78 packets on that
ACCEPT). So `aegis_overlay_ssh_on_tailscale: false` does not close SSH on the
tailnet, the `network.overlay` finding's "SSH closed" is wrong, and the
opt-in rule changes nothing. Inbound tailnet traffic is governed by the
tailnet's access policy (ACLs), not by this playbook. This is Tailscale's
default `--netfilter-mode=on` ("Tailscale creates its firewall rules and
ensures they're evaluated for relevant traffic",
tailscale.com/docs/reference/netfilter-modes).

Options:

- **(a) Report it honestly, change nothing else.** The finding says that
  inbound tailnet traffic is governed by the tailnet ACLs, and WARNs while
  Tailscale runs with `netfilter-mode=on`; drop the "SSH closed" text and
  document that the D-10 rule has no effect in that mode. Small, no change to
  Tailscale.
- **(b) Let ufw govern `tailscale0`.** Set `tailscale set
  --netfilter-mode=nodivert` and add the jumps and rules ourselves, so ufw
  decides per port. Changes Omarchy's Tailscale setup; subnet routing, exit
  nodes and direct (non-relayed) connections each need a rule, and each would
  need a VM test.
- **(c) `--shields-up` unless SSH is opted in.** Blocks every inbound tailnet
  connection. Cannot allow SSH alone, and its effect on Taildrop (which
  Omarchy enables) is untested.

**Decided (owner, 2026-10-24): (a′), a refined (a).** The owner asked which
login protects what is exposed. Two logins do: joining the tailnet happens at
Tailscale's identity provider (Apple, Google, GitHub, Microsoft, Okta,
OneLogin, OIDC, or a passkey; MFA is the provider's,
tailscale.com/kb/1013/sso-providers), and SSH on the machine is key-only once
Omarchy's `omarchy-setup-security-sshd` has authorized a key (it writes
`PasswordAuthentication no` and `KbdInteractiveAuthentication no` and checks
them with `sshd -T`, read at v4.0.6). With a phishing-resistant tailnet login
and key-only SSH, the exposure is acceptable, and password brute force is
still limited by faillock (D-13). So the role:

- WARNs in `network.overlay` while Tailscale runs and `INPUT` jumps to
  `ts-input`, saying that tailnet peers reach every listening port and that
  the tailnet policy and identity-provider login decide who they are. It no
  longer says "SSH closed".
- WARNs in `ssh.password_auth` when sshd's effective settings allow
  password or keyboard-interactive logins.
- Reports in `ssh.authorized_keys` (INFO) every authorized key that is not an
  `sk-` (hardware) key, by user and type only.

The SSH checks run whenever sshd is installed, not only while Tailscale runs:
a password-enabled sshd is the same risk on the LAN once its rule is back,
and the container test can reach this path. (b) stays possible later as an
opt-in variable; `tests/vm/tailscale.sh` already shows that `nodivert` closes
the port to tailnet peers.

## D-25 — Report unknown programs that connect out (Decided 2026-10-24)

The owner asked for a review loop over outgoing traffic instead of a
default-deny desktop ruleset (D-09 follow-up). An nftables/iptables log was
considered and rejected: a netfilter log entry carries addresses, ports and at
most the socket's UID (`log flags skuid`, wiki.nftables.org "Logging
traffic"), not the program, and on a single-user desktop nearly everything
runs as that user. OpenSnitch attributes each connection to an executable.
**Decided:** enable an `opensnitchd` logger, and have the audit WARN on
executables that connected out, are owned by no pacman package, and are not
in `aegis_egress_known`. Not caught: a malicious script run by a
package-owned interpreter (`python`, `node`).

**How it is built (2026-10-24).** Every OpenSnitch log format carries the
program's command line (v1.7.2 `daemon/log/formats`), which can hold
credentials, so the journal was rejected: the owner chose a local collector.
opensnitchd's `remote` logger sends CSV over UDP to `127.0.0.1:7811` (it
supports only UDP or TCP, and its CSV has no line ending, so UDP). The
collector, `aegis-egress-collector` (Python, standard library only), accepts
a datagram only from a loopback socket owned by root (checked in
`/proc/self/net/udp`), validates the first nine fields, never reads the command
line or working directory, and keeps program path, destination, first and
last seen, for 30 days, in a 0600 file. It runs under a systemd sandbox
(`DynamicUser`, no capabilities, loopback only, syscall filter, 64 MB).
A rejected sender is logged as `egress_sender_reject` and the audit WARNs on
it (`egress.collector_sender`). The report is best effort: UDP has no
retry, and an event sent while the collector is down (a restart, a crash)
is lost. Measured 2026-10-25: of three probes run right before a restart,
one arrived after it and one never did. A datagram read after its sending
socket has closed is rejected too, since its owner can no longer be checked
(forced 2026-10-26: 5 of 5 rejected), so events opensnitchd sent just before
it restarted can be lost the same way. It is a report of what programs
connect out, not an audit log.

## D-26 — Outgoing traffic of agent containers (Decided 2026-10-24)

`aegis-agent` (D-07) gets a filtering egress proxy:
[Smokescreen](https://github.com/stripe/smokescreen) (Go, MIT), chosen by the
owner over squid as lighter and purpose-built. **Default: `report`**, which
allows everything and logs hosts outside the allowlist; `enforce`, which
allows only the allowlist, is a switch (variable, and per invocation). In
`enforce` the agent sits on an internal podman network whose only way out
is the proxy. Smokescreen refuses private and internal addresses by default;
the owner kept that. Its README promises `ghcr.io/stripe/smokescreen`, but the
image is not public (token 403, package API 404, 2026-10-24), so the release
binary is used, pinned by SHA-256. Implementation: open-items §2.

**How it is built (2026-10-24).** The role downloads Smokescreen v0.1.0 for
the machine's architecture, checks it against the SHA-256 pinned from the
release's `SHA256SUMS` (its SLSA v1 provenance attestation, from
`stripe/smokescreen`'s `release.yml`, was verified with `gh attestation
verify` when pinned), and installs only the static binary. `aegis-agent`
builds a `FROM scratch` image of it (no shell, no libc, no base image) and
runs one proxy per mode, read-only, as UID 65534, with no capabilities,
`no-new-privileges`, the agent seccomp profile and memory, CPU and PID
limits, on two rootless networks: `aegis-agent-int` (internal, no route out)
and `aegis-agent-ext`. In `report` the agent joins both networks, so traffic
that ignores the proxy settings still gets out; in `enforce` it joins only
the internal one. The audit summarises the proxies' JSON log lines
(`agent.egress`, INFO).

## D-27 — polkit cannot open the faillock tally in `/var/lib/faillock` (Decided 2026-10-27: (a))

Found in the VM (2026-10-27, `pre-aegis-updated` after `run.sh`, Omarchy
4.0.6, polkit 127-3). polkit 127 authenticates through a socket-activated
`polkit-agent-helper@.service` with `ProtectSystem=strict`. The stock
`/usr/lib/pam.d/polkit-1` includes `system-auth`, so `pam_faillock` runs in
that sandbox, and with the D-14 tally directory it logs `Error opening the
tally file for aegis: Read-only file system`; PAM returns a system error and
**`pkexec` refuses the right password**. Differential: the same stack with
`dir = /run/faillock` gave no such error and passed PAM. Measured over SSH
(`pkexec` with a textual agent); there the `/run` attempt then failed at "No
session for cookie", an SSH-only problem after authentication. A `pkexec`
typed in a desktop terminal fails the same way (measured 2026-10-27, after the
fix: with the drop-in removed, "Read-only file system" and no command run; with
it, `pkexec` ran the command as root). Omarchy 4.0.6 starts no graphical polkit agent, so a terminal `pkexec`
is the main way to hit this.

Options: (a) a drop-in `polkit-agent-helper@.service.d/` with
`ReadWritePaths=/var/lib/faillock`, which keeps D-14 and widens the helper's
sandbox by that one directory; (b) move the tally back to `/run/faillock`,
which reverses D-14 (a reboot clears a lockout again); (c) accept that
`pkexec` does not work and document it.
**Recommendation:** (a). It is the smallest change that keeps both the
lockout's persistence and polkit, and the helper can already write to the
tally in Omarchy's default (`/run/faillock`). Needs a VM check that `pkexec`
then accepts the right password and records failures.

**Decided (owner, 2026-10-27):** (a), the recommendation. The
`pam_faillock` role installs
`/etc/systemd/system/polkit-agent-helper@.service.d/aegis-faillock.conf` with
`ReadWritePaths=` the tally directory, only when the unit exists, and asserts
it from the file and from `systemctl show`. The helper's other sandboxing is
unchanged.

## D-28 — Omarchy's FIDO2 polkit stack has no faillock (Decided 2026-10-27: (a), audit only)

`omarchy-setup-security-fido2` (4.0.6, `/usr/bin/omarchy-setup-security-fido2`)
**creates** `/etc/pam.d/polkit-1` when it does not exist, which is the stock
case, with `pam_u2f` `sufficient`, then `pam_unix` only; no `system-auth`, so
no faillock (upstream at `cbd44ba` writes `include system-auth`). Measured in
the VM (2026-10-27, `pam-u2f` 1.4.0-2, no key enrolled, the file exactly as the
script writes it): 10 wrong `pkexec` passwords gave 10 `pam_unix` failures and
a tally of 0 bytes, and the right password then passed PAM. So once a user has
run Omarchy's FIDO2 setup, a process running as the user can guess the
(wheel) password at a polkit prompt without limit. No role touches this file.

Options: (a) audit only: WARN when `/etc/pam.d/polkit-1` authenticates with
`pam_unix` and does not include `system-auth` (or call `pam_faillock`);
(b) a role that rewrites the file to Omarchy upstream's form (`pam_u2f`
`sufficient`, then `include system-auth`), behind a variable defaulting to
off; (c) leave it.
**Recommendation:** (a) now, (b) once Omarchy ships its upstream form in a
release. (a) changes nothing on the machine; (b) edits a file Omarchy's own
script owns, and upstream has already fixed it. D-27 decides whether the
`system-auth` form works under polkit at all, so (b) waits on D-27 either way.

**Decided (owner, 2026-10-27):** (a), the recommendation. Finding
`auth.polkit_faillock` (WARN) in the `pam_faillock` role; the role never
writes `polkit-1`. (b) stays open for when Omarchy ships its upstream form.

## D-29 — sysctl read-back on `linux-hardened`, where two keys do not exist (Decided 2026-10-27: (a))

Booting `linux-hardened` (7.2.10-hardened1-3) in the VM (2026-10-27): its
`/proc/config.gz` has `# CONFIG_KEXEC is not set`, `# CONFIG_KEXEC_FILE is not
set` and `# CONFIG_USERFAULTFD is not set`, so `kernel.kexec_load_disabled` and
`vm.unprivileged_userfaultfd` do not exist. `systemd-sysctl` logs "ignoring"
for both and the boot is fine, but the `sysctl` role's read-back fails on them
(`sysctl: cannot stat …`), so **the playbook, and with it the D-11 drift check,
fails on that kernel** (`--check`: `failed=1`). The features are compiled
out, which is stronger than the sysctl.

Options: (a) a short list of keys whose absence counts as compliant
(`kernel.kexec_load_disabled`, `vm.unprivileged_userfaultfd`), reported as
INFO "not in this kernel"; (b) skip any missing key; (c) leave it, and make
`linux-hardened` a kernel the playbook does not support.
**Recommendation:** (a). (b) would also hide a typo in a key name, which is
the silent-match failure AGENTS.md warns about; (c) contradicts D-02.

**Decided (owner, 2026-10-27):** (a), the recommendation. Variable
`aegis_sysctl_absent_ok`; a listed key missing from the kernel gives INFO
`sysctl.compiled_out`. The file keeps the key, so it is the same on both
kernels. `sysctl --load` then runs with `-e`, which skips unknown keys only
(measured, procps-ng 4.0.7: still exit 1 on a permission error); systemd's
`-key` prefix did not help there (exit 1 either way).

## D-30 — `aegis-agent` does not run on `linux-hardened` (Decided 2026-10-27: (c))

The same boot: `linux-hardened` builds without `CONFIG_OVERLAY_FS_UNPRIVILEGED`,
so a mount of `overlay` inside a user namespace is refused (`permission
denied`, measured) and rootless Podman stops with "'overlay' is not supported
over btrfs". `aegis-agent` (D-07) therefore fails on that kernel (exit 125).
On `linux-omarchy` it works (`run.sh`, the same day).

Options: (a) install `fuse-overlayfs` and point rootless Podman's storage at it
when the running kernel lacks unprivileged overlay; it is a new package
dependency and a FUSE daemon per container; (b) the `vfs` driver: no new
package, but a full copy of each image layer per container, slow and large;
(c) document that `aegis-agent` needs `linux-omarchy`, and have the audit say
so when booted on `linux-hardened`.
**Recommendation:** (c) now, while `linux-hardened` is an opt-in second entry
that nobody has made the default; revisit (a) if the owner makes it the
default (D-02). (a) adds a FUSE daemon to the containment boundary, which
deserves its own look.

**Decided (owner, 2026-10-27):** (c), the recommendation. Finding
`agent.kernel_overlay`: WARN when the running kernel's config says
`# CONFIG_OVERLAY_FS_UNPRIVILEGED is not set`, PASS when it does not, INFO when
the config cannot be read. Revisit (a) if `linux-hardened` becomes the default.

## D-31 — ufw resets `rp_filter` to strict at boot (Decided 2026-10-27: (a))

Found in the VM (2026-10-27) while verifying D-29 on `linux-hardened`: right
after boot, `net.ipv4.conf.{all,default}.rp_filter` read **1**, although
`/etc/sysctl.d/99-zz-aegis-hardened.conf` sets **2** (loose, roadmap #4: strict
drops asymmetric WireGuard/Tailscale traffic). ufw applies its own
`/etc/ufw/sysctl.conf`, which sets both to 1, when it starts, and in that boot
`ufw.service` started at 34.46 s, after `systemd-sysctl` finished at 34.44 s.
On `linux-omarchy` the same day, `run.sh` read 2 after its reboot, so this is
the order of two units, seen to lose once; it is not shown to be specific to
one kernel (wrong, corrected below). Effect: strict reverse-path filtering until the next playbook
run, which re-applies 2 (so each run reports `changed`), and the D-11 drift
check reports it after a package update (wrong, corrected below). Not a weakening: 1 is stricter.

Options: (a) the firewall role sets the two `rp_filter` lines in
`/etc/ufw/sysctl.conf` to 2, so both writers agree (pacman keeps a changed
`/etc/ufw/sysctl.conf` on upgrade: it is in the `backup=()` array of Arch's
ufw 0.36.2-7 PKGBUILD, read 2026-10-27); (b) re-run
`systemd-sysctl` after `ufw.service` with a drop-in, which leaves ufw's file
as shipped but adds a boot-order dependency; (c) accept strict mode, and drop
loose `rp_filter` from the sysctl role.
**Recommendation:** (a). One edit to a config file ufw re-reads at every
start, no ordering to reason about, and it keeps roadmap #4's reason for
loose mode. Needs a VM reboot test on both kernels.

**Decided (owner, 2026-10-27):** (a), the recommendation. The `firewall` role
sets the two `rp_filter` lines in `/etc/ufw/sysctl.conf` to
`aegis_firewall_ufw_rp_filter` (2) and asserts that no `rp_filter` line in
either spelling carries another value. **Correction (2026-10-27):** this was
not seen on `linux-hardened` only. On `linux-omarchy` too, `rp_filter` read 1
right after a boot; `run.sh`'s "state survives a reboot" passed anyway,
because its `--check` run cannot see live sysctl values (D-32). For the same
reason the D-11 drift check did not report it either (corrected 2026-10-28). Measured in
the VM after the change: right after a boot, 2 on both keys on both kernels,
with ufw still starting after `systemd-sysctl` (280.5 s after 279.5 s on
`linux-hardened`, 1059.2 s after 1057.5 s on `linux-omarchy`).

## D-32 — a `--check` run cannot see live sysctl drift (Decided 2026-10-28: (a))

Found while verifying D-31. In check mode the `sysctl` role reads the live
values, but its apply step (a `command` task) is skipped and its live
assert runs only outside check mode, so nothing compares them: in today's
`run.sh` log, run 1 (apply) shows the apply and assert tasks, run 3 (`--check`
after the reboot) shows neither, while `rp_filter` was in fact 1. Two
controls rely on a `--check` run: `run.sh`'s "state survives a reboot" and the
D-11 drift check after each package transaction. Neither can report a live
sysctl value that something else reset; both still see the drop-in file.

Options: (a) in check mode, report the differing keys as changed (a task
that is `changed` when a live value differs, so the drift check notifies and
`run.sh` fails); (b) a separate audit finding (WARN `sysctl.live_drift`) in
both modes, which the drift check does not count as drift; (c) leave it, and
say in the docs that the drift check covers files only.
**Recommendation:** (a). It makes `--check` mean what its users read it as,
and the drift check exists for exactly this; with D-31 fixed, a clean
machine has no live drift to report. Needs the container test (a planted
live difference in check mode) and a `run.sh` pass.

**Decided (owner, 2026-10-28):** (a), the recommendation. The `sysctl` role
collects every live value that differs from the drop-in and, in check mode,
reports them by name as `changed` ("kernel.dmesg_restrict is 0, want 1"); the
D-11 drift check and `run.sh`'s post-reboot `--check` treat that as drift.
Container: a planted live difference is reported, a matching value is not
(a mutant that never reports fails the test). CI `sysctl-apply`: a value
changed at runtime is reported by `--check`, which leaves the kernel as it is. VM (2026-10-28, `pre-aegis-updated` after `pacman -Syu`): `run.sh`
passed in full, and its post-reboot `--check` (which now sees live values)
found none differing; then a live `rp_filter=1` set with `sysctl -w` was
reported by the D-11 drift check after a real `pacman -S` ("net.ipv4.conf.all.rp_filter
is 1, want 2"), and the kernel value was left as it was.

## D-33 — the drift check stops at `commit_signing` (Decided 2026-10-29: (a))

Found while verifying D-32. The drift check runs the playbook from a systemd
unit with `NoNewPrivileges=yes` and `ProtectHome=read-only`, so it cannot
`sudo`, and its script passes `-e ansible_become=false` (since D-11,
`c6d0e01`, 2026-10-22). Tasks that act as the desktop user (`become_user`:
`commit_signing` 3, `opensnitch` 5, the agent egress audit 1) then run as
root with no `$HOME`; the first, `git config --global --get` in
`commit_signing`, fails with "fatal: $HOME not set" (VM, 2026-10-28,
`/var/lib/aegis/drift-check.log`). Ansible stops a host at its first
failure, so **the roles after it are never checked by the drift check:
`firewall`, `opensnitch`, `overlay_network`, `pacman_integrity`**. The
check still reports "Hardening drift", because a failed run exits non-zero
like a drifted one, and `run.sh`'s D-11 test accepts any non-zero result.
So D-11 has caught PAM drift and changes to the sysctl drop-in (live sysctl
values only since D-32), but not ufw drift. The code that causes this is
unchanged since D-11 landed (`c6d0e01`, 2026-10-22: the `become_user` git read,
`-e ansible_become=false`, `commit_signing` before `firewall`); the failure was
observed on 2026-10-28.

Options: (a) tasks that need the desktop user are skipped when the run
cannot become (a variable the drift script sets beside `ansible_become=false`),
each recording INFO "not checked by the drift check"; the drift script tells
a failed run ("drift check broken", with the task) from a drifted one, and
`run.sh` requires `failed=0` in the drift log; (b) the same reads run as root
with `HOME` set to the user's home (root can read it under
`ProtectHome=read-only`), which needs care per task and still cannot write;
(c) let the drift unit `sudo` (drop `NoNewPrivileges`), which widens a root
service that runs on every package transaction.
**Recommendation:** (a). It restores the drift check for the four roles that
matter most to it (ufw, OpenSnitch's daemon, the overlay network, package
integrity) without widening the unit, makes a broken check loud instead of
reading as drift, and adds the test that would have caught this.

**Decided (owner, 2026-10-29):** (a), the recommendation. The drift script
passes `aegis_drift_check_run=true`. `commit_signing` then records INFO
`git.commit_signing` "not checked by the drift check" and ends the role;
the agent egress audit records INFO `agent.egress` the same way instead of
reading root's empty container store (as root, `podman logs` with
`failed_when: false` would have reported "no agent traffic", a wrong answer
rather than a failure). The OpenSnitch user-file tasks stay: their paths
name the user's home and in check mode they only read it, which root can. The
script exits 2 with "Aegis drift check broken" (journal priority `err`, its
own desktop title) when a task other than the audit's verdict failed, the host
was unreachable, or the log has no recap; drift and an audit FAIL still exit 1
with "Hardening drift". `run.sh` requires `failed=0` in the drift log.
Container: the drift check now runs in a service's environment (`env -i`, no
`$HOME`) and with the `signing` tag; before the fix that run failed exactly as
in the VM (`fatal: $HOME not set`, `failed=1`), after it the run is clean and
lists the INFO. Planted: a broken Python interpreter (a failed task) and an
unparsable settings file (no recap) both exit 2; a FAIL finding planted in the
settings still exits 1.

**A second blocker, found in the VM (2026-10-29).** With `commit_signing`
skipped, the check reached `firewall` and stopped there, now correctly as
"drift check broken … failed: firewall : Set the default incoming policy":
ufw opens `/run/ufw.lock` for writing even for `ufw status`
(`OSError: [Errno 30] Read-only file system`), and its `--dry-run` refuses
unless `/etc/ufw/user.rules` is writable. The unit's `ProtectSystem=strict`
allows neither. Two probes in transient units with the same sandbox showed
that with both writable the check runs to the end (`failed=0`, the two INFO
findings, OpenSnitch's tasks fine as root, the only change the planted PAM
revert, ufw's rule files byte-identical before and after). Options: (a) in
the drift check, `firewall` and `overlay_network` read ufw's own files
(`/etc/default/ufw`, `/etc/ufw/ufw.conf`, `user.rules`, `user6.rules`) and
report what a run would change, as D-32 does for sysctl; (b) widen the unit
with `ReadWritePaths=-/run/ufw.lock /etc/ufw`; (c) skip `firewall` with an
INFO. **Decided (owner, 2026-10-29): (a)**, as recommended: (b) would let a
root service started on every package transaction write the firewall config,
against the unit's rule that nothing outside `/var/lib/aegis` is written,
the same widening D-33 (c) was turned down for; (c) drops the ufw reverts
D-11 exists to catch. Each pattern matches exactly what the role's ufw task
would delete, so a rule a run would leave alone is not reported. The live
netfilter rules are not read: ufw loads these files when it starts.
Container: with `/run/ufw.lock` replaced by a directory (so ufw fails as in
the unit, which a control run confirms), a hardened ufw reads clean, and a
disabled ufw, an `allow` incoming default, LocalSend 53317/tcp, `limit
22/tcp` and a missing opted-in `tailscale0` rule are each named, as an
ordinary `--check` also sees them (76/76). VM (2026-10-30,
`pre-aegis-updated` after `pacman -Syu`): `run.sh` passed in full; the drift
check after a real `pacman -S` ran every role to the end (`ok=131 changed=1
failed=0`, against `ok=87 … failed=1` before), read ufw's files, listed the
two INFO findings, and its one change was the planted PAM revert.
