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
repos. The role stays a stub.

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
