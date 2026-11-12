# Upstream baseline: what Omarchy actually ships

The roles are written against what Omarchy really does, not against the PRD's
description of it. Everything below was read from
[basecamp/omarchy](https://github.com/basecamp/omarchy) at commit
`dde0d123bb7e130cb7c8a679ed9d3b8b2a11887e` (2026-10-20, `version` = `4.0.0.alpha`).
Re-check it on each Omarchy release or release candidate. Each row names the
upstream file, so a re-check is a `git diff` of those paths.

**Re-checked 2026-11-11 against `v4.5.0` (`ac2690c`, released 2026-11-05).**
Method: the full upstream trees at `cbd44ba`, `v4.5.0-rc2` and `v4.5.0` from
the GitHub trees API (none truncated), compared by blob id. GitHub's compare
API stops at 300 files, and rc2 to `v4.5.0` is 130 commits and 779 changed or
added files, so it cannot be used here. The paths this repo cites are every
backticked path in a tracked file that exists upstream at `cbd44ba`: 62
files and 6 directories (the last re-check counted 57 by a method it did not
record, so the two sets were not compared). Fourteen changed since `cbd44ba`, and eleven of them since rc2. The
sources of the vendored fixtures (`install/config/firewall.sh`,
`install/config/increase-lockout-limit.sh`, `bin/omarchy-apply-lock`,
`etc/security/faillock.conf`, `LICENSE`) are unchanged. No row in the table
changed. Both rc2 findings below shipped in `v4.5.0` unchanged:
`fix-powerprofilesctl-shebang.sh` is gone and `install/omarchy-base.packages:106`
installs `omarchy-power-profiles-daemon` (D-22 now names the owning package,
2026-11-11), and `omarchy-update-aur-pkgs` still runs before
`end_update_authorization` in `bin/omarchy-update` (an accepted risk in
threat-model.md §5, 2026-11-11). Other changes since rc2 that touch what this
repo relies on:

- `bin/omarchy-update` lost the `#!/bin/bash -p` startup check, the sanitized
  `PATH` and the sudo-timestamp revocation that rc2 had. `v4.0.6` had none of
  them either, so no control here depended on them; recorded so nobody cites
  them later.
- `bin/omarchy-setup-security-sshd` no longer starts sshd or adds the ufw
  rule (still `ufw limit 22/tcp comment "omarchy-sshd"`, now line 84) until a
  key is authorized and password logins are off. A cancelled run leaves
  `openssh` installed but not enabled; `ssh.password_auth` then WARNs about
  Arch's stock config, which is what the server would use if started (read
  from `roles/overlay_network`, which keys on sshd being installed; not run).
- `install/omarchy-other.packages` now lists `v4l2loopback-dkms` (Elgato Cam
  Link). That file lists packages "installed outside of install/packages.sh or
  optional packages" so the ISO carries them; what installs this one, and on
  which machines, was not traced. If installed, it is another out-of-tree
  module (see `module.sig_enforce` in research/secureblue-review.md).
- `install/user/mise.sh` reshims offline; `default/hypr/envs.lua` adds
  `no_donation_nag`; `bin/omarchy-provision-owner` was refactored. It still
  sets root's password to the user's (`printf '%s:%s\n' root "$password" |
  chpasswd`, line 736; D-19), and encrypted installs still keep autologin.

D-23's revisit condition is still unmet: of the 779 files changed or added
since rc2, 757 were read (the other 22 are `applications/Google …` launchers
and icons), and `systemd-cryptenroll`, `tpm2-*` and `clevis` appear only in
`test/shell.d/`. Not traced: `luks_auto_unlock_drop`, which D-23 cites as
removing the staged install key, has no caller inside
`bin/omarchy-provision-owner` at `dde0d12`, rc2 or `v4.5.0` (only its
definition). GitHub code search returned nothing for it and for
`limine_auto_unlock_drop` alike, although both are defined on the default
branch `quattro` that code search reads (`bin/omarchy-provision-owner:913` and
`:967`, checked 2026-11-12), so code search does not answer for this repository
and the caller was not found.

**Re-checked 2026-10-29 against `v4.5.0-rc2` (`5978d93`, 2026-10-27).** The
paths this repo cites (57 backticked paths that exist upstream, plus the 5
files in `tests/fixtures/omarchy/`) were diffed from `cbd44ba` to the tag.
Six changed: `AGENTS.md`, `bin/omarchy-hibernation-setup` (resume device
named by UUID), `docs/update-process.md`, `install/provisioning/setup-form.sh`
(translated prompts), and the two below. No row in the table changed. D-23's
revisit condition is still unmet: TPM or `clevis` unlock appears only in the
same test fixture, and no autologin or SDDM file changed. Two changes in
`v4.5.0-rc2` matter once 4.5.0 ships (`v4.0.6` has neither; open-items.md §2):

- `install/omarchy-base.packages` replaces `power-profiles-daemon` with
  `omarchy-power-profiles-daemon`, and `install/config/fix-powerprofilesctl-shebang.sh`
  is gone (`701f1599`). The D-22 expected-drift entry for
  `/usr/bin/powerprofilesctl` exists only because of that script; on 4.5 it
  would accept a content change that no longer has a benign cause.
  (`bin/omarchy-upgrade-to-quattro` still rewrites the shebang for a channel
  that keeps the stock package.)
- `bin/omarchy-update` runs AUR builds under the update's sudo authorization
  (`24f59da2`, "Authorize omarchy update once, AUR and boot check included",
  2026-10-25). Before, `yay` ran after the keepalive stopped, through the
  no-update wrapper, so PKGBUILD code got no reusable sudo timestamp; now it
  runs while the keepalive is live. This playbook installs nothing from the
  AUR, but a PKGBUILD of any AUR package the user has can now run `sudo`
  without a prompt during `omarchy-update` (read from the code at the tag,
  not run).

**Re-checked 2026-10-23 against `cbd44ba` (41 commits, 226 files later).** Of
the 58 upstream files this repo cites, the changed ones are
`bin/omarchy-drive-password` (LUKS re-key recovery),
`install/provisioning/setup-form.sh` (timezone lookup only) and Omarchy's own
docs. No row in the table below changed. New since `dde0d12`, on the
development branch only (none of it is in `v4.0.6` or `v4.5.0-rc1`):

- `bin/omarchy-kernel set <kernel>` writes `BOOT_ORDER` into
  `/etc/default/limine` and rebuilds the menu, so it is the upstream way to
  make `linux-hardened` the default (D-02). The `kernel` role accepts that
  switch since 2026-10-23 (D-02 follow-up in open-decisions.md).
- `bin/omarchy-apply-pacman` writes `pacman.conf` and the mirrorlist from the
  channel templates plus regional `Server =` lines placed first. The only
  region is `cn`, and all six of its URLs are `https://`.
- `etc/NetworkManager/conf.d/omarchy-connectivity.conf`: the connectivity
  check fetches `http://ping.omacom.io/nm-check.txt` over plain HTTP, on
  purpose (captive portals). Relevant to roadmap #15.
- `default/systemd/timesyncd.conf.d/10-omarchy.conf`:
  `FallbackNTP=ntp.omarchy.org time.cloudflare.com`. Relevant to roadmap #22.

| Area | Omarchy default | Source | PRD said | Aegis role |
|---|---|---|---|---|
| faillock | `deny=10 unlock_time=120`, set **inline** on the `pam_faillock.so` lines of `/etc/pam.d/system-auth`. `/etc/security/faillock.conf` also sets `deny = 10` | `install/config/increase-lockout-limit.sh`, `etc/security/faillock.conf` | relaxed faillock ✔ | `pam_faillock` |
| Lock screen PAM | Its own stack, `/etc/pam.d/omarchy-lock-password`, with the same inline `deny=10 unlock_time=120` | `bin/omarchy-apply-lock` | not mentioned | `pam_faillock` |
| Firewall | ufw: deny incoming, allow outgoing; allows **53317/tcp+udp** (LocalSend) and Docker DNS (`172.16.0.0/12`, `192.168.0.0/16` → `172.17.0.1:53/udp`); ufw-docker installed | `install/config/firewall.sh` | 22 and 53317 open | `firewall` |
| SSH | **Not opened by default.** `omarchy-setup-security-sshd` (opt-in) installs sshd and adds `ufw limit 22/tcp comment "omarchy-sshd"` | `bin/omarchy-setup-security-sshd:73` | "default allowance for port 22" — **inaccurate**: it is opt-in | `firewall`, `overlay_network` |
| Kernel | `linux-omarchy` (Omarchy's own build), not Arch's mainline `linux`; `linux-t2` on T2 Macs | `install/omarchy-other.packages` | "mainline Arch kernel" — **inaccurate** | `kernel` |
| Bootloader | Limine + `limine-mkinitcpio-hook` + `limine-snapper-sync` | `install/omarchy-other.packages` | — | `kernel` |
| Install path | `/usr/share/omarchy` (`OMARCHY_PATH`); 3.x used `~/.local/share/omarchy` | `test/acceptance` and others | — | `preflight` |
| pacman signatures | Global `SigLevel = Required DatabaseOptional`; a migration removed the old `[omarchy]` `Optional TrustAll` override | `default/pacman/*.conf`, `migrations/1787589206.sh` | — | `pacman_integrity` |
| Unsigned repo | On Intel T2 Macs, `[arch-mact2]` is appended with **`SigLevel = Never`** | `install/hardware/pacman.sh` | — | `pacman_integrity` (fails unless excepted) |
| sysctl | Three drop-ins, all performance/networking, no hardening keys: `90-omarchy-arp.conf` (arp_ignore/announce), `90-omarchy-file-watchers.conf` (inotify), `99-omarchy-sysctl.conf` (BBR+fq, MTU probing, zram swappiness=150, dirty-bytes caps). No overlap with Aegis keys today; Aegis writes `99-zz-aegis-hardened.conf` so it sorts last and wins any future overlap | `etc/sysctl.d/` | — | `sysctl` |

## polkit

Omarchy 4.0.6 ships no polkit rules of its own: `/etc/polkit-1/rules.d/` is
empty. The 7 package rules in `/usr/share/polkit-1/rules.d/` include systemd's
`empower.rules`, which grants every action to the `empower` group used by
`run0 --empower` (measured on the VM; file owned by systemd 262 in the test
image).

## pacman guard

`default/libalpm/hooks/00-omarchy-update-guard.hook` runs
`bin/omarchy-update-pacman-guard` before every upgrade transaction. It aborts a
direct system upgrade (`-S` together with `-u`) unless
`OMARCHY_ALLOW_DIRECT_PACMAN=1` or `OMARCHY_UPDATE_PACMAN=1` is set, and tells
the user to run `omarchy update` instead. Plain installs (`pacman -S --needed
pkg`, as our roles do) pass. A fresh install has no sync databases until the
first `omarchy update` (measured on 4.0.6).

## Drift: Omarchy rewrites some of these on update

Omarchy's own update and migration scripts rewrite several of the files above:

- `bin/omarchy-apply-lock` rewrites `/etc/pam.d/omarchy-lock-password` in full,
  and `bin/omarchy-upgrade-to-quattro` re-runs the `deny=10 unlock_time=120` sed
  on `system-auth`.
- `omarchy-setup-security-sshd` re-adds the SSH rule whenever the user runs it.

**D-11 (decided):** the `drift_check` role's pacman hook runs the playbook in
`--check` mode after every transaction and warns when something was
reverted. Re-run the playbook to restore it.
