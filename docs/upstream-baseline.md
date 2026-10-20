# Upstream baseline: what Omarchy actually ships

The roles are written against what Omarchy really does, not against the PRD's
description of it. Everything below was read from
[basecamp/omarchy](https://github.com/basecamp/omarchy) at commit
`dde0d123bb7e130cb7c8a679ed9d3b8b2a11887e` (2026-10-20, `version` = `4.0.0.alpha`).
Re-check it when Omarchy changes. Each row names the upstream file, so a
re-check is a `git diff` of those paths.

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

## Drift: Omarchy rewrites some of these on update

Omarchy's own update and migration scripts rewrite several of the files above:

- `bin/omarchy-apply-lock` rewrites `/etc/pam.d/omarchy-lock-password` in full,
  and `bin/omarchy-upgrade-to-quattro` re-runs the `deny=10 unlock_time=120` sed
  on `system-auth`.
- `omarchy-setup-security-sshd` re-adds the SSH rule whenever the user runs it.

**Re-run the playbook after every `omarchy-update`.** Making this automatic (a
pacman hook or a systemd path unit that re-applies, or at least reports drift)
is tracked as D-11 in [open-decisions.md](open-decisions.md).
