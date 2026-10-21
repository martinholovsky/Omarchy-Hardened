# SnowflakeOS review for Omarchy-Hardened (Aegis)

- **Date:** 2026-10-21
- **Short version:** SnowflakeOS is a beginner-friendly NixOS desktop.
  It is not a hardening project. It ships **four** settings whose purpose
  is security, and two more that are opt-in toggles in a GUI. Everything
  else it gets comes from stock NixOS defaults. The only security work is
  three lines of boot hygiene and turning fwupd on. Its installer has no
  disk-encryption support at all. Omarchy is already ahead of it on almost
  every axis. The only new ideas are small audit-only checks, and three of
  those come from SnowflakeOS's *anti-patterns*, not from its hardening.
- **Website:** https://snowflakeos.org/ (fetched 2026-10-21). It says it is
  "NixOS-based", "focused on beginner friendliness and ease of use", in
  **alpha** and "Not yet ready for daily use!". Its tagline is "Simple,
  Immutable, Reproducible". The site makes no security claims. It has no
  docs pages: the site links only to GitHub, Discord, Matrix, Twitter,
  Mastodon and the SourceForge ISO.
- **Source, confirmed from the site's own links:** the GitHub org
  https://github.com/snowfallorg (42 repos). It is **not** `snowflakelinux`.
  That is the old name, still used in `snowflakeos-iso/README.md:18` and
  on the site's Twitter/Mastodon handles.
- **Repos cloned** into
  a scratch directory outside this repo. They are read only and nothing from them
  was executed, built or evaluated:

  | Repo | Pinned commit | Commit date | Tracked files | Licence |
  |---|---|---|---|---|
  | snowfallorg/snowflakeos-modules | `0a5e0a35ecbd0c840c43597948ccccd247c13b96` | 2026-08-24 | 39 (24 `.nix`) | MIT (`LICENSE`) |
  | snowfallorg/snowflakeos-iso | `1c5e16dd493af91ca893a37c436fc29c956c74cf` | 2026-08-24 | 14 (6 `.nix`) | MIT (`LICENSE`); `NIXPKGSLICENSE` included |
  | snowfallorg/icicle (installer) | `e1a86facacc0a784188efa73379173fccf4285cd` | 2026-08-24 | 104 | GPL-3.0 |

  The GitHub API reports these other licences without our having cloned
  the repos: nix-software-center, nixos-conf-editor and
  snowflakeos-module-manager are GPL-3.0; snow and libsnow are MIT.
- **Pinned nixpkgs** (from `snowflakeos-modules/flake.lock`):
  `56c02bc00adcf003215cc4bd996d6efaf4cff188` (nixos-unstable). Three NixOS
  module files were fetched at that rev to check the inherited defaults:
  `firewall.nix`, `sudo.nix` and `users-groups.nix`.
- **Compared against:** Omarchy at `dde0d123bb7e130cb7c8a679ed9d3b8b2a11887e`
  (5188 blobs). We read `install/omarchy-base.packages`,
  `install/omarchy-other.packages`, `install/login/sddm.sh`,
  `bin/omarchy-update-firmware` and `etc/tmpfiles.d/omarchy-nopasswd-sudo.conf`,
  plus this repo's `docs/roadmap.md` and the role list.

## What it is and whether it is maintained

- **Base:** NixOS, verified. All three flakes use
  `nixpkgs.url = "github:nixos/nixpkgs/nixos-unstable"`
  (`snowflakeos-modules/flake.nix:5`, `snowflakeos-iso/flake.nix:3`).
  The desktop is GNOME on GDM (`modules/nixos/gnome/default.nix:22-26`).
  SnowflakeOS is a branding layer on NixOS, plus a GUI installer (Icicle),
  a GUI package store and a GUI config editor.
- **Maintenance: low activity, essentially one maintainer, alpha.**
  - snowflakeos-modules has 38 commits in total. The last human change was
    on 2026-07-20 ("remove deprecated gdm wayland setting"). The commit on
    2026-08-24 is a `flake.lock` bump.
  - snowflakeos-iso has 62 commits, the last on 2026-08-24 ("update iso
    action"). Its last two `Build ISO` Actions runs, on 2026-08-24, ended
    `failure` and `cancelled`.
  - **The only published ISO is from 2023-11-12** (SourceForge,
    `snowflakeos-unstable-x86_64-linux.iso`), and aarch64 is from 2023-01-15.
    The only git tag is `22.11.20220918.f677051`. There are no GitHub
    releases.
  - The homepage repo was last committed on 2024-01-22.

## Settings inventory

The repos are small (about 960 lines of `.nix` in modules plus iso), so every
`.nix` and `module.yml` file in snowflakeos-modules and snowflakeos-iso was
read. In icicle we read the config templates, `modules/nixos/icicle/default.nix`,
the polkit policy and the parts of `src/utils/install.rs` that handle
passwords, autologin and install.

Classes:
- **a**: Omarchy or our playbook or roadmap already covers it.
- **b**: new, and can be adopted on Arch/Omarchy.
- **c**: NixOS-specific, or doesn't transfer.
- **d**: would break Omarchy, or is anti-hardening.
- **n/a**: not a hardening setting; listed so the inventory is complete.

| # | Setting | Where (pinned) | What it does | Class | Note for Omarchy |
|---|---|---|---|---|---|
| 1 | systemd-boot editor off | `snowflakeos-modules/modules/nixos/efiboot/default.nix:30` (`editor = mkDefault false`); `efiboot/module.yml:27-29` explains why (init=/bin/sh) | Stops cmdline edits at the boot menu | **a** | Roadmap 18c: Limine `editor_enabled: no` |
| 2 | ESP mounted `umask=0077` when vfat | `efiboot/default.nix:41-44` (comment: "random seed file is world accessible"); installer also mounts ESP `umask=0077` at `icicle/icicle-helper/src/main.rs:234-236,345-347` | ESP and the systemd random-seed are root-only | **a** | Roadmap #17: ESP `fmask=0077,dmask=0077` |
| 3 | `/tmp` cleaned on boot | `efiboot/default.nix:40`, `biosboot/default.nix:20`, toggle `efiboot/module.yml:22-26` | Wipes stale /tmp | **b** (audit-only) | Omarchy 4.0.6 already has a tmpfs `/tmp` with `nosuid,nodev` (measured, see below). Add a check that it stays that way |
| 4 | fwupd enabled | `modules/nixos/snowflakeos/graphical.nix:16-17` | Firmware updates via LVFS | **b** (audit-only) | Omarchy ships no fwupd by default. `bin/omarchy-update-firmware:9-18` installs and runs it only when asked |
| 5 | Kernel `linuxPackages_latest` (mkDefault) | `modules/nixos/kernel/default.nix:10`; ISO forces LTS `snowflakeos-iso/modules/nixos/installation/base.nix:23` (zfs build break) | Kernel choice, not hardening | **c** | Omarchy uses `linux-omarchy` |
| 6 | Hardened kernel as a GUI option | `modules/nixos/kernel/module.yml:23` (`linuxPackages_hardened`); installer offers LTS/latest/libre/zen only (`icicle/config/advanced.yml.in:28-47`) | Opt-in, never default | **a** | Roadmap: `linux-hardened` option |
| 7 | Firewall toggle and port lists in GUI | `modules/nixos/networking/module.yml:17-31` | Exposes the NixOS firewall | **a** | ufw default deny incoming |
| 8 | Firewall on (inherited NixOS default, not set by SnowflakeOS) | nixpkgs `56c02bc` `nixos/modules/services/networking/firewall.nix:73-75` (`default = true`), `:175-177` (`allowPing` true) | Stateful deny-inbound | **a** | ufw |
| 9 | sudo on, wheel needs a password (inherited) | nixpkgs `56c02bc` `nixos/modules/security/sudo.nix:46-48`, `:57-59`; installer puts the user in `wheel` (`icicle/config/basic/systems/ARCH/HOSTNAME/default.nix:25`) | Stock NixOS | **a** | Omarchy sudo; note its timed `99-omarchy-nopasswd-*` grants (`etc/tmpfiles.d/omarchy-nopasswd-sudo.conf:5`) |
| 10 | Root password optional, else root locked | `icicle/src/utils/install.rs:213` (`nixos-install --no-root-passwd`), `:271-272`; root prompt only in Advanced (`advanced.yml.in:11-12`) | Root has no password unless the user sets one | **a** | Roadmap #26 "lock root" |
| 11 | User password hashed with `chpasswd -c SHA512` | `icicle/src/utils/install.rs:230-236` | SHA-512 crypt, not yescrypt | **d** (do not copy) / derived **b** check | Omarchy 4.0.6's `login.defs` says YESCRYPT, but its installer still left `$6$` hashes for root and the user (measured, see below) |
| 12 | Optional autologin on the installed system; disables getty/autovt tty1 | `icicle/src/utils/install.rs:515-533`; `modules/nixos/gnome/default.nix:28-30` | Autologin with **no disk encryption available** | **d** / derived **b** check | Omarchy: the ISO sets autologin only knowing the target is encrypted (`install/login/sddm.sh:1-3`) |
| 13 | No disk encryption in the installer | 0 of 11 files in `icicle/src` and `icicle/icicle-helper/src` match `luks\|crypt`; 7 of them do handle partitioning | No LUKS, no TPM | n/a (gap) | Omarchy already has LUKS |
| 14 | Live ISO: polkit grants wheel everything | `snowflakeos-iso/modules/nixos/installation/base.nix:7-19` (the file itself says "dangerous… shouldn't be used anywhere else") | `polkit.Result.YES` for wheel | **c** (live media only) / derived **b** check | Omarchy ships no polkit rules files, only an agent under `shell/plugins/polkit/` |
| 15 | Live ISO: empty password and autologin | `base.nix:40-50`, `installation/graphical.nix:36-39` | Live media convenience | **c** | n/a |
| 16 | Installer helper gated by polkit `auth_admin_keep` | `icicle/data/org.snowflakeos.Icicle.policy.in.in:10-15` | Admin auth for the helper | **c** | Installer only |
| 17 | Extra trusted binary cache `snowflakeos.cachix.org` + key | `modules/nixos/snowflakeos/default.nix:110-113` | Second signed source of system binaries | **a** | Same supply-chain question as third-party pacman repos. Covered by our pacman SigLevel/mirror audits |
| 18 | Flatpak option + Flathub remote, no permission hardening | `icicle/config/advanced.yml.in:20-23`, `icicle/config/flatpak.yml.in:15`, `icicle/config/flatpak/systems/ARCH/HOSTNAME/modules.nix:6` | Plain `services.flatpak.enable` | **a** | Roadmap Flatpak role (and D-01) |
| 19 | AppImage via `appimage-run` (opt-in) | `modules/nixos/packagemanagers/default.nix:15-19` | Unsandboxed AppImages | n/a | Not hardening |
| 20 | `binaryCompat`: nix-ld + envfs (default off) | `modules/nixos/snowflakeos/default.nix:39-43`, `:61-85` | FHS compatibility for foreign binaries | **c** | NixOS-only |
| 21 | `programs.mtr.enable` (privileged mtr wrapper) | `modules/nixos/snowflakeos/default.nix:95-97` | *Adds* a capability/setuid wrapper | **d** (anti-hardening, minor) | Don't copy |
| 22 | gnupg-agent with SSH support | `default.nix:98-101` | Key-agent convenience | n/a | Omarchy-neutral; relevant to the commit-signing role only |
| 23 | Immutability / rollback | Not configured. It comes from NixOS generations; homepage tagline only | Declarative rebuilds, boot-menu rollback | **c** | Omarchy: `limine-snapper-sync` snapshots (`docs/upstream-baseline.md:17`); immutability is aspirational on our roadmap |
| 24 | `allowUnfree` and `NIXPKGS_ALLOW_UNFREE=1` | `snowflakeos-modules/flake.nix:32`; `icicle/config/basic/systems/ARCH/HOSTNAME/default.nix:29-30` | Licence policy | n/a | Not security |
| 25 | GRUB `useOSProber` | `biosboot/default.nix:18`, `efiboot/default.nix:35` | Probes other OSes at boot | n/a | Not relevant (Limine) |

**Searched for and absent.** We swept snowflakeos-modules (`*.nix`, `*.yml`),
snowflakeos-iso (`*.nix`) and icicle (`*.nix`, `*.yml.in`, `*.rs`) with
`git grep -il`. Each term below matched **0 files**: `sysctl`,
`kernelParams`, `kernel\.`, `apparmor`, `selinux`, `lanzaboote`,
`secureboot`, `secure-boot`, `tpm`, `malloc`, `usbguard`, `sudo`, `doas`,
`pam`, `autoUpgrade`, `dnscrypt`, `resolved`, `dns`, `telemetry`, `luks`,
`crypt`.

The sweep was controlled. On the same file sets, `boot.loader` matched
5 files, `flatpak` 4, `fwupd` 1, `firewall` 1 and `hardened` 1, so the
search does find terms that are there.

So SnowflakeOS ships **no** sysctl hardening, no kernel command-line
hardening, no MAC, no Secure Boot or TPM, no hardened malloc, no USB policy,
no DNS privacy, no PAM or faillock tuning, no sudo or doas policy and no
automatic updates.

**Telemetry:** none configured in the reviewed repos. We did not audit
whether nix-software-center, snow or nix-data contact network endpoints on
their own; that is UNVERIFIED.

## Adoptable items (b), ranked

None of these is a SnowflakeOS hardening feature that we lack. Items 1 and 2
are small hygiene settings it has. Items 3 to 5 are audit checks suggested
by its anti-patterns. All are audit-only (`aegis_findings`) unless noted, so
none can break the desktop.

1. **Firmware-update posture check (from #4).**
   - **Arch equivalent:** INFO when `fwupd` is not installed. When it is
     installed, report `fwupdmgr get-updates --json` (pending updates and
     HSI) and whether `fwupd-refresh.timer` is enabled.
   - **Do not auto-apply firmware**, and keep Omarchy's on-demand
     `omarchy-update-firmware` flow.
   - **Risk:** a refresh contacts LVFS (a metadata download, a small privacy
     point). Enabling the timer would be a behaviour change, so it would need
     an `aegis_firmware_*` variable that defaults to off, plus an
     open-decisions entry.
   - **Test:** plant a state with fwupd absent and assert that the INFO
     finding fires.

2. **`/tmp` is tmpfs (from #3).**
   - **Check:** `findmnt -no FSTYPE /tmp` should be `tmpfs`. WARN if `/tmp`
     is on persistent btrfs, or if `tmp.mount` is masked.
   - It fits next to roadmap #17's `/tmp` `nodev,nosuid`.
   - **Risk:** none for audit-only use. Enforcing it is already roadmap #17's
     territory.
   - Stock Omarchy 4.0.6 has it (measured below), so this is a regression
     guard, not a fix.

3. **Polkit blanket-grant audit (from #14).**
   - **Check:** WARN on any rule in `/etc/polkit-1/rules.d/*.rules` or
     `/usr/share/polkit-1/rules.d/*.rules` that returns `polkit.Result.YES`
     with no `action.id` condition. This is exactly SnowflakeOS's ISO rule
     leaking onto an installed system.
   - Stock Omarchy ships no rules files (tree at `dde0d12`). But packages
     (Flatpak, libvirt, etc.) do ship rules files, so match only an
     unconditional YES.
   - **Risk:** false positives on rules that check `subject.isInGroup` *and*
     an action id. The matcher has to be conservative, and it needs a
     planted-rule test.

4. **Autologin-without-encryption audit (from #12).**
   - **Check:** WARN when SDDM autologin is set (`/etc/sddm.conf.d/*`
     `[Autologin] User=`) and the root filesystem is not on a
     `crypto_LUKS` device (`lsblk -no FSTYPE` up the chain of `findmnt /`).
     It encodes Omarchy's own ISO invariant (`install/login/sddm.sh:1-3`).
   - **Risk:** none for audit-only use. Where the SDDM drop-in lives on
     Omarchy 4.0.6 is `/etc/sddm.conf.d/autologin.conf` (`[Autologin]`,
     `User=`, `Session=omarchy.desktop`), measured below.

5. **Password-hash strength audit (from #11).**
   - **Check:** INFO/WARN when a human account's `/etc/shadow` hash prefix
     is `$6$` (SHA-512 crypt) rather than `$y$` (yescrypt). Report
     `ENCRYPT_METHOD` from `/etc/login.defs`.
   - **Risk:** reading `/etc/shadow` needs root. Log only the prefix, never
     the hash. On Omarchy 4.0.6 this check **fires today**: both hashes are
     `$6$` although `login.defs` says YESCRYPT (measured below). It applies to the current
     `shadow` package.

## Not transferable or not worth taking

- **(c)** NixOS generations and declarative rollback (#23), the cachix
  substituter model (#17), nix-ld/envfs (#20), and the live-ISO polkit and
  empty-password settings (#14, #15).
- **(d)** Don't copy these: the privileged `mtr` wrapper (#21), autologin
  offered without any disk encryption (#12, #13), and SHA-512 crypt for
  passwords (#11).

## Checked on a live Omarchy 4.0.6 install (2026-10-21)

These were measured on the VirtualBox test VM (`tests/vm/`). It is a default
encrypted install from the signed 4.0.6 ISO, with `linux-omarchy 7.2.8-9` and
`shadow 4.20.0.arch1-1`. The playbook had already been applied, but it changes
none of these.

| Question | Result |
|---|---|
| `/tmp` filesystem | `tmpfs rw,nosuid,nodev,size=…` (`tmp.mount` is `static`) |
| SDDM autologin | `/etc/sddm.conf.d/autologin.conf`: `[Autologin] User=aegis`, `Session=omarchy.desktop` |
| Root filesystem | btrfs on `/dev/mapper/root`, a `crypto_LUKS` partition, so autologin is paired with encryption, as Omarchy intends |
| `ENCRYPT_METHOD` in `/etc/login.defs` | `YESCRYPT` |
| Hash prefixes in `/etc/shadow` | `root: $6$`, `aegis: $6$`, **SHA-512 crypt, not yescrypt** |
| polkit rules | `/etc/polkit-1/rules.d/` empty; `/usr/share/polkit-1/rules.d/` has 7 package rules files plus one `.example` |
| fwupd | not installed; `fwupd-refresh.timer` not found |

**The SHA-512 hashes are a finding about Omarchy.** `bin/omarchy-provision-owner:810-811`
at `dde0d12` calls `chpasswd` without `-c`, so it should follow `login.defs`
and write yescrypt. The 4.0.6 ISO install still wrote `$6$`. The cause is
therefore in code this review did not read, most likely the ISO-side
installer. That is UNVERIFIED. Changing the password once with `passwd`
rewrites it as yescrypt. That is also UNVERIFIED on this install.

## UNVERIFIED in this note

- Which Omarchy installer code writes the `$6$` hashes.
- Whether nix-software-center, snow or nix-data make network calls of their
  own.
- Licences of repos that were not cloned (taken from GitHub API metadata
  only).
