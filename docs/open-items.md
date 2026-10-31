# Open items

What is still open for work that is already implemented: untested paths,
decisions the owner still has to make, steps only the user can take, and
known harness problems. This is the one list. New hardening ideas are in
[roadmap.md](roadmap.md); the decisions themselves are in
[open-decisions.md](open-decisions.md). Close an item by deleting its row in
the change that closes it.

Last reviewed: 2026-10-31, on `main` after PRs #28 and #29 (merges `6c9dbf6`
and `906cbba`, docs only; the date, package, release and shard-time triggers below
re-checked, none met; CI green
on `main`, runs 41142579036 and 41181862161). Before that: 2026-10-30, on
`main` after PR #27 (merge `af44d01`; D-33, D-34 and D-35 closed; CI green on
the PR head and on `main`, runs 41118567126 and 41120240079). Before that: 2026-10-28, on `main` after PRs #22 to #25 (D-27 to D-32). The
repo is public with `main` protected (ruleset `protect-main`); CI on PR #25
`72/72 checks passed`. VM on 2026-10-28 (`pre-aegis-updated` after an in-place
`pacman -Syu`): `tests/vm/run.sh` passed in full; its post-reboot `--check`,
which now sees live sysctl values (D-32), was clean; the drift check reported a
live `rp_filter` change, and showed D-33. VM on 2026-10-27: D-27 (`pkexec`, SSH
and desktop terminal), D-29/D-30 on `linux-hardened`, D-31 on both kernels. VM
on 2026-10-26 (`pre-aegis-hw`, a real YubiKey): FIDO2 enrolment, D-04 with one
key, and the playbook run as root with one touch (`failed=0`).

## 1. Not tested yet

| Item | Tested so far | What closes it |
|---|---|---|
| A run on real hardware | VirtualBox VM and container only. **Owner, 2026-10-30: deferred one month; revisit on 2026-11-30** | Follow [operating-notes.md](operating-notes.md) §2 on a machine you have backed up, then update the table in §1 there |
| Booting `linux-hardened` (D-02) | VM (2026-10-27, booted twice from the Limine menu, 7.2.10-hardened1-3): with D-29 the playbook applies (`failed=0`) and a `--check` after it is clean (`changed=0`); `sysctl.compiled_out` INFO names the two compiled-out keys; AppArmor (83 profiles, complain), D-01 user namespaces and `bwrap` work; `aegis-agent` cannot start a container there and the audit WARNs (`agent.kernel_overlay`, D-30, by design). After a boot, ufw had reset `rp_filter` to 1 (D-31, fixed). Not booted on hardware | Once on hardware (deferred with the run on real hardware, to 2026-11-30) |
| OpenSnitch 1.8.0 (D-09) | 1.7.2 only, with `hide_systray_warning` working around its UI crash. Arch ships 1.7.2-4 (last updated 2026-01-10); upstream 1.8.0 (2025-12-15) has the fix. The Arch package has been flagged out of date since 2025-12-15, so nothing is left for the owner to do. Still 1.7.2-4 on 2026-10-30 (archlinux.org package search). Omarchy's own repo (`pkgs.omarchy.org/stable`, 247 packages) has no `opensnitch` either (VM, 2026-10-31). The AUR's `opensnitch-git` is not a release either: its PKGBUILD builds whatever upstream's default branch holds at build time, with no checksum (`sha256sums=('SKIP')`), and `1.8.0.r224` is only the version its maintainer last published (read 2026-10-31) | Once Arch ships 1.8.0, check whether `hide_systray_warning` is still needed |
| FIDO2 second factor for sudo (D-04) | Container: planted `pam_u2f` lines and `/etc/fido2/fido2` files, 0, 1 and 2 keys. VM (2026-10-26, `pre-aegis-hw`, YubiKey via `usbattach`): one key enrolled with `omarchy-setup-security-fido2` (it reads the key's PIN from a terminal, so it ran in the guest's own terminal); the playbook keeps `pam_u2f` `sufficient` and WARNs; run as root with the key plugged in it took one touch. The two-key path (`required`) is untested: it needs a second key | Enrol the first key with `omarchy-setup-security-fido2`. It registers **one** key, and on a second run it stops with "already registered" (read at `dde0d12`, `bin/omarchy-setup-security-fido2`). Append the second key to your line in `/etc/fido2/fido2` with `pamu2fcfg -n` (per `pamu2fcfg(1)`; not run here). Then re-run and check that sudo asks for the key **and** the password. A software authenticator as the second key was considered on 2026-10-30 (`soft-fido2` 0.4.56 from PyPI, which emulates a key through `/dev/uhid` and would run as root in the VM): **owner, 2026-10-30: deferred**, because it is an experimental personal project with six releases in four weeks. Revisit when a second hardware key is at hand, or when a software authenticator is packaged in Arch's official repos |
| Tailscale (D-10, D-24) | VM (2026-10-25) against Headscale: `tests/vm/tailscale.sh` passed (a tailnet peer reaches a port ufw denies, the audit WARNs; in `nodivert` mode the port is closed and the finding passes; SSH findings). Its `nodivert` control failed once and passed on the rerun in the same VM; cause unknown, the control now waits longer and prints diagnostics | The tailscale.com login itself stays untested: Omarchy runs that step, not this playbook |
| Audit noise on a long-lived install | VM (2026-10-30), hardened 4.0.6 plus 13 common packages (docker, docker-compose, wireshark-qt, firejail, nmap, tcpdump, gimp, vlc, libreoffice-fresh, nodejs, npm, go, flatpak), docker enabled, and one Flathub app (Flatseal), then two applies: one FAIL that ended every run `failed=1`, VLC's plugin cache (D-34, now accepted drift), and one new WARN, Omarchy's own `codex` connecting out (D-35, expected, §3). Setuid (firejail), file capabilities (wireshark), docker and the Flatpak app added nothing above INFO. What a test cannot give: weeks of upgrades, and time-based checks such as the upgrade age | The same on a machine in daily use |

## 2. Waiting on the owner

| Item | Why it is open |
|---|---|
| AppArmor enforce mode (D-05) | Profiles load in complain mode. After about a week of denials (`journalctl -k \| grep apparmor`), counted from the run on real hardware (§1, deferred to 2026-11-30), choose profiles for `aegis_apparmor_enforce`, which is empty |
| `linux-hardened` as the default boot entry (D-02) | The role never changes the default entry. Switching is a manual step after one clean boot (see §1) |
| Omarchy 4.5.0 changes two things this repo depends on | Found 2026-10-29 in `v4.5.0-rc2` ([upstream-baseline.md](upstream-baseline.md)): the shebang rewrite of `/usr/bin/powerprofilesctl` is gone, so D-22's expected-drift entry for it would accept a change with no benign cause; and AUR builds run under `omarchy-update`'s sudo authorization. Measured 2026-10-30 in the VM: `omarchy-power-profiles-daemon` 0.30-3 is already in Omarchy's repo; installed in place of the stock package, `pacman -Qkk` shows 0 altered files and `powerprofilesctl` starts `#!/usr/bin/python3`, so on 4.5 the D-22 entry would match nothing benign. When 4.5.0 ships: re-run the baseline diff, check in the VM whether `powerprofilesctl` still drifts, and decide whether to drop the D-22 entry (a security setting, so the owner's call) and whether the AUR change needs an audit finding or a line in the threat model |
| `hardened_malloc` (D-03) | Deferred until it reaches the official repos. Checked 2026-10-30: not there (archlinux.org package search, 0 results); AUR only, `14-1`, no longer flagged out of date (`hardened-malloc-git` there builds whatever `main` holds at build time, with no checksum; its listed `13+r728` is only the version last published, 2025-03-11; PKGBUILD read 2026-10-31). Not in Omarchy's own repo either (`pkgs.omarchy.org/stable`, 247 packages; VM, 2026-10-31) |
| Roadmap Tier 2 and Tier 3 | Each item needs a go-ahead ([roadmap.md](roadmap.md)). **Owner, 2026-10-23: none yet.** First the run on real hardware (§1) must pass (the full VM run passed on 2026-10-23), because every role added before the first hardware run widens what that run has to vouch for. Revisit when the real-hardware row in §1 is closed (that run is deferred to 2026-11-30); the items with no desktop effect (18a, #14, #16) come first |

## 3. Steps for the user on their own machine

These are the WARNs a default Omarchy 4.0.6 install still shows after a
run. All are correct.

- **`accounts.password_hash`:** the installer left SHA-512 (`$6$`) hashes for
  root and the user, although `login.defs` says YESCRYPT. Run `sudo passwd
  root` and `sudo passwd $USER` once each. Measured in the VM (2026-10-22):
  `sudo passwd root` turned root's `$6$` into `$y$` (yescrypt), even with the
  same password, because `pam_unix` without a hash option follows
  `login.defs`. Plain `passwd` as the user refuses the same password ("The
  password has not been changed"), so keeping the password needs `sudo`.
  `sudo passwd $USER` was measured too (VM, 2026-10-30): the user's `$6$`
  became `$y$` with the same password, sudo still accepted it, and the
  finding then named only root. The
  container test checks that a yescrypt hash reads as PASS. The playbook never
  resets passwords.
- **`git.commit_signing`:** no signing key is named. Create one on your
  FIDO2 key and set `aegis_commit_signing_pubkey` to its `.pub` file
  (measured in the VM with a YubiKey, 2026-10-30):
  - install `libfido2` first (`sudo pacman -S libfido2`) unless you ran
    `omarchy-setup-security-fido2`, which installs it; without it
    `ssh-keygen` fails with "libfido2.so.1: cannot open shared object file";
  - `ssh-keygen -t ed25519-sk -f ~/.ssh/id_ed25519_sk` asks for the key's
    **PIN** if it has one. Type it; **do not touch the key at the PIN
    prompt**: a YubiKey touch types an OTP, which counts as a wrong PIN
    (8 wrong in a row block the PIN, and only a reset that erases the key's
    FIDO2 credentials unblocks it). Touch only when it blinks after the PIN;
  - every release tag (`git tag -a`) then needs a touch within about 30 s;
    commits are not signed (owner, 2026-10-30; `aegis_commit_signing_commits:
    true` signs them too). A missed touch fails with the misleading
    "Couldn't sign message: invalid format".
- **`egress.unknown_programs`** (once something in your session has run it;
  what starts it was not traced): Omarchy's own
  `codex`, installed with mise under your home, connects out, and no package
  owns it (D-35). If you trust it, add
  `/home/*/.local/share/mise/installs/codex/*/bin/codex` to
  `aegis_egress_known`.

## 4. Harness and tooling

| Item | Detail |
|---|---|
| Container test time | The single `container-test` job reached 28m19s on `main` (2026-10-28T07:45), past the 28-minute revisit line of its 35-minute timeout. Owner, 2026-10-29: raise the timeout, then shard. Done 2026-10-30: three shards (`tests/container/run.sh 1` to `3`, cut at `SHARD_STARTS`) run in parallel; each runs the common setup (46 s in CI) and then about 480 to 630 s of sections, by the 2026-10-28 CI section times; `container-test` now only aggregates them. Locally, on a loaded host, the shards took 1038, 1188 and 1083 s (24/24, 21/21, 47/47) against 4068 s for one full run the day before. First CI run (PR #27, run 41100690159, 2026-10-30): shards 657, 695 and 625 s as jobs (529, 678 and 586 s in the container; 24/24, 21/21, 47/47 in their logs), the aggregate `container-test` 5 s, the whole run about 12 minutes against up to 28m19s for the single job before. Revisit when a shard takes more than 20 minutes (80% of its 25-minute timeout), or rebalance `SHARD_STARTS` from that run's `[t+Ns]` marks |
| VM snapshot `pre-aegis-updated` is behind the package mirror | 2026-10-28: run 1 of `tests/vm/run.sh` failed installing OpenSnitch, because `stable-mirror.omarchy.org` returned 404 for `python-platformdirs-4.13.0-1`, a version the snapshot's pacman databases still name. Worked around by running `pacman -Syu` in the restored VM before `run.sh`. `tests/vm/update-snapshot.sh` refreshes it, but it deletes and retakes `pre-aegis-updated`, which `pre-aegis-hw` (the enrolled YubiKey) hangs off. Owner, 2026-10-29: keep the workaround, so `pre-aegis-hw` is not put at risk; revisit at the next full VM run, when a stale snapshot costs a long `pacman -Syu` |
