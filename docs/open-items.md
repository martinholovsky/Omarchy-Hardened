# Open items

What is still open for work that is already implemented: untested paths,
decisions the owner still has to make, steps only the user can take, and
known harness problems. This is the one list. New hardening ideas are in
[roadmap.md](roadmap.md); the decisions themselves are in
[open-decisions.md](open-decisions.md). Close an item by deleting its row in
the change that closes it.

Last reviewed: 2026-10-27, on `feat/d27-d30`. The repo is public with `main`
protected (ruleset `protect-main`); PRs #19 to #21 merged, CI on `main`
`67/67 checks passed`. VM on 2026-10-27 (`pre-aegis-updated`): `tests/vm/run.sh`
passed in full with D-27 to D-30; `pkexec` then recorded failures in the tally
(D-27), and `linux-hardened` applied and checked clean (D-29, D-30), which
also found D-31. VM on 2026-10-26 (`pre-aegis-hw`, a real YubiKey): FIDO2
enrolment, D-04 with one key, and the playbook run as root with one touch
(`failed=0`).

## 1. Not tested yet

| Item | Tested so far | What closes it |
|---|---|---|
| A run on real hardware | VirtualBox VM and container only | Follow [operating-notes.md](operating-notes.md) §2 on a machine you have backed up, then update the table in §1 there |
| Booting `linux-hardened` (D-02) | VM (2026-10-27, booted twice from the Limine menu, 7.2.10-hardened1-3): with D-29 the playbook applies (`failed=0`) and a `--check` after it is clean (`changed=0`); `sysctl.compiled_out` INFO names the two compiled-out keys; AppArmor (83 profiles, complain), D-01 user namespaces and `bwrap` work; `aegis-agent` cannot start a container there and the audit WARNs (`agent.kernel_overlay`, D-30, by design). After a boot, ufw had reset `rp_filter` to 1 (D-31, fixed). Not booted on hardware | Once on hardware |
| OpenSnitch 1.8.0 (D-09) | 1.7.2 only, with `hide_systray_warning` working around its UI crash. Arch ships 1.7.2-4 (last updated 2026-01-10); upstream 1.8.0 (2025-12-15) has the fix. The Arch package has been flagged out of date since 2025-12-15, so nothing is left for the owner to do. Still 1.7.2-4 on 2026-10-27 (archlinux.org package search) | Once Arch ships 1.8.0, check whether `hide_systray_warning` is still needed |
| FIDO2 second factor for sudo (D-04) | Container: planted `pam_u2f` lines and `/etc/fido2/fido2` files, 0, 1 and 2 keys. VM (2026-10-26, `pre-aegis-hw`, YubiKey via `usbattach`): one key enrolled with `omarchy-setup-security-fido2` (it reads the key's PIN from a terminal, so it ran in the guest's own terminal); the playbook keeps `pam_u2f` `sufficient` and WARNs; run as root with the key plugged in it took one touch. The two-key path (`required`) is untested: it needs a second key | Enrol the first key with `omarchy-setup-security-fido2`. It registers **one** key, and on a second run it stops with "already registered" (read at `dde0d12`, `bin/omarchy-setup-security-fido2`). Append the second key to your line in `/etc/fido2/fido2` with `pamu2fcfg -n` (per `pamu2fcfg(1)`; not run here). Then re-run and check that sudo asks for the key **and** the password |
| Commit signing with an `ed25519-sk` key (D-08) | Container: key strings only, including refusal of a non-`sk` key | Set `aegis_commit_signing_pubkey`, make a commit, and check `git log --show-signature` |
| Tailscale (D-10, D-24) | VM (2026-10-25) against Headscale: `tests/vm/tailscale.sh` passed (a tailnet peer reaches a port ufw denies, the audit WARNs; in `nodivert` mode the port is closed and the finding passes; SSH findings). Its `nodivert` control failed once and passed on the rerun in the same VM; cause unknown, the control now waits longer and prints diagnostics | The tailscale.com login itself stays untested: Omarchy runs that step, not this playbook |
| Audit noise on a long-lived install | Only fresh installs | Run the audit on a machine that has had packages installed for weeks |

## 2. Waiting on the owner

| Item | Why it is open |
|---|---|
| AppArmor enforce mode (D-05) | Profiles load in complain mode. After about a week of denials (`journalctl -k \| grep apparmor`), choose profiles for `aegis_apparmor_enforce`, which is empty |
| `linux-hardened` as the default boot entry (D-02) | The role never changes the default entry. Switching is a manual step after one clean boot (see §1) |
| A `--check` run cannot see live sysctl drift (D-32) | Found 2026-10-27: in check mode the sysctl role skips its apply and live assert, so `run.sh`'s post-reboot check and the D-11 drift check missed `rp_filter`=1 (D-31). Recommendation in [open-decisions.md](open-decisions.md) |
| `hardened_malloc` (D-03) | Deferred until it reaches the official repos. Checked 2026-10-27: not there (archlinux.org package search, 0 results); AUR only, `14-1` |
| Roadmap Tier 2 and Tier 3 | Each item needs a go-ahead ([roadmap.md](roadmap.md)). **Owner, 2026-10-23: none yet.** First the run on real hardware (§1) must pass (the full VM run passed on 2026-10-23), because every role added before the first hardware run widens what that run has to vouch for. Revisit when the real-hardware row in §1 is closed; the items with no desktop effect (18a, #14, #16) come first |

## 3. Steps for the user on their own machine

These are the two WARNs a default Omarchy 4.0.6 install still shows after a
run. Both are correct.

- **`accounts.password_hash`:** the installer left SHA-512 (`$6$`) hashes for
  root and the user, although `login.defs` says YESCRYPT. Run `sudo passwd
  root` and `sudo passwd $USER` once each. Measured in the VM (2026-10-22):
  `sudo passwd root` turned root's `$6$` into `$y$` (yescrypt), even with the
  same password, because `pam_unix` without a hash option follows
  `login.defs`. Plain `passwd` as the user refuses the same password ("The
  password has not been changed"), so keeping the password needs `sudo`. The
  `sudo passwd $USER` path uses the same PAM stack but was not run here. The
  container test checks that a yescrypt hash reads as PASS. The playbook never
  resets passwords.
- **`git.commit_signing`:** no signing key is named. Set
  `aegis_commit_signing_pubkey` to your `sk-ssh-ed25519` public key.

## 4. Harness and tooling

| Item | Detail |
|---|---|
| Container test time | The `container-test` job took 18m46s to 26m56s over the last nine green CI runs (2026-10-26 and 2026-10-27, `gh run list`), against `timeout-minutes: 35`. The longest, 26m56s, was PR #22 at 70 checks; the same code took 20m37s on `main` minutes later, so most of the spread is the runner, not the suite. Nothing is cached: every run starts from the pinned Arch image, runs `pacman -Syu` and installs the collections. Since 2026-10-25 every `---` line of `inside.sh` shows the seconds since the start (`[t+Ns]`) and the run ends with `elapsed:`. Measured on PR #9's CI run (2026-10-25, 1287 s in the container): setup (`pacman -Syu` and the collections) took 16 s, so caching an image would save about 1%; the rest is spread over 33 sections of playbook runs, 30 to 110 s each (largest: D-11 drift 109 s, D-04 FIDO2 104 s, polkit 76 s, `su` logins 68 s). Next, if the time matters: split the sections across parallel CI jobs, or make each playbook run cheaper. The VM side (`run.sh` 2026-10-27, `profile_tasks`): run 1 took 12m32s, run 2 9m58s, run 3 (`--check`) 11m41s; the slowest tasks of run 1 were the D-11 playbook copy (125 s), the integrity sweep (90 s), two AppArmor complain-mode loops (84 s and 71 s) and two sysctl reads (45 s each). Revisit at the latest when a CI run takes more than 28 minutes (80% of the timeout) |
