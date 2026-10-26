# Open items

What is still open for work that is already implemented: untested paths,
decisions the owner still has to make, steps only the user can take, and
known harness problems. This is the one list. New hardening ideas are in
[roadmap.md](roadmap.md); the decisions themselves are in
[open-decisions.md](open-decisions.md). Close an item by deleting its row in
the change that closes it.

Last reviewed: 2026-10-25, on `test/tailscale-headscale`. A full
`tests/vm/run.sh` from `pre-aegis-hw` at `e0d18ea` exited 0: run 2 and the
post-reboot `--check` at `changed=0`, every post-reboot check PASS including
the OpenSnitch prompt check (UI running, a new program got out), and 2 WARN,
the two in §3. A mutant (the UI's prompt default back to deny) made that
check fail. `tests/vm/tailscale.sh` passed on its rerun in the same VM; its
`nodivert` control had failed once (see §1).

## 1. Not tested yet

| Item | Tested so far | What closes it |
|---|---|---|
| A run on real hardware | VirtualBox VM and container only | Follow [operating-notes.md](operating-notes.md) §2 on a machine you have backed up, then update the table in §1 there |
| Booting `linux-hardened` (D-02) | The VM checks only that Limine lists it after `linux-omarchy`. It was never booted | Pick it once in the Limine menu, run `--check`, and confirm that the sysctl values, AppArmor and `aegis-agent` work on it |
| polkit's PAM stack on Omarchy 4.0.6 | Read only: `omarchy-setup-security-fido2` as installed in the 4.0.6 VM writes `/etc/pam.d/polkit-1` with `auth required pam_unix.so` and no `system-auth`, so faillock may not count polkit password failures; upstream at `cbd44ba` writes `include system-auth`. No role touches this file | Ten wrong passwords at a polkit prompt on 4.0.6, then check the faillock tally; decide whether a role should own `polkit-1` |
| OpenSnitch 1.8.0 (D-09) | 1.7.2 only, with `hide_systray_warning` working around its UI crash. Arch ships 1.7.2-4 (last updated 2026-01-10); upstream 1.8.0 (2025-12-15) has the fix. The Arch package has been flagged out of date since 2025-12-15 (checked 2026-10-26), so nothing is left for the owner to do | Once Arch ships 1.8.0, check whether `hide_systray_warning` is still needed |
| FIDO2 second factor for sudo (D-04) | Container: planted `pam_u2f` lines and `/etc/fido2/fido2` files, 0, 1 and 2 keys. VM (2026-10-26, `pre-aegis-hw`, YubiKey via `usbattach`): one key enrolled with `omarchy-setup-security-fido2` (it reads the key's PIN from a terminal, so it ran in the guest's own terminal); the playbook keeps `pam_u2f` `sufficient` and WARNs; run as root with the key plugged in it took one touch. The two-key path (`required`) is untested: it needs a second key | Enrol the first key with `omarchy-setup-security-fido2`. It registers **one** key, and on a second run it stops with "already registered" (read at `dde0d12`, `bin/omarchy-setup-security-fido2`). Append the second key to your line in `/etc/fido2/fido2` with `pamu2fcfg -n` (per `pamu2fcfg(1)`; not run here). Then re-run and check that sudo asks for the key **and** the password |
| Commit signing with an `ed25519-sk` key (D-08) | Container: key strings only, including refusal of a non-`sk` key | Set `aegis_commit_signing_pubkey`, make a commit, and check `git log --show-signature` |
| Tailscale (D-10, D-24) | VM (2026-10-25) against Headscale: `tests/vm/tailscale.sh` passed (a tailnet peer reaches a port ufw denies, the audit WARNs; in `nodivert` mode the port is closed and the finding passes; SSH findings). Its `nodivert` control failed once and passed on the rerun in the same VM; cause unknown, the control now waits longer and prints diagnostics | The tailscale.com login itself stays untested: Omarchy runs that step, not this playbook |
| Audit noise on a long-lived install | Only fresh installs | Run the audit on a machine that has had packages installed for weeks |

## 2. Waiting on the owner

| Item | Why it is open |
|---|---|
| AppArmor enforce mode (D-05) | Profiles load in complain mode. After about a week of denials (`journalctl -k \| grep apparmor`), choose profiles for `aegis_apparmor_enforce`, which is empty |
| `linux-hardened` as the default boot entry (D-02) | The role never changes the default entry. Switching is a manual step after one clean boot (see §1) |
| `hardened_malloc` (D-03) | Deferred |
| Licence check before going public (D-12) | The repo is Apache-2.0. The toolchain it invokes (ansible-core, community.general) is GPL-3.0. That needs a proper look before the repo is public |
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
| Ansible "junk after the JSON data" on a local run | Cause found in the VM (2026-10-22): Arch's `/etc/pam.d/sudo` (package `sudo` 1.9.17.p2-6, unmodified) runs `pam_systemd.so`, which writes an OSC 3008 sequence when the sudo session ends. Over an SSH pty it trails the module JSON. The VM inventory now sets `ansible_ssh_use_tty: false`: 0 warnings, against 1 with the pty, on the same become task, which returned the right result both times. A user's own run uses `ansible_connection: local`, which was not tested; if the warning shows there it is noise from the same source |
| Container test time | The `container-test` job took 15m53s and 17m55s in the last two CI runs (`c3d9673`, `cadc647`; 22m03s at most over the last four), and 22m33s on PR #7 (2026-10-25), against `timeout-minutes: 35`. Nothing is cached: every run starts from the pinned Arch image, runs `pacman -Syu` and installs the collections. Since 2026-10-25 every `---` line of `inside.sh` shows the seconds since the start (`[t+Ns]`) and the run ends with `elapsed:`. Measured on PR #9's CI run (2026-10-25, 1287 s in the container): setup (`pacman -Syu` and the collections) took 16 s, so caching an image would save about 1%; the rest is spread over 33 sections of playbook runs, 30 to 110 s each (largest: D-11 drift 109 s, D-04 FIDO2 104 s, polkit 76 s, `su` logins 68 s). Next, if the time matters: split the sections across parallel CI jobs, or make each playbook run cheaper. Revisit at the latest when a CI run takes more than 28 minutes (80% of the timeout) |
