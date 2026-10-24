# Open items

What is still open for work that is already implemented: untested paths,
decisions the owner still has to make, steps only the user can take, and
known harness problems. This is the one list. New hardening ideas are in
[roadmap.md](roadmap.md); the decisions themselves are in
[open-decisions.md](open-decisions.md). Close an item by deleting its row in
the change that closes it.

Last reviewed: 2026-10-23, on `docs/closure-corrections` (PR #4). A full
`tests/vm/run.sh` from `pre-aegis-updated` at `c3d9673` exited 0 on a quiet
host (20:12 to 20:52 UTC): run 2 and the post-reboot `--check` both at
`changed=0`, every post-reboot check PASS including step 4, and 2 WARN, the
two in §3. CI green on `c3d9673` (lint, live sysctl apply, container test).

## 1. Not tested yet

| Item | Tested so far | What closes it |
|---|---|---|
| A run on real hardware | VirtualBox VM and container only | Follow [operating-notes.md](operating-notes.md) §2 on a machine you have backed up, then update the table in §1 there |
| Booting `linux-hardened` (D-02) | The VM checks only that Limine lists it after `linux-omarchy`. It was never booted | Pick it once in the Limine menu, run `--check`, and confirm that the sysctl values, AppArmor and `aegis-agent` work on it |
| FIDO2 second factor for sudo (D-04) | Container: planted `pam_u2f` lines and `/etc/fido2/fido2` files, 0, 1 and 2 keys. VM: runs in its not-set-up state (INFO). No real key has been used; since 2026-10-24 the VM can have one: snapshot `pre-aegis-hw` has xHCI, and a YubiKey attached after boot shows up in the guest as `1050:0407` with a user-accessible `/dev/hidraw*` ([tests/vm/README.md](../tests/vm/README.md) §5c). Enrolment has not been run there yet | On hardware: enrol the first key with `omarchy-setup-security-fido2`. It registers **one** key, and on a second run it stops with "already registered" (read at `dde0d12`, `bin/omarchy-setup-security-fido2`). Append the second key to your line in `/etc/fido2/fido2` with `pamu2fcfg -n` (per `pamu2fcfg(1)`; not run here). Then re-run and check that sudo asks for the key **and** the password |
| Commit signing with an `ed25519-sk` key (D-08) | Container: key strings only, including refusal of a non-`sk` key | Set `aegis_commit_signing_pubkey`, make a commit, and check `git log --show-signature` |
| Tailscale (D-10, D-24) | VM spike (2026-10-24) against Headscale: a tailnet peer reached a port ufw denies, with the D-10 rule absent and present (D-24). `tests/vm/tailscale.sh` scripts that and the new WARN; not run yet | One `tests/vm/tailscale.sh` run after `tests/vm/run.sh`. The tailscale.com login itself stays untested: Omarchy runs that step, not this playbook |
| Firewall with real traffic | Container, against Omarchy's seeded ufw rules | LocalSend refused, Docker DNS still working, SSH only where allowed |
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
| Container test time | The `container-test` job took 15m53s and 17m55s in the last two CI runs (`c3d9673`, `cadc647`; 22m03s at most over the last four), against `timeout-minutes: 35`. Revisit when a CI run takes more than 28 minutes (80% of the timeout): split the job or raise the limit |
