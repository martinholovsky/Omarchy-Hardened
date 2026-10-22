# Open items

What is still open for work that is already implemented: untested paths,
decisions the owner still has to make, steps only the user can take, and
known harness problems. This is the one list. New hardening ideas are in
[roadmap.md](roadmap.md); the decisions themselves are in
[open-decisions.md](open-decisions.md). Close an item by deleting its row in
the change that closes it.

Last reviewed: 2026-10-22, after PR #2 (`1d13df2`). Evidence at that point:
CI green on `16ffcb9` (lint, live sysctl apply, container test 44/44); the
final VM run from `pre-aegis-updated` exited 0, with run 2 and the
post-reboot `--check` both at `changed=0`.

## 1. Not tested yet

| Item | Tested so far | What closes it |
|---|---|---|
| A run on real hardware | VirtualBox VM and container only | Follow [operating-notes.md](operating-notes.md) §2 on a machine you have backed up, then update the table in §1 there |
| Booting `linux-hardened` (D-02) | The VM checks only that Limine lists it after `linux-omarchy`. It was never booted | Pick it once in the Limine menu, run `--check`, and confirm that the sysctl values, AppArmor and `aegis-agent` work on it |
| FIDO2 second factor for sudo (D-04) | Container: planted `pam_u2f` lines and `/etc/fido2/fido2` files, 0, 1 and 2 keys. No real key; VM USB passthrough needs the PUEL-licensed Extension Pack | On hardware: enrol two keys with `omarchy-setup-security-fido2`, re-run, and check that sudo then asks for the key **and** the password |
| Commit signing with an `ed25519-sk` key (D-08) | Container: key strings only, including refusal of a non-`sk` key | Set `aegis_commit_signing_pubkey`, make a commit, and check `git log --show-signature` |
| Tailscale (D-10) | Container: the ufw rule on `tailscale0` is added and removed. No tailnet login | Log in, set `aegis_overlay_ssh_on_tailscale: true`, and SSH in over the tailnet while LAN SSH is refused |
| Firewall with real traffic | Container, against Omarchy's seeded ufw rules | LocalSend refused, Docker DNS still working, SSH only where allowed |
| `sudo` and `su` share one lockout; a non-wheel user cannot `su` (VM step 4) | Container, with real logins driven by `expect` | Script step 4 in `tests/vm/run.sh` |
| ASan/TSan builds under `vm.mmap_rnd_bits=32` (D-16) | Not tested | Build and run a sanitizer binary on a hardened machine |
| Audit noise on a long-lived install | Only fresh installs | Run the audit on a machine that has had packages installed for weeks |

## 2. Waiting on the owner

| Item | Why it is open |
|---|---|
| Autologin clears the lockout at boot | Omarchy's `/etc/pam.d/sddm-autologin` ends with `pam_faillock.so authsucc`, so after a reboot the successful autologin resets the tally (config read on 4.0.6; the reboot itself was not tested). Changing that is a security trade-off and needs a new D- entry before any code |
| `empower` group at FAIL (D-20 extension) | Added under D-20's rule without a separate decision: systemd 262's `empower.rules` grants every polkit action to that group. Confirm or change the severity |
| AppArmor enforce mode (D-05) | Profiles load in complain mode. After about a week of denials (`journalctl -k \| grep apparmor`), choose profiles for `aegis_apparmor_enforce`, which is empty |
| `linux-hardened` as the default boot entry (D-02) | The role never changes the default entry. Switching is a manual step after one clean boot (see §1) |
| `hardened_malloc` (D-03) | Deferred |
| Licence check before going public (D-12) | The repo is Apache-2.0. The toolchain it invokes (ansible-core, community.general) is GPL-3.0. That needs a proper look before the repo is public |
| Roadmap Tier 2 and Tier 3 | Each item needs a go-ahead ([roadmap.md](roadmap.md)) |

## 3. Steps for the user on their own machine

These are the two WARNs a default Omarchy 4.0.6 install still shows after a
run. Both are correct.

- **`accounts.password_hash`:** the installer left SHA-512 (`$6$`) hashes for
  root and the user, although `login.defs` says YESCRYPT. Run `passwd`, and
  `sudo passwd root`, once each. It is not yet verified that this rehashes
  with yescrypt. The finding should turn to PASS on the next run if it does.
  The playbook never resets passwords.
- **`git.commit_signing`:** no signing key is named. Set
  `aegis_commit_signing_pubkey` to your `sk-ssh-ed25519` public key.

## 4. Harness and tooling

| Item | Detail |
|---|---|
| Ansible "junk after the JSON data" warnings in the VM | The final VM run's `tests/vm/.state/run.out` holds 1273 lines of `Module invocation had junk after the JSON data: ]3008;end=…`. The per-run logs (`run1.log` to `run3.log`) hold none. These look like OSC 3008 terminal escape sequences printed in the guest after the module output. Where they come from was not investigated. Ansible still parsed every result and the run passed, but whether the noise could ever hide a module's output was not checked |
| Container test time | 21m0s and 20m51s in the last two CI runs, against `timeout-minutes: 35` |
