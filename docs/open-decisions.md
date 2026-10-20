# Open decisions

Security choices the PRD leaves open, or where two of its goals conflict. A
stub role stays a stub until its decision is recorded here as **Decided**, with
the reasoning. Each entry gives a recommendation, but the decision is the
owner's to make.

Status: **Open** · **Decided** · **Deferred**

---

## D-01 — Unprivileged user namespaces vs Flatpak/browser sandboxes (Open)

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

## D-02 — Kernel: replace `linux-omarchy` or install alongside it (Open)

Omarchy ships its own `linux-omarchy`, not Arch `linux`. `linux-hardened` lags
mainline and has no Omarchy-specific patches. Out-of-tree modules (NVIDIA, T2)
need `-headers` and DKMS. **Recommendation:** install `linux-hardened`
*alongside* `linux-omarchy`, add a Limine entry, make it the default only
after one clean boot, and keep `linux-omarchy` as the fallback entry.

## D-03 — hardened_malloc scope (Open)

Preloading it system-wide (`/etc/ld.so.preload`) breaks or slows some apps
(Electron, JIT runtimes, some games). **Recommendation:** an opt-in per-app
allowlist through wrapper or `LD_PRELOAD` drop-ins, not a global preload.

## D-04 — FIDO2 for LUKS and sudo: recovery path (Open)

Requiring a hardware key at boot and for sudo locks you out when the key is
lost. Before this role does anything it needs: at least two enrolled keys, a
LUKS recovery passphrase or key kept offline, and a decision on whether the
TTY/root console keeps a password fallback. **Recommendation:** two keys
required at enrolment, recovery passphrase kept, `pam_u2f` as `required` for
`sudo` only (not login) in phase 1.

## D-05 — AppArmor enforce vs complain (Open)

**Recommendation:** ship profiles in complain mode first, collect denials for a
week, then switch to enforce one profile at a time.

## D-06 — Which apps move to Flatpak (Open)

Omarchy installs browsers and chat clients as native packages, and some
Omarchy integrations call them by path. Decide the list.

## D-07 — AI agent containment boundary (Open)

Choose between Distrobox (convenient, but by default shares `$HOME` and is a
weak boundary), a rootless Podman container with no home mount, or a microVM.
**Recommendation:** rootless Podman, project directory bind-mounted only,
egress through OpenSnitch rules.

## D-08 — Commit signing key type (Open)

SSH signing key on a FIDO2 token (`ed25519-sk`) or GPG. **Recommendation:**
`ed25519-sk`, which works with the same keys as D-04.

## D-09 — OpenSnitch default action (Open)

Default-deny makes every new connection prompt, which gets noisy. Decide
deny vs ask, and the rule set to pre-seed (pacman mirrors, Omarchy update
host, Tailscale).

## D-10 — Overlay network: Tailscale or plain WireGuard (Open)

Tailscale adds a coordination server you have to trust; WireGuard needs manual
key distribution.

## D-11 — Drift after `omarchy-update` (Open)

Omarchy's update scripts rewrite PAM files (see
[upstream-baseline.md](upstream-baseline.md)). Options: document "re-run after
update" (current), a pacman `PostTransaction` hook that runs the playbook in
check mode and warns, or a hook that re-applies. **Recommendation:** a
check-mode hook that warns. Re-applying automatically from a pacman hook is too
much hidden behaviour.

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
is planned).
