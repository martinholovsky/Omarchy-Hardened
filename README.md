# Omarchy-Hardened (codename Aegis)

An Ansible playbook that retrofits defence in depth onto an
[Omarchy](https://github.com/basecamp/omarchy) / Arch Linux workstation:
kernel and sysctl lockdown, a stricter login lockout, a tighter firewall,
package-signature auditing, and later MAC, sandboxing and AI agent
containment. It keeps the Hyprland desktop Omarchy gives you. The
requirements are in [docs/PRD.md](docs/PRD.md).

**Status: pre-alpha scaffold.** Five roles are implemented and tested in a
container; the rest are stubs that change nothing. Do not run it on a machine
you cannot recover.

## What it does today

| Role | PRD | Status | What it changes |
|---|---|---|---|
| `preflight` | — | ✅ implemented | Nothing. Refuses non-Arch hosts, finds the Omarchy install, prints the baseline |
| `sysctl` | 3.1 | ✅ implemented | Writes `/etc/sysctl.d/99-zz-aegis-hardened.conf`: `dmesg_restrict=1`, `kptr_restrict=2`, `kexec_load_disabled=1`, `yama.ptrace_scope=1`, then reads the live values back |
| `pam_faillock` | 3.2 | ✅ implemented | Sets `deny=3 unlock_time=900` in `faillock.conf` **and** in the inline arguments Omarchy puts in `system-auth` and the lock-screen PAM stack, then verifies |
| `firewall` | 3.4 | ✅ implemented | ufw default-deny incoming; removes LocalSend (53317) and the opt-in SSH rule; keeps Docker DNS (configurable) |
| `pacman_integrity` | 3.5 | ✅ audit only | Fails the run if any repo's `SigLevel` accepts unsigned or untrusted packages |
| `kernel` | 3.1 | ⏳ stub | `linux-hardened` alongside `linux-omarchy` (D-02) |
| `hardened_malloc` | 3.1 | ⏳ stub | Per-app opt-in (D-03) |
| `fido2` | 3.2 | ⏳ stub | FIDO2 for LUKS + sudo (D-04) |
| `apparmor` | 3.3 | ⏳ stub | D-05 |
| `flatpak` | 3.3 | ⏳ stub | D-06 |
| `agent_containment` | 3.3 | ⏳ stub | D-07 |
| `commit_signing` | 3.3 | ⏳ stub | D-08 |
| `opensnitch` | 3.4 | ⏳ stub | D-09 |
| `overlay_network` | 3.4 | ⏳ stub | D-10 |

Immutability (PRD 3.6) is aspirational and has no role yet.

Next candidates, ranked by risk to Omarchy, are in [docs/roadmap.md](docs/roadmap.md).
That list merges a 2026 re-check of Securix-Linux and a review of secureblue.

The PRD's picture of Omarchy differs from the real thing in two places: SSH is
**not** opened by default (it is opt-in), and the kernel is `linux-omarchy`,
not mainline `linux`. The verified baseline is in
[docs/upstream-baseline.md](docs/upstream-baseline.md).

## Use

On the Omarchy machine:

```bash
sudo pacman -S --needed ansible-core
git clone git@github.com:martinholovsky/Omarchy-Hardened.git
cd Omarchy-Hardened
ansible-galaxy collection install -r requirements.yml

# 1. Dry run. Read the diff.
ansible-playbook omarchy-harden.yml --check --diff --ask-become-pass

# 2. Apply one area at a time.
ansible-playbook omarchy-harden.yml --tags sysctl --ask-become-pass
ansible-playbook omarchy-harden.yml --tags auth   --ask-become-pass
ansible-playbook omarchy-harden.yml --tags network --ask-become-pass
```

Tags: `p0` `p1` `p2`, area tags (`kernel`, `auth`, `isolation`, `network`,
`supply-chain`), and one tag per role. All the tunables are in each role's
`defaults/main.yml` and are named `aegis_<area>_*`.

**Before applying `auth`:** after three wrong passwords you are locked out for
15 minutes, and the lock screen counts too. Keep a second logged-in TTY open
the first time. `faillock --user "$USER" --reset` (as root) clears a lockout.

**After every `omarchy-update`:** run the playbook again. Omarchy's update
scripts rewrite some PAM files (D-11).

## Develop

You need [uv](https://docs.astral.sh/uv/) and podman (the container test
uses podman only).

```bash
uv sync                                    # locked ansible-core, ansible-lint, yamllint
uv run ansible-galaxy collection install -r requirements.yml
uvx pre-commit install --hook-type pre-commit --hook-type pre-push
uv run ansible-lint && uv run yamllint --strict .
tests/container/run.sh                     # 11 checks in a pinned Arch image
```

`tests/container/run.sh` seeds the PAM and ufw state Omarchy leaves behind,
using snippets vendored from Omarchy at a pinned commit. It then runs the
roles, checks the result with `grep` and `ufw status` (not with the roles' own
asserts), runs everything a second time to prove idempotence, and checks that
an unsigned repository fails the audit. The kernel `sysctl` apply step and
anything boot- or hardware-related cannot run in a container; those still need
a VM test.

CI (`.github/workflows/ci.yml`) runs the same lint, a full-history gitleaks
scan, and the container test.

## Layout

```
omarchy-harden.yml        entry playbook
roles/<name>/             one role per PRD item (defaults/ + tasks/)
tests/container/          container test harness
tests/fixtures/omarchy/   upstream snippets (MIT, pinned commit)
docs/PRD.md               requirements
docs/upstream-baseline.md what Omarchy really ships (verified)
docs/open-decisions.md    security decisions each stub is waiting on
docs/roadmap.md           ranked backlog (Securix-Linux + secureblue reviews)
docs/research/            the two source reviews
docs/adr/                 architecture decisions
```

## Licence

Apache-2.0. The fixture files in `tests/fixtures/omarchy/` are from Omarchy
(MIT), and their licence is kept next to them.
