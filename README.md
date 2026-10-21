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
| `sysctl` | 3.1 | ✅ implemented | Renders `/etc/sysctl.d/99-zz-aegis-hardened.conf` from one variable: the PRD set (`dmesg_restrict`, `kptr_restrict`, `kexec_load_disabled`, `yama.ptrace_scope`) plus roadmap Tier 1 (BPF, perf, userfaultfd, ldisc, `protected_fifos/regular=2`, `suid_dumpable=0`, IPv4/IPv6 redirect and source-route off, loose `rp_filter`, syncookies, rfc1337, IPv6 privacy addresses), plus decisions D-15 to D-17 (`sysrq=16`, ASLR `mmap_rnd_bits=32`/`compat=16`, `oops_limit=100`). Applies it, re-applies on runtime drift, reads every value back, and asserts `vm.mmap_min_addr >= 65536` |
| `pam_faillock` | 3.2 | ✅ implemented | Sets `deny=10` (Omarchy's count), `unlock_time=900` (Omarchy: 120 s) and a persistent tally dir in `faillock.conf` **and** in the inline arguments Omarchy puts in `system-auth` and the lock-screen PAM stack; routes `su` through `system-auth`, restricted to wheel; locks root too (`even_deny_root`, D-19); then verifies |
| `firewall` | 3.4 | ✅ implemented | ufw default-deny incoming; removes LocalSend (53317) and the opt-in SSH rule; keeps Docker DNS (configurable) |
| `pacman_integrity` | 3.5 | ✅ audit only | Emits findings: weak `SigLevel` (including `Include=` files), non-HTTPS mirrors, last full upgrade older than 7 days, setuid files no package owns, world-writable and unowned files, `pacman -Qkk` drift, NOPASSWD sudoers rules, members of docker/libvirt/disk/input |
| `audit_report` | — | ✅ implemented | Runs last: prints every finding, writes `/var/lib/aegis/audit.jsonl` (0600), fails on any FAIL not listed in `aegis_audit_skip` |
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
That list merges a 2026 re-check of Securix-Linux and reviews of secureblue,
Kicksecure security-misc and SnowflakeOS.

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

**Before applying `auth`:** the lockout policy is:

- **threshold:** 10 consecutive failures
- **window:** within 900 s (`fail_interval`, pam_faillock's default)
- **lockout:** 15 minutes (`unlock_time = 900`)
- **counter:** shared by console, sudo, `su` and the lock screen. SSH counts too, but only for password logins; Omarchy's opt-in sshd is key-only.
- **root:** locks after the same 10 failures, also for 15 minutes (`even_deny_root`). Omarchy gives root your password, so this caps guessing at a root prompt. The rescue shell (`sulogin`) does not use PAM, so a lock cannot block recovery.
- **unlock:** wait 15 minutes, or run `faillock --user "$USER" --reset` as root.

Keep a second logged-in TTY open the first time you apply it.

**Read [docs/operating-notes.md](docs/operating-notes.md) before the first
run.** It covers what changes for you, which settings stay until a reboot,
how to undo each change, what is still untested, and how to test in a
VirtualBox VM.

**What `pam_faillock` also changes:** failure records live in
`/var/lib/faillock`, so a lockout survives a reboot. `su`/`su-l` now
authenticate through `system-auth`, so they are counted too, and only members
of `wheel` may use `su`. Root is locked too after 10 failures
(`even_deny_root`, decision D-19).

**Audit findings:** every run ends with a summary and writes
`/var/lib/aegis/audit.jsonl`. A FAIL stops the run. If you accept a FAIL (for
example you chose sudoless Docker), add its id to `aegis_audit_skip`, e.g.
`-e '{"aegis_audit_skip": ["groups.docker"]}'`. It is then reported as
ACCEPTED.

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
tests/container/run.sh                     # 26 checks in a pinned Arch image
```

`tests/container/run.sh` seeds the PAM and ufw state Omarchy leaves behind,
using snippets vendored from Omarchy at a pinned commit. It then runs the
roles, checks the result with `grep`, `ufw status`, `faillock` and real `su`
logins driven by `expect` (not with the roles' own asserts). It then runs
everything a second time to prove idempotence. Each audit check is also
exercised with a planted problem: an unsigned repo, a weak `SigLevel` inside
an `Include=` file, a plain-HTTP mirror, an unowned setuid binary, a modified
package binary, docker group membership. It also checks that every sysctl key
exists on a real kernel. Keys visible only in the host network namespace are
checked in a second, read-only container.

Applying sysctls to a live kernel changes the host, some settings until reboot,
so `tests/container/sysctl-apply.sh` refuses to run unless
`AEGIS_ALLOW_HOST_SYSCTL=1`. CI runs it on a throwaway VM. Boot- and
hardware-related roles still need a VM test.

CI (`.github/workflows/ci.yml`) runs the lint, a full-history gitleaks scan,
the container test, and the live sysctl apply.

## Layout

```
omarchy-harden.yml        entry playbook
roles/<name>/             one role per PRD item (defaults/ + tasks/)
tests/container/          container test harness
tests/fixtures/omarchy/   upstream snippets (MIT, pinned commit)
docs/PRD.md               requirements
docs/upstream-baseline.md what Omarchy really ships (verified)
docs/open-decisions.md    security decisions each stub is waiting on
docs/operating-notes.md   before/after a run: effects, rollback, untested areas, VM test
docs/roadmap.md           ranked backlog merged from the reviews below
docs/research/            the source reviews (Securix-Linux, secureblue, Kicksecure, SnowflakeOS)
docs/adr/                 architecture decisions
```

## Licence

Apache-2.0. The fixture files in `tests/fixtures/omarchy/` are from Omarchy
(MIT), and their licence is kept next to them.
