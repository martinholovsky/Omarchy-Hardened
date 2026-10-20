# Changelog

Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/). Versioning:
SemVer once 1.0 ships.

## [Unreleased]

### Added

- Project scaffold: `omarchy-harden.yml`, one role per PRD item, pinned
  collections (`ansible.posix` 2.2.2, `community.general` 13.5.0) and locked
  dev tooling (ansible-core 2.21.5, ansible-lint 26.10.1, yamllint 1.38.0).
- `preflight`: refuses non-Arch hosts, locates Omarchy, prints the baseline.
- `sysctl`: `dmesg_restrict`, `kptr_restrict`, `kexec_load_disabled`,
  `yama.ptrace_scope`, verified against the live kernel. The unprivileged-userns
  switch is refused until D-01 is decided.
- `pam_faillock`: `deny=10 unlock_time=900` in `faillock.conf` and in Omarchy's
  inline PAM arguments (`system-auth`, `omarchy-lock-password`), with read-back
  verification.
- `firewall`: removes the LocalSend and opt-in SSH ufw rules, keeps
  default-deny incoming, verifies with `ufw status`.
- `pacman_integrity`: audit-only check that no repository accepts unsigned
  packages, with an explicit exception list.
- Stub roles for kernel, hardened_malloc, fido2, apparmor, flatpak,
  agent_containment, commit_signing, opensnitch, overlay_network.
- Container test (11 checks) against Omarchy's PAM and ufw baseline in a
  digest-pinned Arch image. It also checks idempotence and a negative case.
- CI: pre-commit (shellcheck, yamllint, ansible-lint), full-history gitleaks
  with a checksum-verified binary, the container test. Dependabot for Actions
  and uv.
- Docs: verified upstream baseline, open security decisions D-01 to D-12,
  ADR 0001.
- Research: a review of Securix-Linux re-checked against 2026 kernels (192
  settings classified) and a review of secureblue at `5be4f13`, merged into
  `docs/roadmap.md`. D-01 now records the verified facts: no
  `bubblewrap-suid` on Arch, and no mainline AppArmor userns-restrict sysctl.

### Changed

- `SECURITY.md`: GitHub private vulnerability reporting is not available on
  private repos, so the report link is replaced until the repo goes public.
