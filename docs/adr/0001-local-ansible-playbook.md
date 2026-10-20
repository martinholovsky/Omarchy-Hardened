# ADR 0001 — Deliver hardening as a local Ansible playbook

- Status: Accepted
- Date: 2026-10-20

## Context

Omarchy's plugin system runs unsandboxed UI code (QML/Quickshell widgets) and
has no root-level plugin hook. Hardening delivered as a plugin would sit inside
the trust boundary it is meant to protect.

## Decision

Ship a standalone playbook, `omarchy-harden.yml`, that the user runs locally
with `sudo` after a normal Omarchy install. Every role must:

1. be idempotent (a second run changes nothing; CI checks this);
2. support `--check --diff`;
3. **verify after it applies**: read back the state that will actually be in
   force and fail if it differs, so that an upstream change which silently
   breaks a regex or a module cannot be reported as success.

## Consequences

- No hardening is applied until the user runs the playbook, and Omarchy updates
  can undo some of it (see D-11).
- The project is not tied to Omarchy's plugin API.
- Roles that cannot be tested in a container (kernel, FIDO2, AppArmor) need a
  VM test harness before they leave stub status.
