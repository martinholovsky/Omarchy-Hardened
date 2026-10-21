# AGENTS.md

Guidance for coding agents working in this repository.

## What this is

An Ansible playbook (`omarchy-harden.yml`) that hardens an Omarchy / Arch Linux
workstation. Requirements: `docs/PRD.md`. Verified upstream behaviour:
`docs/upstream-baseline.md`. Pending security decisions: `docs/open-decisions.md`.

## Rules

- **Never implement a stub role until its decision in `docs/open-decisions.md`
  is marked Decided.** These are security trade-offs and the owner makes them.
- **Check upstream before encoding it.** Any claim about what Omarchy does must
  cite a file at a pinned commit in `docs/upstream-baseline.md`. The PRD is
  wrong about some of it (SSH, kernel).
- **Every role verifies after it applies.** Read back the state that is actually
  in force (live sysctl, PAM file contents, `ufw status`) and `assert` on it.
  A task that can silently match nothing — `lineinfile`/`replace` regexes —
  must be followed by such a check.
- Roles must be idempotent and must work under `--check --diff`.
- Audit-only checks append findings (`{id, status, detail}`, status
  PASS/INFO/WARN/FAIL) to `aegis_findings` and never fail directly;
  `audit_report` decides. Every new check needs a planted-problem test in
  `tests/container/inside.sh` that proves it fires.
- A setting with a real trade-off ships behind a variable that defaults to
  Omarchy's current behaviour, with an Open entry in `docs/open-decisions.md`.
- Variables are named `aegis_<area>_*` (see `.ansible-lint` for why the
  role-prefix rule is skipped).
- Pin everything: collections in `requirements.yml`, Python tooling in
  `uv.lock`, GitHub Actions and pre-commit hooks by commit SHA, the test image
  by digest.

## Verify a change

```bash
uv run yamllint --strict . && uv run ansible-lint
uv run ansible-playbook omarchy-harden.yml --syntax-check
tests/container/run.sh        # must end with "N/N checks passed"
```

If you add a check to `tests/container/inside.sh`, bump `checks_total`.

## Docs

Update `README.md` (role status table), `CHANGELOG.md`, and the affected
`docs/` file in the same change as the code.
