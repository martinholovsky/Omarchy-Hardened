#!/usr/bin/env bash
# zizmor-gate.sh — BLOCKING local gate for CI configuration (GitHub Actions workflows,
# composite action.yml, dependabot.yml), run from the pre-commit hook.
#
# Why local and not a GitHub Actions job: operator decision 2026-11-28 ("run zizmor
# locally, not on GitHub"); GitHub Actions in the DN repos were also billing-refused at the
# time, so a CI job would not have run at all.
#
#   every commit          offline audits over the whole repo (~0.2 s)
#   CI config staged      ALSO the online audits (impostor-commit, known-vulnerable-actions,
#                         ref-confusion, stale-action-refs, ref-version-mismatch), with the
#                         token of the logged-in `gh` CLI. Those are the audits that catch a
#                         hijacked or fork-only SHA pin, which is exactly when a ref changes.
#
# Fails closed: zizmor missing or not the pinned version → fail; `gh` not logged in while
# CI config is staged → fail. Escape hatches are explicit and printed:
#   ZIZMOR_OFFLINE=1 git commit ...   skip only the online audits (says so)
#   git commit --no-verify            skip every hook
#
# Limitation: audits the WORKING TREE, not the staged blob. A partially staged workflow is
# audited as it sits on disk.
#
# Same file in every repo that uses it (dn-platform/scripts/zizmor-gate.sh is the source).
set -euo pipefail

readonly ZIZMOR_VERSION="1.33.1"
readonly INSTALL_HINT="pipx install --force 'zizmor==${ZIZMOR_VERSION}'   (or: uv tool install 'zizmor==${ZIZMOR_VERSION}')"

root="$(git rev-parse --show-toplevel)"
cd "$root"

# Inputs zizmor understands. Nothing to audit is a pass, but it is stated, not silent.
if [[ ! -d .github ]] && ! git ls-files -- 'action.yml' 'action.yaml' '*/action.yml' '*/action.yaml' | grep -q .; then
    echo "zizmor-gate: no .github/ or action.yml in this repo — 0 inputs, nothing to audit"
    exit 0
fi

if ! command -v zizmor >/dev/null 2>&1; then
    echo "zizmor-gate: FAIL — zizmor is not installed. Install: ${INSTALL_HINT}" >&2
    exit 1
fi
have="$(zizmor --version 2>/dev/null | awk '{print $2}')"
if [[ "$have" != "$ZIZMOR_VERSION" ]]; then
    echo "zizmor-gate: FAIL — zizmor ${have:-unknown} found, ${ZIZMOR_VERSION} pinned. Install: ${INSTALL_HINT}" >&2
    exit 1
fi

staged_ci="$(git diff --cached --name-only --diff-filter=ACMR \
    | grep -E '^\.github/|(^|/)action\.ya?ml$|^\.pre-commit-config\.yaml$' || true)"

if [[ -n "$staged_ci" && "${ZIZMOR_OFFLINE:-0}" != "1" ]]; then
    if ! token="$(gh auth token 2>/dev/null)" || [[ -z "$token" ]]; then
        echo "zizmor-gate: FAIL — CI config is staged and the online audits need a GitHub token," >&2
        echo "  but \`gh auth token\` returned none. Run \`gh auth login\`, or re-run with" >&2
        echo "  ZIZMOR_OFFLINE=1 to skip ONLY the online audits (impostor commits, vulnerable actions)." >&2
        exit 1
    fi
    echo "zizmor-gate: CI config staged ($(printf '%s\n' "$staged_ci" | wc -l | tr -d ' ') file(s)) — offline + online audits"
    GH_TOKEN="$token" zizmor --no-progress --format plain .
else
    if [[ -n "$staged_ci" ]]; then
        echo "zizmor-gate: ZIZMOR_OFFLINE=1 — online audits SKIPPED for staged CI config"
    fi
    zizmor --offline --no-progress --format plain .
fi
