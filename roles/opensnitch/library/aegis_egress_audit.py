#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright: Omarchy-Hardened contributors
# SPDX-License-Identifier: Apache-2.0
"""Report programs that connected out but belong to no pacman package (D-25)."""

from __future__ import annotations

import fnmatch
import json
import os
import subprocess
import time

from ansible.module_utils.basic import AnsibleModule

DOCUMENTATION = r"""
module: aegis_egress_audit
short_description: List programs in the egress collector's table that no package owns
description:
  - Read-only. Reads the state file written by aegis-egress-collector (D-25).
  - Paths are only ever passed to C(pacman -Qqo --) as data, never executed.
options:
  state_file: {type: path, required: true}
  known: {type: list, elements: str, default: []}
  window_days: {type: int, default: 7}
"""

MAX_STATE_BYTES = 8 * 1024 * 1024
MAX_PATHS = 300  # distinct programs checked against pacman per run
MAX_DESTS = 5  # destinations listed per unknown program
PACMAN_TIMEOUT = 10  # seconds per call; pacman -Qo normally answers in milliseconds
DEADLINE = 60  # seconds for all calls; whatever is left over is reported as unverified
BREAKER = 3  # consecutive pacman failures before the rest are reported unverified
DELETED = " (deleted)"  # the kernel's suffix for an executable unlinked while running


def _valid_path(value):
    return (isinstance(value, str) and value.startswith("/") and len(value) <= 4096
            and not any(ord(ch) < 32 or ord(ch) == 127 for ch in value))


def _rows(state_file):
    if os.path.getsize(state_file) > MAX_STATE_BYTES:
        raise ValueError("state file larger than %d bytes" % MAX_STATE_BYTES)
    with open(state_file, encoding="utf-8") as handle:
        doc = json.load(handle)
    if not isinstance(doc, dict) or doc.get("version") != 1 or not isinstance(doc.get("entries"), list):
        raise ValueError("unexpected state format")
    stats = doc.get("stats") if isinstance(doc.get("stats"), dict) else {}
    rows = []
    for row in doc["entries"]:
        if (isinstance(row, dict) and _valid_path(row.get("path")) and isinstance(row.get("dest"), str)
                and isinstance(row.get("last"), int) and len(row["dest"]) <= 253):
            rows.append(row)
    return rows, stats, doc.get("saved")


def _owned(path):
    """True if a package owns PATH, False if none does, None if pacman failed."""
    target = path[: -len(DELETED)] if path.endswith(DELETED) else path
    try:
        proc = subprocess.run(["pacman", "-Qqo", "--", target], capture_output=True,
                              timeout=PACMAN_TIMEOUT, check=False)
    except (OSError, subprocess.TimeoutExpired):
        return None
    if proc.returncode in (0, 1):  # 1: no package owns it, or it no longer exists
        return proc.returncode == 0
    return None


def main():
    module = AnsibleModule(
        argument_spec={
            "state_file": {"type": "path", "required": True},
            "known": {"type": "list", "elements": "str", "default": []},
            "window_days": {"type": "int", "default": 7},
        },
        supports_check_mode=True,
    )
    params = module.params
    if not os.path.exists(params["state_file"]):
        module.exit_json(changed=False, present=False)
    try:
        rows, stats, saved = _rows(params["state_file"])
    except (OSError, ValueError) as exc:
        module.exit_json(changed=False, present=True, error="cannot read %s: %s" % (params["state_file"], exc))
    cutoff = int(time.time()) - params["window_days"] * 86400
    recent = {}
    for row in rows:
        if row["last"] >= cutoff:
            recent.setdefault(row["path"], []).append(row)
    paths = sorted(recent)
    unknown, unverified = [], []
    deadline = time.monotonic() + DEADLINE
    failures = 0
    for path in paths[:MAX_PATHS]:
        if any(fnmatch.fnmatchcase(path, pattern) for pattern in params["known"]):
            continue
        # Fail closed: past the deadline or with pacman failing, a program is
        # reported as unverified, never as owned.
        owned = None if failures >= BREAKER or time.monotonic() > deadline else _owned(path)
        failures = failures + 1 if owned is None else 0
        if owned:
            continue
        dests = sorted(recent[path], key=lambda r: r["last"], reverse=True)
        item = {"path": path, "dests": [r["dest"] for r in dests[:MAX_DESTS]],
                "more_dests": max(0, len(dests) - MAX_DESTS), "last": dests[0]["last"]}
        (unverified if owned is None else unknown).append(item)
    module.exit_json(
        changed=False, present=True, error=None, saved=saved, programs=len(paths),
        unchecked=max(0, len(paths) - MAX_PATHS), unknown=unknown, unverified=unverified,
        rejected_sender=int(stats.get("rejected_sender", 0) or 0),
    )


if __name__ == "__main__":
    main()
