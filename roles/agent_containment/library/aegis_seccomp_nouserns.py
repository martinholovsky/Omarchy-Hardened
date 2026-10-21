#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright: Omarchy-Hardened contributors
# SPDX-License-Identifier: Apache-2.0
"""Derive a seccomp profile from Podman's default that forbids new user namespaces."""

from __future__ import annotations

import json
import os
import tempfile

from ansible.module_utils.basic import AnsibleModule

DOCUMENTATION = r"""
module: aegis_seccomp_nouserns
short_description: Write Podman's default seccomp profile minus user-namespace creation
description:
  - Reads the containers-common default profile, where clone/clone3/unshare are
    allowed unconditionally, and writes a copy in which unshare and clone are
    allowed only without CLONE_NEWUSER (EPERM otherwise) and clone3, whose flags
    seccomp cannot inspect, returns ENOSYS so libc falls back to clone. This is
    how Docker's default profile treats unprivileged containers (D-01, D-07).
options:
  src: {type: path, default: /usr/share/containers/seccomp.json}
  dest: {type: path, required: true}
"""

CLONE_NEWUSER = 0x10000000
EPERM, ENOSYS = 1, 38
GATED = ("unshare", "clone")


def derive(profile):
    out = json.loads(json.dumps(profile))
    for rule in out.get("syscalls", []):
        if rule.get("action") == "SCMP_ACT_ALLOW" and not rule.get("args"):
            rule["names"] = [n for n in rule.get("names", []) if n not in GATED + ("clone3",)]
    out["syscalls"] = [r for r in out.get("syscalls", []) if r.get("names")]
    for name in GATED:
        # x86_64 / aarch64: the flags are argument 0 for both syscalls.
        out["syscalls"].append({
            "names": [name], "action": "SCMP_ACT_ALLOW",
            "args": [{"index": 0, "value": CLONE_NEWUSER, "valueTwo": 0, "op": "SCMP_CMP_MASKED_EQ"}],
            "comment": "aegis: allowed without CLONE_NEWUSER",
        })
        out["syscalls"].append({
            "names": [name], "action": "SCMP_ACT_ERRNO", "errnoRet": EPERM,
            "args": [{"index": 0, "value": CLONE_NEWUSER, "valueTwo": CLONE_NEWUSER, "op": "SCMP_CMP_MASKED_EQ"}],
            "comment": "aegis: no new user namespaces (D-01)",
        })
    out["syscalls"].append({
        "names": ["clone3"], "action": "SCMP_ACT_ERRNO", "errnoRet": ENOSYS,
        "comment": "aegis: flags not inspectable; ENOSYS makes libc fall back to clone",
    })
    return out


def main():
    module = AnsibleModule(
        argument_spec={
            "src": {"type": "path", "default": "/usr/share/containers/seccomp.json"},
            "dest": {"type": "path", "required": True},
        },
        supports_check_mode=True,
    )
    src, dest = module.params["src"], module.params["dest"]
    try:
        with open(src, encoding="utf-8") as handle:
            profile = json.load(handle)
    except (OSError, ValueError) as exc:
        module.fail_json(msg=f"cannot read {src}: {exc}")
    text = json.dumps(derive(profile), indent=2, sort_keys=True) + "\n"
    try:
        with open(dest, encoding="utf-8") as handle:
            current = handle.read()
    except OSError:
        current = None
    changed = current != text
    if changed and not module.check_mode:
        directory = os.path.dirname(dest) or "."
        fd, tmp = tempfile.mkstemp(dir=directory, prefix=".aegis-seccomp.")
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(text)
        os.chmod(tmp, 0o644)
        os.replace(tmp, dest)
    module.exit_json(changed=changed, dest=dest)


if __name__ == "__main__":
    main()
