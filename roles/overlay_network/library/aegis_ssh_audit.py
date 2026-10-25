#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright: Omarchy-Hardened contributors
# SPDX-License-Identifier: Apache-2.0
"""Read-only SSH server checks for D-24: password logins and key types."""

from __future__ import annotations

import os
import pwd
import re
import subprocess

from ansible.module_utils.basic import AnsibleModule

DOCUMENTATION = r"""
module: aegis_ssh_audit
short_description: Audit sshd's effective password settings and authorized key types
description:
  - Read-only. Reports key types per user, never key material or comments.
  - Returns installed=false when the sshd binary is absent (Omarchy's default).
options:
  sshd_path: {type: path, default: /usr/bin/sshd}
  min_uid: {type: int, default: 1000}
"""

# A key line may start with options (from="...",command="..."), so the key
# type is the first token that looks like one. sk- types live on a FIDO key.
KEY_TYPE_RE = re.compile(r"^(sk-)?(ssh-|ecdsa-)[A-Za-z0-9@.\-]+$")
# Regular accounts only: root, and uid >= min_uid up to (not including) nobody.
NOBODY_UID = 65534


def _effective(sshd_path):
    # sshd -T prints the global settings in force after every Include and
    # drop-in, lowercased (OpenSSH 9.x) or CamelCase (10.x): compare lowercased.
    try:
        proc = subprocess.run([sshd_path, "-T"], capture_output=True, text=True, timeout=30, check=False)
    except (OSError, subprocess.TimeoutExpired) as exc:
        return None, str(exc)
    if proc.returncode != 0:
        return None, (proc.stderr.strip() or f"exit {proc.returncode}")
    settings = {}
    for line in proc.stdout.splitlines():
        key, _, value = line.partition(" ")
        settings.setdefault(key.lower(), []).append(value.strip())
    return settings, None


def _key_files(entry, home, user):
    files = []
    for template in entry.split():
        path = template.replace("%%", "\0").replace("%h", home).replace("%u", user).replace("\0", "%")
        files.append(path if os.path.isabs(path) else os.path.join(home, path))
    return files


def _keys(settings, min_uid):
    templates = " ".join(settings.get("authorizedkeysfile", [".ssh/authorized_keys"]))
    found = []
    for entry in pwd.getpwall():
        if entry.pw_uid != 0 and not min_uid <= entry.pw_uid < NOBODY_UID:
            continue
        for path in _key_files(templates, entry.pw_dir, entry.pw_name):
            try:
                with open(path, encoding="utf-8", errors="replace") as handle:
                    lines = handle.read().splitlines()
            except OSError:
                continue
            for line in lines:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                key_type = next((t for t in line.split() if KEY_TYPE_RE.match(t)), "unknown")
                found.append({"user": entry.pw_name, "type": key_type,
                              "hardware": key_type.startswith("sk-")})
    return found


def main():
    module = AnsibleModule(
        argument_spec={
            "sshd_path": {"type": "path", "default": "/usr/bin/sshd"},
            "min_uid": {"type": "int", "default": 1000},
        },
        supports_check_mode=True,
    )
    params = module.params
    if not os.path.exists(params["sshd_path"]):
        module.exit_json(changed=False, installed=False)
    settings, error = _effective(params["sshd_path"])
    result = {"installed": True, "effective_error": error}
    if settings is not None:
        result["password_authentication"] = settings.get("passwordauthentication", ["unknown"])[0].lower()
        result["kbdinteractive_authentication"] = (
            settings.get("kbdinteractiveauthentication", ["unknown"])[0].lower())
        result["authorized_keys"] = _keys(settings, params["min_uid"])
    module.exit_json(changed=False, **result)


if __name__ == "__main__":
    main()
