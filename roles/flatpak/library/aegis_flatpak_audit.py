#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright: Omarchy-Hardened contributors
# SPDX-License-Identifier: Apache-2.0
"""Read-only Flatpak audit: remotes and the permissions of installed apps."""

from __future__ import annotations

import configparser
import shutil
import subprocess

from ansible.module_utils.basic import AnsibleModule

DOCUMENTATION = r"""
module: aegis_flatpak_audit
short_description: List system Flatpak remotes and apps with broad permissions
options:
  timeout: {type: int, default: 60}
"""

# Filesystem grants that expose the whole host or home directory.
BROAD_FILESYSTEMS = {"host", "host-os", "host-etc", "home"}


def _run(argv, timeout):
    try:
        result = subprocess.run(argv, capture_output=True, text=True, timeout=timeout, check=False)
    except (OSError, subprocess.TimeoutExpired) as exc:
        return None, str(exc)
    if result.returncode != 0:
        return None, result.stderr.strip()
    return result.stdout, ""


def _broad(perms_text):
    parser = configparser.ConfigParser(strict=False, interpolation=None, delimiters=("=",))
    parser.optionxform = str
    try:
        parser.read_string(perms_text)
    except configparser.Error:
        return ["unparseable permissions"]
    found = []
    context = parser["Context"] if parser.has_section("Context") else {}
    for fs in filter(None, context.get("filesystems", "").split(";")):
        base = fs.split(":", 1)[0].lstrip("!")
        if base in BROAD_FILESYSTEMS and not fs.startswith("!"):
            found.append(f"filesystems={fs}")
    if "all" in context.get("devices", "").split(";"):
        found.append("devices=all")
    sockets = context.get("sockets", "").split(";")
    for sock in ("session-bus", "system-bus"):
        if sock in sockets:
            found.append(f"sockets={sock}")
    if parser.has_section("Session Bus Policy"):
        for name, value in parser["Session Bus Policy"].items():
            if value == "talk" and name.startswith("org.freedesktop.Flatpak"):
                found.append(f"talk {name} (can launch host commands)")
    return found


def main():
    module = AnsibleModule(argument_spec={"timeout": {"type": "int", "default": 60}},
                           supports_check_mode=True)
    timeout = module.params["timeout"]
    if shutil.which("flatpak") is None:
        module.exit_json(changed=False, installed=False, remotes=[], apps=[], broad=[], errors=[])
    errors = []
    out, err = _run(["flatpak", "remotes", "--system", "--columns=name,subset"], timeout)
    remotes = []
    if out is None:
        errors.append(f"flatpak remotes: {err}")
    else:
        for line in out.splitlines():
            fields = line.split("\t")
            if fields and fields[0]:
                remotes.append({"name": fields[0], "subset": fields[1].strip() if len(fields) > 1 else ""})
    out, err = _run(["flatpak", "list", "--app", "--columns=application"], timeout)
    apps = [] if out is None else [a for a in out.split() if a]
    if out is None:
        errors.append(f"flatpak list: {err}")
    broad = []
    for app in apps:
        perms, err = _run(["flatpak", "info", "--show-permissions", app], timeout)
        if perms is None:
            errors.append(f"{app}: {err}")
            continue
        hits = _broad(perms)
        if hits:
            broad.append({"app": app, "permissions": hits})
    module.exit_json(changed=False, installed=True, remotes=remotes, apps=apps, broad=broad, errors=errors)


if __name__ == "__main__":
    main()
