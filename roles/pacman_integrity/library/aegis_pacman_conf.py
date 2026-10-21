#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright: Omarchy-Hardened contributors
# SPDX-License-Identifier: Apache-2.0
"""Read-only parser for pacman.conf, its Include= files and pacman.log."""

from __future__ import annotations

import datetime
import glob
import os
import re

from ansible.module_utils.basic import AnsibleModule

DOCUMENTATION = r"""
module: aegis_pacman_conf
short_description: Parse pacman.conf (following Include=) and the last full upgrade time
description:
  - Read-only. Returns every repository section with its SigLevel and Server
    values, including values that come from Include= files, plus the time of
    the last "starting full system upgrade" line in pacman.log.
options:
  path:
    description: pacman.conf to parse.
    type: path
    default: /etc/pacman.conf
  log_path:
    description: pacman log to scan for the last full system upgrade.
    type: path
    default: /var/log/pacman.log
"""

RETURN = r"""
sections:
  description: One entry per section, in file order.
  type: list
  elements: dict
  returned: always
include_errors:
  description: Include= targets that matched no readable file.
  type: list
  elements: str
  returned: always
last_full_upgrade:
  description: ISO timestamp of the last full system upgrade, or null.
  type: str
  returned: always
upgrade_age_days:
  description: Whole days since last_full_upgrade, or null.
  type: int
  returned: always
"""

MAX_INCLUDE_DEPTH = 10
UPGRADE_RE = re.compile(r"^\[([^\]]+)\] \[PACMAN\] starting full system upgrade")


def _strip(line: str) -> str:
    # pacman's parser cuts everything after '#', then trims whitespace.
    return line.split("#", 1)[0].strip()


def _parse(path, section, sections, errors, seen, depth):
    real = os.path.realpath(path)
    if depth > MAX_INCLUDE_DEPTH or real in seen:
        errors.append(f"{path}: include loop or depth > {MAX_INCLUDE_DEPTH}")
        return section
    seen = seen | {real}
    with open(path, encoding="utf-8", errors="replace") as handle:
        for raw in handle:
            line = _strip(raw)
            if not line:
                continue
            if line.startswith("[") and line.endswith("]"):
                section = line[1:-1].strip()
                sections.setdefault(section, {"siglevel": [], "servers": [], "files": []})
                continue
            if "=" not in line:
                continue
            key, value = (part.strip() for part in line.split("=", 1))
            entry = sections.setdefault(section, {"siglevel": [], "servers": [], "files": []})
            if path not in entry["files"]:
                entry["files"].append(path)
            if key == "SigLevel":
                entry["siglevel"].append(value)
            elif key == "Server":
                entry["servers"].append(value)
            elif key == "Include":
                matches = sorted(glob.glob(value))
                if not matches:
                    errors.append(f"{path}: Include = {value} matched no file")
                for match in matches:
                    if not os.access(match, os.R_OK):
                        errors.append(f"{path}: Include = {match} is not readable")
                        continue
                    section = _parse(match, section, sections, errors, seen, depth + 1)
    return section


def _last_upgrade(log_path):
    last = None
    try:
        with open(log_path, encoding="utf-8", errors="replace") as handle:
            for line in handle:
                match = UPGRADE_RE.match(line)
                if match:
                    last = match.group(1)
    except FileNotFoundError:
        return None, None
    if last is None:
        return None, None
    try:
        stamp = datetime.datetime.strptime(last, "%Y-%m-%dT%H:%M:%S%z")
    except ValueError:
        return last, None
    age = datetime.datetime.now(datetime.timezone.utc) - stamp
    return last, age.days


def main():
    module = AnsibleModule(
        argument_spec={
            "path": {"type": "path", "default": "/etc/pacman.conf"},
            "log_path": {"type": "path", "default": "/var/log/pacman.log"},
        },
        supports_check_mode=True,
    )
    sections: dict[str, dict[str, list[str]]] = {}
    errors: list[str] = []
    try:
        _parse(module.params["path"], "options", sections, errors, frozenset(), 0)
    except OSError as exc:
        module.fail_json(msg=f"cannot read {module.params['path']}: {exc}")
    last, age = _last_upgrade(module.params["log_path"])
    module.exit_json(
        changed=False,
        sections=[{"name": name, **data} for name, data in sections.items()],
        include_errors=errors,
        last_full_upgrade=last,
        upgrade_age_days=age,
    )


if __name__ == "__main__":
    main()
