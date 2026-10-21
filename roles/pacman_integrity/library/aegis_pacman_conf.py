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
first_log_entry:
  description: >-
    ISO timestamp of the first line in pacman.log (on a fresh install, the
    install itself), or null. Used when no full upgrade has run yet.
  type: str
  returned: always
first_log_age_days:
  description: Whole days since first_log_entry, or null.
  type: int
  returned: always
"""

MAX_INCLUDE_DEPTH = 10
UPGRADE_RE = re.compile(r"^\[([^\]]+)\] \[PACMAN\] starting full system upgrade")
STAMP_RE = re.compile(r"^\[([^\]]+)\] ")


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


def _age_days(stamp):
    if stamp is None:
        return None
    try:
        when = datetime.datetime.strptime(stamp, "%Y-%m-%dT%H:%M:%S%z")
    except ValueError:
        return None
    return (datetime.datetime.now(datetime.timezone.utc) - when).days


def _log_times(log_path):
    """Return (last full upgrade, first log entry) timestamps from pacman.log.

    The Omarchy installer runs `pacman -r /mnt -Sy ...`, never -Syu, so a fresh
    install has no upgrade line; its first entry dates the install instead.
    """
    last = first = None
    try:
        with open(log_path, encoding="utf-8", errors="replace") as handle:
            for line in handle:
                if first is None:
                    stamp = STAMP_RE.match(line)
                    if stamp:
                        first = stamp.group(1)
                match = UPGRADE_RE.match(line)
                if match:
                    last = match.group(1)
    except FileNotFoundError:
        pass
    return last, first


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
    last, first = _log_times(module.params["log_path"])
    module.exit_json(
        changed=False,
        sections=[{"name": name, **data} for name, data in sections.items()],
        include_errors=errors,
        last_full_upgrade=last,
        upgrade_age_days=_age_days(last),
        first_log_entry=first,
        first_log_age_days=_age_days(first),
    )


if __name__ == "__main__":
    main()
