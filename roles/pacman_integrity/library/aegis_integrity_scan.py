#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright: Omarchy-Hardened contributors
# SPDX-License-Identifier: Apache-2.0
"""Read-only filesystem and package-integrity sweep."""

from __future__ import annotations

import grp
import os
import pwd
import re
import stat
import subprocess

from ansible.module_utils.basic import AnsibleModule

DOCUMENTATION = r"""
module: aegis_integrity_scan
short_description: Inventory setuid, world-writable and unowned files; NOPASSWD rules; package drift
description:
  - Read-only. Walks the given roots without following symlinks, skipping the
    excluded prefixes, and reports what it found together with how many files
    it examined.
options:
  roots: {type: list, elements: path, required: true}
  excludes: {type: list, elements: path, default: []}
  max_report: {type: int, default: 50}
  max_files: {type: int, default: 2000000}
  sudoers_paths: {type: list, elements: path, default: [/etc/sudoers, /etc/sudoers.d]}
  check_package_files: {type: bool, default: true}
  drift_ignore: {type: list, elements: path, default: []}
"""

QKK_RE = re.compile(r"^warning: (\S+): (/.*) \((.+)\)$")
PERM_REASONS = ("Permissions mismatch", "UID mismatch", "GID mismatch")
CONTENT_REASONS = ("Size mismatch", "checksum mismatch", "Symlink path mismatch")
# sudo skips files in sudoers.d whose name ends in '~' or contains a '.'.
SUDOERS_SKIP_RE = re.compile(r"(~$|\.)")


def _pacman_owned(module):
    result = subprocess.run(
        ["pacman", "-Qlq"], capture_output=True, text=True, timeout=600, check=False
    )
    if result.returncode != 0:
        module.fail_json(msg=f"pacman -Qlq failed: {result.stderr.strip()}")
    return {line.rstrip("/") for line in result.stdout.splitlines() if line}


def _walk(roots, excludes, owned, uids, gids, cap, max_files):
    out = {
        "truncated": False,
        "files_scanned": 0,
        "setuid": [],
        "world_writable_files": [],
        "world_writable_dirs": [],
        "unowned": [],
        "unowned_count": 0,
        "world_writable_count": 0,
        "walk_errors": [],
    }
    excl = tuple(e.rstrip("/") + "/" for e in excludes) + tuple(excludes)

    def excluded(path):
        return path in excludes or path.startswith(excl)

    def onerror(err):
        out["walk_errors"].append(f"{getattr(err, 'filename', '?')}: {err.strerror}")

    for root in roots:
        if not os.path.isdir(root) or excluded(root):
            continue
        for dirpath, dirnames, filenames in os.walk(root, onerror=onerror, followlinks=False):
            if out["files_scanned"] >= max_files:
                out["truncated"] = True
                break
            dirnames[:] = [d for d in dirnames if not excluded(os.path.join(dirpath, d))]
            for name in dirnames + filenames:
                path = os.path.join(dirpath, name)
                try:
                    st = os.lstat(path)
                except OSError as exc:
                    out["walk_errors"].append(f"{path}: {exc.strerror}")
                    continue
                mode = st.st_mode
                if stat.S_ISLNK(mode):
                    continue
                if stat.S_ISREG(mode):
                    out["files_scanned"] += 1
                    if mode & (stat.S_ISUID | stat.S_ISGID):
                        out["setuid"].append({
                            "path": path,
                            "mode": oct(stat.S_IMODE(mode)),
                            "uid": st.st_uid,
                            "gid": st.st_gid,
                            "package_owned": path in owned,
                        })
                if mode & stat.S_IWOTH:
                    if stat.S_ISDIR(mode) and not mode & stat.S_ISVTX:
                        out["world_writable_count"] += 1
                        if len(out["world_writable_dirs"]) < cap:
                            out["world_writable_dirs"].append(path)
                    elif stat.S_ISREG(mode):
                        out["world_writable_count"] += 1
                        if len(out["world_writable_files"]) < cap:
                            out["world_writable_files"].append(path)
                if st.st_uid not in uids or st.st_gid not in gids:
                    out["unowned_count"] += 1
                    if len(out["unowned"]) < cap:
                        out["unowned"].append(path)
    out["walk_errors"] = out["walk_errors"][:cap]
    return out


def _nopasswd(paths):
    found = []
    files = []
    for path in paths:
        if os.path.isdir(path):
            for name in sorted(os.listdir(path)):
                if not SUDOERS_SKIP_RE.search(name):
                    files.append(os.path.join(path, name))
        elif os.path.isfile(path):
            files.append(path)
    for path in files:
        with open(path, encoding="utf-8", errors="replace") as handle:
            for number, line in enumerate(handle, 1):
                text = line.strip()
                if text.startswith("#") or "NOPASSWD" not in text:
                    continue
                found.append({
                    "file": path,
                    "line": number,
                    "text": text[:300],
                    "all_commands": bool(re.search(r"NOPASSWD:\s*ALL\b", text)),
                })
    return {"sudoers_files": files, "nopasswd": found}


def _package_drift(cap, ignore):
    ignore = tuple(ignore)

    result = subprocess.run(
        ["pacman", "-Qkk"], capture_output=True, text=True, timeout=1800, check=False
    )
    perms, content, other = [], [], 0
    for line in (result.stdout + "\n" + result.stderr).splitlines():
        match = QKK_RE.match(line.strip())
        if not match:
            continue
        pkg, path, reason = match.groups()
        if path in ignore or path.startswith(tuple(p.rstrip("/") + "/" for p in ignore)):
            continue
        entry = {"package": pkg, "path": path, "reason": reason}
        if any(r in reason for r in PERM_REASONS):
            perms.append(entry)
        elif any(r in reason for r in CONTENT_REASONS):
            content.append(entry)
        else:
            other += 1
    return {
        "drift_permissions": perms[:cap],
        "drift_permissions_count": len(perms),
        "drift_content": content[:cap],
        "drift_content_count": len(content),
        "drift_other_count": other,
    }


def main():
    module = AnsibleModule(
        argument_spec={
            "roots": {"type": "list", "elements": "path", "required": True},
            "excludes": {"type": "list", "elements": "path", "default": []},
            "max_report": {"type": "int", "default": 50},
            "max_files": {"type": "int", "default": 2000000},
            "sudoers_paths": {
                "type": "list", "elements": "path",
                "default": ["/etc/sudoers", "/etc/sudoers.d"],
            },
            "check_package_files": {"type": "bool", "default": True},
            "drift_ignore": {"type": "list", "elements": "path", "default": []},
        },
        supports_check_mode=True,
    )
    params = module.params
    owned = _pacman_owned(module)
    uids = {entry.pw_uid for entry in pwd.getpwall()}
    gids = {entry.gr_gid for entry in grp.getgrall()}
    result = _walk(
        params["roots"], params["excludes"], owned, uids, gids,
        params["max_report"], params["max_files"],
    )
    result.update(_nopasswd(params["sudoers_paths"]))
    result["package_files_known"] = len(owned)
    if params["check_package_files"]:
        result.update(_package_drift(params["max_report"], params["drift_ignore"]))
    module.exit_json(changed=False, **result)


if __name__ == "__main__":
    main()
