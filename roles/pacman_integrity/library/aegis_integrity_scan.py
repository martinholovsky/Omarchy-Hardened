#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright: Omarchy-Hardened contributors
# SPDX-License-Identifier: Apache-2.0
"""Read-only filesystem and package-integrity sweep."""

from __future__ import annotations

import glob
import grp
import gzip
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
  drift_expected:
    description:
      - Known, benign drift. Each item has C(path), C(reasons) (the exact set of
        C(pacman -Qkk) reasons allowed) and C(why). A file whose reasons match
        exactly is reported in drift_accepted instead of counting as drift.
    type: list
    elements: dict
    default: []
  drift_tightened_is_accepted:
    description:
      - Accept permission-only drift that removes mode bits without adding any
        and keeps owner and group, judged against the package's mtree.
    type: bool
    default: true
"""

QKK_RE = re.compile(r"^warning: (\S+): (/.*) \((.+)\)$")
PERM_REASONS = ("Permissions mismatch", "UID mismatch", "GID mismatch")
CONTENT_REASONS = ("Size mismatch", "checksum mismatch", "Symlink path mismatch")
MTREE_OCTAL_RE = re.compile(r"\\([0-7]{3})")
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


def _mtree_unescape(token):
    # mtree escapes unusual bytes as \ooo; rebuild the bytes, then decode.
    raw = MTREE_OCTAL_RE.sub(lambda m: chr(int(m.group(1), 8)), token)
    return raw.encode("latin-1").decode("utf-8", errors="replace")


def _mtree(pkg):
    """Return {path: (mode, uid, gid)} from the package's local mtree, or {}."""
    result = subprocess.run(
        ["pacman", "-Q", "--", pkg], capture_output=True, text=True, timeout=60, check=False
    )
    fields = result.stdout.split()
    if result.returncode != 0 or len(fields) != 2:
        return {}
    candidates = glob.glob(os.path.join("/var/lib/pacman/local", glob.escape(f"{pkg}-{fields[1]}"), "mtree"))
    if not candidates:
        return {}
    out, defaults = {}, {}
    try:
        with gzip.open(candidates[0], "rt", encoding="latin-1") as handle:
            for line in handle:
                tokens = line.split()
                if not tokens or tokens[0].startswith("#"):
                    continue
                keys = dict(t.split("=", 1) for t in tokens[1:] if "=" in t)
                if tokens[0] == "/set":
                    defaults.update(keys)
                    continue
                if tokens[0] == "/unset":
                    for name in tokens[1:]:
                        defaults.pop(name, None)
                    continue
                attrs = {**defaults, **keys}
                if not {"mode", "uid", "gid"} <= attrs.keys():
                    continue
                path = "/" + _mtree_unescape(tokens[0]).removeprefix("./")
                out[path] = (int(attrs["mode"], 8), int(attrs["uid"]), int(attrs["gid"]))
    except (OSError, ValueError, EOFError):
        return {}
    return out


def _only_tightened(pkg, path, found, cache):
    """True when the only change is mode bits removed, owner and group kept."""
    if set(found) != {"Permissions mismatch"}:
        return False
    if pkg not in cache:
        cache[pkg] = _mtree(pkg)
    expected = cache[pkg].get(path)
    if expected is None:
        return False
    try:
        st = os.lstat(path)
    except OSError:
        return False
    mode, uid, gid = expected
    actual = stat.S_IMODE(st.st_mode)
    return (st.st_uid, st.st_gid) == (uid, gid) and actual & ~mode == 0 and actual != mode


def _package_drift(cap, ignore, expected, tightened_ok):
    ignore = tuple(ignore)
    known = {item["path"]: item for item in expected}

    result = subprocess.run(
        ["pacman", "-Qkk"], capture_output=True, text=True, timeout=1800, check=False
    )
    # pacman prints one line per reason ("GID mismatch", "Permissions
    # mismatch", ...), so group by path: each list names a file once.
    reasons: dict[tuple[str, str], list[str]] = {}
    for line in (result.stdout + "\n" + result.stderr).splitlines():
        match = QKK_RE.match(line.strip())
        if not match:
            continue
        pkg, path, reason = match.groups()
        if path in ignore or path.startswith(tuple(p.rstrip("/") + "/" for p in ignore)):
            continue
        reasons.setdefault((pkg, path), []).append(reason)
    perms, content, accepted, other = [], [], [], 0
    mtrees: dict[str, dict] = {}
    for (pkg, path), found in reasons.items():
        entry = {"package": pkg, "path": path, "reasons": found}
        item = known.get(path)
        if item is not None and set(item.get("reasons", [])) == set(found):
            accepted.append({**entry, "why": item.get("why", "")})
            continue
        if tightened_ok and _only_tightened(pkg, path, found, mtrees):
            accepted.append({**entry, "why": "permissions only tightened (package mtree)"})
            continue
        is_perm = any(r in reason for reason in found for r in PERM_REASONS)
        is_content = any(r in reason for reason in found for r in CONTENT_REASONS)
        if is_perm:
            perms.append(entry)
        if is_content:
            content.append(entry)
        if not (is_perm or is_content):
            other += 1
    return {
        "drift_permissions": perms[:cap],
        "drift_permissions_count": len(perms),
        "drift_content": content[:cap],
        "drift_content_count": len(content),
        "drift_other_count": other,
        "drift_accepted": accepted[:cap],
        "drift_accepted_count": len(accepted),
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
            "drift_expected": {"type": "list", "elements": "dict", "default": []},
            "drift_tightened_is_accepted": {"type": "bool", "default": True},
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
        result.update(_package_drift(
            params["max_report"], params["drift_ignore"],
            params["drift_expected"], params["drift_tightened_is_accepted"],
        ))
    module.exit_json(changed=False, **result)


if __name__ == "__main__":
    main()
