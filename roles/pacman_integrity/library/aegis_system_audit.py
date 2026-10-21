#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright: Omarchy-Hardened contributors
# SPDX-License-Identifier: Apache-2.0
"""Read-only checks taken from the SnowflakeOS review (roadmap 18m-18o)."""

from __future__ import annotations

import configparser
import glob
import os
import pwd
import re
import subprocess

from ansible.module_utils.basic import AnsibleModule

DOCUMENTATION = r"""
module: aegis_system_audit
short_description: Audit polkit blanket grants, autologin without encryption, weak password hashes
description:
  - Read-only. Never prints a password hash, only its algorithm prefix.
options:
  polkit_dirs: {type: list, elements: path, default: [/etc/polkit-1/rules.d, /usr/share/polkit-1/rules.d]}
  sddm_paths: {type: list, elements: path, default: [/etc/sddm.conf, /etc/sddm.conf.d]}
  shadow_path: {type: path, default: /etc/shadow}
  login_defs: {type: path, default: /etc/login.defs}
  min_uid: {type: int, default: 1000}
"""

# A rule that returns YES somewhere but never looks at action.id grants
# everything it matches (SnowflakeOS's live-ISO rule is the model case).
POLKIT_YES_RE = re.compile(r"polkit\.Result\.YES\b")
POLKIT_ACTION_RE = re.compile(r"\baction\.id\b|\baction\.lookup\b")
# crypt(5) prefixes. yescrypt ($y$), gost-yescrypt ($gy$), scrypt ($7$) and
# bcrypt ($2?$) are acceptable; MD5, SHA-256/512 crypt and DES are weak.
WEAK_PREFIXES = {"$1$": "MD5", "$5$": "SHA-256", "$6$": "SHA-512"}
STRONG_PREFIX_RE = re.compile(r"^\$(y|gy|7|2[abxy])\$")


def _polkit(dirs):
    files, blanket = 0, []
    for directory in dirs:
        for path in sorted(glob.glob(os.path.join(glob.escape(directory), "*.rules"))):
            files += 1
            try:
                with open(path, encoding="utf-8", errors="replace") as handle:
                    text = handle.read()
            except OSError:
                continue
            # Ignore comments so a commented-out example does not count.
            code = re.sub(r"/\*.*?\*/|//[^\n]*", "", text, flags=re.S)
            if POLKIT_YES_RE.search(code) and not POLKIT_ACTION_RE.search(code):
                blanket.append(path)
    return {"polkit_rules_files": files, "polkit_blanket": blanket}


def _sddm_autologin(paths):
    found = []
    candidates = []
    for path in paths:
        if os.path.isdir(path):
            candidates += sorted(glob.glob(os.path.join(glob.escape(path), "*.conf")))
        elif os.path.isfile(path):
            candidates.append(path)
    for path in candidates:
        parser = configparser.ConfigParser(strict=False, interpolation=None)
        try:
            parser.read(path, encoding="utf-8")
        except (configparser.Error, OSError):
            continue
        user = parser.get("Autologin", "User", fallback="").strip()
        if user:
            found.append({"file": path, "user": user})
    return found


def _root_encrypted():
    # Fails closed: anything it cannot establish counts as "not encrypted",
    # which only matters (as a WARN) when autologin is on.
    try:
        source = subprocess.run(
            ["findmnt", "-no", "SOURCE", "/"], capture_output=True, text=True, timeout=30, check=False
        ).stdout.strip()
        source = re.sub(r"\[.*\]$", "", source)  # btrfs subvolume suffix
        if not source.startswith("/dev/"):
            return False, source or "unknown"
        chain = subprocess.run(
            ["lsblk", "-s", "-no", "TYPE,FSTYPE", source],
            capture_output=True, text=True, timeout=30, check=False,
        ).stdout.split()
    except (OSError, subprocess.TimeoutExpired):
        return False, "unknown (findmnt/lsblk failed)"
    return ("crypt" in chain or "crypto_LUKS" in chain), source


def _hashes(shadow_path, min_uid):
    weak, checked = [], 0
    with open(shadow_path, encoding="utf-8", errors="replace") as handle:
        for line in handle:
            fields = line.rstrip("\n").split(":")
            if len(fields) < 2:
                continue
            name, value = fields[0], fields[1]
            try:
                uid = pwd.getpwnam(name).pw_uid
            except KeyError:
                continue
            if uid != 0 and uid < min_uid:
                continue
            if value == "":
                weak.append({"user": name, "algorithm": "empty password"})
                checked += 1
                continue
            if value.startswith(("!", "*")):
                continue  # locked or no password: nothing to crack
            checked += 1
            if STRONG_PREFIX_RE.match(value):
                continue
            prefix = next((p for p in WEAK_PREFIXES if value.startswith(p)), None)
            weak.append({"user": name, "algorithm": WEAK_PREFIXES.get(prefix, "DES or unknown")})
    return weak, checked


def _encrypt_method(login_defs):
    try:
        with open(login_defs, encoding="utf-8", errors="replace") as handle:
            for line in handle:
                match = re.match(r"^\s*ENCRYPT_METHOD\s+(\S+)", line)
                if match:
                    return match.group(1)
    except OSError:
        pass
    return None


def main():
    module = AnsibleModule(
        argument_spec={
            "polkit_dirs": {"type": "list", "elements": "path",
                            "default": ["/etc/polkit-1/rules.d", "/usr/share/polkit-1/rules.d"]},
            "sddm_paths": {"type": "list", "elements": "path",
                           "default": ["/etc/sddm.conf", "/etc/sddm.conf.d"]},
            "shadow_path": {"type": "path", "default": "/etc/shadow"},
            "login_defs": {"type": "path", "default": "/etc/login.defs"},
            "min_uid": {"type": "int", "default": 1000},
        },
        supports_check_mode=True,
    )
    params = module.params
    result = _polkit(params["polkit_dirs"])
    result["autologin"] = _sddm_autologin(params["sddm_paths"])
    result["root_encrypted"], result["root_source"] = _root_encrypted()
    try:
        result["weak_hashes"], result["hashes_checked"] = _hashes(params["shadow_path"], params["min_uid"])
    except OSError as exc:
        module.fail_json(msg=f"cannot read {params['shadow_path']}: {exc}")
    result["encrypt_method"] = _encrypt_method(params["login_defs"])
    module.exit_json(changed=False, **result)


if __name__ == "__main__":
    main()
