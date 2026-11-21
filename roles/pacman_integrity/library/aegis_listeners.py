#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright: Omarchy-Hardened contributors
# SPDX-License-Identifier: Apache-2.0
"""Inventory of listening sockets (roadmap #29, D-37 review)."""

from __future__ import annotations

import fnmatch
import re
import subprocess

from ansible.module_utils.basic import AnsibleModule

DOCUMENTATION = r"""
module: aegis_listeners
short_description: List listening TCP/UDP sockets, split into loopback and exposed
description:
  - Read-only. Runs C(ss -Htulpn) (or parses I(ss_output) in tests).
  - An exposed listener matching an entry of I(known) (C(process:port), globs
    allowed, e.g. C(avahi-daemon:5353) or C(*:68)) is not reported as unknown.
options:
  ss_output: {type: str, required: false}
  known: {type: list, elements: str, default: []}
"""

PROC_RE = re.compile(r'users:\(\("([^"]{1,64})"')
MAX_LINES = 5000


def _split_addr(local):
    """'0.0.0.0:5353' / '[::]:22' / '127.0.0.53%lo:53' / '*:631' -> (host, port)."""
    host, _, port = local.rpartition(":")
    host = host.strip("[]")
    iface = ""
    if "%" in host:
        host, iface = host.split("%", 1)
    return host, port, iface


def _loopback(host, iface):
    return iface == "lo" or host.startswith("127.") or host == "::1"


def parse(output, known):
    rows = {"exposed": [], "loopback": [], "unknown": [], "parsed": 0}
    seen = set()
    for line in output.splitlines()[:MAX_LINES]:
        cols = line.split()
        if len(cols) < 5 or cols[0] not in ("tcp", "udp"):
            continue
        rows["parsed"] += 1
        host, port, iface = _split_addr(cols[4])
        match = PROC_RE.search(line)
        proc = match.group(1) if match else "?"
        key = (cols[0], proc, port, _loopback(host, iface))
        if key in seen:  # IPv4 and IPv6 twins, several fds
            continue
        seen.add(key)
        item = {"proto": cols[0], "addr": cols[4][:80], "port": port, "process": proc}
        if _loopback(host, iface):
            rows["loopback"].append(item)
            continue
        rows["exposed"].append(item)
        if not any(fnmatch.fnmatchcase(proc + ":" + port, pattern) for pattern in known):
            rows["unknown"].append(item)
    return rows


def main():
    module = AnsibleModule(
        argument_spec={
            "ss_output": {"type": "str", "required": False},
            "known": {"type": "list", "elements": "str", "default": []},
        },
        supports_check_mode=True,
    )
    output = module.params["ss_output"]
    if output is None:
        try:
            proc = subprocess.run(["ss", "-Htulpn"], capture_output=True, text=True, timeout=20, check=False)
        except (OSError, subprocess.TimeoutExpired) as err:
            module.exit_json(changed=False, error="ss failed: %s" % err, exposed=[], loopback=[], unknown=[], parsed=0)
        if proc.returncode != 0:
            module.exit_json(changed=False, error="ss failed: %s" % proc.stderr.strip()[:200],
                             exposed=[], loopback=[], unknown=[], parsed=0)
        output = proc.stdout
    module.exit_json(changed=False, error="", **parse(output, module.params["known"]))


if __name__ == "__main__":
    main()
