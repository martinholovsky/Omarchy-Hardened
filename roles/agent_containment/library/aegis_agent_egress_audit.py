#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright: Omarchy-Hardened contributors
# SPDX-License-Identifier: Apache-2.0
"""Summarise the agent egress proxy's decisions (D-26)."""

from __future__ import annotations

import fnmatch
import json
import re

from ansible.module_utils.basic import AnsibleModule

DOCUMENTATION = r"""
module: aegis_agent_egress_audit
short_description: Summarise Smokescreen's per-request log lines from the aegis-agent proxies
description:
  - Read-only; parses the JSON lines Smokescreen writes (logrus JSONFormatter).
  - Lines are untrusted input. Only requested_host, allow and enforce_would_deny are read.
options:
  lines: {type: list, elements: str, required: true}
  allowlist: {type: list, elements: str, default: []}
"""

MAX_LINES = 50000
MAX_LINE = 8192
MAX_HOSTS = 200  # distinct hosts kept in the summary
HOST_RE = re.compile(r"[A-Za-z0-9_.:\[\]-]{1,300}")


def _host(value):
    """requested_host without its port, lowercased; None if it does not look like one."""
    if not isinstance(value, str) or not HOST_RE.fullmatch(value):
        return None
    host = value.lower()
    if host.startswith("["):  # [v6]:port
        host = host[1:host.find("]")] if "]" in host else host
    elif host.count(":") == 1:
        host = host.split(":", 1)[0]
    return host or None


def _listed(host, allowlist):
    for raw in allowlist:
        entry = raw.lower()
        if entry.startswith("*.") and fnmatch.fnmatchcase(host, entry):
            return True
        if host == entry:
            return True
    return False


def summarise(lines, allowlist):
    hosts, malformed, considered = {}, 0, 0
    for raw in lines[:MAX_LINES]:
        if len(raw) > MAX_LINE or not raw.lstrip().startswith("{"):
            continue
        try:
            rec = json.loads(raw)
        except ValueError:
            malformed += 1
            continue
        if not isinstance(rec, dict) or "requested_host" not in rec:
            continue
        host = _host(rec.get("requested_host"))
        if host is None:
            malformed += 1
            continue
        considered += 1
        if host not in hosts:
            if len(hosts) >= MAX_HOSTS:
                continue
            hosts[host] = {"host": host, "requests": 0, "denied": 0, "listed": _listed(host, allowlist)}
        hosts[host]["requests"] += 1
        if rec.get("allow") is False:
            hosts[host]["denied"] += 1
    ordered = sorted(hosts.values(), key=lambda h: (-h["requests"], h["host"]))
    return {
        "requests": considered,
        "hosts": ordered,
        "unlisted": [h for h in ordered if not h["listed"]],
        "denied": [h for h in ordered if h["denied"]],
        "malformed": malformed,
        "truncated": len(lines) > MAX_LINES,
    }


def main():
    module = AnsibleModule(
        argument_spec={
            "lines": {"type": "list", "elements": "str", "required": True},
            "allowlist": {"type": "list", "elements": "str", "default": []},
        },
        supports_check_mode=True,
    )
    module.exit_json(changed=False, **summarise(module.params["lines"], module.params["allowlist"]))


if __name__ == "__main__":
    main()
