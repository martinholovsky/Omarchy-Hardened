#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright: Omarchy-Hardened contributors
# SPDX-License-Identifier: Apache-2.0
"""DNS transport and DNSSEC mode in force in systemd-resolved (D-39 (a))."""

from __future__ import annotations

import ipaddress
import json
import subprocess

from ansible.module_utils.basic import AnsibleModule

DOCUMENTATION = r"""
module: aegis_dns
short_description: Report the DNS-over-TLS and DNSSEC modes systemd-resolved uses
description:
  - Read-only. Runs C(resolvectl --json=short status) (systemd 259 or later,
    the io.systemd.Resolve.DumpDNSConfiguration reply), or parses
    I(status_json) in tests.
  - One row per scope that has DNS servers (global, each link). A link without
    its own mode uses the global one. With no servers anywhere, the global
    fallback servers are the scope.
options:
  status_json: {type: str, required: false}
"""

MAX_SCOPES = 64
MAX_SERVERS = 16
AF_INET = 2
AF_INET6 = 10
# systemd's parse_boolean(); resolvectl prints these modes as +X / -X.
TRUE_WORDS = {"1", "yes", "y", "true", "t", "on"}
FALSE_WORDS = {"0", "no", "n", "false", "f", "off"}


def _mode(value, default):
    if not isinstance(value, str) or not value:
        return default
    word = value.lower()
    if word in TRUE_WORDS:
        return "yes"
    if word in FALSE_WORDS:
        return "no"
    return word[:32]


def _server(entry):
    """{'address': [1,1,1,1], 'family': 2, 'port': 853, 'name': 'x'} -> '1.1.1.1:853#x'."""
    if not isinstance(entry, dict):
        return "?"
    raw = entry.get("address")
    family = entry.get("family")
    try:
        packed = bytes(raw) if isinstance(raw, list) else b""
        if family == AF_INET and len(packed) == 4:
            text = str(ipaddress.IPv4Address(packed))
        elif family == AF_INET6 and len(packed) == 16:
            text = str(ipaddress.IPv6Address(packed))
        else:
            text = "?"
    except (TypeError, ValueError):
        text = "?"
    port = entry.get("port")
    if isinstance(port, int) and port not in (0, 53):
        text = ("[%s]:%d" % (text, port)) if family == AF_INET6 else ("%s:%d" % (text, port))
    name = entry.get("name")
    if isinstance(name, str) and name:
        text += "#" + name[:64]
    return text


def assess(configs):
    """Effective modes per scope that has servers."""
    if not isinstance(configs, list):
        return {"error": "resolvectl JSON is not a list", "scopes": []}
    configs = [c for c in configs[:MAX_SCOPES] if isinstance(c, dict)]
    glob = next((c for c in configs if not c.get("ifname") and not c.get("delegate")), None)
    if glob is None:
        return {"error": "resolvectl JSON has no global configuration", "scopes": []}
    g_dot = _mode(glob.get("dnsOverTLS"), "no")
    g_sec = _mode(glob.get("dnssec"), "no")
    scopes = []
    for conf in configs:
        servers = conf.get("servers") or []
        if not isinstance(servers, list) or not servers:
            continue
        name = "global" if conf is glob else ("link " + str(conf.get("ifname") or conf.get("delegate"))[:32])
        scopes.append({
            "scope": name,
            "dot": _mode(conf.get("dnsOverTLS"), g_dot),
            "dnssec": _mode(conf.get("dnssec"), g_sec),
            "servers": [_server(s) for s in servers[:MAX_SERVERS]],
        })
    if not scopes:
        fallback = glob.get("fallbackServers") or []
        if isinstance(fallback, list) and fallback:
            scopes.append({"scope": "fallback", "dot": g_dot, "dnssec": g_sec,
                           "servers": [_server(s) for s in fallback[:MAX_SERVERS]]})
    return {"error": "" if scopes else "no DNS servers configured", "scopes": scopes}


def main():
    module = AnsibleModule(
        argument_spec={"status_json": {"type": "str", "required": False}},
        supports_check_mode=True,
    )
    output = module.params["status_json"]
    if output is None:
        try:
            proc = subprocess.run(["resolvectl", "--json=short", "status"],
                                  capture_output=True, text=True, timeout=20, check=False)
        except (OSError, subprocess.TimeoutExpired) as err:
            module.exit_json(changed=False, error="resolvectl failed: %s" % err, scopes=[])
        if proc.returncode != 0:
            module.exit_json(changed=False, error="resolvectl failed: %s" % proc.stderr.strip()[:200], scopes=[])
        output = proc.stdout
    try:
        configs = json.loads(output)
    except ValueError as err:
        module.exit_json(changed=False, error="resolvectl JSON unreadable: %s" % err, scopes=[])
    module.exit_json(changed=False, **assess(configs))


if __name__ == "__main__":
    main()
