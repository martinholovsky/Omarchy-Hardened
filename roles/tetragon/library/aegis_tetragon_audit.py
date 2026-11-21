#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright: Omarchy-Hardened contributors
# SPDX-License-Identifier: Apache-2.0
"""Summarise Tetragon's policy events per policy for the audit (D-37)."""

from __future__ import annotations

import calendar
import fnmatch
import json
import os
import re
import time

from ansible.module_utils.basic import AnsibleModule

DOCUMENTATION = r"""
module: aegis_tetragon_audit
short_description: Count Tetragon policy events in the export log, per policy and program
description:
  - Read-only. Reads Tetragon's JSON export file and its rotated backups.
  - Never returns command lines (process.arguments); only the program, its
    parent, the policy and the object the event is about (a path, a BPF
    program name or a number).
options:
  export_file: {type: path, required: true}
  window_days: {type: int, default: 7}
  known: {type: dict, default: {}}
  run_started: {type: float, default: 0}
  past_runs: {type: list, elements: raw, default: []}
"""

EVENT_KEYS = ("process_kprobe", "process_tracepoint", "process_lsm", "process_uprobe")
MAX_TOTAL_BYTES = 64 * 1024 * 1024  # across the current file and its backups
MAX_LINE_BYTES = 256 * 1024
MAX_ITEMS = 5  # distinct (program, object) rows listed per policy
MAX_FIELD = 300
TIME_RE = re.compile(r"^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})(?:\.\d+)?Z$")
# Kernel modules shipped by packages live here; anything else is reported.
MODULE_DIR = "/usr/lib/modules/"
# Ansible copies each module to <tmp>/ansible-tmp-*/AnsiballZ_<name>.py and runs it with python.
ANSIBALLZ = "/AnsiballZ_"
MAX_WINDOWS = 200


def _clean(value):
    text = value if isinstance(value, str) else ""
    text = "".join(ch if 32 <= ord(ch) != 127 else "?" for ch in text)
    return text[:MAX_FIELD]


def _epoch(stamp):
    match = TIME_RE.match(stamp) if isinstance(stamp, str) else None
    if not match:
        return None
    return calendar.timegm(time.strptime(match.group(1), "%Y-%m-%dT%H:%M:%S"))


def _target(args, function=""):
    """The object an event is about: a path, a BPF program, else hook(number)."""
    first_int = None
    for arg in args if isinstance(args, list) else []:
        if not isinstance(arg, dict):
            continue
        for key in ("file_arg", "linux_binprm_arg", "path_arg"):
            if isinstance(arg.get(key), dict) and arg[key].get("path"):
                return _clean(arg[key]["path"])
        if isinstance(arg.get("bpf_attr_arg"), dict):
            attr = arg["bpf_attr_arg"]
            return _clean("bpf %s %s" % (attr.get("ProgType", "?"), attr.get("ProgName", "")))
        if first_int is None and isinstance(arg.get("int_arg"), int):
            first_int = arg["int_arg"]
    if function:
        return _clean("%s(%s)" % (function, "" if first_int is None else first_int))
    return "" if first_int is None else str(first_int)


def _files(export_file):
    """The export file first, then its rotated backups, newest first."""
    folder, name = os.path.split(export_file)
    stem, ext = os.path.splitext(name)
    out = [export_file] if os.path.isfile(export_file) else []
    try:
        names = os.listdir(folder)
    except OSError:
        names = []
    backups = [os.path.join(folder, n) for n in names
               if n.startswith(stem + "-") and n.endswith(ext) and n != name]
    backups = [p for p in backups if os.path.isfile(p) and not os.path.islink(p)]
    return out + sorted(backups, key=os.path.getmtime, reverse=True)


def _ansible_module(proc, parent):
    """An Ansible module of this playbook: python3 running an AnsiballZ_ file."""
    for node in (proc, parent):
        args = node.get("arguments") if isinstance(node.get("arguments"), str) else ""
        if ANSIBALLZ in args and node.get("binary", "").startswith("/usr/bin/python"):
            return True
    return False


def _in_windows(stamp, windows):
    return any(start <= stamp <= end for start, end in windows)


def _known(known, policy, binary):
    patterns = list(known.get(policy) or []) + list(known.get("*") or [])
    return any(fnmatch.fnmatchcase(binary, str(p)) for p in patterns)


def _windows(raw):
    out = []
    for item in (raw if isinstance(raw, list) else [])[-MAX_WINDOWS:]:
        if (isinstance(item, list) and len(item) == 2
                and all(isinstance(x, (int, float)) for x in item) and item[0] <= item[1]):
            out.append((float(item[0]), float(item[1])))
    return out


def summarise(export_file, window_days, known, run_started, now=None, past_runs=None):
    """Count events per policy. Not warned about: events during this run, and
    events from this playbook's own Ansible modules during an earlier run."""
    now = time.time() if now is None else now
    since = now - window_days * 86400
    windows = _windows(past_runs)
    result = {"present": False, "files": 0, "events": 0, "parse_errors": 0, "truncated": False, "policies": {}}
    budget = MAX_TOTAL_BYTES
    for path in _files(export_file):
        result["present"] = True
        result["files"] += 1
        with open(path, "rb") as handle:
            for raw in handle:
                budget -= len(raw)
                if budget < 0:
                    result["truncated"] = True
                    break
                if len(raw) > MAX_LINE_BYTES:
                    result["parse_errors"] += 1
                    continue
                try:
                    doc = json.loads(raw)
                except ValueError:
                    result["parse_errors"] += 1
                    continue
                if not isinstance(doc, dict):
                    result["parse_errors"] += 1
                    continue
                key = next((k for k in EVENT_KEYS if isinstance(doc.get(k), dict)), None)
                stamp = _epoch(doc.get("time"))
                if key is None or stamp is None:
                    continue
                if stamp < since:
                    continue
                event = doc[key]
                policy = _clean(event.get("policy_name")) or "(no policy)"
                proc = event.get("process") if isinstance(event.get("process"), dict) else {}
                parent = event.get("parent") if isinstance(event.get("parent"), dict) else {}
                binary = _clean(proc.get("binary")) or "?"
                target = _target(event.get("args"), _clean(event.get("function_name")))
                entry = result["policies"].setdefault(
                    policy, {"events": 0, "warn": 0, "known": 0, "during_run": 0, "expected": 0, "rows": {}})
                entry["events"] += 1
                result["events"] += 1
                if run_started and stamp >= run_started:
                    entry["during_run"] += 1
                    continue
                if _in_windows(stamp, windows) and _ansible_module(proc, parent):
                    entry["during_run"] += 1
                    continue
                if _known(known, policy, binary):
                    entry["known"] += 1
                    continue
                if policy == "aegis-kernel-modules" and target.startswith(MODULE_DIR):
                    entry["expected"] += 1
                    continue
                entry["warn"] += 1
                row = entry["rows"].setdefault(
                    (binary, target), {"binary": binary, "parent": _clean(parent.get("binary")),
                                       "target": target, "count": 0, "last": 0})
                row["count"] += 1
                row["last"] = max(row["last"], stamp)
        if result["truncated"]:
            break
    for entry in result["policies"].values():
        rows = sorted(entry["rows"].values(), key=lambda r: (-r["count"], -r["last"]))
        entry["distinct"] = len(rows)
        entry["rows"] = rows[:MAX_ITEMS]
    return result


def main():
    module = AnsibleModule(
        argument_spec={
            "export_file": {"type": "path", "required": True},
            "window_days": {"type": "int", "default": 7},
            "known": {"type": "dict", "default": {}},
            "run_started": {"type": "float", "default": 0},
            "past_runs": {"type": "list", "elements": "raw", "default": []},
        },
        supports_check_mode=True,
    )
    params = module.params
    try:
        result = summarise(params["export_file"], params["window_days"], params["known"] or {},
                           params["run_started"], past_runs=params["past_runs"])
    except OSError as err:
        module.exit_json(changed=False, present=True, error="cannot read the export log: %s" % err,
                         files=0, events=0, parse_errors=0, truncated=False, policies={})
    module.exit_json(changed=False, error="", **result)


if __name__ == "__main__":
    main()
