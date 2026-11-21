#!/usr/bin/python3 -I
# Copyright: Omarchy-Hardened contributors
# SPDX-License-Identifier: Apache-2.0
# ruff: noqa: T201, EM101, EM102, TRY003, CPY001, S603, S606
# (T201: a CLI and a helper that answer on stdout. EM/TRY003: UsageError carries
#  one short sentence for the user. CPY001: SPDX header above. S603/S606: every
#  process is started from a fixed absolute path with an argv list, never a
#  shell; component and unit names are allowlisted before they get there.)
"""Aegis status panel back end (D-38).

Installed under three names; the name picks the mode:

  aegis-status  (root, systemd timer) writes /run/aegis/status.json
  aegis-helper  (root, via pkexec or sudo) runs one allowlisted action
  aegis         (the desktop user) reads the status and starts the actions

Trust boundary: the helper runs as root on behalf of whoever passed polkit or
sudo. It accepts only the verbs in VERBS and the component ids in
/etc/aegis/panel.json (root-owned, written by the playbook), and only ever runs
fixed programs with argv lists. Standard library only.
"""

from __future__ import annotations

import grp
import json
import os
import pwd
import re
import subprocess
import sys
import time
from pathlib import Path
from typing import TYPE_CHECKING, TypedDict

if TYPE_CHECKING:
    from collections.abc import Callable

CONFIG = Path("/etc/aegis/panel.json")
STATUS = Path("/run/aegis/status.json")
PAUSED = Path("/run/aegis/paused.json")
DISABLED = Path("/var/lib/aegis/panel-disabled.json")
AUDIT = Path("/var/lib/aegis/audit.jsonl")
DRIFT_LOG = Path("/var/lib/aegis/drift-check.log")
HELPER = "/usr/local/libexec/aegis-helper"
SYSTEMCTL = "/usr/bin/systemctl"
SYSTEMD_RUN = "/usr/bin/systemd-run"
JOURNALCTL = "/usr/bin/journalctl"
LOGGER = "/usr/bin/logger"

ID_RE = re.compile(r"[a-z][a-z0-9-]{0,31}")  # always fullmatch
UNIT_RE = re.compile(r"[A-Za-z0-9@_.-]{1,64}\.service")  # always fullmatch
MAX_PAUSE_MINUTES = 120
MAX_LOG_LINES = 400
MAX_DETAIL = 300
MAX_ISSUES = 10
MAX_AUDIT_BYTES = 4 * 1024 * 1024
FIRST_HUMAN_UID = 1000
PRINTABLE_FROM = 0x20
DEL = 0x7F
SEVERITY = {"ok": 0, "off": 0, "unknown": 1, "paused": 2, "disabled": 2, "warn": 2, "fail": 3}
STATUSES = ("PASS", "INFO", "WARN", "FAIL", "ACCEPTED")
SAFE_ENV = {"PATH": "/usr/bin:/usr/sbin", "LC_ALL": "C.UTF-8"}

Json = dict[str, object]


class Component(TypedDict):
    """One entry of /etc/aegis/panel.json, validated."""

    id: str
    name: str
    units: list[str]
    findings: list[str]
    pausable: bool
    logs: list[str]
    log_grep: str


class Finding(TypedDict):
    """One line of the audit file, reduced to what the panel shows."""

    id: str
    status: str
    detail: str


class UnitState(TypedDict):
    """What systemd says about one unit."""

    name: str
    load: str
    active: str
    enabled: str


class UsageError(Exception):
    """A request the helper refuses."""


def _clean(value: object, limit: int = MAX_DETAIL) -> str:
    text = value if isinstance(value, str) else ""
    text = "".join(ch if ch == "\n" or PRINTABLE_FROM <= ord(ch) != DEL else "?" for ch in text)
    return text[:limit]


def _read_json(path: Path) -> object:
    try:
        with path.open(encoding="utf-8") as handle:
            return json.load(handle)
    except (OSError, ValueError):
        return None


def _read_state(path: Path) -> dict[str, dict[str, object]]:
    raw = _read_json(path)
    if not isinstance(raw, dict):
        return {}
    return {k: v for k, v in raw.items() if isinstance(k, str) and isinstance(v, dict)}


def _write_json(path: Path, data: object, mode: int = 0o600, group: int | None = None) -> None:
    """Write atomically: a reader never sees half a file."""
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(f".{path.name}.{os.getpid()}")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, mode)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(data, handle, indent=1, sort_keys=True)
        if group is not None:
            os.chown(tmp, 0, group)
        tmp.chmod(mode)
        tmp.replace(path)
    except BaseException:
        tmp.unlink(missing_ok=True)
        raise


def _run(argv: list[str], timeout: int = 20) -> subprocess.CompletedProcess[str]:
    return subprocess.run(argv, capture_output=True, text=True, timeout=timeout, check=False, env=SAFE_ENV)


def load_config(path: Path = CONFIG) -> dict[str, Component]:
    """Component definitions, validated; anything malformed is dropped."""
    raw = _read_json(path)
    items = raw.get("components", []) if isinstance(raw, dict) else []
    out: dict[str, Component] = {}
    for item in items if isinstance(items, list) else []:
        if not isinstance(item, dict) or not ID_RE.fullmatch(str(item.get("id", ""))):
            continue
        units = [u for u in item.get("units", []) if isinstance(u, str) and UNIT_RE.fullmatch(u)]
        logs = [u for u in item.get("logs", []) if isinstance(u, str) and (UNIT_RE.fullmatch(u) or u == "kernel")]
        out[item["id"]] = Component(
            id=item["id"],
            name=_clean(item.get("name", item["id"]), 60),
            units=units,
            findings=[p for p in item.get("findings", []) if isinstance(p, str) and p],
            pausable=bool(item.get("pausable")) and bool(units),
            logs=logs,
            log_grep=_clean(item.get("log_grep", ""), 40),
        )
    return out


# Status file, written by root.


def unit_state(unit: str) -> UnitState:
    """Load, active and enablement state of one unit."""
    proc = _run([SYSTEMCTL, "show", "-P", "LoadState", "-P", "ActiveState", "-P", "UnitFileState", "--", unit])
    load, active, enabled = [*proc.stdout.splitlines(), "", "", ""][:3]
    return UnitState(name=unit, load=load, active=active, enabled=enabled)


def read_findings(path: Path = AUDIT) -> list[Finding]:
    """Read the last audit's findings; empty if the file is missing or oversized."""
    try:
        if path.stat().st_size > MAX_AUDIT_BYTES:
            return []
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError:
        return []
    out: list[Finding] = []
    for line in lines:
        try:
            item = json.loads(line)
        except ValueError:
            continue
        if isinstance(item, dict) and isinstance(item.get("id"), str) and isinstance(item.get("status"), str):
            out.append(Finding(id=item["id"], status=item["status"], detail=_clean(item.get("detail", ""))))
    return out


def _until(entry: dict[str, object] | None) -> float:
    value = (entry or {}).get("until", 0)
    return float(value) if isinstance(value, (int, float)) else 0.0


def component_state(  # noqa: PLR0911, PLR0913 (one return per state; the state is these six inputs)
    comp: Component,
    units: list[UnitState],
    findings: list[Finding],
    *,
    paused: dict[str, dict[str, object]],
    disabled: dict[str, dict[str, object]],
    now: float,
) -> str:
    """Return the worst state of one component: disabled, paused, fail, warn, off, unknown or ok."""
    if comp["id"] in disabled:
        return "disabled"
    if _until(paused.get(comp["id"])) > now:
        return "paused"
    statuses = {f["status"] for f in findings}
    if "FAIL" in statuses:
        return "fail"
    installed = [u for u in units if u["load"] == "loaded"]
    if any(u["active"] != "active" for u in installed) or "WARN" in statuses:
        return "warn"
    if units and not installed and not findings:
        return "off"
    if not units and not findings:
        return "unknown"
    return "ok"


def _counts(findings: list[Finding]) -> dict[str, int]:
    return {s: sum(1 for f in findings if f["status"] == s) for s in STATUSES}


def _issues(findings: list[Finding]) -> list[Finding]:
    return [f for f in findings if f["status"] in {"FAIL", "WARN"}][:MAX_ISSUES]


def _mtime(path: Path) -> int:
    try:
        return int(path.stat().st_mtime)
    except OSError:
        return 0


def build_status(  # noqa: PLR0913 (keyword-only inputs, injected in tests)
    config: dict[str, Component],
    findings: list[Finding],
    *,
    state_of: Callable[[str], UnitState] = unit_state,
    now: float | None = None,
    paused: dict[str, dict[str, object]] | None = None,
    disabled: dict[str, dict[str, object]] | None = None,
) -> Json:
    """Build the document the panel reads: one entry per component."""
    now = time.time() if now is None else now
    paused = _read_state(PAUSED) if paused is None else paused
    disabled = _read_state(DISABLED) if disabled is None else disabled
    components: list[Json] = []
    claimed: set[str] = set()
    for comp in config.values():
        mine = [f for f in findings if any(f["id"].startswith(p) for p in comp["findings"])]
        claimed.update(f["id"] for f in mine)
        units = [state_of(u) for u in comp["units"]]
        state = component_state(comp, units, mine, paused=paused, disabled=disabled, now=now)
        components.append(
            {
                "id": comp["id"],
                "name": comp["name"],
                "state": state,
                "units": units,
                "counts": _counts(mine),
                "issues": _issues(mine),
                "paused_until": int(_until(paused.get(comp["id"]))) if state == "paused" else 0,
                "actions": {
                    "pause": comp["pausable"] and state not in {"paused", "disabled", "off"},
                    "resume": state in {"paused", "disabled"},
                    "disable": comp["pausable"] and state != "disabled",
                    "logs": bool(comp["logs"]),
                },
            }
        )
    other = [f for f in findings if f["id"] not in claimed]
    if other:
        statuses = {f["status"] for f in other}
        components.append(
            {
                "id": "other",
                "name": "Other checks",
                "state": "fail" if "FAIL" in statuses else "warn" if "WARN" in statuses else "ok",
                "units": [],
                "counts": _counts(other),
                "issues": _issues(other),
                "paused_until": 0,
                "actions": {"pause": False, "resume": False, "disable": False, "logs": False},
            }
        )
    states = [str(c["state"]) for c in components]
    worst = max(states, key=lambda s: SEVERITY.get(s, 1), default="unknown")
    return {
        "version": 1,
        "generated": int(now),
        "worst": worst,
        "audit_time": _mtime(AUDIT),
        "drift_time": _mtime(DRIFT_LOG),
        "components": components,
    }


def cmd_collect() -> int:
    """aegis-status: write the status file (root)."""
    if os.geteuid() != 0:
        print("aegis-status: run as root (aegis-status.service)", file=sys.stderr)
        return 2
    try:
        group = grp.getgrnam("wheel").gr_gid
    except KeyError:
        group = 0
    _write_json(STATUS, build_status(load_config(), read_findings()), mode=0o640, group=group)
    return 0


# Helper actions, run as root through pkexec or sudo.


def _requester() -> str:
    for var, via in (("PKEXEC_UID", "pkexec"), ("SUDO_UID", "sudo")):
        value = os.environ.get(var, "")
        if value.isdigit():
            return f"uid {value} via {via}"
    return "root"


def _log(message: str) -> None:
    _run([LOGGER, "-t", "aegis-helper", "-p", "auth.notice", "--", message])
    print(message)


def _notify(title: str, message: str) -> None:
    """Desktop notification for every logged-in user, as the drift check does."""
    for bus in Path("/run/user").glob("*/bus"):
        uid = bus.parent.name
        if not uid.isdigit() or int(uid) < FIRST_HUMAN_UID:
            continue
        try:
            user = pwd.getpwuid(int(uid)).pw_name
        except KeyError:
            continue
        env = f"DBUS_SESSION_BUS_ADDRESS=unix:path={bus}"
        _run(
            [
                "/usr/bin/runuser",
                "-u",
                user,
                "--",
                "/usr/bin/env",
                env,
                "/usr/bin/notify-send",
                "-a",
                "Aegis",
                title,
                message,
            ],
            timeout=10,
        )


def _refresh() -> None:
    _run([SYSTEMCTL, "start", "--no-block", "aegis-status.service"])


def _component(config: dict[str, Component], cid: str) -> Component:
    if not ID_RE.fullmatch(cid) or cid not in config:
        raise UsageError(f"unknown component: {cid!r}")
    return config[cid]


def _forget(path: Path, cid: str, mode: int) -> None:
    state = _read_state(path)
    if cid in state:
        del state[cid]
        _write_json(path, state, mode=mode)


def do_unlock(_config: dict[str, Component], args: list[str], _now: float) -> int:
    """Start admin mode: polkit keeps this authorization for a few minutes."""
    if args:
        raise UsageError("unlock takes no arguments")
    _log(f"admin mode unlocked by {_requester()}")
    return 0


def do_pause(config: dict[str, Component], args: list[str], now: float) -> int:
    """Stop a component and schedule its return; a pause always ends."""
    if len(args) != 2 or not args[1].isdigit() or not 1 <= int(args[1]) <= MAX_PAUSE_MINUTES:  # noqa: PLR2004 (component, minutes)
        raise UsageError(f"usage: pause <component> <1-{MAX_PAUSE_MINUTES} minutes>")
    comp = _component(config, args[0])
    if not comp["pausable"]:
        raise UsageError(f"{comp['id']} cannot be paused")
    minutes = int(args[1])
    _run([SYSTEMCTL, "stop", "--", f"aegis-resume-{comp['id']}.timer"])
    timer = _run(
        [
            SYSTEMD_RUN,
            f"--unit=aegis-resume-{comp['id']}",
            f"--on-active={minutes}m",
            "--timer-property=AccuracySec=10s",
            "--",
            HELPER,
            "resume",
            comp["id"],
        ]
    )
    if timer.returncode != 0:
        raise UsageError(f"could not schedule the resume, {comp['id']} left running: {_clean(timer.stderr)}")
    for unit in comp["units"]:
        _run([SYSTEMCTL, "stop", "--", unit])
    paused = _read_state(PAUSED)
    paused[comp["id"]] = {"until": int(now) + minutes * 60, "by": _requester()}
    _write_json(PAUSED, paused, mode=0o644)
    _log(f"{comp['id']} paused for {minutes} min by {_requester()}")
    _notify("Aegis: protection paused", f"{comp['name']} is paused for {minutes} minutes")
    _refresh()
    return 0


def do_resume(config: dict[str, Component], args: list[str], _now: float) -> int:
    """Turn a paused or disabled component back on."""
    if len(args) != 1:
        raise UsageError("usage: resume <component>")
    comp = _component(config, args[0])
    for unit in comp["units"]:
        _run([SYSTEMCTL, "enable", "--now", "--", unit])
    _run([SYSTEMCTL, "stop", "--", f"aegis-resume-{comp['id']}.timer"])
    _forget(PAUSED, comp["id"], 0o644)
    _forget(DISABLED, comp["id"], 0o600)
    _log(f"{comp['id']} resumed by {_requester()}")
    _refresh()
    return 0


def do_logs(config: dict[str, Component], args: list[str], _now: float) -> int:
    """Print the component's recent journal, from its fixed sources only."""
    if len(args) != 1:
        raise UsageError("usage: logs <component>")
    comp = _component(config, args[0])
    for source in comp["logs"]:
        cmd = [JOURNALCTL, "--no-pager", "-q", "-o", "short-iso", "-n", str(MAX_LOG_LINES)]
        cmd += ["-k"] if source == "kernel" else ["-u", source]
        if comp["log_grep"]:
            cmd += ["--grep", comp["log_grep"]]
        print(f"==> {source}")
        print(_clean(_run(cmd, timeout=30).stdout, 200_000))
    _log(f"logs of {comp['id']} read by {_requester()}")
    return 0


def do_disable(config: dict[str, Component], args: list[str], now: float) -> int:
    """Turn a component off until the next apply. Only under sudo (D-38)."""
    if os.environ.get("PKEXEC_UID"):
        raise UsageError("disable needs sudo in a terminal (D-38): run  aegis disable <component>")
    if len(args) != 1:
        raise UsageError("usage: disable <component>")
    comp = _component(config, args[0])
    if not comp["pausable"]:
        raise UsageError(f"{comp['id']} cannot be disabled from the panel")
    for unit in comp["units"]:
        _run([SYSTEMCTL, "disable", "--now", "--", unit])
    disabled = _read_state(DISABLED)
    disabled[comp["id"]] = {"since": int(now), "by": _requester()}
    _write_json(DISABLED, disabled, mode=0o600)
    _log(f"{comp['id']} disabled by {_requester()} until the next apply")
    _notify("Aegis: protection disabled", f"{comp['name']} is off until the next playbook run")
    _refresh()
    return 0


VERBS: dict[str, Callable[[dict[str, Component], list[str], float], int]] = {
    "unlock": do_unlock,
    "pause": do_pause,
    "resume": do_resume,
    "logs": do_logs,
    "disable": do_disable,
}


def helper(argv: list[str], config: dict[str, Component], now: float | None = None) -> int:
    """Run one allowlisted action. Raises UsageError for anything else."""
    if not argv or argv[0] not in VERBS:
        raise UsageError(f"usage: aegis-helper {'|'.join(VERBS)} ...")
    return VERBS[argv[0]](config, argv[1:], time.time() if now is None else now)


def cmd_helper(argv: list[str]) -> int:
    """aegis-helper: entry point under pkexec or sudo."""
    if os.geteuid() != 0:
        print("aegis-helper: needs root (use the aegis command)", file=sys.stderr)
        return 2
    try:
        return helper(argv, load_config())
    except UsageError as err:
        # A refused request is a security event: the panel never sends one.
        _run(
            [
                LOGGER,
                "-t",
                "aegis-helper",
                "-p",
                "auth.warning",
                "--",
                f"refused for {_requester()}: {_clean(' '.join(argv), 200)}: {err}",
            ]
        )
        print(f"aegis-helper: {err}", file=sys.stderr)
        return 2


# Command line for the desktop user.


def _print_status(status: dict[str, object]) -> None:
    print(f"Aegis: {str(status.get('worst', 'unknown')).upper()}")
    comps = status.get("components", [])
    for comp in comps if isinstance(comps, list) else []:
        counts = comp.get("counts", {})
        until = comp.get("paused_until") or 0
        extra = f" until {time.strftime('%H:%M', time.localtime(until))}" if until else ""
        print(
            f"  {comp['name']:<24} {str(comp['state']).upper():<9}{extra}"
            f"  WARN {counts.get('WARN', 0)}  FAIL {counts.get('FAIL', 0)}"
        )
        for issue in comp.get("issues", []):
            print(f"      {issue['status']} {issue['id']}: {str(issue['detail'])[:120]}")


def cmd_cli(argv: list[str]) -> int:
    """Aegis: status for the user; privileged actions through pkexec or sudo."""
    usage = (
        "usage: aegis status [--json] | unlock | pause <component> <minutes> | resume <component> | "
        "logs <component> | disable <component>"
    )
    if not argv or argv[0] in {"-h", "--help"}:
        print(usage)
        return 0 if argv else 2
    verb, args = argv[0], argv[1:]
    if verb == "status":
        status = _read_json(STATUS)
        if not isinstance(status, dict):
            print(
                f"aegis: cannot read {STATUS} (is aegis-status.timer running, and are you in wheel?)", file=sys.stderr
            )
            return 1
        if args == ["--json"]:
            print(json.dumps(status))
        else:
            _print_status(status)
        return 0
    # --wait: the panel opens a terminal for this command; keep it open.
    wait = "--wait" in args
    args = [a for a in args if a != "--wait"]
    if verb not in {"unlock", "pause", "resume", "logs", "disable"}:
        print(usage, file=sys.stderr)
        return 2
    # disable is sudo only (D-38: key and password); the rest go through polkit.
    elevate = ["/usr/bin/sudo"] if verb == "disable" else ["/usr/bin/pkexec"]
    argv_ = [*elevate, HELPER, verb, *args]
    if verb == "logs" and sys.stdout.isatty():
        with subprocess.Popen(argv_, stdout=subprocess.PIPE) as proc:
            subprocess.run(["/usr/bin/less", "-R", "+G"], stdin=proc.stdout, check=False)
        code = proc.returncode or 0
    elif wait:
        code = subprocess.run(argv_, check=False).returncode
    else:
        os.execv(argv_[0], argv_)
    if wait:
        input("\nPress Enter to close. ")
    return code


def main() -> int:
    """Dispatch on the name this file was installed under."""
    name = Path(sys.argv[0]).name
    if name == "aegis-status":
        return cmd_collect()
    if name == "aegis-helper":
        return cmd_helper(sys.argv[1:])
    return cmd_cli(sys.argv[1:])


if __name__ == "__main__":
    sys.exit(main())
