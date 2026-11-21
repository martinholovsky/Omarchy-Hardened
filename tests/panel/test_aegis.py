"""Unit tests for the D-38 panel back end (roles/control_panel/files/aegis.py)."""

from __future__ import annotations

import importlib.util
import json
import os
import tempfile
import unittest
from pathlib import Path
from typing import Any
from unittest import mock

SRC = Path(__file__).resolve().parents[2] / "roles" / "control_panel" / "files" / "aegis.py"
_spec = importlib.util.spec_from_file_location("aegis_panel", SRC)
if _spec is None or _spec.loader is None:
    raise ImportError(SRC)
aegis = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(aegis)

RAW_CONFIG = {
    "components": [
        {
            "id": "tetragon",
            "name": "Tetragon",
            "units": ["tetragon.service"],
            "findings": ["tetragon."],
            "pausable": True,
            "logs": ["tetragon.service"],
        },
        {
            "id": "firewall",
            "name": "Firewall",
            "units": ["ufw.service"],
            "findings": ["firewall."],
            "pausable": False,
            "logs": ["kernel"],
            "log_grep": "UFW",
        },
        {"id": "Bad Id", "units": ["x.service"]},
        {"id": "evil", "units": ["x.service; rm -rf /", "../../etc/passwd"], "pausable": True},
    ]
}


def unit(name: str, active: str = "active", load: str = "loaded") -> dict[str, str]:
    return {"name": name, "load": load, "active": active, "enabled": "enabled"}


class Base(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp())
        cfg = self.tmp / "panel.json"
        cfg.write_text(json.dumps(RAW_CONFIG), encoding="utf-8")
        self.config = aegis.load_config(cfg)


class ConfigTest(Base):
    def test_malformed_entries_are_dropped(self) -> None:
        self.assertEqual(sorted(self.config), ["evil", "firewall", "tetragon"])
        self.assertEqual(self.config["evil"]["units"], [])
        self.assertFalse(self.config["evil"]["pausable"], "no valid unit, so nothing to pause")

    def test_firewall_is_never_pausable(self) -> None:
        self.assertFalse(self.config["firewall"]["pausable"])


class StateTest(Base):
    def state(
        self,
        units: list[dict[str, str]],
        findings: list[dict[str, str]],
        paused: dict[str, Any] | None = None,
        disabled: dict[str, Any] | None = None,
    ) -> str:
        return str(
            aegis.component_state(
                self.config["tetragon"], units, findings, paused=paused or {}, disabled=disabled or {}, now=1000.0
            )
        )

    def test_states(self) -> None:
        ok = [unit("tetragon.service")]
        self.assertEqual(self.state(ok, [{"id": "tetragon.x", "status": "PASS", "detail": ""}]), "ok")
        self.assertEqual(self.state(ok, [{"id": "tetragon.x", "status": "WARN", "detail": ""}]), "warn")
        self.assertEqual(self.state(ok, [{"id": "tetragon.x", "status": "FAIL", "detail": ""}]), "fail")
        self.assertEqual(self.state([unit("tetragon.service", "failed")], []), "warn")
        self.assertEqual(self.state([unit("tetragon.service", "inactive", "not-found")], []), "off")
        self.assertEqual(self.state(ok, [], paused={"tetragon": {"until": 2000}}), "paused")
        self.assertEqual(self.state(ok, [], paused={"tetragon": {"until": 500}}), "ok", "an expired pause is over")
        self.assertEqual(self.state(ok, [], disabled={"tetragon": {}}), "disabled")


class StatusTest(Base):
    def test_counts_issues_other_and_worst(self) -> None:
        findings = [
            {"id": "tetragon.cred_access", "status": "WARN", "detail": "x"},
            {"id": "tetragon.service", "status": "PASS", "detail": ""},
            {"id": "pacman.siglevel", "status": "FAIL", "detail": "weak"},
        ]
        status = aegis.build_status(self.config, findings, state_of=unit, now=1000.0, paused={}, disabled={})
        by_id = {c["id"]: c for c in status["components"]}
        self.assertEqual(by_id["tetragon"]["counts"]["WARN"], 1)
        self.assertEqual(by_id["tetragon"]["state"], "warn")
        self.assertTrue(by_id["tetragon"]["actions"]["pause"])
        self.assertFalse(by_id["firewall"]["actions"]["pause"])
        self.assertEqual(by_id["other"]["state"], "fail", "findings no component claims are not lost")
        self.assertEqual(status["worst"], "fail")


class HelperTest(Base):
    def setUp(self) -> None:
        super().setUp()
        self.calls: list[list[str]] = []
        for name, value in (
            ("_run", mock.Mock(side_effect=self._run)),
            ("_log", mock.Mock()),
            ("_notify", mock.Mock()),
            ("PAUSED", self.tmp / "paused.json"),
            ("DISABLED", self.tmp / "disabled.json"),
        ):
            patcher = mock.patch.object(aegis, name, value)
            patcher.start()
            self.addCleanup(patcher.stop)

    def _run(self, argv: list[str], timeout: int = 20) -> Any:  # noqa: ARG002 (same signature as aegis._run)
        self.calls.append(argv)
        return mock.Mock(returncode=0, stdout="", stderr="")

    def refused(self, *argv: str, env: dict[str, str] | None = None) -> None:
        with mock.patch.dict(os.environ, env or {}, clear=False), self.assertRaises(aegis.UsageError):
            aegis.helper(list(argv), self.config, now=1000.0)
        self.assertEqual(
            [c for c in self.calls if "stop" in c or "disable" in c], [], "a refused request changed something"
        )

    def test_refusals(self) -> None:
        self.refused()
        self.refused("shell")
        self.refused("pause", "tetragon\n", "10")
        self.refused("pause", "--now", "10")
        self.refused("pause", "nosuch", "10")
        self.refused("pause", "tetragon", "0")
        self.refused("pause", "tetragon", "121")
        self.refused("pause", "tetragon", "10m")
        self.refused("pause", "firewall", "10")
        self.refused("disable", "firewall")
        self.refused("disable", "tetragon", env={"PKEXEC_UID": "1000"})
        self.refused("unlock", "extra")

    def test_pause_stops_schedules_and_records(self) -> None:
        self.assertEqual(aegis.helper(["pause", "tetragon", "15"], self.config, now=1000.0), 0)
        self.assertIn([aegis.SYSTEMCTL, "stop", "--", "tetragon.service"], self.calls)
        timer = next(c for c in self.calls if c[0] == aegis.SYSTEMD_RUN)
        self.assertIn("--on-active=15m", timer)
        self.assertEqual(timer[-3:], [aegis.HELPER, "resume", "tetragon"])
        paused = json.loads((self.tmp / "paused.json").read_text(encoding="utf-8"))
        self.assertEqual(paused["tetragon"]["until"], 1000 + 15 * 60)

    def test_resume_clears_pause_and_disable(self) -> None:
        (self.tmp / "paused.json").write_text('{"tetragon": {"until": 9999}}', encoding="utf-8")
        (self.tmp / "disabled.json").write_text('{"tetragon": {}}', encoding="utf-8")
        self.assertEqual(aegis.helper(["resume", "tetragon"], self.config, now=1000.0), 0)
        self.assertIn([aegis.SYSTEMCTL, "enable", "--now", "--", "tetragon.service"], self.calls)
        self.assertEqual(json.loads((self.tmp / "paused.json").read_text(encoding="utf-8")), {})
        self.assertEqual(json.loads((self.tmp / "disabled.json").read_text(encoding="utf-8")), {})

    def test_disable_under_sudo(self) -> None:
        with mock.patch.dict(os.environ, {"SUDO_UID": "1000"}, clear=False):
            os.environ.pop("PKEXEC_UID", None)
            self.assertEqual(aegis.helper(["disable", "tetragon"], self.config, now=1000.0), 0)
        self.assertIn([aegis.SYSTEMCTL, "disable", "--now", "--", "tetragon.service"], self.calls)

    def test_logs_uses_fixed_sources(self) -> None:
        self.assertEqual(aegis.helper(["logs", "firewall"], self.config), 0)
        cmd = next(c for c in self.calls if c[0] == aegis.JOURNALCTL)
        self.assertIn("-k", cmd)
        self.assertEqual(cmd[-2:], ["--grep", "UFW"])


if __name__ == "__main__":
    unittest.main()
