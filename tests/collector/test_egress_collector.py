# Copyright: Omarchy-Hardened contributors
# SPDX-License-Identifier: Apache-2.0
"""Unit tests for roles/opensnitch/files/aegis-egress-collector.py (D-25).

Standard library only, so they also run on the target's system Python:
    python3 -I -m unittest discover -s tests/collector -v
"""

from __future__ import annotations

import contextlib
import importlib.util
import json
import random
import socket
import stat
import sys
import tempfile
import unittest
from pathlib import Path
from typing import TYPE_CHECKING, Any
from unittest import mock

if TYPE_CHECKING:
    from types import ModuleType

COLLECTOR = Path(__file__).resolve().parents[2] / "roles/opensnitch/files/aegis-egress-collector.py"


def _load() -> ModuleType:
    spec = importlib.util.spec_from_file_location("aegis_egress_collector", COLLECTOR)
    if spec is None or spec.loader is None:
        msg = f"cannot load {COLLECTOR}"
        raise ImportError(msg)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module  # dataclasses resolve the module by name
    spec.loader.exec_module(module)
    return module


ec = _load()

# A line as opensnitchd v1.7.2 writes it: 9 leading fields, then the command
# line (which here holds a fake secret and commas), cwd, action, rule.
VALID = (
    "192.168.1.5,51234,140.82.112.3,github.com,443,tcp,4242,1000,/usr/bin/git,"
    "[git -c http.extraheader=Authorization: Bearer SECRET,with,commas clone],/home/u,allow,aegis-git"
)


def line(**overrides: str) -> bytes:
    fields = dict(
        zip(
            ["src_ip", "src_port", "dst_ip", "dst_host", "dst_port", "proto", "pid", "uid", "path"],
            VALID.split(",")[:9],
            strict=True,
        )
    )
    fields.update(overrides)
    return (",".join(fields.values()) + ",[args],/cwd,allow,rule").encode()


class ParseEvent(unittest.TestCase):
    def test_keeps_only_program_and_destination(self) -> None:
        event = ec.parse_event(VALID.encode())
        self.assertEqual(event, ec.Event(path="/usr/bin/git", dest="github.com"))

    def test_the_command_line_never_reaches_the_event(self) -> None:
        event = ec.parse_event(VALID.encode())
        self.assertNotIn("SECRET", repr(event))

    def test_ip_is_used_when_no_name_was_resolved(self) -> None:
        self.assertEqual(ec.parse_event(line(dst_host="")).dest, "140.82.112.3")

    def test_names_are_normalised(self) -> None:
        self.assertEqual(ec.parse_event(line(dst_host="GitHub.COM.")).dest, "github.com")

    def test_ipv6(self) -> None:
        event = ec.parse_event(line(src_ip="::1", dst_ip="2606:4700::1111", dst_host=""))
        self.assertEqual(event.dest, "2606:4700::1111")

    def test_trailing_newline_is_accepted(self) -> None:
        self.assertEqual(ec.parse_event(VALID.encode() + b"\n").path, "/usr/bin/git")

    def test_rejections(self) -> None:
        cases = {
            "too few fields": b"1.2.3.4,1,5.6.7.8",
            "bad source ip": line(src_ip="999.1.1.1"),
            "bad destination ip": line(dst_ip="not-an-ip"),
            "port too high": line(dst_port="65536"),
            "port not a number": line(src_port="44a"),
            "negative port": line(dst_port="-1"),
            "protocol with symbols": line(proto="tcp;rm"),
            "pid not a number": line(pid="12x"),
            "uid not a number": line(uid="-0"),
            "relative path": line(path="usr/bin/git"),
            "path with a newline": line(path="/usr/bin/gi\nt"),
            "path with ESC": line(path="/usr/bin/\x1b[2Jgit"),
            "path with DEL": line(path="/usr/bin/\x7fgit"),
            "path too long": line(path="/" + "a" * 4096),
            "name with a space": line(dst_host="git hub.com"),
            "name with a slash": line(dst_host="github.com/x"),
            "name too long": line(dst_host="a." * 127 + "com"),
            "label too long": line(dst_host="a" * 64 + ".com"),
            "invalid utf-8": VALID.encode() + b"\xff",
            "nul byte": line(path="/usr/bin/git\x00"),
            "oversized": VALID.encode() + b"x" * ec.MAX_DATAGRAM,
        }
        for name, payload in cases.items():
            with self.subTest(name), self.assertRaises(ec.Rejected):
                ec.parse_event(payload)

    def test_random_bytes_never_raise_anything_but_rejected(self) -> None:
        rng = random.Random(25)  # fixed seed: reproducible
        for _ in range(3000):
            payload = rng.randbytes(rng.randrange(0, 300))
            with contextlib.suppress(ec.Rejected):
                ec.parse_event(payload)

    def test_mutated_valid_lines_never_raise_anything_but_rejected(self) -> None:
        rng = random.Random(24)
        base = bytearray(VALID.encode())
        for _ in range(3000):
            data = bytearray(base)
            for _ in range(rng.randrange(1, 6)):
                data[rng.randrange(len(data))] = rng.randrange(256)
            try:
                event = ec.parse_event(bytes(data))
            except ec.Rejected:
                continue
            # Whatever got through still satisfies the stored invariants.
            self.assertEqual(ec.valid_path(event.path), event.path)
            self.assertEqual(ec.valid_dest(event.dest), event.dest)


PROC_HEADER = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n"


def proc_row(port: int, uid: int, local_ip: str = "0100007F") -> str:
    return f"  1: {local_ip}:{port:04X} 0100007F:1E83 01 00000000:00000000 00:00000000 00000000 {uid:>5} 0 123 2\n"


class Senders(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.proc = Path(self.tmp.name) / "udp"

    def check(self, rows: str) -> Any:
        self.proc.write_text(PROC_HEADER + rows, encoding="ascii")
        return ec.SenderCheck(self.proc)

    def test_root_socket_on_loopback_is_allowed(self) -> None:
        self.assertTrue(self.check(proc_row(40000, 0)).allowed(("127.0.0.1", 40000), 0.0))

    def test_other_users_socket_is_rejected(self) -> None:
        self.assertFalse(self.check(proc_row(40000, 1000)).allowed(("127.0.0.1", 40000), 0.0))

    def test_unknown_port_is_rejected(self) -> None:
        self.assertFalse(self.check(proc_row(40000, 0)).allowed(("127.0.0.1", 40001), 0.0))

    def test_root_socket_on_another_address_does_not_count(self) -> None:
        self.assertFalse(self.check(proc_row(40000, 0, "0101A8C0")).allowed(("127.0.0.1", 40000), 0.0))

    def test_non_loopback_source_is_rejected(self) -> None:
        self.assertFalse(self.check(proc_row(40000, 0)).allowed(("192.168.1.10", 40000), 0.0))

    def test_unreadable_proc_fails_closed(self) -> None:
        checker = ec.SenderCheck(Path(self.tmp.name) / "missing")
        with self.assertLogs(ec.LOG, "WARNING"):
            self.assertFalse(checker.allowed(("127.0.0.1", 40000), 0.0))

    def test_verdict_is_cached_then_rechecked(self) -> None:
        checker = self.check(proc_row(40000, 0))
        self.assertTrue(checker.allowed(("127.0.0.1", 40000), 0.0))
        self.proc.write_text(PROC_HEADER + proc_row(40000, 1000), encoding="ascii")
        self.assertTrue(checker.allowed(("127.0.0.1", 40000), ec.SENDER_CACHE_SECONDS - 1))
        self.assertFalse(checker.allowed(("127.0.0.1", 40000), ec.SENDER_CACHE_SECONDS + 1))


class Handling(unittest.TestCase):
    def collector(self, allowed: bool) -> Any:
        senders = mock.Mock(spec=ec.SenderCheck)
        senders.allowed.return_value = allowed
        return ec.Collector(table=ec.Table(), senders=senders)

    def test_accepted_event_is_counted(self) -> None:
        col = self.collector(allowed=True)
        col.handle(VALID.encode(), 0, ("127.0.0.1", 1), 100.0)
        col.handle(VALID.encode(), 0, ("127.0.0.1", 1), 200.0)
        entry = col.table.entries[ec.Event("/usr/bin/git", "github.com")]
        self.assertEqual((entry.first, entry.last, entry.count), (100, 200, 2))
        self.assertTrue(col.table.dirty)

    def test_sender_rejection_never_parses(self) -> None:
        col = self.collector(allowed=False)
        with mock.patch.object(ec, "parse_event") as parse:
            col.handle(VALID.encode(), 0, ("127.0.0.1", 1), 1.0)
        parse.assert_not_called()
        self.assertEqual((col.table.stats.rejected_sender, len(col.table.entries)), (1, 0))

    def test_truncated_datagram_is_rejected(self) -> None:
        col = self.collector(allowed=True)
        col.handle(VALID.encode(), socket.MSG_TRUNC, ("127.0.0.1", 1), 1.0)
        self.assertEqual((col.table.stats.rejected_format, len(col.table.entries)), (1, 0))

    def test_table_is_bounded(self) -> None:
        col = self.collector(allowed=True)
        with mock.patch.object(ec, "MAX_ENTRIES", 3):
            for n in range(5):
                col.handle(line(path=f"/opt/p{n}"), 0, ("127.0.0.1", 1), 1.0)
            col.handle(line(path="/opt/p0"), 0, ("127.0.0.1", 1), 2.0)  # known pair still counts
        self.assertEqual(len(col.table.entries), 3)
        self.assertEqual(col.table.stats.table_full, 2)
        self.assertEqual(col.table.entries[ec.Event("/opt/p0", "github.com")].count, 2)

    def test_expire_drops_old_pairs(self) -> None:
        table = ec.Table()
        ec.record(table, ec.Event("/opt/old", "a.example"), 0)
        ec.record(table, ec.Event("/opt/new", "a.example"), ec.RETENTION_SECONDS + 10)
        ec.expire(table, ec.RETENTION_SECONDS + 10)
        self.assertEqual([e.path for e in table.entries], ["/opt/new"])


class Persistence(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.dir = Path(self.tmp.name)

    def test_round_trip_and_file_mode(self) -> None:
        table = ec.Table()
        ec.record(table, ec.Event("/usr/bin/git", "github.com"), 50)
        table.stats.rejected_sender = 3
        ec.save(table, self.dir, 60)
        state = self.dir / ec.STATE_FILE
        self.assertEqual(stat.S_IMODE(state.stat().st_mode), 0o600)
        self.assertEqual(json.loads(state.read_text(encoding="utf-8"))["stats"]["rejected_sender"], 3)
        self.assertEqual(list(self.dir.glob(".egress-*")), [])  # no temp file left behind
        loaded = ec.load(self.dir)
        self.assertEqual(loaded.entries, table.entries)
        self.assertFalse(table.dirty)

    def test_missing_state_starts_empty(self) -> None:
        self.assertEqual(ec.load(self.dir).entries, {})

    def test_corrupt_state_is_set_aside(self) -> None:
        (self.dir / ec.STATE_FILE).write_text("{not json", encoding="utf-8")
        with self.assertLogs(ec.LOG, "WARNING"):
            self.assertEqual(ec.load(self.dir).entries, {})
        self.assertTrue((self.dir / (ec.STATE_FILE + ".bad")).exists())

    def test_oversized_state_is_set_aside(self) -> None:
        with mock.patch.object(ec, "MAX_STATE_BYTES", 10):
            (self.dir / ec.STATE_FILE).write_text(json.dumps({"version": 1, "entries": []}), encoding="utf-8")
            with self.assertLogs(ec.LOG, "WARNING"):
                self.assertEqual(ec.load(self.dir).entries, {})

    def test_invalid_rows_are_skipped(self) -> None:
        rows = [
            {"path": "/usr/bin/git", "dest": "github.com", "first": 1, "last": 2, "count": 1},
            {"path": "relative", "dest": "github.com", "first": 1, "last": 2, "count": 1},
            {"path": "/usr/bin/x", "dest": "bad host!", "first": 1, "last": 2, "count": 1},
            {"path": "/usr/bin/y", "dest": "a.example", "first": 5, "last": 2, "count": 1},
            {"path": "/usr/bin/z", "dest": "a.example", "first": 1, "last": 2},
            "not a row",
        ]
        doc = {"version": 1, "entries": rows}
        (self.dir / ec.STATE_FILE).write_text(json.dumps(doc), encoding="utf-8")
        self.assertEqual(list(ec.load(self.dir).entries), [ec.Event("/usr/bin/git", "github.com")])

    def test_sender_rejects_are_logged_once_as_a_named_event(self) -> None:
        table = ec.Table()
        table.stats.rejected_sender = 2
        with self.assertLogs(ec.LOG, "WARNING") as logs:
            ec._flush(table, self.dir)
        self.assertIn("egress_sender_reject", "\n".join(logs.output))
        with mock.patch.object(ec.LOG, "warning") as warn:
            ec._flush(table, self.dir)
        warn.assert_not_called()


if __name__ == "__main__":
    unittest.main()
