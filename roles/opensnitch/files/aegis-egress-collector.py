#!/usr/bin/python3
# Copyright: Omarchy-Hardened contributors
# SPDX-License-Identifier: Apache-2.0
# ruff: noqa: EM101, TRY003, N818, CPY001
# (EM101/TRY003: Rejected carries a short reason code, not a message;
#  N818: "Rejected" reads as the outcome; CPY001: SPDX header above.)
"""Record which program connected out to where (D-25).

opensnitchd's "remote" logger sends one CSV datagram per intercepted
connection to this collector on 127.0.0.1. The collector keeps only the
executable path and the destination. The same datagram also carries the
program's command line and working directory; those are never parsed, stored
or logged, because a command line can hold credentials.

Trust boundary: every datagram is untrusted input. It must come from a socket
owned by root (opensnitchd), checked through /proc/self/net/udp, and every field
that is kept is validated against an allowlist before it reaches the table.
Anything else is dropped and only counted. Standard library only.
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import logging
import os
import re
import select
import signal
import socket
import sys
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from types import FrameType

LOG = logging.getLogger("aegis-egress-collector")

STATE_VERSION = 1
STATE_FILE = "egress.json"
MAX_DATAGRAM = 8192  # opensnitch CSV lines are well under this; longer = drop
MAX_STATE_BYTES = 8 * 1024 * 1024
MAX_ENTRIES = 5000  # distinct (program, destination) pairs kept
MAX_PATH = 4096  # PATH_MAX
MAX_HOST = 253  # longest DNS name in text form
MAX_PORT = 65535
FLUSH_SECONDS = 30.0
RETENTION_SECONDS = 30 * 86400
SENDER_CACHE_SECONDS = 10.0
SENDER_CACHE_MAX = 64
# Fields before the command line in opensnitch v1.7.2 CSV
# (daemon/log/formats/csv.go): SrcIp, SrcPort, DstIp, DstHost, DstPort,
# Protocol, ProcessId, UserId, ProcessPath, then ProcessArgs, ProcessCwd, ...
LEADING_FIELDS = 9
LOOPBACK = "127.0.0.1"
LOOPBACK_HEX = "0100007F"  # 127.0.0.1 as /proc/net/udp prints it (little-endian)

_LABEL = r"[A-Za-z0-9_](?:[A-Za-z0-9_-]{0,61}[A-Za-z0-9_])?"
HOST_RE = re.compile(rf"{_LABEL}(?:\.{_LABEL})*\.?")
PROTO_RE = re.compile(r"[a-z0-9]{1,12}")
DIGITS_RE = re.compile(r"[0-9]{1,10}")


class Rejected(ValueError):
    """A datagram or a stored entry that failed validation."""


@dataclass(frozen=True, slots=True)
class Event:
    """The part of one connection event that is kept."""

    path: str
    dest: str


@dataclass(slots=True)
class Entry:
    """When a (program, destination) pair was first and last seen."""

    first: int
    last: int
    count: int


@dataclass(slots=True)
class Stats:
    """Counters only; no payload is ever kept for a rejected datagram."""

    received: int = 0
    accepted: int = 0
    rejected_sender: int = 0
    rejected_format: int = 0
    table_full: int = 0


@dataclass(slots=True)
class Table:
    """The bounded in-memory table and its counters."""

    entries: dict[Event, Entry] = field(default_factory=dict)
    stats: Stats = field(default_factory=Stats)
    dirty: bool = False
    reported_sender_rejects: int = 0


def _port(text: str) -> int:
    if not DIGITS_RE.fullmatch(text) or int(text) > MAX_PORT:
        raise Rejected("port")
    return int(text)


def _ip(text: str) -> str:
    try:
        return str(ipaddress.ip_address(text))
    except ValueError as exc:
        raise Rejected("address") from exc


def valid_path(text: str) -> str:
    """Return TEXT if it is an absolute path without control characters."""
    if not text.startswith("/") or len(text) > MAX_PATH:
        raise Rejected("path")
    if any(ord(ch) < 32 or ord(ch) == 127 for ch in text):  # noqa: PLR2004 (C0 controls, DEL)
        raise Rejected("path")
    return text


def valid_dest(text: str) -> str:
    """Return TEXT normalised if it is a DNS name or an IP address."""
    if not text or len(text) > MAX_HOST:
        raise Rejected("destination")
    try:
        return _ip(text)
    except Rejected:
        pass
    if not HOST_RE.fullmatch(text):
        raise Rejected("destination")
    return text.lower().rstrip(".")


def parse_event(payload: bytes) -> Event:
    """Validate one CSV datagram and keep only the program and destination.

    A comma inside the path itself cuts the path short. The prefix kept is a
    directory the same owner controls, so it cannot pass for a package-owned
    file (/usr is root's) and is still reported as unknown.
    """
    if len(payload) > MAX_DATAGRAM:
        raise Rejected("size")
    try:
        text = payload.decode("utf-8", errors="strict")
    except UnicodeDecodeError as exc:
        raise Rejected("encoding") from exc
    if "\x00" in text:
        raise Rejected("nul")
    # maxsplit keeps the command line and everything after it in one unread
    # tail element: it is never inspected.
    parts = text.rstrip("\n").split(",", LEADING_FIELDS)
    if len(parts) < LEADING_FIELDS:
        raise Rejected("field count")
    src_ip, src_port, dst_ip, dst_host, dst_port, proto, pid, uid, path = parts[:LEADING_FIELDS]
    _ip(src_ip)
    _port(src_port)
    dst = _ip(dst_ip)
    _port(dst_port)
    if not PROTO_RE.fullmatch(proto):
        raise Rejected("protocol")
    if not DIGITS_RE.fullmatch(pid) or not DIGITS_RE.fullmatch(uid):
        raise Rejected("pid/uid")
    dest = valid_dest(dst_host) if dst_host else dst
    return Event(path=valid_path(path), dest=dest)


def record(table: Table, event: Event, now: int) -> None:
    """Count EVENT; a new pair is refused once the table is full."""
    entry = table.entries.get(event)
    if entry is not None:
        entry.last = now
        entry.count += 1
    elif len(table.entries) >= MAX_ENTRIES:
        table.stats.table_full += 1
        return
    else:
        table.entries[event] = Entry(first=now, last=now, count=1)
    table.stats.accepted += 1
    table.dirty = True


def expire(table: Table, now: int) -> None:
    """Drop pairs not seen within the retention period."""
    cutoff = now - RETENTION_SECONDS
    stale = [event for event, entry in table.entries.items() if entry.last < cutoff]
    for event in stale:
        del table.entries[event]
    if stale:
        table.dirty = True


class SenderCheck:
    """Accept only datagrams sent from a loopback UDP socket owned by root.

    /proc/self/net/udp lists every UDP socket in this network namespace with
    its owner's uid. Not /proc/net/udp: the unit's ProcSubset=pid hides that
    symlink (ENOENT, measured in the VM on 2026-10-25), and every datagram was
    rejected. opensnitchd keeps one connected socket open, so its source
    port is looked up once and then cached briefly. Residual risk: if root's
    socket closes and another user binds the same port within the cache
    window, its datagrams pass until the entry expires; the most it can do is
    add rows to the table. Fails closed: an unreadable table rejects.
    """

    def __init__(self, proc_udp: Path = Path("/proc/self/net/udp")) -> None:
        """Read socket owners from PROC_UDP (a fixture in tests)."""
        self._proc_udp = proc_udp
        self._cache: dict[int, tuple[bool, float]] = {}

    def _owner_uid(self, port: int) -> int | None:
        wanted = f"{LOOPBACK_HEX}:{port:04X}"
        try:
            with self._proc_udp.open(encoding="ascii", errors="replace") as handle:
                next(handle, None)  # header line
                for line in handle:
                    cols = line.split()
                    if len(cols) > 7 and cols[1] == wanted and cols[7].isdigit():  # noqa: PLR2004 (uid column)
                        return int(cols[7])
        except OSError:
            LOG.warning("cannot read %s; rejecting datagrams", self._proc_udp)
        return None

    def allowed(self, address: tuple[str, int], now: float) -> bool:
        """Return whether ADDRESS is a loopback socket owned by root."""
        host, port = address
        if host != LOOPBACK:
            return False
        cached = self._cache.get(port)
        if cached is not None and cached[1] > now:
            return cached[0]
        if len(self._cache) >= SENDER_CACHE_MAX:
            self._cache.clear()
        ok = self._owner_uid(port) == 0
        self._cache[port] = (ok, now + SENDER_CACHE_SECONDS)
        return ok


@dataclass(slots=True)
class Collector:
    """Applies the sender check and the parser to each datagram."""

    table: Table
    senders: SenderCheck

    def handle(self, payload: bytes, flags: int, address: tuple[str, int], now: float) -> None:
        """Count PAYLOAD as accepted or rejected; never log its contents."""
        self.table.stats.received += 1
        if not self.senders.allowed(address, now):
            self.table.stats.rejected_sender += 1
            return
        if flags & socket.MSG_TRUNC:
            self.table.stats.rejected_format += 1
            return
        try:
            event = parse_event(payload)
        except Rejected:
            self.table.stats.rejected_format += 1
            return
        record(self.table, event, int(now))


def _entries_from(data: object) -> dict[Event, Entry]:
    """Validate a decoded state document; malformed rows are skipped."""
    if not isinstance(data, dict) or data.get("version") != STATE_VERSION:
        raise Rejected("state version")
    rows = data.get("entries")
    if not isinstance(rows, list):
        raise Rejected("state entries")
    entries: dict[Event, Entry] = {}
    for row in rows[:MAX_ENTRIES]:
        if not isinstance(row, dict):
            continue
        try:
            event = Event(path=valid_path(str(row["path"])), dest=valid_dest(str(row["dest"])))
            first, last, count = int(row["first"]), int(row["last"]), int(row["count"])
        except (KeyError, TypeError, ValueError):
            continue
        if 0 <= first <= last and count > 0:
            entries[event] = Entry(first=first, last=last, count=count)
    return entries


def load(state_dir: Path) -> Table:
    """Load the saved table; a bad file is set aside and the table starts empty."""
    path = state_dir / STATE_FILE
    try:
        if path.stat().st_size > MAX_STATE_BYTES:
            raise Rejected("state file too large")
        return Table(entries=_entries_from(json.loads(path.read_text(encoding="utf-8"))))
    except FileNotFoundError:
        return Table()
    except (OSError, ValueError) as exc:  # Rejected and JSONDecodeError are ValueErrors
        LOG.warning("ignoring saved state (%s); it is kept as %s.bad", type(exc).__name__, STATE_FILE)
        try:
            path.replace(path.with_name(STATE_FILE + ".bad"))
        except OSError:
            LOG.warning("could not set the saved state aside")
        return Table()


def save(table: Table, state_dir: Path, now: int) -> None:
    """Write the table atomically: temp file, fsync, rename, fsync the dir."""
    stats = table.stats
    doc = {
        "version": STATE_VERSION,
        "saved": now,
        "stats": {
            "received": stats.received,
            "accepted": stats.accepted,
            "rejected_sender": stats.rejected_sender,
            "rejected_format": stats.rejected_format,
            "table_full": stats.table_full,
        },
        "entries": [
            {"path": ev.path, "dest": ev.dest, "first": en.first, "last": en.last, "count": en.count}
            for ev, en in sorted(table.entries.items(), key=lambda item: (item[0].path, item[0].dest))
        ],
    }
    fd, tmp_name = tempfile.mkstemp(prefix=".egress-", dir=state_dir)
    tmp = Path(tmp_name)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(doc, handle, separators=(",", ":"))
            handle.flush()
            os.fsync(handle.fileno())
        tmp.chmod(0o600)
        tmp.replace(state_dir / STATE_FILE)
    except BaseException:
        tmp.unlink(missing_ok=True)
        raise
    dir_fd = os.open(state_dir, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(dir_fd)
    finally:
        os.close(dir_fd)
    table.dirty = False


def _flush(table: Table, state_dir: Path) -> None:
    now = int(time.time())
    rejects = table.stats.rejected_sender
    if rejects > table.reported_sender_rejects:
        # Only root (opensnitchd) sends here, so another sender is a
        # tampering signal, not noise: a named event at WARNING. Nothing from
        # the datagram itself is logged.
        LOG.warning("egress_sender_reject: %d datagram(s) from a non-root or non-loopback sender since start", rejects)
        table.reported_sender_rejects = rejects
        table.dirty = True  # persist the counter for the audit
    expire(table, now)
    if not table.dirty:
        return
    save(table, state_dir, now)
    s = table.stats
    LOG.info(
        "saved %d entries (received %d, accepted %d, rejected: sender %d, format %d, table full %d)",
        len(table.entries),
        s.received,
        s.accepted,
        s.rejected_sender,
        s.rejected_format,
        s.table_full,
    )


def serve(port: int, state_dir: Path) -> int:
    """Receive datagrams until SIGTERM/SIGINT, saving the table periodically."""
    collector = Collector(table=load(state_dir), senders=SenderCheck())
    stop = False

    def on_signal(_signum: int, _frame: FrameType | None) -> None:
        nonlocal stop
        stop = True

    signal.signal(signal.SIGTERM, on_signal)
    signal.signal(signal.SIGINT, on_signal)
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.bind((LOOPBACK, port))
        LOG.info("listening on %s:%d, %d saved entries", LOOPBACK, port, len(collector.table.entries))
        next_flush = time.monotonic() + FLUSH_SECONDS
        while not stop:
            try:
                readable, _, _ = select.select([sock], [], [], max(0.0, next_flush - time.monotonic()))
            except InterruptedError:
                continue
            if readable:
                # One byte more than the limit, so an oversized datagram shows
                # as MSG_TRUNC instead of being silently cut to size.
                payload, _ancillary, flags, address = sock.recvmsg(MAX_DATAGRAM + 1)
                collector.handle(payload, flags, address, time.time())
            if time.monotonic() >= next_flush:
                _flush(collector.table, state_dir)
                next_flush = time.monotonic() + FLUSH_SECONDS
    _flush(collector.table, state_dir)
    return 0


def main(argv: list[str] | None = None) -> int:
    """Parse arguments and run; exit 0 on a clean stop, 1 on failure, 2 on usage."""
    parser = argparse.ArgumentParser(description=(__doc__ or "").splitlines()[0])
    parser.add_argument("--port", type=int, required=True, help="UDP port on 127.0.0.1 (1024-65535)")
    parser.add_argument("--state-dir", type=Path, required=True, help="directory for egress.json")
    args = parser.parse_args(argv)
    if not 1024 <= args.port <= MAX_PORT:  # noqa: PLR2004 (first unprivileged port)
        parser.error("--port must be 1024-65535")
    if not args.state_dir.is_dir():
        parser.error(f"--state-dir {args.state_dir} is not a directory")
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s", stream=sys.stderr)
    try:
        return serve(args.port, args.state_dir)
    except OSError:  # e.g. the port is in use or the state dir is not writable
        LOG.exception("cannot run")  # systemd restarts the unit
        return 1


if __name__ == "__main__":
    sys.exit(main())
