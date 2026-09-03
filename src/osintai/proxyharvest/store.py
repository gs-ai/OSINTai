"""SQLite persistence for candidates, validations, the working set, and cycles.

The store is the durability boundary. Everything the CLI shows and everything
exported is derived from it, so a killed run resumes with its history intact and
churn is measurable across cycles rather than guessed at.
"""

import json
import os
import sqlite3
import time
from contextlib import closing
from typing import Dict, Iterable, List, Optional

from .models import Classification, ProxyCandidate, ValidationResult, first_seen_iso

SCHEMA = """
CREATE TABLE IF NOT EXISTS candidates (
    key          TEXT PRIMARY KEY,
    ip           TEXT NOT NULL,
    port         INTEGER NOT NULL,
    protocol     TEXT NOT NULL,
    source_id    TEXT,
    first_seen   REAL NOT NULL,
    last_seen    REAL NOT NULL,
    seen_count   INTEGER NOT NULL DEFAULT 1
);

CREATE TABLE IF NOT EXISTS validations (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    key          TEXT NOT NULL,
    cycle_id     INTEGER,
    ok           INTEGER NOT NULL,
    latency_ms   REAL,
    anonymity    TEXT,
    exit_ip      TEXT,
    confirmed    INTEGER NOT NULL DEFAULT 0,
    error        TEXT,
    checked_at   REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_validations_key ON validations(key);
CREATE INDEX IF NOT EXISTS idx_validations_cycle ON validations(cycle_id);

CREATE TABLE IF NOT EXISTS working_set (
    key           TEXT PRIMARY KEY,
    ip            TEXT NOT NULL,
    port          INTEGER NOT NULL,
    protocol      TEXT NOT NULL,
    source_id     TEXT,
    latency_ms    REAL,
    anonymity     TEXT,
    exit_ip       TEXT,
    network_class TEXT,
    class_conf    REAL,
    class_basis   TEXT,
    asn           INTEGER,
    as_org        TEXT,
    country       TEXT,
    ptr           TEXT,
    first_seen    REAL NOT NULL,
    last_ok       REAL NOT NULL,
    ok_count      INTEGER NOT NULL DEFAULT 1,
    fail_count    INTEGER NOT NULL DEFAULT 0,
    retired_at    REAL
);
CREATE INDEX IF NOT EXISTS idx_working_active ON working_set(retired_at);

CREATE TABLE IF NOT EXISTS cycles (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    started_at    REAL NOT NULL,
    finished_at   REAL,
    interval_s    REAL,
    sources_ok    INTEGER DEFAULT 0,
    sources_failed INTEGER DEFAULT 0,
    candidates    INTEGER DEFAULT 0,
    validated     INTEGER DEFAULT 0,
    passed        INTEGER DEFAULT 0,
    yield_rate    REAL,
    working_size  INTEGER DEFAULT 0,
    notes         TEXT
);

CREATE TABLE IF NOT EXISTS source_stats (
    source_id     TEXT NOT NULL,
    cycle_id      INTEGER NOT NULL,
    ok            INTEGER NOT NULL,
    renderer      TEXT,
    candidates    INTEGER DEFAULT 0,
    elapsed_ms    REAL,
    error         TEXT,
    PRIMARY KEY (source_id, cycle_id)
);
"""


class HarvestStore:
    """Thin SQLite wrapper. One connection, WAL, explicit commits."""

    def __init__(self, path: str):
        self.path = os.path.abspath(os.path.expanduser(path))
        parent = os.path.dirname(self.path)
        if parent:
            os.makedirs(parent, exist_ok=True)
        self.conn = sqlite3.connect(self.path, timeout=30.0)
        self.conn.row_factory = sqlite3.Row
        self.conn.execute("PRAGMA journal_mode=WAL")
        self.conn.execute("PRAGMA synchronous=NORMAL")
        with closing(self.conn.cursor()) as cursor:
            cursor.executescript(SCHEMA)
        self.conn.commit()

    def close(self) -> None:
        try:
            self.conn.commit()
        finally:
            self.conn.close()

    def __enter__(self) -> "HarvestStore":
        return self

    def __exit__(self, *exc_info) -> None:
        self.close()

    # ---- cycles --------------------------------------------------------
    def start_cycle(self, interval_s: float) -> int:
        cursor = self.conn.execute(
            "INSERT INTO cycles (started_at, interval_s) VALUES (?, ?)",
            (time.time(), interval_s),
        )
        self.conn.commit()
        return int(cursor.lastrowid)

    CYCLE_METRICS = (
        "sources_ok", "sources_failed", "candidates", "validated",
        "passed", "yield_rate", "working_size", "notes",
    )

    def finish_cycle(self, cycle_id: int, **fields) -> None:
        """Stamp the cycle finished, updating only the metrics that were passed.

        The statement is fixed and COALESCE leaves omitted columns untouched, so
        no caller-supplied text ever reaches the SQL text itself.
        """
        unknown = set(fields) - set(self.CYCLE_METRICS)
        if unknown:
            raise ValueError(f"unknown cycle metric(s): {sorted(unknown)}")
        params = {name: fields.get(name) for name in self.CYCLE_METRICS}
        params["finished_at"] = time.time()
        params["cycle_id"] = cycle_id
        self.conn.execute(
            """
            UPDATE cycles SET
                sources_ok     = COALESCE(:sources_ok, sources_ok),
                sources_failed = COALESCE(:sources_failed, sources_failed),
                candidates     = COALESCE(:candidates, candidates),
                validated      = COALESCE(:validated, validated),
                passed         = COALESCE(:passed, passed),
                yield_rate     = COALESCE(:yield_rate, yield_rate),
                working_size   = COALESCE(:working_size, working_size),
                notes          = COALESCE(:notes, notes),
                finished_at    = :finished_at
            WHERE id = :cycle_id
            """,
            params,
        )
        self.conn.commit()

    def recent_cycles(self, limit: int = 10) -> List[Dict]:
        rows = self.conn.execute(
            "SELECT * FROM cycles ORDER BY id DESC LIMIT ?", (limit,)
        ).fetchall()
        return [dict(row) for row in rows]

    # ---- candidates ----------------------------------------------------
    def record_candidates(self, candidates: Iterable[ProxyCandidate]) -> int:
        now = time.time()
        rows = [
            (c.key, c.ip, c.port, c.protocol, c.source_id, now, now)
            for c in candidates
        ]
        if not rows:
            return 0
        self.conn.executemany(
            """
            INSERT INTO candidates (key, ip, port, protocol, source_id, first_seen, last_seen)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(key) DO UPDATE SET
                last_seen = excluded.last_seen,
                seen_count = seen_count + 1
            """,
            rows,
        )
        self.conn.commit()
        return len(rows)

    # ---- validations ---------------------------------------------------
    def record_validations(self, results: Iterable[ValidationResult], cycle_id: Optional[int]) -> None:
        rows = [
            (
                r.candidate.key,
                cycle_id,
                1 if r.ok else 0,
                r.latency_ms,
                r.anonymity,
                r.exit_ip,
                1 if r.confirmed else 0,
                r.error,
                r.checked_at,
            )
            for r in results
        ]
        if not rows:
            return
        self.conn.executemany(
            """
            INSERT INTO validations
                (key, cycle_id, ok, latency_ms, anonymity, exit_ip, confirmed, error, checked_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            rows,
        )
        self.conn.commit()

    # ---- working set ---------------------------------------------------
    def upsert_working(self, result: ValidationResult, classification: Classification) -> None:
        candidate = result.candidate
        now = result.checked_at or time.time()
        self.conn.execute(
            """
            INSERT INTO working_set (
                key, ip, port, protocol, source_id, latency_ms, anonymity, exit_ip,
                network_class, class_conf, class_basis, asn, as_org, country, ptr,
                first_seen, last_ok, ok_count, fail_count, retired_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1, 0, NULL)
            ON CONFLICT(key) DO UPDATE SET
                latency_ms = excluded.latency_ms,
                anonymity = excluded.anonymity,
                exit_ip = excluded.exit_ip,
                network_class = excluded.network_class,
                class_conf = excluded.class_conf,
                class_basis = excluded.class_basis,
                asn = excluded.asn,
                as_org = excluded.as_org,
                country = excluded.country,
                ptr = excluded.ptr,
                last_ok = excluded.last_ok,
                ok_count = working_set.ok_count + 1,
                retired_at = NULL
            """,
            (
                candidate.key, candidate.ip, candidate.port, candidate.protocol,
                candidate.source_id, result.latency_ms, result.anonymity, result.exit_ip,
                classification.network_class, classification.confidence,
                "; ".join(classification.basis), classification.asn,
                classification.as_org, classification.country, classification.ptr,
                now, now,
            ),
        )
        self.conn.commit()

    def mark_failures(self, keys: Iterable[str], retire_after: int = 3) -> int:
        """Increment failure counts; retire entries past the threshold.

        Retirement is a soft delete: the row stays for churn analysis, but it
        leaves W and stops being exported.
        """
        key_list = list(keys)
        if not key_list:
            return 0
        self.conn.executemany(
            "UPDATE working_set SET fail_count = fail_count + 1 WHERE key = ? AND retired_at IS NULL",
            [(k,) for k in key_list],
        )
        cursor = self.conn.execute(
            "UPDATE working_set SET retired_at = ? WHERE retired_at IS NULL AND fail_count >= ?",
            (time.time(), retire_after),
        )
        self.conn.commit()
        return cursor.rowcount

    def working_set(self, limit: Optional[int] = None) -> List[Dict]:
        """Active working set, best (lowest latency) first."""
        query = (
            "SELECT * FROM working_set WHERE retired_at IS NULL "
            "ORDER BY latency_ms IS NULL, latency_ms ASC"
        )
        params: List = []
        if limit:
            query += " LIMIT ?"
            params.append(limit)
        rows = self.conn.execute(query, params).fetchall()
        return [self._working_row(row) for row in rows]

    def working_size(self) -> int:
        row = self.conn.execute(
            "SELECT COUNT(*) AS n FROM working_set WHERE retired_at IS NULL"
        ).fetchone()
        return int(row["n"]) if row else 0

    @staticmethod
    def _working_row(row: sqlite3.Row) -> Dict:
        data = dict(row)
        return {
            "key": data["key"],
            "ip": data["ip"],
            "port": data["port"],
            "protocol": data["protocol"],
            "source_id": data["source_id"],
            "latency_ms": round(data["latency_ms"], 1) if data["latency_ms"] is not None else None,
            "anonymity": data["anonymity"],
            "exit_ip": data["exit_ip"],
            "network_class": data["network_class"],
            "classification_confidence": data["class_conf"],
            "classification_basis": data["class_basis"],
            "asn": data["asn"],
            "as_org": data["as_org"],
            "country": data["country"],
            "ptr": data["ptr"],
            "first_seen": first_seen_iso(data["first_seen"]),
            "last_ok": first_seen_iso(data["last_ok"]),
            "last_ok_epoch": data["last_ok"],
            "ok_count": data["ok_count"],
            "fail_count": data["fail_count"],
        }

    # ---- source stats --------------------------------------------------
    def record_source_stats(self, cycle_id: int, results: Iterable) -> None:
        rows = [
            (
                r.source_id, cycle_id, 1 if r.ok else 0, r.renderer,
                len(r.candidates), r.elapsed_ms, r.error or r.skipped_reason,
            )
            for r in results
        ]
        if not rows:
            return
        self.conn.executemany(
            """
            INSERT INTO source_stats (source_id, cycle_id, ok, renderer, candidates, elapsed_ms, error)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(source_id, cycle_id) DO UPDATE SET
                ok = excluded.ok,
                renderer = excluded.renderer,
                candidates = excluded.candidates,
                elapsed_ms = excluded.elapsed_ms,
                error = excluded.error
            """,
            rows,
        )
        self.conn.commit()

    def source_yield(self, cycles: int = 5) -> List[Dict]:
        """Per-source candidate contribution over the most recent cycles."""
        rows = self.conn.execute(
            """
            SELECT source_id,
                   SUM(ok) AS ok_cycles,
                   COUNT(*) AS cycles,
                   SUM(candidates) AS candidates
            FROM source_stats
            WHERE cycle_id > (SELECT COALESCE(MAX(id), 0) - ? FROM cycles)
            GROUP BY source_id
            ORDER BY candidates DESC
            """,
            (cycles,),
        ).fetchall()
        return [dict(row) for row in rows]

    # ---- misc ----------------------------------------------------------
    def stats(self) -> Dict:
        def scalar(sql: str) -> int:
            row = self.conn.execute(sql).fetchone()
            return int(row[0]) if row and row[0] is not None else 0

        return {
            "candidates_total": scalar("SELECT COUNT(*) FROM candidates"),
            "validations_total": scalar("SELECT COUNT(*) FROM validations"),
            "working_active": self.working_size(),
            "working_retired": scalar(
                "SELECT COUNT(*) FROM working_set WHERE retired_at IS NOT NULL"
            ),
            "cycles": scalar("SELECT COUNT(*) FROM cycles"),
        }

    def dump_json(self) -> str:
        return json.dumps(self.stats(), indent=2)
