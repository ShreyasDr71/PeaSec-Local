"""SQLite schema and small helpers. Metadata is plaintext; secrets are *_ct blobs."""
from __future__ import annotations

import json
import re
import sqlite3
import time
import uuid

_IDENT = re.compile(r"[a-z_]{1,40}")

SCHEMA = """
CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS contacts (
  fpr TEXT PRIMARY KEY, name TEXT, title TEXT, dept TEXT,
  ed_pub BLOB NOT NULL, x_pub BLOB NOT NULL, addr TEXT, last_seen REAL,
  paired_at REAL, demo INTEGER DEFAULT 0);
CREATE TABLE IF NOT EXISTS credentials (
  id TEXT PRIMARY KEY, scope TEXT NOT NULL, group_id TEXT, owner_fpr TEXT,
  name TEXT NOT NULL, url TEXT, username TEXT, account_type TEXT, criticality TEXT,
  notes TEXT, secret_ct BLOB, created_at REAL, updated_at REAL, rotated_at REAL);
CREATE TABLE IF NOT EXISTS group_docs (
  group_id TEXT, version INTEGER, doc TEXT NOT NULL, hash TEXT NOT NULL,
  PRIMARY KEY (group_id, version));
CREATE TABLE IF NOT EXISTS requests (
  id TEXT PRIMARY KEY, direction TEXT NOT NULL, requester_fpr TEXT, requester_name TEXT,
  target_fpr TEXT, target_name TEXT, group_id TEXT, cred_id TEXT, cred_name TEXT,
  criticality TEXT, ticket TEXT, reason TEXT, minutes INTEGER, status TEXT NOT NULL,
  decided_by TEXT, comment TEXT, created_at REAL, decided_at REAL, lease_id TEXT);
CREATE TABLE IF NOT EXISTS leases (
  id TEXT PRIMARY KEY, direction TEXT NOT NULL, cred_id TEXT, cred_name TEXT, group_id TEXT,
  username TEXT, url TEXT, criticality TEXT, holder_fpr TEXT, holder_name TEXT,
  grantor_fpr TEXT, grantor_name TEXT, request_id TEXT, ticket TEXT,
  granted_at REAL, expires_at REAL, status TEXT NOT NULL, ended_at REAL, secret_ct BLOB);
CREATE TABLE IF NOT EXISTS rotation_tasks (
  id TEXT PRIMARY KEY, cred_id TEXT, cred_name TEXT, reason TEXT, status TEXT NOT NULL,
  created_at REAL, closed_at REAL, closed_by TEXT, note TEXT);
CREATE TABLE IF NOT EXISTS audit (
  seq INTEGER PRIMARY KEY, ts REAL, actor_fpr TEXT, event_type TEXT,
  subject TEXT, details TEXT, prev_hash TEXT, hash TEXT, sig BLOB);
CREATE TABLE IF NOT EXISTS receipts (
  id TEXT PRIMARY KEY, peer_fpr TEXT, record TEXT, sig BLOB, received_at REAL);
CREATE TABLE IF NOT EXISTS anchors (peer_fpr TEXT PRIMARY KEY, seq INTEGER, hash TEXT, ts REAL);
CREATE TABLE IF NOT EXISTS outbox (
  id TEXT PRIMARY KEY, peer_fpr TEXT, msg_type TEXT, body TEXT, created_at REAL,
  attempts INTEGER DEFAULT 0);
CREATE TABLE IF NOT EXISTS tombstones (lease_id TEXT PRIMARY KEY, ts REAL);
CREATE TABLE IF NOT EXISTS seen_msgs (msg_id TEXT PRIMARY KEY, ts REAL);
CREATE TABLE IF NOT EXISTS alerts (
  id TEXT PRIMARY KEY, ts REAL, kind TEXT, message TEXT, ref TEXT, ack INTEGER DEFAULT 0);
"""


def open_db(path: str) -> sqlite3.Connection:
    conn = sqlite3.connect(path, isolation_level=None, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.executescript(SCHEMA)
    return conn


def new_id() -> str:
    return str(uuid.uuid4())


def now() -> float:
    return round(time.time(), 3)


def rows(conn: sqlite3.Connection, sql: str, params=()) -> list[dict]:
    return [dict(r) for r in conn.execute(sql, params)]


def row(conn: sqlite3.Connection, sql: str, params=()) -> dict | None:
    r = conn.execute(sql, params).fetchone()
    return dict(r) if r else None


def _check_cols(names) -> None:
    for n in names:
        if not _IDENT.fullmatch(n):
            raise ValueError(f"bad column name {n!r}")


def insert(conn: sqlite3.Connection, table: str, values: dict, replace: bool = False) -> None:
    _check_cols(values)
    cols = ",".join(values)
    marks = ",".join("?" for _ in values)
    verb = "INSERT OR REPLACE" if replace else "INSERT"
    conn.execute(f"{verb} INTO {table} ({cols}) VALUES ({marks})", tuple(values.values()))


def update(conn: sqlite3.Connection, table: str, key: str, key_val, values: dict) -> None:
    _check_cols(values)
    sets = ",".join(f"{c}=?" for c in values)
    conn.execute(f"UPDATE {table} SET {sets} WHERE {key}=?", (*values.values(), key_val))


def get_meta(conn: sqlite3.Connection, key: str, default=None):
    r = conn.execute("SELECT value FROM meta WHERE key=?", (key,)).fetchone()
    return json.loads(r[0]) if r else default


def set_meta(conn: sqlite3.Connection, key: str, value) -> None:
    conn.execute("INSERT OR REPLACE INTO meta (key, value) VALUES (?, ?)", (key, json.dumps(value)))


def add_alert(conn: sqlite3.Connection, kind: str, message: str, ref: str = "") -> None:
    insert(conn, "alerts", {"id": new_id(), "ts": now(), "kind": kind, "message": message, "ref": ref})
