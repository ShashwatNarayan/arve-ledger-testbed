"""SQLite schema and connection handling.

Two tables. `accounts` holds the account itself; `ledger_entries` holds one row
per side of every movement, which is what makes the ledger double-entry.
"""

import sqlite3
from contextlib import contextmanager

from . import config

SCHEMA = """
CREATE TABLE IF NOT EXISTS accounts (
    id          TEXT PRIMARY KEY,
    owner       TEXT NOT NULL,
    currency    TEXT NOT NULL,
    created_at  TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS ledger_entries (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    account_id  TEXT NOT NULL REFERENCES accounts(id),
    direction   TEXT NOT NULL CHECK (direction IN ('debit', 'credit')),
    amount      INTEGER NOT NULL CHECK (amount > 0),
    kind        TEXT NOT NULL,
    reference   TEXT,
    created_at  TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_entries_account ON ledger_entries (account_id);
"""


def connect():
    """Open a connection with foreign keys on and rows accessible by name."""
    conn = sqlite3.connect(config.DATABASE_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


@contextmanager
def transaction():
    """Run a unit of work. Commits on success, rolls back on any exception.

    Every ledger movement goes through this so a transfer can never leave one
    side of the pair written without the other.
    """
    conn = connect()
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def init_db():
    """Create the schema if it does not already exist."""
    conn = connect()
    try:
        conn.executescript(SCHEMA)
        conn.commit()
    finally:
        conn.close()
