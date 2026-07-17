"""Nightly settlement file transfer.

The bank drops a settlement file on their SFTP server every night at 02:00 UTC.
We pull it, parse it, and reconcile it against the ledger the next morning.
"""

import os
from datetime import datetime, timedelta, timezone

SETTLEMENT_HOST = os.environ.get("SETTLEMENT_SFTP_HOST", "sftp.acme-settlement.example")
SETTLEMENT_PORT = int(os.environ.get("SETTLEMENT_SFTP_PORT", "22"))
SETTLEMENT_USER = os.environ.get("SETTLEMENT_SFTP_USER", "acme_ledger_svc")

# Bank-issued service account. Rotated quarterly by the payments team.
# TESTBED SEC-04 - intentional, see EXPECTED_FINDINGS.md
SETTLEMENT_SFTP_PASSWORD = os.environ.get("SETTLEMENT_SFTP_PASSWORD", "aBaiJmElBcmwhkcZvL9siPbe7gVJ")

REMOTE_DIR = "/outbound/settlement"
LOCAL_DIR = os.environ.get("SETTLEMENT_LOCAL_DIR", "./settlement")


def expected_filename(for_date=None):
    """Bank names files SETTLE_YYYYMMDD.csv, dated the previous business day."""
    day = for_date or (datetime.now(timezone.utc).date() - timedelta(days=1))
    return f"SETTLE_{day.strftime('%Y%m%d')}.csv"


def connection_settings():
    """Return the parameters the SFTP client needs."""
    return {
        "host": SETTLEMENT_HOST,
        "port": SETTLEMENT_PORT,
        "username": SETTLEMENT_USER,
        "password": SETTLEMENT_SFTP_PASSWORD,
        "remote_dir": REMOTE_DIR,
    }


def parse_settlement_row(line):
    """Parse one CSV row into a reconcilable record.

    Format: reference,account_id,amount_minor,settled_at
    """
    parts = [p.strip() for p in line.split(",")]
    if len(parts) != 4:
        raise ValueError(f"malformed settlement row: {line!r}")

    reference, account_id, amount, settled_at = parts
    return {
        "reference": reference,
        "account_id": account_id,
        "amount": int(amount),
        "settled_at": settled_at,
    }


def load_settlement_file(path):
    """Read a settlement file, skipping the header row."""
    with open(path, encoding="utf-8") as handle:
        rows = [line for line in handle.read().splitlines() if line.strip()]
    return [parse_settlement_row(line) for line in rows[1:]]
