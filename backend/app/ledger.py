"""Double-entry ledger core.

Balances are never stored. They are derived by summing entries, so the entry
table is the single source of truth.

All amounts are integer minor units (cents). Nothing here uses floats.
"""

import uuid
from datetime import datetime, timezone

from . import config, models


class LedgerError(Exception):
    """Raised when a movement cannot be posted."""


def _now():
    return datetime.now(timezone.utc).isoformat()


def _new_id(prefix):
    return f"{prefix}_{uuid.uuid4().hex[:16]}"


def _validate_amount(amount):
    if not isinstance(amount, int):
        raise LedgerError("amount must be an integer number of minor units")
    if amount <= 0:
        raise LedgerError("amount must be positive")
    if amount > config.MAX_TRANSACTION_MINOR:
        raise LedgerError("amount exceeds the per-transaction limit")


def _post_entry(conn, account_id, direction, amount, kind, reference):
    conn.execute(
        "INSERT INTO ledger_entries "
        "(account_id, direction, amount, kind, reference, created_at) "
        "VALUES (?, ?, ?, ?, ?, ?)",
        (account_id, direction, amount, kind, reference, _now()),
    )


def _require_account(conn, account_id):
    row = conn.execute(
        "SELECT id, owner, currency FROM accounts WHERE id = ?", (account_id,)
    ).fetchone()
    if row is None:
        raise LedgerError(f"account {account_id} does not exist")
    return row


def create_account(owner, currency=None):
    """Open a new account and return it."""
    if not owner or not owner.strip():
        raise LedgerError("owner is required")

    account_id = _new_id("acct")
    record = {
        "id": account_id,
        "owner": owner.strip(),
        "currency": (currency or config.DEFAULT_CURRENCY).upper(),
        "created_at": _now(),
    }
    with models.transaction() as conn:
        conn.execute(
            "INSERT INTO accounts (id, owner, currency, created_at) "
            "VALUES (?, ?, ?, ?)",
            (
                record["id"],
                record["owner"],
                record["currency"],
                record["created_at"],
            ),
        )
    return record


def deposit(account_id, amount, reference=None):
    """Credit an account. The counterparty is external to this ledger."""
    _validate_amount(amount)
    with models.transaction() as conn:
        _require_account(conn, account_id)
        _post_entry(conn, account_id, "credit", amount, "deposit", reference)
    return {"account_id": account_id, "amount": amount, "direction": "credit"}


def withdraw(account_id, amount, reference=None):
    """Debit an account, refusing to overdraw it."""
    _validate_amount(amount)
    with models.transaction() as conn:
        _require_account(conn, account_id)
        if _balance(conn, account_id) < amount:
            raise LedgerError("insufficient funds")
        _post_entry(conn, account_id, "debit", amount, "withdrawal", reference)
    return {"account_id": account_id, "amount": amount, "direction": "debit"}


def transfer(from_account_id, to_account_id, amount, reference=None):
    """Move funds between two accounts.

    Writes both sides of the pair inside one transaction: a debit against the
    source and a matching credit against the destination.
    """
    _validate_amount(amount)
    if from_account_id == to_account_id:
        raise LedgerError("cannot transfer to the same account")

    transfer_id = _new_id("txfr")
    ref = reference or transfer_id

    with models.transaction() as conn:
        source = _require_account(conn, from_account_id)
        destination = _require_account(conn, to_account_id)

        if source["currency"] != destination["currency"]:
            raise LedgerError("currency mismatch between accounts")
        if _balance(conn, from_account_id) < amount:
            raise LedgerError("insufficient funds")

        _post_entry(conn, from_account_id, "debit", amount, "transfer", ref)
        _post_entry(conn, to_account_id, "credit", amount, "transfer", ref)

    return {
        "transfer_id": transfer_id,
        "from_account_id": from_account_id,
        "to_account_id": to_account_id,
        "amount": amount,
        "reference": ref,
    }


def _balance(conn, account_id):
    row = conn.execute(
        "SELECT "
        "COALESCE(SUM(CASE WHEN direction = 'credit' THEN amount ELSE 0 END), 0) "
        "- COALESCE(SUM(CASE WHEN direction = 'debit' THEN amount ELSE 0 END), 0) "
        "AS balance FROM ledger_entries WHERE account_id = ?",
        (account_id,),
    ).fetchone()
    return row["balance"]


def get_balance(account_id):
    """Return the derived balance for an account."""
    with models.transaction() as conn:
        account = _require_account(conn, account_id)
        return {
            "account_id": account_id,
            "owner": account["owner"],
            "currency": account["currency"],
            "balance": _balance(conn, account_id),
        }


def list_transactions(account_id, limit=100):
    """Return an account's entries, newest first."""
    limit = max(1, min(int(limit), 500))
    with models.transaction() as conn:
        _require_account(conn, account_id)
        rows = conn.execute(
            "SELECT id, direction, amount, kind, reference, created_at "
            "FROM ledger_entries WHERE account_id = ? "
            "ORDER BY id DESC LIMIT ?",
            (account_id, limit),
        ).fetchall()
    return [dict(row) for row in rows]
