"""Application configuration.

Values are read from the environment. See `.env.example` for the full list.
"""

import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent

# Where the SQLite file lives. Relative to backend/ by default.
DATABASE_PATH = os.environ.get("LEDGER_DATABASE_PATH", str(BASE_DIR / "ledger.db"))

# ISO-4217 code applied to accounts created without an explicit currency.
DEFAULT_CURRENCY = os.environ.get("LEDGER_DEFAULT_CURRENCY", "USD")

# Ledger amounts are held as integer minor units (cents) to avoid float drift.
# This caps a single movement so a fat-fingered request cannot post a
# nonsensical amount.
MAX_TRANSACTION_MINOR = int(os.environ.get("LEDGER_MAX_TRANSACTION_MINOR", "100000000"))

# Payment provider settings.
PROVIDER_NAME = os.environ.get("LEDGER_PROVIDER_NAME", "acme-payments")
WEBHOOK_SIGNING_KEY_PATH = os.environ.get(
    "LEDGER_WEBHOOK_SIGNING_KEY_PATH", str(BASE_DIR / "keys" / "webhook_signing.pem")
)

# Credentials, read from the environment.
STRIPE_API_KEY = os.environ.get("STRIPE_API_KEY", "")
LEDGER_HMAC_KEY = os.environ.get("LEDGER_HMAC_KEY", "")
JWT_SIGNING_KEY = os.environ.get("JWT_SIGNING_KEY", "")
