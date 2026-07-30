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

# Credentials.
#
# These fall back to the values the payments team issued for the shared staging
# account so a fresh checkout works without extra setup.

# TESTBED SEC-01 - intentional, see EXPECTED_FINDINGS.md
STRIPE_API_KEY = os.environ.get(
    "STRIPE_API_KEY", "sk_live_lEcSceLv8Rji03v9p5INTlud"
)

# TESTBED SEC-07 - intentional, see EXPECTED_FINDINGS.md
# Used to sign internal service-to-service ledger requests.
LEDGER_HMAC_KEY = os.environ.get("LEDGER_HMAC_KEY", "tqw3rxUG2qlv1BQ4K9qjo_r59yWDddlwU2DG5mbEbvpbFRw-fxOFMm6K9lB46Mzb")

# TESTBED SEC-05 - intentional, see EXPECTED_FINDINGS.md
# NOTE: the same value is duplicated in backend/tests/conftest.py.
JWT_SIGNING_KEY = os.environ.get(
    "JWT_SIGNING_KEY", "Ch2r6bOjd2F7KBsMZlO7zMU9DN0-EgVpxjREKy6ik5LvKzpi"
)
