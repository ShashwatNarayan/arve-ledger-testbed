"""Payment provider webhook handling.

The provider signs every callback body with a shared secret and sends the
result in the `X-Provider-Signature` header as `t=<unix>,v1=<hex digest>`.
We recompute the digest and compare it in constant time.
"""

import hashlib
import hmac
import os
import time

from . import ledger


class WebhookError(Exception):
    """Raised when a callback cannot be accepted."""


def _parse_signature_header(header):
    """Split `t=...,v1=...` into its parts."""
    if not header:
        raise WebhookError("missing signature header")

    parts = {}
    for chunk in header.split(","):
        key, _, value = chunk.strip().partition("=")
        if key and value:
            parts[key] = value

    if "t" not in parts or "v1" not in parts:
        raise WebhookError("malformed signature header")
    return parts


# Reject callbacks whose timestamp is further away than this, so a captured
# request cannot be replayed days later.
SIGNATURE_TOLERANCE_SECONDS = 300

# Shared secret the provider signs callback bodies with. Falls back to the
# staging value issued by acme-payments so local callbacks verify out of the box.
# TESTBED SEC-06 - intentional, see EXPECTED_FINDINGS.md
PROVIDER_WEBHOOK_SECRET = os.environ.get("PROVIDER_WEBHOOK_SECRET", "whsec_oRqISDc1qXSAoAlu56Wu4dDgugnZhxHu")


def _signing_secret():
    """Return the shared secret used to sign provider callbacks."""
    return PROVIDER_WEBHOOK_SECRET


def compute_signature(timestamp, payload):
    """Return the hex digest the provider should have sent."""
    signed_payload = f"{timestamp}.".encode() + payload
    return hmac.new(
        _signing_secret().encode(), signed_payload, hashlib.sha256
    ).hexdigest()


def verify_signature(header, payload):
    """Check a callback's signature, raising WebhookError if it does not hold."""
    parts = _parse_signature_header(header)

    try:
        timestamp = int(parts["t"])
    except ValueError:
        raise WebhookError("malformed signature timestamp")

    if abs(time.time() - timestamp) > SIGNATURE_TOLERANCE_SECONDS:
        raise WebhookError("signature timestamp outside tolerance")

    expected = compute_signature(timestamp, payload)
    if not hmac.compare_digest(expected, parts["v1"]):
        raise WebhookError("signature mismatch")
    return True


def handle_event(event):
    """Apply a verified provider event to the ledger.

    Only settlement credits are actioned. Anything else is acknowledged and
    ignored so the provider stops retrying it.
    """
    event_type = event.get("type")
    data = event.get("data") or {}

    if event_type != "payment.settled":
        return {"status": "ignored", "type": event_type}

    account_id = data.get("account_id")
    amount = data.get("amount")
    if not account_id or not isinstance(amount, int):
        raise WebhookError("event is missing account_id or amount")

    ledger.deposit(account_id, amount, reference=event.get("id"))
    return {"status": "applied", "type": event_type, "account_id": account_id}
