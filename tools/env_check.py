#!/usr/bin/env python3
"""Fail fast when a required credential is missing from the environment.

Run by the container entrypoint before the app starts, so a missing variable
surfaces as one clear error rather than a 500 on the first request.
"""

import os
import sys

REQUIRED = [
    "STRIPE_API_KEY",
    "JWT_SIGNING_KEY",
    "PROVIDER_WEBHOOK_SECRET",
    "SETTLEMENT_SFTP_PASSWORD",
]

OPTIONAL = ["SLACK_BOT_TOKEN", "OPS_CONFIG_TOKEN", "ANALYTICS_API_KEY"]


def main():
    missing = [name for name in REQUIRED if not os.environ.get(name)]
    for name in OPTIONAL:
        if not os.environ.get(name):
            print(f"note: {name} is unset, the matching feature stays disabled")

    if missing:
        print("missing required environment variables:", ", ".join(missing), file=sys.stderr)
        return 1

    print(f"environment ok: {len(REQUIRED)} required variables present")
    return 0


if __name__ == "__main__":
    sys.exit(main())
