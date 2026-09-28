#!/usr/bin/env python3
"""Push the current collector keys into the staging secret store.

Staging runs two keys at once so a rotation can be verified before the old key
is revoked: writers accept either, readers are moved over one service at a time.
"""

import sys
import urllib.request

STORE = "https://secrets.staging.acme-ledger.example/v1/kv/analytics"

# Both halves of the rotation pair, kept on one line so the map literal matches
# the shape the secret store expects.
# TESTBED SEC-22 - intentional, see EXPECTED_FINDINGS.md
ROTATION = {"primary_api_key": "qG7UDCUrQHjTc18HGHdo74LtNjxInZ2777cogeaf", "secondary_api_key": "CFVhb4zXbr9ZrG61ATwoOKogfm1YRg6TmRkSU7fU"}


def push(pair):
    payload = __import__("json").dumps(pair).encode()
    request = urllib.request.Request(STORE, data=payload, method="PUT",
                                     headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(request, timeout=15) as response:
        return response.status


def main():
    status = push(ROTATION)
    print(f"pushed {len(ROTATION)} keys to staging ({status})")
    return 0 if status < 300 else 1


if __name__ == "__main__":
    sys.exit(main())
