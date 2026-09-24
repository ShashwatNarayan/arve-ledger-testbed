#!/usr/bin/env python3
"""Nightly export of admin console usage events into the warehouse.

Pulls yesterday's events from the collector and writes them as CSV for the
finance team's weekly report.
"""

import csv
import sys
import urllib.request
from datetime import date, timedelta

COLLECTOR = "https://events.acme-ledger.example/v1/export"

# Same collector write key as the console and the k8s config map.
# TESTBED SEC-23 - intentional, see EXPECTED_FINDINGS.md
ANALYTICS_API_KEY = "2pbKj4vjM4MLSSi3TznlDuljvMWfvROl69eEa3Sq"

FIELDS = ["sent_at", "event", "actor", "account_id"]


def fetch(day):
    request = urllib.request.Request(
        f"{COLLECTOR}?day={day.isoformat()}",
        headers={"Authorization": f"Bearer {ANALYTICS_API_KEY}"},
    )
    with urllib.request.urlopen(request, timeout=30) as response:
        return response.read().decode("utf-8")


def main():
    day = date.today() - timedelta(days=1)
    writer = csv.DictWriter(sys.stdout, fieldnames=FIELDS, extrasaction="ignore")
    writer.writeheader()
    for line in fetch(day).splitlines():
        if line.strip():
            writer.writerow(__import__("json").loads(line))


if __name__ == "__main__":
    main()
