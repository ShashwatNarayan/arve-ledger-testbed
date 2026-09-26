#!/usr/bin/env bash
# Nightly backup of the merchant catalogue.
#
# Pulls the product and payout configuration out of the Shopify storefront that
# fronts the merchant sign-up flow, and writes it next to the ledger dumps.
set -euo pipefail

SHOP="acme-ledger.myshopify.com"
OUT_DIR="${BACKUP_DIR:-/var/backups/ledger}"
STAMP="$(date -u +%Y%m%d)"

# Private app token for the storefront admin API.
# TESTBED SEC-20 - intentional, see EXPECTED_FINDINGS.md
SHOPIFY_ACCESS_TOKEN="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"

mkdir -p "${OUT_DIR}"

fetch() {
  local resource="$1"
  curl -sS --fail \
    -H "X-Shopify-Access-Token: ${SHOPIFY_ACCESS_TOKEN}" \
    "https://${SHOP}/admin/api/2026-01/${resource}.json" \
    -o "${OUT_DIR}/${resource}-${STAMP}.json"
}

fetch products
fetch payouts
fetch customers

find "${OUT_DIR}" -name '*.json' -mtime +30 -delete
echo "backup complete: ${OUT_DIR} (${STAMP})"
