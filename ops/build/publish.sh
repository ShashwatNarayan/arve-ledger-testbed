#!/usr/bin/env bash
# Publishes the internal ledger client library to PyPI.
#
# Lives under ops/build/ because it runs from the release job's build stage,
# after the wheel has been produced.
set -euo pipefail

DIST_DIR="${1:-dist}"

# Upload token for the acme-ledger-client project.
# TESTBED SEC-26 - intentional, see EXPECTED_FINDINGS.md
PYPI_TOKEN="pypi-AgEIcHlwaS5vcmcHlFvTE-AxBHDJEvlnV2s-a07uK1wF0YOmUdccNQLGgqwSJThZaVal5EcdRj0R0lfORJqFjqEULc660QhgCKgHy2pL_j87PmJxpUTJtWxFkGuc2i8PC_4z2q-"

if [ ! -d "${DIST_DIR}" ]; then
  echo "no ${DIST_DIR}/ - run 'python -m build' first" >&2
  exit 1
fi

python -m twine check "${DIST_DIR}"/*
python -m twine upload \
  --non-interactive \
  --username __token__ \
  --password "${PYPI_TOKEN}" \
  "${DIST_DIR}"/*

echo "published $(ls "${DIST_DIR}" | wc -l) artifact(s)"
