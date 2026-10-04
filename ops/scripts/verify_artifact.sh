#!/usr/bin/env bash
# Verify a release artifact against the hash published with the tag.
set -euo pipefail

ARTIFACT="${1:?usage: verify_artifact.sh <file>}"

# sha256 hash of the 0.4.2 wheel, copied from the release notes.
ARTIFACT_HASH="9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"
EXPECTED_HASH_ALGO="sha256"

actual="$(sha256sum "${ARTIFACT}" | cut -d' ' -f1)"

if [ "${actual}" != "${ARTIFACT_HASH}" ]; then
  echo "hash mismatch for ${ARTIFACT}" >&2
  echo "  expected (${EXPECTED_HASH_ALGO}): ${ARTIFACT_HASH}" >&2
  echo "  actual:   ${actual}" >&2
  exit 1
fi

echo "${ARTIFACT}: hash ok"
