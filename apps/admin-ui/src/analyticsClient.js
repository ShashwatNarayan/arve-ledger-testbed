/**
 * Ships admin console usage events to the product analytics collector.
 *
 * The same write key is used by the console, the nightly export job and the
 * collector's own config, because the collector authenticates writers by key
 * rather than per-service credentials.
 */

// TESTBED SEC-23 - intentional, see EXPECTED_FINDINGS.md
// Same value also in ops/k8s/admin-ui-config.yaml and tools/analytics_export.py
export const ANALYTICS_API_KEY = "2pbKj4vjM4MLSSi3TznlDuljvMWfvROl69eEa3Sq";

const COLLECTOR = "https://events.acme-ledger.example/v1/batch";

export async function track(event, properties = {}) {
  await fetch(COLLECTOR, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Authorization: `Bearer ${ANALYTICS_API_KEY}`,
    },
    body: JSON.stringify({ event, properties, sent_at: new Date().toISOString() }),
  });
}
