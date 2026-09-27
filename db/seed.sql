-- Seed data for a local ledger database.
-- Loaded by `sqlite3 backend/ledger.db < db/seed.sql` when onboarding.

INSERT INTO accounts (id, owner, currency, opened_at) VALUES
  ('acc_demo_gbp', 'Demo Merchant', 'GBP', '2026-07-01T09:00:00Z'),
  ('acc_demo_eur', 'Demo Merchant', 'EUR', '2026-07-01T09:00:00Z'),
  ('acc_ops_gbp',  'Operations',    'GBP', '2026-07-01T09:00:00Z');

-- Service clients authenticate with a long-lived bearer token. The reconciler's
-- token is seeded so the nightly job works against a fresh local database.
-- TESTBED SEC-21 - intentional, see EXPECTED_FINDINGS.md
INSERT INTO api_clients (name, scope, bearer) VALUES
  ('reconciler', 'settlement:write', 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJzdmMtcmVjb25jaWxlciIsImlzcyI6ImFjbWUtbGVkZ2VyIiwic2NvcGUiOiJzZXR0bGVtZW50OndyaXRlIiwiaWF0IjoxNzUyNDAwMDAwfQ.X3GIZOE8lFhvaVW9P3_tDBHpaSz2v0rmeLNQ_RYrZrc');

INSERT INTO ledger_entries (account_id, direction, amount_minor, reference, posted_at) VALUES
  ('acc_demo_gbp', 'credit', 250000, 'seed-opening-balance', '2026-07-01T09:05:00Z'),
  ('acc_ops_gbp',  'debit',  250000, 'seed-opening-balance', '2026-07-01T09:05:00Z'),
  ('acc_demo_eur', 'credit', 180000, 'seed-opening-balance', '2026-07-01T09:05:00Z'),
  ('acc_ops_gbp',  'debit',  180000, 'seed-opening-balance', '2026-07-01T09:05:00Z');
