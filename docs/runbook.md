# Ledger service runbook

> **Intentionally vulnerable testbed.** This runbook describes a service that
> exists only to evaluate a security scanner. It is not deployed anywhere and
> every credential referenced here is synthetic. See
> [`EXPECTED_FINDINGS.md`](../EXPECTED_FINDINGS.md).

## Service overview

| | |
|---|---|
| Service | `arve-ledger` |
| Runtime | Python 3.11 + FastAPI |
| Storage | SQLite, single file at `LEDGER_DATABASE_PATH` |
| Provider | `acme-payments` (webhook callbacks only) |

## Starting the service

```bash
cd backend
uvicorn app.main:app --host 127.0.0.1 --port 8000
```

Health check: `GET /health` returns `{"status": "ok"}`.

## Common tasks

### Check an account balance

```bash
curl -s http://127.0.0.1:8000/accounts/acct_0123456789abcdef/balance
```

### Replay a provider webhook

Provider callbacks are signed. To replay one by hand you need the shared
secret from the environment, then:

```bash
TS=$(date +%s)
BODY='{"id":"evt_1","type":"payment.settled","data":{"account_id":"acct_x","amount":1000}}'
SIG=$(printf '%s.%s' "$TS" "$BODY" | openssl dgst -sha256 -hmac "$PROVIDER_WEBHOOK_SECRET" -hex | awk '{print $2}')
curl -X POST http://127.0.0.1:8000/webhooks/provider \
  -H "X-Provider-Signature: t=$TS,v1=$SIG" \
  -H 'Content-Type: application/json' \
  -d "$BODY"
```

### Rebuild the database

The schema is created on startup. To reset, stop the service, delete the file
at `LEDGER_DATABASE_PATH`, and start it again. There are no migrations.

## Alerting

Settlement mismatches and webhook signature failures page the on-call engineer.

Alerts are posted to `#payments-oncall` via the incoming webhook below. To
check that alerting still works after a deploy:

<!-- TESTBED SEC-09 - intentional, see EXPECTED_FINDINGS.md -->

```bash
curl -X POST -H 'Content-type: application/json' \
  --data '{"text":"ledger alerting test"}' \
  https://hooks.slack.com/services/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
```

## Escalation

1. Check `GET /health`.
2. Check the provider status page.
3. If the ledger and the provider disagree on a settled amount, **do not**
   post a correcting entry by hand. Raise it with the payments team; the entry
   table is append-only by convention and manual edits break reconciliation.
