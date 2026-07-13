# arve-ledger-testbed

> # ⚠️ THIS REPOSITORY IS INTENTIONALLY VULNERABLE
>
> It contains **deliberately planted hardcoded secrets and knowingly vulnerable
> dependencies**. They are the point of the repository, not accidents.
>
> - **Never deploy this.** Not to production, not to staging, not to a laptop
>   exposed to a network.
> - **Never use it as a reference implementation.** Nothing here is an example
>   of how to build a payments system.
> - **Every credential in this repository is synthetic and non-functional.**
>   Each one is randomly generated with the correct *shape* so that scanners
>   match it, and is valid for no real service. Nothing here has ever been a
>   live credential.
> - The planted flaws are catalogued in
>   [`EXPECTED_FINDINGS.md`](EXPECTED_FINDINGS.md).
>
> **Evaluating a scanner against this repo? Start with
> [`README_TEAM.md`](README_TEAM.md)** — it explains what is planted, where, how
> to scan for it, and how to score the results.

## Why this exists

This is a test fixture for **ARVE**, an AI-assisted security code discovery
engine. ARVE ingests a Git repository, runs real open-source scanners against it
in a locked-down Docker sandbox, and normalizes every scanner's output into one
canonical finding format so results can be correlated, prioritized, and
explained. Its founding rule is *tools find the evidence, AI only explains the
evidence* — a language model is never asked whether code is insecure.

Evaluating that pipeline requires a repository whose answers are already known.
This is that repository. It carries **17 planted findings** whose exact
locations, severities and advisory identifiers are recorded up front, so ARVE's
output can be diffed against ground truth rather than eyeballed.

Two scanners are currently integrated, and the planted flaws are scoped to
exactly what they can detect:

| Engine | Detects | Findings here |
|---|---|---|
| **Gitleaks** | Hardcoded secrets, in the working tree **and in Git history** | `SEC-01` … `SEC-09` |
| **OSV-Scanner** | Dependencies with published advisories, read from lockfiles | `DEP-01` … `DEP-08` |

There is deliberately **no SQL injection, XSS, path traversal, SSRF, or broken
access control** here. Those need SAST (Semgrep), which is not wired into ARVE
yet, so planting them would test nothing.

## What the application does

A minimal double-entry payments ledger. Seven endpoints, SQLite, no auth system.
The application is kept trivially simple on purpose — the complexity budget
belongs to the vulnerability matrix, not the architecture.

| Method | Path | Purpose |
|---|---|---|
| `POST` | `/accounts` | Create an account |
| `POST` | `/accounts/{id}/deposit` | Deposit funds |
| `POST` | `/accounts/{id}/withdraw` | Withdraw funds |
| `POST` | `/transfers` | Transfer between accounts (writes debit + credit rows) |
| `GET` | `/accounts/{id}/balance` | Get an account balance |
| `GET` | `/accounts/{id}/transactions` | List an account's transactions |
| `POST` | `/webhooks/provider` | Receive a provider webhook, verify its HMAC signature |

Balances are never stored; they are derived by summing ledger entries. Amounts
are integer minor units (cents) throughout — no floats.

## Running the backend

Requires Python 3.11+.

```bash
python -m venv .venv
.venv/Scripts/activate          # Windows
# source .venv/bin/activate     # macOS / Linux

pip install -r backend/requirements.txt

cd backend
uvicorn app.main:app --reload
```

The API is then at <http://127.0.0.1:8000>, with interactive docs at
<http://127.0.0.1:8000/docs>.

> `backend/requirements.txt` pins **deliberately outdated packages**. That is
> intentional — see `DEP-01` and `DEP-02` in the findings catalogue. Do not
> "fix" the pins; doing so silently destroys the test fixture.

## Running the web console

The `web/` directory is a single static page that calls two of the endpoints. It
exists mainly so the repository has a **second package ecosystem with its own
lockfile at a nested path**, which tests whether a scanner recurses properly
instead of only checking the repository root.

```bash
cd web
npm install     # installs deliberately vulnerable packages - see DEP-03..DEP-08
npm start       # serves the page and proxies /api/* to the backend
```

Then open <http://127.0.0.1:5173>. Start the backend first, or the proxy will
return `502 upstream unreachable`.

## Repository layout

```
.
├── README.md                     you are here
├── README_TEAM.md                start here if you are evaluating a scanner
├── EXPECTED_FINDINGS.md          the answer key, human-readable
├── expected-findings.json        the answer key, machine-readable
├── plan.md                       how this testbed was built
├── seed_history.py               reproduces the planted commit history
├── .env.example
├── .github/workflows/deploy.yml
├── docs/runbook.md
├── backend/
│   ├── requirements.in           direct dependencies
│   ├── requirements.txt          compiled lockfile (DEP-01, DEP-02)
│   ├── keys/webhook_signing.pem
│   ├── app/                      main, config, models, ledger, api, webhooks
│   └── tests/conftest.py
└── web/
    ├── package.json
    ├── package-lock.json         DEP-03 .. DEP-08
    ├── dev-server.js             static server + /api proxy
    ├── index.html
    └── src/main.js
```

## A note on the Git history

Some findings exist **only in history** and are absent from the working tree, so
that history scanning is exercised rather than just a filesystem walk. The
commit sequence is reproducible via `seed_history.py`. Commit messages read like
ordinary development on purpose — the history is meant to look like real work,
not like a test fixture.

## Reporting

If you found this repository outside its intended context and are wondering
whether to report the leaked credentials in it: **you don't need to.** They are
fake, documented, and deliberate. Start with
[`EXPECTED_FINDINGS.md`](EXPECTED_FINDINGS.md).
