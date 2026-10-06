# NEW PROJECT START — README

**Read this file completely before writing any code.**

This document is the build specification for a deliberately vulnerable test
repository. It explains what to build, why it exists, and exactly which flaws to
plant. Follow it as a spec, not as inspiration.

---

## ⚠️ What this repository is

This is a **security scanner testbed**. It is a small payments-ledger API that
contains **intentional, documented vulnerabilities**.

- It is **not production software** and must never be deployed anywhere.
- Every credential in it is **fake** — correctly *shaped* so scanners match them,
  but not valid for any real service.
- The vulnerabilities are **the deliverable**, not accidents.

Anyone who finds this repository should immediately understand from the root
`README.md` that it is intentionally broken. Writing that root README is part of
the build.

---

## Why this exists — the parent project

This testbed exists to evaluate a security engine called **ARVE**.

ARVE is an AI-assisted security code discovery engine. It ingests a Git
repository, runs real open-source scanners against it inside a locked-down Docker
sandbox, then normalizes every scanner's output into one canonical finding format
so the results can be correlated, prioritized, and explained.

ARVE's founding rule is:

> **Tools find the evidence. AI only explains the evidence.**

ARVE never asks a language model "is this code insecure?" Real scanners decide;
the AI layer only explains what they found. That is why its output can always
point at a concrete artifact.

### What ARVE currently supports

Two engines are integrated:

| Engine | Detects | ARVE `finding_type` |
|---|---|---|
| **Gitleaks** | Hardcoded secrets, API keys, private keys, tokens — in working-tree files **and in Git history** | `secret` |
| **OSV-Scanner** | Dependencies with known published advisories, read from lockfiles | `dependency` |

Semgrep (SAST) is a **later phase and is not connected yet**.

### The critical scoping rule

> **Only plant vulnerabilities that Gitleaks or OSV-Scanner can find.**

Do **NOT** write SQL injection, XSS, path traversal, SSRF, insecure
deserialization, or broken access control expecting them to be detected. Those
require Semgrep, which is not wired up. Planting them would test nothing and
would pollute the results with flaws the engine cannot possibly report.

If the natural way to write a piece of this app happens to be insecure, that is
fine and realistic — just do not count it as a planted finding, and do not list it
in the answer key.

---

## What "difficulty" means here

This is the most important design idea in this document, and it is easy to get
wrong.

Gitleaks and OSV-Scanner are **exact-match detectors, not analyzers**:

- **OSV-Scanner** reads a lockfile, extracts `package@version`, and looks it up in
  a vulnerability database. It either matches or it does not. There is no such
  thing as a *subtly* vulnerable dependency.
- **Gitleaks** runs regex rules and Shannon entropy over file bytes and commit
  history. There is no such thing as a *clever* hardcoded secret.

Therefore **do not try to obfuscate anything.** An obfuscated secret is simply an
undetectable secret, which tests nothing.

Difficulty in this testbed comes from three places instead:

1. **Discovery difficulty** — is the lockfile somewhere the scanner has to work to
   find? Is the secret in a file type or path that gets skipped?
2. **History difficulty** — is the secret still at `HEAD`, or only in an older
   commit?
3. **Normalization difficulty** — this is the real target. Gitleaks and
   OSV-Scanner are already well tested by their own maintainers. **What is
   unproven is ARVE's own code**: its severity normalizer, its deterministic
   fingerprinting, and its `OPEN → RESOLVED → REOPENED` lifecycle.

Design every planted finding to stress category 3 wherever possible.

---

## Project to build: minimal payments ledger

A small double-entry ledger API. **Keep the application deliberately simple** —
the complexity budget belongs to the vulnerability matrix, not the architecture.

Target size: roughly **15 source files**. If it is growing past that, stop adding
features.

### Stack

- **Backend:** Python + FastAPI + SQLite (no database service required)
- **Web:** a single minimal static page + one JS file

The web side exists almost entirely so the repository has a **second package
ecosystem with its own lockfile at a nested path**. Do not build a real frontend
app. One HTML page that calls two endpoints is enough.

### Functionality — this is the whole feature list

1. Create an account
2. Deposit funds
3. Withdraw funds
4. Transfer between two accounts (writes two ledger rows — debit and credit)
5. Get an account balance
6. List transactions for an account
7. Receive a payment-provider webhook and verify its HMAC signature

That is all. No authentication system, no admin panel, no reporting, no
background workers. The webhook handler exists because it gives a *realistic
reason* for signing secrets to be in the codebase.

### Directory layout

```
arve-ledger-testbed/
├── README.md                    ← "this repo is intentionally vulnerable"
├── EXPECTED_FINDINGS.md         ← human-readable answer key
├── expected-findings.json       ← machine-readable answer key
├── seed_history.py              ← reproducibly builds the planted Git history
├── .env.example
├── .github/
│   └── workflows/
│       └── deploy.yml
├── docs/
│   └── runbook.md
├── backend/
│   ├── requirements.txt
│   ├── keys/
│   │   └── webhook_signing.pem
│   ├── app/
│   │   ├── main.py
│   │   ├── config.py
│   │   ├── models.py
│   │   ├── ledger.py
│   │   ├── api.py
│   │   └── webhooks.py
│   └── tests/
│       └── conftest.py
└── web/
    ├── package.json
    ├── package-lock.json
    ├── index.html
    └── src/
        └── main.js
```

Two ecosystems, two lockfiles, both at nested paths. That alone tests whether
ARVE's OSV integration recurses properly instead of only checking the repo root.

---

## Planted vulnerability matrix

Every item below must be planted **and** recorded in the answer key. Each has an
ID used consistently across the code comments and both answer-key files.

### Group A — Secrets (Gitleaks, `finding_type: secret`)

| ID | What | Where | Stresses |
|---|---|---|---|
| **SEC-01** | Stripe-shaped secret key | `backend/app/config.py`, at `HEAD` | Baseline. If this is missed, the pipeline is broken |
| **SEC-02** | AWS access key ID + secret access key | `.github/workflows/deploy.yml` | Non-Python path; workflow YAML is sometimes skipped by path filters |
| **SEC-03** | RSA private key block | `backend/keys/webhook_signing.pem` | A distinct Gitleaks rule class from token regexes |
| **SEC-04** | SFTP password for "bank settlement files" | Added in an early commit, **deleted in a later commit** | **Git history scanning.** Absent from the working tree; still in history |
| **SEC-05** | JWT signing key, identical value in **two** files | `backend/app/config.py` **and** `backend/tests/conftest.py` | **Fingerprint behaviour** — one finding or two? Whatever ARVE does must be deliberate |
| **SEC-06** | A secret that **moves to a different line** between two commits | `backend/app/webhooks.py` | **`secret_hash` line-independent identity.** ARVE must report the *same* finding, not resolve-and-reopen |
| **SEC-07** | High-entropy generic key with no vendor prefix | `backend/app/config.py` as `LEDGER_HMAC_KEY` | Entropy rule rather than a named-vendor regex |
| **SEC-08** | A real-shaped value sitting in `.env.example` | `.env.example` | Ambiguous by design. Tests the `FALSE_POSITIVE` / `SUPPRESSED` lifecycle |
| **SEC-09** | Slack incoming-webhook URL | `docs/runbook.md` | Markdown, non-code path |

### Group B — Vulnerable dependencies (OSV-Scanner, `finding_type: dependency`)

**Verify every version at <https://osv.dev> before pinning it.** Advisories and
affected ranges change; a version that was vulnerable when this spec was written
may have been re-evaluated. The answer key must reflect what osv.dev says *at
build time*, not what this document guesses.

| ID | Ecosystem | Intent | Stresses |
|---|---|---|---|
| **DEP-01** | PyPI | A **directly** declared package with a well-known advisory | Baseline direct dependency |
| **DEP-02** | PyPI | A package that is only vulnerable **transitively** — pinned parent pulls a vulnerable child | Transitive resolution depth |
| **DEP-03** | npm | A direct dependency with a high-severity advisory | Baseline for the second ecosystem |
| **DEP-04** | npm | A vulnerable package reachable **only** through another package's dependency tree | Lockfile graph parsing |
| **DEP-05** | either | One package carrying **two distinct advisories** | Fingerprint uniqueness per (package, advisory) — must produce two findings, not one |
| **DEP-06** | either | An advisory whose GitHub severity string is `moderate` | **`normalize_severity`** — GitHub uses `moderate`, ARVE's canonical value is `MEDIUM` |
| **DEP-07** | either | An advisory with a **GHSA ID but no CVE ID** | The `ghsa` field must populate and `cve` must stay null |
| **DEP-08** | either | An advisory with **no CVSS score at all** | Severity fallback path — must land on the `MEDIUM` default, not crash or emit null |

Good starting candidates to check on osv.dev — **confirm each before use**:
`PyYAML 5.1`, `Jinja2 2.10`, `urllib3 1.24.1`, `requests 2.19.1` (for the
transitive case), `lodash 4.17.11`, `minimist 1.2.0`, `axios 0.21.0`.

DEP-05 through DEP-08 are the highest-value items in this table. They are the ones
that exercise ARVE's own normalizer rather than OSV-Scanner's matcher.

---

## Git history requirements

Several findings only exist in history, so the commit sequence is part of the
build. Write `seed_history.py` to construct it reproducibly, and commit that
script.

Required sequence, roughly:

1. Initial project skeleton — clean, no planted findings
2. Add the ledger core and the vulnerable Python dependencies
3. **Add SEC-04** (the SFTP password) as part of a plausible "add settlement job"
   commit
4. Add the web package and its vulnerable npm dependencies
5. Add the webhook handler containing **SEC-06** at its original line
6. Refactor `webhooks.py` so **SEC-06 moves to a different line number** — same
   secret value, new position
7. **Delete SEC-04** in a "clean up settlement config" commit — the secret leaves
   the working tree but remains in history
8. Add remaining secrets and documentation

Commit messages must read like ordinary development. Do not write
`"add vulnerable password"` — write `"add nightly settlement file transfer"`. The
point is that the history looks like real work.

---

## The answer key — build this as you go

Do **not** write the code first and document it afterwards. **Every time you plant
something, record it immediately.** A finding that exists in the code but not in
the answer key is worse than useless: it will look like a scanner false positive
during evaluation.

### `EXPECTED_FINDINGS.md`

Human-readable. One section per finding:

- The ID (`SEC-01`, `DEP-03`, …)
- What was planted, in one sentence
- Exact file path, and line number **at `HEAD`** (or "history only — commit N")
- Which engine should report it
- Expected canonical `severity`
- The advisory identifier where applicable (CVE / GHSA)
- **What this finding is testing** — the "stresses" column from the matrix above
- Any expected lifecycle behaviour (for SEC-04 and SEC-06 especially)

### `expected-findings.json`

Machine-readable, so ARVE's output can be diffed against it directly. Mirror
ARVE's `NormalizedFinding` field names exactly so no translation layer is needed:

```json
{
  "findings": [
    {
      "id": "SEC-01",
      "engine": "gitleaks",
      "finding_type": "secret",
      "severity": "HIGH",
      "file_path": "backend/app/config.py",
      "line_start": 0,
      "rule_id": "stripe-access-token",
      "history_only": false,
      "tests": "baseline detection at HEAD",
      "notes": ""
    },
    {
      "id": "DEP-06",
      "engine": "osv",
      "finding_type": "dependency",
      "severity": "MEDIUM",
      "package_name": "",
      "package_version": "",
      "ecosystem": "npm",
      "cve": null,
      "ghsa": "",
      "history_only": false,
      "tests": "GitHub severity string 'moderate' must normalize to MEDIUM",
      "notes": ""
    }
  ]
}
```

Fill in every empty field with the real values as you build. Line numbers must be
accurate at the final commit — **verify them after the last commit**, since
refactors move them.

---

## Rules for the fake credentials

These matter. Get them wrong and the testbed silently fails.

1. **Never commit a real credential.** Not a rotated one, not an expired one, not
   a free-tier one. Every value is synthetic.

2. **Do not use famous documented example keys.** `AKIAIOSFODNN7EXAMPLE` and
   friends appear in AWS's own public documentation, and scanners frequently
   **allowlist them by default**. Using one would produce a silent miss that looks
   like a scanner bug. Generate a random value with the correct *prefix and
   length* instead — for AWS, `AKIA` followed by 16 random uppercase alphanumerics.

3. **Shape over content.** Gitleaks matches on pattern and entropy, so a
   correctly shaped random string triggers detection identically to a live key.

4. **The RSA key in `SEC-03` should be a genuinely generated throwaway key** —
   `openssl genrsa -out webhook_signing.pem 2048` — so the PEM structure is
   valid. It has never been used for anything and never will be.

5. Keep a comment near each planted secret with its ID, e.g.
   `# TESTBED SEC-01 — intentional, see EXPECTED_FINDINGS.md`. This keeps the
   repository honest for human readers while remaining completely invisible to
   Gitleaks, which does not care about comments.

---

## Root `README.md` to write

Short, and unmissable at the top:

- A prominent warning that the repository is **intentionally vulnerable** and must
  never be deployed or used as a reference implementation
- One paragraph on what ARVE is and why this testbed exists
- How to run the backend locally
- A pointer to `EXPECTED_FINDINGS.md`
- An explicit statement that **all credentials are synthetic and non-functional**

---

## Definition of done

- [ ] Backend runs locally and all seven endpoints work
- [ ] `web/` builds a lockfile and the page calls at least two endpoints
- [ ] Both lockfiles committed (`backend` and `web`), at nested paths
- [ ] All nine `SEC-*` findings planted
- [ ] All eight `DEP-*` findings planted, **each verified against osv.dev**
- [ ] `seed_history.py` reproduces the required commit sequence
- [ ] SEC-04 is absent from the working tree but present in history
- [ ] SEC-06 sits at a different line than it did when introduced
- [ ] `EXPECTED_FINDINGS.md` documents all 17 findings
- [ ] `expected-findings.json` validates and every field is populated
- [ ] Line numbers verified accurate at the final commit
- [ ] Root `README.md` carries the intentional-vulnerability warning
- [ ] `git log` reads like ordinary development

---

## After the build

Run the reference scanners locally first, before pointing ARVE at the repository:

```bash
gitleaks detect --source . --report-path gitleaks-baseline.json
osv-scanner scan source --recursive . --format json --output osv-baseline.json
```

These baselines separate two very different failures:

- A finding the reference tool **also** missed → the testbed is wrong; fix the
  plant.
- A finding the reference tool **caught** but ARVE did not → ARVE has a real bug.

Without those baselines you cannot tell which is which, and you will waste days
debugging the wrong system. Commit both baseline files.
