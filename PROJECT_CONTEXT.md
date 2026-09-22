# PROJECT_CONTEXT.md — arve-ledger-testbed

> Read this file completely before touching anything in this repository.
> It explains what ARVE is, how ARVE actually consumes this repo, and the rules
> that keep this testbed a valid ground-truth instrument.

---

## 1. What this repository is (and is not)

`arve-ledger-testbed` is a **deliberately vulnerable** fixture used to evaluate
**ARVE** (Adaptive Remediation & Verification Engine), an academic group project
building an AI-assisted application-security platform.

It is a **ground-truth instrument**: every planted flaw is recorded, before or
while it is planted, in a machine-readable answer key so ARVE's output can be
scored for precision and recall instead of eyeballed.

It is **not**:
- a proxy for ARVE's overall capability. It only measures the Gitleaks + OSV-Scanner
  path. Never describe testbed scores as "how good ARVE is".
- a real application. The code exists only to give planted flaws a realistic home.
- a place for SQLi / XSS / SSRF / IDOR / path traversal. Those need SAST (Semgrep),
  which is not wired into ARVE yet. Planting them tests nothing and pollutes scoring.

All credentials in this repo are **synthetic, random, non-functional, correctly shaped**.

---

## 2. ARVE in one page

ARVE ingests a GitHub repository at a pinned commit, runs open-source scanners in a
locked-down Docker sandbox, and normalizes every scanner's output into one canonical
finding format. Founding rule: **tools find the evidence, AI only explains it** — an
LLM is never asked whether code is insecure, and never assigns severity.

Stack (for orientation only — you are not editing ARVE from here):
FastAPI · Python 3.12 · SQLAlchemy 2.0 · Pydantic v2 · Alembic · Neon Postgres ·
Celery + Redis · Docker sandbox · Backblaze B2 for raw artifacts · React 19 + Vite.

Main repo: `ShashwatNarayan/arve`. This repo: `ShashwatNarayan/arve-ledger-testbed`.

### The pipeline this testbed flows through

```
GitHub repo @ commit SHA
   │  Phase 2 — Ingestion (GitHub API tarball / file fetch)
   ▼
FileFilter  ──► files not allowed are stored as SKIPPED and NEVER reach a scanner
   │
   ▼
repository_files (status = INGESTED only)
   │  Phase 3 — ScanWorkspaceManager writes ONLY the INGESTED files to disk
   ▼
Workspace /code  (read-only mount, NO .git directory)
   │
   ├─► GitleaksEngine  → gitleaks.json
   └─► OsvEngine       → osv.json
   │
   ▼  Phase 4A — mappers → NormalizedFinding → security_findings table
```

**The single most important fact for this work:** ARVE's scanners never see the
repository as it exists on disk. They see the *filtered, ingested subset*, with no
Git history. A planted flaw can therefore be missed for three independent reasons,
and the answer key must let an evaluator tell them apart:

| Miss type | Cause | Whose bug |
|---|---|---|
| **Ingestion gap** | FileFilter skipped the file | ARVE Phase 2 |
| **Scanner gap** | The pinned scanner doesn't detect it | testbed plant, or scanner limitation |
| **Normalizer gap** | Detected, but mangled/collapsed/dropped in mapping | ARVE Phase 4A |

---

## 3. ARVE facts you must design against

These are taken from the ARVE codebase snapshot available to the team. ARVE is
under active development — treat them as *current behaviour to be recorded*, not
as permanent truth. Where the answer key depends on one, record it in the
`arve_pipeline` block (see §6) so it can be re-checked later.

### 3.1 Pinned scanner versions inside ARVE

| Engine | ARVE image | Command ARVE runs |
|---|---|---|
| Gitleaks | `ghcr.io/gitleaks/gitleaks:v8.24.2` | `dir /code --report-format json --report-path /output/gitleaks.json --redact` |
| OSV-Scanner | `ghcr.io/google/osv-scanner:v1.9.2` | `--format json --output /output/osv.json -r /code` |

The committed baselines in this repo were produced with **gitleaks 8.30.1** and
**osv-scanner 2.5.1**. Rules and lockfile extractors differ across versions.
**Every new plant must be verified against ARVE's pinned versions**, and
additionally against the reference versions; record both results.

Other sandbox facts: Gitleaks runs with `--network=none`; OSV runs with network
(bridge) so it can query osv.dev; containers are `--read-only`, non-root, 1 GB RAM.

### 3.2 Gitleaks runs in `dir` mode, not `git` mode

ARVE scans the materialized workspace, which has no `.git`. Consequences:
- **History-only secrets are invisible to ARVE** (e.g. `SEC-04`). That is an
  expected ARVE miss today, not a testbed bug. Keep history plants anyway — they
  document the gap and will score correctly once ARVE adds history scanning.
- `README_TEAM.md` tells humans to use `gitleaks git .`. That is correct for the
  reference baseline. ARVE's equivalent is `gitleaks dir` over the ingested subset.
  Keep both numbers.

### 3.3 The ingestion FileFilter (`backend/app/ingestion/filters/file_filter.py`)

Evaluation order for each path (normalized to `/`):

1. Any **directory** segment in: `.git node_modules venv .venv __pycache__ dist build target coverage vendor .cache .idea .vscode` → SKIPPED `ignored_directory`
2. Size > **1,048,576 bytes** → SKIPPED `file_too_large`
3. Lower-cased **filename** in the allow-list below, or path matches `^\.github/workflows/.*\.(yml|yaml)$` → INGESTED
4. Extension in the binary/media list → SKIPPED `binary_or_media_file`
5. Extension in the source allow-list → INGESTED
6. Otherwise → SKIPPED `unsupported_file_type`

Allowed filenames: `package.json package-lock.json yarn.lock pnpm-lock.yaml requirements.txt pyproject.toml pipfile pom.xml build.gradle go.mod cargo.toml dockerfile docker-compose.yml docker-compose.yaml makefile .gitignore`

Allowed extensions: `.py .js .jsx .ts .tsx .mjs .cjs .java .go .rs .c .h .cpp .hpp .php .rb .kt .swift .cs .ex .exs .scala .html .css .scss .sass .less .vue .svelte .astro .json .yaml .yml .toml .env .env.example .sql .graphql .gql .sh .bash .ps1 .md .markdown`

Binary/media extensions: `.png .jpg .jpeg .gif .svg .ico .webp .mp4 .mov .avi .mp3 .wav .zip .tar .gz .7z .rar .pdf .doc .docx .xls .xlsx .exe .dll .so .dylib .bin .woff .woff2 .ttf .eot .pyc .pyo .pyd .db .sqlite .sqlite3 .log`

Extension is computed with Python `os.path.splitext`, which produces surprises:

| Path | `splitext` ext | ARVE result |
|---|---|---|
| `.env.example` | `.example` | **SKIPPED** — the `.env.example` entry in the allow-list can never match |
| `.env` | `""` | **SKIPPED** |
| `backend/keys/webhook_signing.pem` | `.pem` | **SKIPPED** |
| `.npmrc`, `id_ed25519`, `LICENSE` | `""` | **SKIPPED** |
| `application.properties`, `main.tf`, `*.tfvars`, `*.xml` (not `pom.xml`), `*.ini`, `*.cfg`, `*.ipynb` | — | **SKIPPED** |
| `poetry.lock`, `Pipfile.lock`, `Cargo.lock`, `Gemfile.lock`, `composer.lock`, `gradle.lockfile`, `go.sum` | — | **SKIPPED** (lockfiles OSV needs!) |
| `requirements-dev.txt` | `.txt` | **SKIPPED** (only the exact name `requirements.txt` is allowed) |

Implication for the existing key: **`SEC-03` (.pem) and `SEC-08` (.env.example)
are already silently dropped by ARVE's ingestion today.** They were never
flagged because the baselines were made by running scanners directly on the repo.

Do not "fix" the testbed to dodge this. Surfacing it is exactly what this
testbed is for. Record it.

### 3.4 Normalization behaviour (Phase 4A mappers)

- Canonical severities: `CRITICAL HIGH MEDIUM LOW INFO`. GitHub `moderate` → `MEDIUM`.
  OSV severity resolution: numeric CVSS score → `database_specific` score →
  `database_specific.severity` text → `ecosystem_specific.severity` → default `MEDIUM`.
- **Gitleaks findings are hard-coded to `MEDIUM` severity** in ARVE's mapper. The
  answer key's `severity` (e.g. `HIGH` for SEC-01) is the *intended* severity; ARVE
  will currently disagree for every HIGH secret. Record, don't adjust.
- Secret identity: ARVE sets `secret_hash = Gitleaks Fingerprint`. In `dir` mode the
  Gitleaks fingerprint is `file:rule:startLine` — **line-dependent**, and because
  ARVE passes `--redact` there is no secret value to hash. So in practice:
  - a secret that moves lines looks like a new finding (SEC-06 stresses this);
  - **two different secrets matched by the same rule on the same line produce the
    same fingerprint** and may collapse into one ARVE finding.
- Dependency fingerprint: `SHA256(engine | dependency | package | ecosystem | vuln_id | file_path)`
  → the same vulnerable package in two lockfiles must be **two** findings; one
  package with two advisories must be **two** findings (DEP-05).
- Finding lifecycle states: `OPEN RESOLVED REOPENED FALSE_POSITIVE SUPPRESSED`.
- Engine names: `osv`, `gitleaks`. Finding types: `dependency`, `secret`.

---

## 4. Current repository state (before this change)

17 planted findings, all verified detected by the reference tools on 2026-08-31.

| Group | IDs | Location summary |
|---|---|---|
| Secrets (Gitleaks) | SEC-01…09 | `backend/app/config.py` (01, 05, 07), `.github/workflows/deploy.yml` (02, two findings), `backend/keys/webhook_signing.pem` (03), `backend/app/settlement.py` history-only (04), `backend/tests/conftest.py` (05 copy), `backend/app/webhooks.py` (06, moves line in history), `.env.example` (08), `docs/runbook.md` (09) |
| Dependencies (OSV) | DEP-01…08 | `backend/requirements.txt` (PyPI: PyYAML 5.1, certifi 2018.4.16 transitive) and `web/package-lock.json` (npm: lodash, follow-redirects, minimist, jquery, serialize-javascript, stringstream) |

Counts: 10 Gitleaks findings at HEAD, 12 across history; 30 OSV records
(29 planted + 1 known scanner over-match, `PYSEC-2024-230` on certifi).
History: 11 commits, rebuilt reproducibly by `seed_history.py`. SEC-04 and SEC-06
answer-key entries contain **real commit hashes** that must not change.

Key files: `expected-findings.json` (machine answer key — the one scoring uses),
`EXPECTED_FINDINGS.md` (human answer key), `README_TEAM.md` (evaluator guide),
`gitleaks-baseline.json` / `osv-baseline.json` (reference outputs, secrets redacted),
`plan.md` (original build log), `seed_history.py`.

---

## 5. Invariants — never violate these

1. **Existing IDs are frozen.** Never renumber, repurpose or delete SEC-01…09 /
   DEP-01…08. New plants continue the sequence (SEC-10+, DEP-09+). Negative
   controls use NEG-01+.
2. **Existing line numbers are frozen.** Do not edit any file that currently holds
   a plant: `backend/app/config.py`, `backend/tests/conftest.py`,
   `backend/app/webhooks.py`, `.github/workflows/deploy.yml`, `.env.example`,
   `docs/runbook.md`, `backend/keys/webhook_signing.pem`, `backend/requirements.txt`,
   `backend/requirements.in`, `web/package.json`, `web/package-lock.json`.
   New plants go in **new files**.
3. **Existing commit hashes are frozen.** New history is *appended* after the
   current 11 commits. After any rebuild, the hashes recorded for SEC-04 and SEC-06
   must be byte-identical. If `seed_history.py` cannot guarantee that, stop and ask.
4. **The answer key is written as you plant, never afterwards.** A planted but
   unrecorded flaw looks like a false positive; a recorded but unplanted one looks
   like a miss. Either invalidates the evaluation.
5. **Only plant what Gitleaks or OSV-Scanner can detect** (plus negative controls
   that must produce nothing).
6. **Never obfuscate.** Difficulty comes from *where* a flaw lives, file type,
   history, and normalizer stress — never from encoding tricks.
7. **Never use documented example credentials** (`AKIAIOSFODNN7EXAMPLE` etc.) as
   positive plants — scanners allowlist them. They are allowed only as negative controls.
8. **Every credential is synthetic.** Generate random values with the right prefix,
   length and alphabet. Never a real, rotated, expired or free-tier credential.
9. **Never commit an unredacted scanner report.** Baselines redact `Secret`/`Match`,
   because raw reports contain history-only secrets and would put them back at HEAD.
10. Each planted secret carries a comment `TESTBED SEC-NN — intentional, see EXPECTED_FINDINGS.md`
    (use the file type's comment syntax; for formats without comments, record it
    only in the answer key).

---

## 6. Answer-key conventions

Schema is additive — keep every existing field. New in this change
(`schema_version: "1.1"`):

```jsonc
{
  "id": "SEC-12",
  "engine": "gitleaks",
  "finding_type": "secret",
  "severity": "HIGH",                // intended severity
  "file_path": "web/status/styles.css",
  "file_type": "css",                // NEW: language / format label
  "line_start": 14,
  "rule_id": "mapbox-api-token",
  "history_only": false,
  "tests": "one line: what this plant exists to check",
  "notes": "detail, gotchas, substitutions made",
  "testbed": { "expected_finding_count": 1, "additional_locations": [] },
  "scanner_verification": {          // NEW
    "gitleaks_8_24_2": true,         // ARVE-pinned version
    "gitleaks_8_30_1": true          // reference version
  },
  "arve_pipeline": {                 // NEW — present on EVERY finding, incl. SEC-01…DEP-08
    "ingestion": "INGESTED",         // or "SKIPPED"
    "skip_reason": null,             // ignored_directory | file_too_large | unsupported_file_type | binary_or_media_file
    "reaches_scanner": true,         // false if skipped OR history_only
    "expected_arve_detected": true,
    "known_arve_divergence": null    // e.g. "severity MEDIUM (mapper hard-codes)", "collapses with SEC-18"
  }
}
```

Negative controls live in a separate top-level array `negative_controls` with
`id`, `file_path`, `what`, `why_it_must_not_fire`, and verification results.
If a pinned scanner *does* fire on one, move it to `known_false_positives` with the
reason — that is still valuable precision data.

Add a top-level `coverage_matrix` summarising plants by file type × engine ×
ingestion status, and update every aggregate count (`planted_finding_count`,
expected Gitleaks findings at HEAD / across history / via ARVE ingestion,
expected OSV records) so nothing in the key is stale.

---

## 7. Hard-won planting gotchas (from the original build)

- `generic-api-key` needs the **keyword and value on the same line**. Wrapped
  assignments are silently undetected.
- AWS key IDs must use the real base32 alphabet (`A–Z`, `2–7`). `0 1 8 9` → undetected.
- Generic rules apply entropy thresholds and stop-word allow-lists; low-entropy or
  word-like random values can silently miss. **Run the scanner on every plant as you
  make it**, never at the end.
- The osv.dev query API can return advisories whose affected range excludes the
  version. Re-check every advisory against its own ranges.
- A vulnerable package carries **every** advisory published against it. Prefer
  packages with few advisories so expected counts are unambiguous, and record the
  full inventory, not just the target advisory.
- OSV reports Go **stdlib** advisories derived from the `go` directive in `go.mod`.
  Either pin a current toolchain version or record them in the inventory.
- OSV may normalize version strings (`5.1` → `5.1.0` for PyPI). Record it.
- OSV reads **lockfiles**, not manifests (`package.json`, `build.gradle`,
  `Cargo.toml` alone produce nothing). Maven `pom.xml` is read directly.
- Lockfiles should be genuine package-manager output. If a toolchain is unavailable,
  a hand-authored minimal lockfile is acceptable **only** if the pinned OSV version
  parses it — record `"lockfile_origin": "hand-authored"` in notes.
- Keep every clean support package at **zero** advisories (noise floor = 0).
- GitHub **push protection / secret scanning** may block pushing real-shaped tokens
  (GitHub PATs, Slack, npm, Stripe…). Bypass per secret as "used in tests", or
  disable push protection for this repo. ARVE ingests from GitHub, so the push must
  succeed with every file intact.

---

## 8. Scope boundaries for this repo

In scope: new secret plants across many file types, new dependency plants across
ecosystems and lockfile formats, negative controls, normalizer-stress plants,
appended history, verification tooling, documentation.

Out of scope (do not do from this repo): SAST-class flaws; changes to ARVE itself
(fixing its FileFilter, history scanning or fingerprinting belongs in the `arve`
repo — the testbed's job is to *expose* those gaps); making the app feature-rich.
Satellite services added for new file types are **stubs** — plausible, small,
not required to build (the existing `backend/` must still run).
