# Build plan — `arve-ledger-testbed`

Working plan for constructing the deliberately vulnerable payments-ledger testbed
described in `NEW_PROJECT_START_README.md`. Five phases, executed in order.

**Status:** ✅ **complete** — all five phases done, 16/16 definition-of-done items met
**Superseded by:** the [v1.1 expansion](#v11-expansion--arve-pipeline-coverage) at the end of this file, which takes the testbed from 17 to 47 findings and adds ARVE pipeline attribution
**Dependency verification date:** 2026-08-31 (every version queried live against the
osv.dev API — see Phase 2)

---

## Guardrails (apply to every phase)

1. **The app stays trivially simple.** Seven endpoints, ~15 source files, SQLite,
   no auth. If a feature isn't in the spec's feature list, it doesn't get built.
2. **Only plant what Gitleaks or OSV-Scanner can detect.** No SQLi, XSS, path
   traversal, SSRF, or access-control bugs. Semgrep isn't wired up; planting those
   would test nothing and would pollute the results with flaws the engine cannot
   possibly report.
3. **Never obfuscate.** These are exact-match detectors, not analyzers. Difficulty
   comes from *where* things live, from *Git history*, and from stressing ARVE's own
   normalizer — never from cleverness.
4. **The answer key is written as we go, never afterwards.** Every plant is recorded
   in `EXPECTED_FINDINGS.md` and `expected-findings.json` in the same step that
   plants it. A documented-but-unplanted or planted-but-undocumented finding
   invalidates the whole evaluation.
5. **Every credential is synthetic, random, and non-functional** — but correctly
   shaped. No famous documented examples (`AKIAIOSFODNN7EXAMPLE` and friends are
   allowlisted by scanners by default and would produce a silent miss that looks
   like a scanner bug).

---

## Phase 1 — Application skeleton

Build the whole app with **zero planted findings**. This is the clean base that
commit 1 of the seeded history represents.

### Deliverables

| Path | Purpose |
|---|---|
| `README.md` | Prominent intentional-vulnerability warning, what ARVE is, how to run, pointer to `EXPECTED_FINDINGS.md`, explicit "all credentials are synthetic" statement |
| `backend/app/main.py` | FastAPI app factory, DB init |
| `backend/app/config.py` | Settings (secrets land here in Phase 3) |
| `backend/app/models.py` | SQLite schema: `accounts`, `ledger_entries` |
| `backend/app/ledger.py` | Double-entry core: debit/credit row pairs, balance calculation |
| `backend/app/api.py` | The seven routes |
| `backend/app/webhooks.py` | HMAC signature verification |
| `backend/tests/conftest.py` | Test fixtures |
| `web/index.html` | One static page |
| `web/src/main.js` | Calls two endpoints |
| `docs/runbook.md` | Ops notes |
| `.env.example` | Config template |
| `.github/workflows/deploy.yml` | CI workflow |
| `.gitignore` | Standard |

### The seven endpoints — this is the entire feature list

1. `POST /accounts` — create an account
2. `POST /accounts/{id}/deposit` — deposit funds
3. `POST /accounts/{id}/withdraw` — withdraw funds
4. `POST /transfers` — transfer between two accounts (writes debit + credit rows)
5. `GET /accounts/{id}/balance` — get balance
6. `GET /accounts/{id}/transactions` — list transactions
7. `POST /webhooks/provider` — receive provider webhook, verify HMAC signature

The webhook handler exists specifically to give signing secrets a *realistic reason*
to be in the codebase.

**Done when:** the backend starts, all seven endpoints respond correctly, and the
static page successfully calls two of them.

---

## Phase 2 — Dependency findings (DEP-01 … DEP-08)

Write both lockfiles at nested paths, and record all eight findings in the answer key
in the same step.

### Verified versions

Every version below was queried against the live osv.dev API on **2026-08-31**. The
spec's candidate list was checked and only partly adopted: `axios@0.21.0` now carries
25 advisories and `urllib3@1.24.1` carries 22 — mostly 2026 CVEs, still growing —
which would drown the answer key. Lower-noise packages hitting the same stress points
were substituted.

#### PyPI — `backend/requirements.txt` (pip-compile style, `# via` annotations)

| ID | Package | Target advisory | Severity | Records | Stresses |
|---|---|---|---|---|---|
| DEP-01 | `PyYAML==5.1` | GHSA-3pqx-4fqf-j49f / CVE-2019-20477 | CRITICAL | 6 | direct-dependency baseline |
| DEP-02 | `certifi==2018.4.16` | GHSA-xqr8-7jwr-rhp7 / CVE-2023-37920 | HIGH | 4 | transitive only — `# via httpx, httpcore` |

#### npm — `web/package.json` + `web/package-lock.json`

Genuine npm-resolved lockfileVersion 3, 8 entries total.

| ID | Package | Target advisory | Severity | Records | Stresses |
|---|---|---|---|---|---|
| DEP-03 | `lodash@4.17.11` (direct) | GHSA-p6mc-m468-83gw / CVE-2020-8203 | HIGH | 7 | second-ecosystem baseline |
| DEP-04 | `follow-redirects@1.14.7` | GHSA-pw2r-vq6v-hr8c / CVE-2022-0536 | MEDIUM | 4 | **lockfile-only** — reachable only through `http-proxy` |
| DEP-05 | `minimist@1.2.0` (dev) | GHSA-vh95-rmgr-6w4m **and** GHSA-xvch-5gv4-984h | MEDIUM + CRITICAL | exactly 2 | fingerprint uniqueness per (package, advisory) — must produce **two** findings, not one |
| DEP-06 | `jquery@3.3.1` (direct) | GHSA-6c3j-c64m-qhgq / CVE-2019-11358 | MEDIUM | 3, **all `moderate`** | `normalize_severity` — GitHub `moderate` to canonical `MEDIUM` |
| DEP-07 | `serialize-javascript@2.1.2` (dev) | GHSA-5c6j-r48x-rmvq | HIGH | 2 | **no CVE alias** — `ghsa` must populate, `cve` must stay null |
| DEP-08 | `stringstream@0.0.5` (dev) | GHSA-mf6x-7mm4-x2g7 / CVE-2018-21270 | MEDIUM | 1 | `"severity": []` — no CVSS vector at all; the fallback must not crash or emit null |

**Corrections made during Phase 2**, after re-checking every advisory against its own
affected ranges rather than trusting the osv.dev query endpoint:

- `http-proxy@1.18.1` is **not vulnerable** — GHSA-6x33-pw7p-hmpq is fixed in exactly
  that version. It was kept in the tree as the deliberately *clean* parent for DEP-04,
  and DEP-07 moved to `serialize-javascript@2.1.2`.
- `CVE-2022-0155` is **fixed in follow-redirects 1.14.7**, so DEP-04's target moved to
  CVE-2022-0536.
- `requests` cannot be DEP-02's parent — modern versions pin `certifi>=2023.5.7`.
  `httpx`/`httpcore` leave certifi unconstrained, so they are the parents instead, and
  `requests` was dropped from the project entirely (nothing imported it).

### Two things to be honest about

**DEP-08 is not a perfect null-severity case.** No *standalone* OSV record exists with
neither a CVSS vector nor a GitHub severity string. Records with zero severity signal
are all `PYSEC-*` / `MAL-*` entries, and those always sit in an alias group beside a
GHSA that *does* carry CVSS — which makes the expected answer ambiguous, since it
depends on whether ARVE normalizes per-record or per-group. `stringstream@0.0.5` is
the cleanest unambiguous option: one record, no alias siblings, empty `severity`
array, only `database_specific.severity: "MODERATE"` to fall back on. The alternative,
if the harder ambiguous case is wanted, is `wheel==0.37.0` (PYSEC-2022-43017, genuinely
no severity fields), documenting both acceptable outcomes.

**The noise floor is deliberately zero — verified, not assumed.** All 24 support
packages across both trees were queried individually and return **0 advisories**.
OSV-Scanner should report exactly 8 packages / **29 records**, every one of them
planted. This *will* drift as new CVEs land, so the answer key carries a
`verified 2026-08-31` stamp and lists the full inventory for diffing.

**Done when:** both lockfiles exist at nested paths and all 8 DEP entries are written
into both answer-key files with real package, version, GHSA, CVE, and severity values.

---

## Phase 3 — Secret findings (SEC-01 … SEC-09)

Generate synthetic credentials and plant them. Record each in the answer key as it is
planted. History behaviour for SEC-04 and SEC-06 is set up here but only *realized* in
Phase 4.

| ID | Shape | Gitleaks rule targeted | Location | Stresses |
|---|---|---|---|---|
| SEC-01 | `sk_live_` + 24 random alphanumerics | `stripe-access-token` | `backend/app/config.py` | baseline at HEAD — if this is missed, the pipeline is broken |
| SEC-02 | `AKIA` + 16 random uppercase alphanumerics, plus a 40-char secret access key | `aws-access-token` + `generic-api-key` | `.github/workflows/deploy.yml` | non-Python path; workflow YAML is sometimes skipped by path filters |
| SEC-03 | real `openssl genrsa 2048` throwaway key | `private-key` | `backend/keys/webhook_signing.pem` | a distinct rule class from token regexes |
| SEC-04 | SFTP password, high entropy | `generic-api-key` | `backend/app/settlement.py` — **added commit 3, deleted commit 7** | **Git history scanning** — absent from the working tree, still in history |
| SEC-05 | identical value in two files | `generic-api-key` | `backend/app/config.py` **and** `backend/tests/conftest.py` | **fingerprint behaviour** — one finding or two? Whatever ARVE does must be deliberate |
| SEC-06 | webhook secret that **moves line** in commit 6 | `generic-api-key` | `backend/app/webhooks.py` | **line-independent `secret_hash` identity** — must report the *same* finding, not resolve-and-reopen |
| SEC-07 | 64-char base64url, no vendor prefix | entropy rule | `backend/app/config.py` as `LEDGER_HMAC_KEY` | entropy path rather than a named-vendor regex |
| SEC-08 | real-shaped vendor key | vendor rule | `.env.example` | ambiguous by design — `FALSE_POSITIVE` / `SUPPRESSED` lifecycle |
| SEC-09 | `https://hooks.slack.com/services/T…/B…/…` | `slack-webhook-url` | `docs/runbook.md` | Markdown, non-code path |

Each planted secret carries a `# TESTBED SEC-0N — intentional, see EXPECTED_FINDINGS.md`
comment. Gitleaks ignores comments entirely, so this keeps the repository honest for
human readers at zero cost to detection.

### Two shape constraints found by running gitleaks during planting

Both produced plants that were **silently undetectable** — the exact failure this
testbed exists to avoid:

1. **`generic-api-key` requires the keyword and value on the same line.** SEC-07 was
   first written as a three-line wrapped assignment and was not detected at all.
2. **AWS key IDs must use the real base32 alphabet (`A-Z`, `2-7`).** Gitleaks rejects
   any `AKIA...` value containing `0`, `1`, `8` or `9`, at any entropy. Only 4 of 40
   naively-random candidates were detected; 30 of 30 base32-alphabet candidates were.

Result: 9 planted secrets produce **10** gitleaks findings at HEAD (SEC-02 and SEC-05
each yield two; SEC-04 is history-only). An earlier revision of this line said 11.

`backend/app/settlement.py` exists only in history and does not count against the
~15-file budget.

**Done when:** all nine secrets are planted with correctly shaped random values, each
carries its ID comment, and all nine are recorded in both answer-key files.

---

## Phase 4 — Git history

Write `seed_history.py`, commit it, and run it. Commit messages must read like ordinary
development — `"add nightly settlement file transfer"`, never `"add vulnerable password"`.

### Required commit sequence

**As built — 13 commits, dated across three weeks** (an earlier revision of this line said 11):

| # | Commit | Contains |
|---|---|---|
| 1 | initial project skeleton | clean — no planted findings |
| 2 | add double-entry ledger core and the seven endpoints | — |
| 3 | pin backend dependencies with pip-compile | DEP-01, DEP-02 |
| 4 | add nightly settlement file transfer | **SEC-04 enters** |
| 5 | add operator console with dev proxy | DEP-03 … DEP-08 |
| 6 | add provider webhook handler with signature verification | **SEC-06 at line 43**, SEC-03 |
| 7 | hoist webhook module constants to the top of the file | **SEC-06 moves to line 22** |
| 8 | clean up settlement config, the transfer moved to the platform job | **SEC-04 deleted** |
| 9 | use staging credentials as local fallbacks | SEC-01, SEC-05, SEC-07, SEC-08 |
| 10 | add deploy workflow and on-call runbook | SEC-02, SEC-09 |
| 11 | document the planted findings and how the testbed was built | answer keys |

The sequence was split finer than the spec's eight steps because real history has
more commits, not fewer — separating "pin dependencies" from "add ledger core", and
"add credentials" from "add workflow", reads like ordinary work rather than a fixture.

### Script design

`seed_history.py` stages real working-tree files for everything that is added once and
never changed. Only two artifacts evolve across commits, so only those are embedded in
the script as constants:

- `backend/app/webhooks.py` **v1** (SEC-06 at its pre-refactor line)
- `backend/app/settlement.py` (does not exist at HEAD)

This keeps the real source files as the single source of truth while still making the
add-then-delete and the line-move fully reproducible from a clean checkout.

### The trap in writing this script

SEC-04's password could not be embedded as a literal. Doing so would put it back **at
HEAD** inside `seed_history.py`, where a working-tree scan would find it — destroying
the one finding whose entire purpose is to be history-only. The build script would have
silently broken the test it exists to create.

It is therefore **derived deterministically from a fixed seed**. The history stays
reproducible, the literal exists only inside the commits where it belongs, and in those
commits it is plain text that Gitleaks matches normally. SEC-06 has no such problem — it
legitimately lives at HEAD — so the script reads it back out of the working tree, which
also stops the script drifting out of sync with the planted value.

**Done when:** `git log` reads like ordinary development, SEC-04 is absent from the
working tree but present in history, and SEC-06 sits at a different line than it did
when introduced.

---

## Phase 5 — Verification and reference baselines

### Tooling

**Done in Phase 3, earlier than planned.** Both binaries were downloaded to the session
scratchpad (nothing installed, no PATH changes): **gitleaks 8.30.1** and
**osv-scanner 2.5.1**. Pulling gitleaks forward proved its worth immediately — it caught
two planted secrets that were silently undetectable (see Phase 3 notes).

### Steps

1. **Verify every line number in the answer key** against the final commit. Refactors
   move lines; the numbers recorded during Phases 2–3 are provisional until checked here.
2. Run the reference scanners:

   ```bash
   gitleaks detect --source . --report-path gitleaks-baseline.json
   osv-scanner scan source --recursive . --format json --output osv-baseline.json
   ```

3. **Commit both baseline reports.** They are what separates the two failure modes:
   - the reference tool **also** missed it → the testbed is wrong, fix the plant
   - the reference tool **caught** it but ARVE did not → ARVE has a real bug
4. **Report every planted finding the reference tools themselves missed**, with an
   assessment of why. Most likely candidate: SEC-08 in `.env.example`, which Gitleaks
   may allowlist by path or filename — that ambiguity is the whole point of SEC-08, but
   it has to be documented now rather than discovered during evaluation.
5. Validate that `expected-findings.json` parses and every field is populated.

---

## Definition of done

- [ ] Backend runs locally and all seven endpoints work
- [ ] `web/` has a lockfile and the page calls at least two endpoints
- [ ] Both lockfiles committed at nested paths (`backend/`, `web/`)
- [ ] All nine `SEC-*` findings planted
- [ ] All eight `DEP-*` findings planted, each verified against osv.dev
- [ ] `seed_history.py` reproduces the required commit sequence
- [ ] SEC-04 absent from the working tree, present in history
- [ ] SEC-06 at a different line than when introduced
- [ ] `EXPECTED_FINDINGS.md` documents all 17 findings
- [ ] `expected-findings.json` validates and every field is populated
- [ ] Line numbers verified accurate at the final commit
- [ ] Root `README.md` carries the intentional-vulnerability warning
- [ ] `git log` reads like ordinary development
- [ ] `gitleaks-baseline.json` and `osv-baseline.json` committed
- [ ] Any reference-tool miss reported and explained

---

## Open decisions

1. **DEP-08 package choice** — shipped as `stringstream@0.0.5` (unambiguous, expects
   MEDIUM). Still swappable for `wheel==0.37.0` if the harder ambiguous case is wanted.
2. ~~**Scanner installation**~~ — resolved: scratchpad binaries, gitleaks 8.30.1 and
   osv-scanner 2.5.1. Nothing installed on the host.

## Outcome

Both reference scanners detect **all 17 planted findings**. No planted finding was
missed by its reference tool, so there is no known gap between what is documented and
what is detectable.

Three plants were silently undetectable when first written and were caught only because
the scanners were run *during* planting rather than after — see the baseline section of
`EXPECTED_FINDINGS.md`.

---

# v1.1 expansion — ARVE pipeline coverage

**Status:** ✅ complete. 47 planted findings (up from 17), 6 negative controls,
3 recorded scanner limitations, verified against all four scanner versions on
**2026-09-22**.

## What changed, and why

v1.0 answered *"can the scanners find it?"*. Every plant sat in a file type the
scanners were already known to read, and the answer key recorded what a scanner
finds **on disk**.

That is not what ARVE scans. ARVE ingests a repository through a `FileFilter`,
writes only the allowed files to a workspace, and scans that workspace **with no
`.git` directory**. So a plant can be missed for three unrelated reasons, and
v1.0 could not tell them apart:

| Miss type | Cause | Whose bug |
|---|---|---|
| Ingestion gap | the filter skipped the file | ARVE Phase 2 |
| Scanner gap | the pinned scanner does not detect it | testbed or scanner |
| Normalizer gap | detected, then collapsed or mangled | ARVE Phase 4A |

v1.1 makes that distinction the point of the fixture. Every finding now carries
an `arve_pipeline` block, and the plants are chosen so that each gap is isolated
by a **control pair** — two plants identical in every respect except the one
being tested.

## The control pairs

| Pair | Identical | Differs | Isolates |
|---|---|---|---|
| SEC-03 / **SEC-18** | `private-key` rule, real key | `.pem` vs `.yaml` | extension allow-list |
| SEC-20 / **SEC-26** | `.sh`, vendor rule | `ops/scripts/` vs `ops/build/` | ignored-directory filter |
| SEC-15 / **SEC-17** | no file extension at all | `.npmrc` vs `Dockerfile` | filename allow-list |
| DEP-05 / **DEP-19** | minimist 1.2.0, same advisories | different lockfiles | `file_path` in the fingerprint (works) |
| **DEP-19** / **DEP-20** | same lockfile machinery | two files vs two versions | version missing from the fingerprint (broken) |
| SEC-22 / **SEC-23** | `generic-api-key` | 2 secrets 1 line vs 1 secret 3 files | `secret_hash` identity, in both directions |

## Phases

| Phase | Work | Outcome |
|---|---|---|
| 0 | Recon: scanner images, rebuild determinism, candidate verification | 8 of 32 candidate rows changed before anything was planted |
| 1 | Schema 1.1 on all 17 existing findings | ingestion status computed, not guessed |
| 2 | `SEC-10` … `SEC-27` | 18 secrets, 15 file types, 4 ingestion gaps |
| 3 | `DEP-09` … `DEP-20` | 12 dependencies, 6 new ecosystems, 5 ingestion gaps |
| 4 | `NEG-01` … `NEG-06` | all silent in all four scanner versions |
| 5 | Appended history + SEC-27's rotation | commits 1–10 byte-identical on rebuild |
| 6 | `verify_plants.py`, baselines, docs | counts are computed, not hand-maintained |

## What Phase 0 changed before a single plant was made

Verifying candidates first, against the real scanners and the live osv.dev API,
rejected a third of the proposed matrix:

- **`lodash 4.17.21` is not patched.** It was proposed as the "clean version"
  negative control and still carries **3** live advisories. It would have been a
  control that quietly expected findings. Replaced with `4.18.1` (0 advisories,
  registry hash verified).
- **`axios` carries 29–30 advisories** at both proposed versions, `log4j-core
  2.14.1` carries 7, `guzzlehttp/psr7` 6, `jinja2 3.1.4` 6. All replaced with
  1–2 record packages so expected counts are unambiguous.
- **A Mapbox token in a URL does not match `mapbox-api-token`** — the rule needs
  the literal word `mapbox` immediately before the `=`. Recorded as `LIM-01`.
- **A Google API key followed by `&` matches no rule at all.** Google's own
  documented `?key=…&callback=…` order is invisible to gitleaks. Recorded as
  `LIM-02`; the plant puts the key last so it is detectable.
- **Maven resolves transitively over the network** in both OSV versions, so
  commons-text 1.9 dragged in a vulnerable `commons-lang3 3.11`. Pinned to
  3.20.0 in `dependencyManagement` to hold the noise floor at zero.

## Two bugs found in the testbed's own tooling

**`seed_history.py` could never re-stamp a commit hash.** Its substitution
pattern contained two literal **backspace bytes** (0x08) where the source should
have read `\b`. Terminals erase the preceding character when printing a
backspace, so every listing of the file — including `inspect.getsource` — showed
a correct-looking regex. The pattern matched nothing, the rewrite silently did
nothing, and the function returned `False` while still printing the mappings it
had computed. Present since the original build and never noticed, because the
rewrite only runs when a quoted hash actually changes — which first happens with
SEC-27.

**Hand-maintained counts had drifted.** The commit count appeared as 11, 12 and
13 in different files; the `HEAD` finding count as both 10 and 11. Fixed, and
made structurally impossible to repeat: `scripts/verify_plants.py` is now the
single source of truth and prints every number the documents quote.

## Reproducibility, stated precisely

A `--force` rebuild reproduces **commits 1–10 byte-identically** — the range
holding every hash the answer key quotes (SEC-04's add/delete, SEC-06's
introduce/move, and the two baseline commits). Verified by rebuilding a scratch
clone and diffing. Commits 11 onward stage files this project keeps editing, so
their hashes move; SEC-27's two commits sit there and are re-stamped
automatically.

Two things are load-bearing and were found by testing, not assumption:

1. `core.autocrlf` is pinned to `input` by the script. With it off, every blob
   and therefore every hash changes.
2. The commit-1 `README.md` blob is embedded in the script. Reading it from the
   working tree meant that editing the README rewrote commit 1 and every hash
   after it — which Phase 6 would have done.

## Out of scope, unchanged

No SAST-class flaws, no allowlist or `.gitleaksignore` files, no edits to files
holding existing plants, no rewriting of existing commits, and **no changes to
ARVE itself** — the gaps are documented in `ARVE_ISSUES.md` for filing against
the ARVE repository, with evidence and scoring impact but no proposed fixes.
