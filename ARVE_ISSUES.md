# ARVE issues — evidence from the testbed

Four issue-ready writeups to file against `ShashwatNarayan/arve`. Each is
**evidence only**: observed behaviour, the code path it comes from, the testbed
finding that demonstrates it, and what it does to scoring. **No fixes are
proposed here, and no ARVE change is made from this repository** — the
testbed's job is to expose the gap, not to close it.

Scope: everything below concerns the Gitleaks + OSV-Scanner path only. Nothing
here says ARVE is wrong to behave this way; several of these are deliberate
trade-offs. What matters is that each one is *known*, and that its effect on a
score is understood before anyone reads a number off this testbed.

| # | Title | ARVE phase | Plants affected today |
|---|---|---|---|
| [1](#issue-1) | Ingestion `FileFilter` silently drops secret-bearing files and most lockfiles | Phase 2 | SEC-03, SEC-08 (+9 planned in v1.1) |
| [2](#issue-2) | Gitleaks runs in `dir` mode, so Git history is unreachable | Phase 3 | SEC-04, SEC-06 |
| [3](#issue-3) | `secret_hash` is the line-dependent dir-mode fingerprint | Phase 4A | SEC-06, SEC-22, SEC-27 |
| [4](#issue-4) | Dependency fingerprint omits the package version | Phase 4A | DEP-20 |

Versions this was measured against: ARVE-pinned **gitleaks 8.24.2** and
**osv-scanner 1.9.2**, reference **gitleaks 8.30.1** and **osv-scanner 2.5.1**,
all run from the official images on **2026-09-22**. ARVE behaviour is quoted
from the codebase snapshot recorded in `PROJECT_CONTEXT.md` §3; if ARVE has
moved on, re-check before filing.

---

<a id="issue-1"></a>

## Issue 1 — Ingestion `FileFilter` silently drops secret-bearing files and most lockfiles

### Observed behaviour

Files are marked `SKIPPED` at ingestion and never written to the scan
workspace, so no scanner ever sees them. There is no finding, and no signal in
the output that anything was withheld — a skipped file and a clean file look
identical downstream.

Three distinct causes, all confirmed against the current testbed with
`scripts/arve_filter_mirror.py` (a mirror of the filter, which may drift):

**(a) `.pem` is not in the extension allow-list.** Private key files —
arguably the highest-value secret a repository can contain — are dropped as
`unsupported_file_type`.

**(b) `os.path.splitext` makes two allow-list entries unreachable.** The
extension allow-list contains `.env` and `.env.example`, but the extension is
computed with `os.path.splitext`, which returns:

| Path | `splitext` extension | Result |
|---|---|---|
| `.env.example` | `.example` | SKIPPED — the `.env.example` entry can never match |
| `.env` | `""` (whole name is the stem) | SKIPPED — the `.env` entry can never match |
| `.npmrc`, `id_ed25519`, `LICENSE` | `""` | SKIPPED |

Both entries were presumably added *intending* to ingest these files. Neither
can ever fire. A reader of the allow-list would reasonably conclude the
opposite of what happens.

**(c) Most lockfiles are not in the filename allow-list.** The allow-list
covers `package-lock.json`, `yarn.lock`, `pnpm-lock.yaml`, `requirements.txt`,
`go.mod`, `pom.xml` and a few others, but not:

`poetry.lock` · `Pipfile.lock` · `Cargo.lock` · `Gemfile.lock` ·
`composer.lock` · `gradle.lockfile` · `go.sum` · `requirements-dev.txt`

OSV-Scanner reads **lockfiles**, not manifests. Ingesting `Cargo.toml` while
skipping `Cargo.lock` means the Rust ecosystem is scanned as though it were
empty. `requirements-dev.txt` is a near-miss of a different kind: the
filename allow-list is an exact match against `requirements.txt`, so every
`requirements-*.txt` variant is skipped — **osv-scanner v1.9.2 parses those
filenames perfectly well**, so this is purely an ingestion loss.

### Code path

`backend/app/ingestion/filters/file_filter.py` → `FileFilter.evaluate()`, steps
3–6 (filename allow-list → binary/media extensions → source extension
allow-list → `unsupported_file_type`). Skipped files are stored with
`status = SKIPPED` and never reach `ScanWorkspaceManager`, so they are absent
from `/code`.

### Testbed evidence

Already in the repository:

| Plant | File | Filter verdict | ARVE findings | Reference gitleaks |
|---|---|---|---|---|
| **SEC-03** | `backend/keys/webhook_signing.pem` | SKIPPED `unsupported_file_type` | **0** | 1 (`private-key`) |
| **SEC-08** | `.env.example` | SKIPPED `unsupported_file_type` | **0** | 1 (`sendgrid-api-token`) |

Measured: `gitleaks dir` over the full tree reports **10** findings; over the
ingested subset only, it reports **8**. Both pinned and reference versions
agree, so this is not a scanner-version artifact.

The v1.1 expansion adds plants that isolate each remaining cause — a
`.properties` file, a `.npmrc`, a `.tf` file, an oversized JSON fixture, a file
under `ops/build/`, and five lockfiles (`gradle.lockfile`, `Cargo.lock`,
`poetry.lock`, `requirements-dev.txt`, `Gemfile.lock`) whose contents
osv-scanner v1.9.2 has been confirmed to parse when it is allowed to see them.

### Scoring impact

Recall is computed against plants that **cannot** be found, so ARVE is penalised
for a Phase 2 decision rather than a detection failure. With v1.1 in place,
roughly a third of the secret plants and five of the twelve new dependency
lockfiles are invisible — enough to dominate a recall number and make it
meaningless as a measure of the scanner path.

The second-order effect matters more: a skipped file is indistinguishable from
a clean file in ARVE's output, so a user of ARVE cannot tell that the `.pem` in
their repository was never examined. Whatever is decided about the allow-list,
**the absence of any "skipped" signal in the finding output is the part that
misleads**.

---

<a id="issue-2"></a>

## Issue 2 — Gitleaks runs in `dir` mode, so Git history is unreachable

### Observed behaviour

ARVE materialises only the ingested files into `/code` and runs
`gitleaks dir /code`. The workspace has no `.git` directory, so secrets that
were committed and later deleted are invisible. A credential that was pushed to
GitHub is compromised until rotated, regardless of whether a later commit
removed the file — ARVE currently reports nothing for exactly that case.

This is a deliberate architecture consequence (ingestion fetches files, not a
clone), not a bug in the engine wrapper. Filing it so the limitation is recorded
against the scoring model rather than discovered during an evaluation.

### Code path

`PROJECT_CONTEXT.md` §3.1–3.2: the Gitleaks engine runs
`dir /code --report-format json --report-path /output/gitleaks.json --redact`.
Phase 3 `ScanWorkspaceManager` writes only `INGESTED` files to the read-only
workspace; nothing clones the repository.

### Testbed evidence

**SEC-04** — an SFTP password in `backend/app/settlement.py`, added in commit
`5f9ec864` and deleted in `5c1f6a8f`. The file does not exist at `HEAD`.

Measured, both gitleaks versions:

| Scan | Findings for `settlement.py` |
|---|---|
| `gitleaks git` over the repository | **1**, at line 16 in commit `5f9ec864` |
| `gitleaks dir` at `HEAD` (what ARVE does) | **0** |

**SEC-06** is the same gap seen from the other side: the webhook secret moves
from line 43 to line 22 between two commits, with a byte-identical value. ARVE
only ever sees line 22, so the lifecycle behaviour SEC-06 exists to test —
does the finding stay `OPEN` across a refactor — is never exercised. The plant
is not miscounted; it is simply untestable today.

Totals: **12** findings across history, **10** at `HEAD`, **8** after ingestion.

### Scoring impact

One plant (SEC-04) is permanently unrecoverable, and the two most interesting
lifecycle tests in the suite (SEC-06 today, SEC-27 in v1.1) degrade from
"tests fingerprint stability" to "not applicable". Any recall figure quoted
from this testbed must say which of the three numbers above it used, or it is
not reproducible.

---

<a id="issue-3"></a>

## Issue 3 — `secret_hash` is the line-dependent dir-mode fingerprint

### Observed behaviour

ARVE sets `secret_hash` to the Gitleaks `Fingerprint`. In `dir` mode that
fingerprint is `file:rule:startLine` — it contains **no part of the secret
value**, because ARVE also passes `--redact`, which removes the value from the
report entirely.

Two consequences follow, in opposite directions:

**(a) Different secrets collide.** Two distinct secrets matched by the same rule
on the same line produce the *same* fingerprint and are liable to collapse into
one finding.

**(b) The same secret, changed, does not.** Conversely, a secret that is
*rotated in place* — same file, same line, new value — keeps the same
fingerprint, so a replaced credential looks like the same, still-open finding,
and a rotation is never observed. Moving a secret to a different line, by
contrast, produces a new fingerprint and looks like a new leak.

### Code path

`PROJECT_CONTEXT.md` §3.4: `secret_hash = Gitleaks Fingerprint`; the engine runs
`dir` with `--redact`. In `dir` mode gitleaks builds the fingerprint as
`file:rule:startLine` (in `git` mode it is
`commit:file:rule:startLine`, which is equally line-dependent).

### Testbed evidence

**SEC-22** (planted in v1.1) is built for exactly this. Two *different*
synthetic credentials, both matched by `generic-api-key`, on **one line** of
`tools/sync_keys.py`:

```
ROTATION = {"primary_api_key": "<secret A>", "secondary_api_key": "<secret B>"}
```

Measured on a scratch copy, both gitleaks versions report **two findings** with
**identical fingerprints**:

```
generic-api-key  tools/sync_keys.py:2  col 15   fingerprint: tools/sync_keys.py:generic-api-key:2
generic-api-key  tools/sync_keys.py:2  col 78   fingerprint: tools/sync_keys.py:generic-api-key:2
```

The only field distinguishing them is `StartColumn`, which ARVE's
`NormalizedFinding` does not carry — and which is independently unreliable on
long lines (see `EXPECTED_FINDINGS.md`, LIM-03). So ARVE has no field with which
to tell the two credentials apart. Expected result: **two leaked credentials,
one finding, one rotation** — the second credential is silently dropped.

**SEC-27** (planted in v1.1) demonstrates (b): a New Relic key in
`services/notifier-rust/notifier.toml` whose value is *changed in place* in a
later commit. Reference `gitleaks git` reports two findings (old value and new).
ARVE sees one file at `HEAD`, one line, one fingerprint — a single finding that
stays `OPEN` across the rotation and never registers that the credential
changed.

**SEC-06** is the existing, milder case: same value, line 43 → line 22. If ARVE
ever gains history scanning without changing this field, that plant will
resolve-and-reopen on a secret that was never fixed and never re-leaked.

### Scoring impact

Precision and recall both distort, in ways that partly cancel and therefore hide
each other. SEC-22 costs one true positive (a real credential is never
reported). SEC-27 produces a finding whose lifecycle is wrong rather than a
miscount — the worst kind for a remediation tool, because the finding looks
healthy.

More broadly, `--redact` plus a line-based fingerprint means **no ARVE finding
identity is derived from the secret itself**. Any future dedupe-by-credential
behaviour (the design question SEC-05 poses, where either answer is defensible)
cannot be implemented from the data currently stored.

---

<a id="issue-4"></a>

## Issue 4 — Dependency fingerprint omits the package version

### Observed behaviour

The dependency fingerprint is

```
SHA256(engine | dependency | package | ecosystem | vuln_id | file_path)
```

The **version is not an input**. When one lockfile legitimately contains two
different versions of the same package, and one advisory covers both, the two
records produce an identical fingerprint and collapse into a single finding.

This is the mirror image of a property the answer key relies on elsewhere:
because `file_path` *is* an input, the same package+version in two lockfiles
correctly produces two findings (DEP-19 tests that, and it works).

### Code path

`PROJECT_CONTEXT.md` §3.4, dependency fingerprint definition; OSV mapper,
Phase 4A.

### Testbed evidence

**DEP-20** (planted in v1.1). A single genuine pnpm lockfile,
`apps/partner-webhooks/pnpm-lock.yaml`, containing two versions of `minimist`:
`1.2.5` as a direct dependency, and `0.0.8` pinned exactly by `mkdirp@0.5.1`
(a real, advisory-free parent). Measured with **both** osv-scanner versions:

| Package | Version | Advisory | Fingerprint inputs identical? |
|---|---|---|---|
| minimist | 0.0.8 | GHSA-vh95-rmgr-6w4m | — (only 0.0.8 is affected) |
| minimist | **0.0.8** | **GHSA-xvch-5gv4-984h** | **yes, with the row below** |
| minimist | **1.2.5** | **GHSA-xvch-5gv4-984h** | **yes, with the row above** |

OSV reports **3** records. ARVE is expected to emit **2** findings: the two
`GHSA-xvch-5gv4-984h` rows differ only by version, which the fingerprint
discards.

Note the remediation consequence: the two versions have **different fixed
versions** and are reached through different dependency paths (one direct, one
via `mkdirp`), so they are two distinct pieces of work. One of them disappears.

### Scoring impact

A straightforward under-count: 3 OSV records → 2 ARVE findings, with no error
and nothing in the output indicating a merge happened. Because the surviving
finding carries *a* version, the result looks entirely plausible; the only way
to notice is to diff against the scanner's raw output.

The same collapse occurs for any transitive dependency that appears at several
versions in one lockfile, which is common in npm and pnpm trees — so the effect
on a real repository is likely larger than one finding.

---

## Reproducing any of this

```bash
# What ARVE's ingestion filter would keep, for the current working tree
python scripts/arve_filter_mirror.py

# The three numbers that matter (full history / HEAD on disk / ARVE's view)
python scripts/verify_plants.py        # added in the v1.1 expansion
```

`expected-findings.json` carries the per-finding `arve_pipeline` block —
`ingestion`, `skip_reason`, `reaches_scanner`, `expected_arve_count` and
`known_arve_divergence` — for every plant, so the numbers above can be
recomputed rather than trusted.
