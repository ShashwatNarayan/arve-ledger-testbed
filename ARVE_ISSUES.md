# ARVE issues — evidence from the testbed

Nine issue-ready writeups to file against `ShashwatNarayan/arve`. Each is
**evidence only**: observed behaviour, the code path it comes from, the testbed
finding that proves it, and what it does to scoring. **No fixes are proposed
here, and no ARVE change is made from this repository** — the testbed's job is to
expose the gap, not to close it.

Nothing below says ARVE is wrong to behave this way; several are deliberate
trade-offs. What matters is that each is *known*, and that its effect on a score
is understood before anyone reads a number off this testbed.

## Status board

Tick these off as they are filed. `verify_plants.py` reproduces every number.

| # | Title | Phase | Proven by | Impact | Status |
|---|---|---|---|---|---|
| [1](#issue-1) | Extension allow-list misses `.pem`, `.properties`, `.tf` | Phase 2 | SEC-03, SEC-11, SEC-19 | 3 secrets never scanned | ☐ not filed |
| [2](#issue-2) | `splitext` makes the `.env`/dotfile entries unreachable | Phase 2 | SEC-08, SEC-15 | 2 secrets never scanned; 2 allow-list entries are dead code | ☐ not filed |
| [3](#issue-3) | Lockfiles are skipped, so whole ecosystems scan as empty | Phase 2 | DEP-10, DEP-12, DEP-16, DEP-17, DEP-18 | Rust, Ruby, Gradle, Poetry invisible | ☐ not filed |
| [4](#issue-4) | 1 MiB size limit drops large data files | Phase 2 | SEC-25 | bulk credential leaks invisible | ☐ not filed |
| [5](#issue-5) | `build/` directory ignore drops hand-written tooling | Phase 2 | SEC-26 | supply-chain token invisible | ☐ not filed |
| [6](#issue-6) | `dir` mode means Git history is unreachable | Phase 3 | SEC-04 | 1 plant unrecoverable; 2 lifecycle tests inert | ☐ not filed |
| [7](#issue-7) | `secret_hash` is line-dependent, so two secrets collapse | Phase 4A | SEC-22, SEC-27, SEC-06, SEC-23 | a real credential silently lost | ☐ not filed |
| [8](#issue-8) | Dependency fingerprint omits the version | Phase 4A | DEP-20, DEP-19 | 3 records → 2 findings, silently | ☐ not filed |
| [9](#issue-9) | Scanner-upgrade hazards in the fingerprint inputs | Phase 4A | DEP-01, DEP-15 | mass resolve-and-reopen, or double-counting | ☐ not filed |

**Issues 1–5 share one root cause** (the ingestion `FileFilter`) and could be
filed as one epic with five cases. They are separated because each has a
different fix and a different blast radius.

Measured on **2026-09-22** with ARVE-pinned **gitleaks 8.24.2** / **osv-scanner
1.9.2** and reference **gitleaks 8.30.1** / **osv-scanner 2.5.1**, from the
official images. ARVE behaviour is quoted from the codebase snapshot recorded in
`PROJECT_CONTEXT.md` §3 — re-check before filing, since ARVE moves.

> **One caveat that applies to all of issues 1–5.** The ingestion verdicts come
> from `scripts/arve_filter_mirror.py`, a mirror of ARVE's filter. **No ARVE run
> has confirmed them.** Before filing, run ARVE against this repository and
> compare its `repository_files` statuses with the mirror. If they disagree, the
> mirror is wrong and that is itself worth reporting.

---

<a id="issue-1"></a>

## Issue 1 — Extension allow-list misses `.pem`, `.properties` and `.tf`

### Observed behaviour

Files with these extensions are marked `SKIPPED unsupported_file_type` and never
written to the scan workspace. No scanner sees them, no finding is produced, and
**nothing in the output distinguishes "scanned and clean" from "never looked
at"**.

### Code path

`backend/app/ingestion/filters/file_filter.py` → `FileFilter.evaluate()`, step 5
(extension allow-list) falling through to step 6 (`unsupported_file_type`).
Skipped files are stored with `status = SKIPPED` and never reach
`ScanWorkspaceManager`, so they are absent from `/code`.

### Testbed evidence

| Plant | File | Secret | Pinned gitleaks 8.24.2, shown the file | ARVE |
|---|---|---|---|---|
| **SEC-03** | `backend/keys/webhook_signing.pem` | RSA private key | ✅ detected, `private-key`, line 5 | **0** |
| **SEC-11** | `services/settlement-java/…/application.properties` | Twilio API key | ✅ detected, `twilio-api-key`, line 12 | **0** |
| **SEC-19** | `ops/terraform/main.tf` | Terraform Cloud token | ✅ detected, `hashicorp-tf-api-token`, line 17 | **0** |

**The control that removes all doubt: SEC-18.** An EC private key in
`ops/k8s/secrets.yaml` — *the same `private-key` rule* as SEC-03 — is ingested
and reported. Same rule, same class of secret, different extension. So the
difference is provably the allow-list, not the rule.

These are not exotic file types: `.pem` is where private keys live,
`application.properties` is where JVM services keep credentials, and `.tf` is
where cloud credentials concentrate.

### Scoring impact

Three plants are counted as recall misses for a Phase 2 decision rather than a
detection failure. Worse for a real user: a `.pem` in their repository is never
examined, and ARVE's output looks identical to a clean result.

---

<a id="issue-2"></a>

## Issue 2 — `os.path.splitext` makes the `.env` and dotfile entries unreachable

### Observed behaviour

`ALLOWED_EXTENSIONS` contains `.env` and `.env.example`. **Neither can ever
match.** The extension is computed with `os.path.splitext`, which returns:

| Path | `splitext` extension | Result |
|---|---|---|
| `.env.example` | `.example` | SKIPPED — the `.env.example` entry is dead code |
| `.env` | `""` — the whole name is the stem | SKIPPED — the `.env` entry is dead code |
| `.npmrc`, `.dockerignore`, `id_ed25519` | `""` | SKIPPED |

Someone added those two entries intending to ingest those files. A reader of the
allow-list would reasonably conclude the opposite of what happens.

### Code path

`FileFilter.evaluate()` step 5, `os.path.splitext(filename)[1]`. For any name
beginning with a dot and containing no further dot, `splitext` treats the whole
name as the stem and returns an empty extension.

### Testbed evidence

| Plant | File | Secret | Pinned scanner, shown the file | ARVE |
|---|---|---|---|---|
| **SEC-08** | `.env.example` | SendGrid token | ✅ `sendgrid-api-token`, line 23 | **0** |
| **SEC-15** | `apps/admin-ui/.npmrc` | npm publish token | ✅ `npm-access-token`, line 6 | **0** |

**The control: SEC-17.** `ops/Dockerfile` also has no extension — `splitext`
returns `""` for it too — but `dockerfile` is in the *filename* allow-list, so it
is ingested and its Hugging Face token is reported. The deciding factor is the
filename list, not the missing extension.

### Scoring impact

Two plants lost. SEC-08 additionally makes the `FALSE_POSITIVE`/`SUPPRESSED`
triage-lifecycle test impossible to run, since the finding never exists.

A dotfile is a normal place for credentials: `.npmrc` holds a publish token,
`.env` is the canonical secrets file. The `.env` entry in particular suggests the
gap is unintended rather than a policy decision.

---

<a id="issue-3"></a>

## Issue 3 — Lockfiles are skipped, so whole ecosystems are scanned as empty

### Observed behaviour

OSV-Scanner reads **lockfiles**, not manifests. ARVE's filename allow-list
covers `package-lock.json`, `yarn.lock`, `pnpm-lock.yaml`, `requirements.txt`,
`go.mod` and `pom.xml` — but not:

`poetry.lock` · `Pipfile.lock` · `Cargo.lock` · `Gemfile.lock` ·
`composer.lock` · `gradle.lockfile` · `go.sum` · `requirements-*.txt`

**The failure mode is worse than a missed file.** In several ecosystems the
*manifest* is ingested and the *lockfile* is not, so ARVE ingests a file that
declares dependencies, hands OSV nothing it can resolve, and reports a clean
result for an ecosystem it never examined:

| Ecosystem | Ingested | Skipped — the file OSV actually reads |
|---|---|---|
| Rust | `Cargo.toml` ✅ | `Cargo.lock` ⛔ |
| Python (Poetry) | `pyproject.toml` ✅ | `poetry.lock` ⛔ |
| JVM (Gradle) | `build.gradle` ✅ | `gradle.lockfile` ⛔ |
| Ruby | — | `Gemfile.lock` ⛔ |

### Code path

`FileFilter.evaluate()` step 3 (filename allow-list) and step 5 (extension
allow-list). Lockfile names match neither, so they fall to step 6.

`requirements-dev.txt` is a distinct sub-case: the allow-list matches the **exact
string** `requirements.txt`, so every `requirements-dev.txt`, `-test.txt`,
`-ci.txt` variant is skipped, and `.txt` is in no extension list either.

### Testbed evidence

**Every one of these is parsed correctly by ARVE's own pinned osv-scanner 1.9.2
when it is allowed to see the file.** All five lockfiles are genuine
package-manager output.

| Plant | Lockfile | Package | Records if scanned | ARVE |
|---|---|---|---|---|
| **DEP-10** | `gradle.lockfile` | snakeyaml 1.33 | 1 (HIGH) | **0** |
| **DEP-12** | `Cargo.lock` | ansi_term 0.12.1 | 1 | **0** |
| **DEP-16** | `poetry.lock` | wheel 0.37.0 | 2 | **0** |
| **DEP-17** | `requirements-dev.txt` | jinja2 3.1.5 | 2 | **0** |
| **DEP-18** | `Gemfile.lock` | addressable 2.7.0 | 2 (both HIGH) | **0** |

**The control: DEP-15.** `packages.lock.json` (NuGet) **is** ingested — not
because NuGet is supported, but because the filename happens to end in `.json`,
which is in the extension allow-list. Coverage of an ecosystem is currently an
accident of file naming.

### Scoring impact

Eight advisory records lost, but the headline is qualitative: **a repository
whose dependencies are entirely in Cargo, Bundler, Poetry or Gradle gets a clean
dependency report from ARVE regardless of how vulnerable it is.** That is a
false negative at the level of a whole ecosystem, and nothing in the output
indicates it happened.

---

<a id="issue-4"></a>

## Issue 4 — The 1 MiB size limit drops large data files

### Observed behaviour

Files over **1,048,576 bytes** are `SKIPPED file_too_large`. The size check runs
**before** the extension check, so being an allowed type cannot rescue a file.

### Code path

`FileFilter.evaluate()` step 2, `MAX_FILE_SIZE_BYTES = 1_048_576`, evaluated
ahead of steps 3–5.

### Testbed evidence

**SEC-25** — a Square access token inside
`db/fixtures/merchant_export.json`, a 1,262,651-byte merchant catalogue export
(214,075 bytes over the cap). The pinned gitleaks finds it at line 38901 when
shown the file; ARVE reports nothing. The `.json` extension is allowed, and never
reached.

The other 5,399 records in that fixture contain no credential-shaped values, so
the file is realistic rather than a bag of secrets.

### Scoring impact

One plant lost — but the class matters more than the count. Large exports,
database dumps and fixtures are exactly where *bulk* credential leaks live: one
oversized file can hold thousands of customer tokens. A size cap is a reasonable
performance control; the issue is that exceeding it is silent, and that the
riskiest files are the ones most likely to exceed it.

---

<a id="issue-5"></a>

## Issue 5 — The `build/` directory ignore drops hand-written tooling

### Observed behaviour

Any path with a directory segment in
`{.git, node_modules, venv, .venv, __pycache__, dist, build, target, coverage, vendor, .cache, .idea, .vscode}`
is `SKIPPED ignored_directory` — **before** the size and extension checks.

The list exists to skip *generated* output. But `build/` and `target/` are also
ordinary names for hand-written release tooling that is tracked in Git.

### Code path

`FileFilter.evaluate()` step 1, matching any directory segment of the path.

### Testbed evidence

**The cleanest isolation in the testbed**, because the two plants differ in
exactly one path segment:

| Plant | File | Type | Rule | ARVE |
|---|---|---|---|---|
| SEC-20 | `ops/**scripts**/backup.sh` | shell | `shopify-access-token` | ✅ 1 |
| **SEC-26** | `ops/**build**/publish.sh` | shell | `pypi-upload-token` | **0** |

Same file type, same kind of vendor token, both tracked in Git — `.gitignore`
deliberately does not ignore `ops/build/`. The only difference is the directory
name.

### Scoring impact

One plant lost, and it is a **PyPI upload token** — a supply-chain credential
whose compromise lets an attacker publish a malicious package version. Release
tooling is where publish credentials live, and `build/` is a natural place to put
release tooling.

---

<a id="issue-6"></a>

## Issue 6 — Gitleaks runs in `dir` mode, so Git history is unreachable

### Observed behaviour

ARVE materialises only the ingested files into `/code` and runs
`gitleaks dir /code`. The workspace has **no `.git` directory**, so a secret that
was committed and later deleted is invisible. A credential that was pushed is
compromised until rotated, regardless of any later commit removing it.

This is an architectural consequence (ingestion fetches files, not a clone), not
a defect in the engine wrapper. Filed so the limitation is recorded against the
scoring model rather than discovered mid-evaluation.

### Code path

`PROJECT_CONTEXT.md` §3.1–3.2: the engine runs
`dir /code --report-format json --report-path /output/gitleaks.json --redact`.
Phase 3 `ScanWorkspaceManager` writes only `INGESTED` files to a read-only
workspace; nothing clones the repository.

### Testbed evidence

**SEC-04** — an SFTP password in `backend/app/settlement.py`, added in commit
`5f9ec864` and deleted in `5c1f6a8f`. Measured, both gitleaks versions:

| Scan | Findings for `settlement.py` |
|---|---|
| `gitleaks git` over the repository | **1**, line 16, commit `5f9ec864` |
| `gitleaks dir` at HEAD (what ARVE does) | **0** |

Totals: **34** findings across history, **31** at HEAD on disk.

Two further plants are not *lost* but rendered **inert**, which is easy to miss
when reading a score:

- **SEC-06** moves from line 43 to line 22 with a byte-identical value. ARVE only
  ever sees line 22, so the "does the finding stay OPEN across a refactor?" test
  never runs.
- **SEC-27** is rotated in place. History holds two values; ARVE sees one.

### Scoring impact

One plant permanently unrecoverable, and the two most interesting lifecycle tests
in the suite degrade to "not applicable". Any recall figure quoted from this
testbed must state which of 34 / 31 / 24 it used, or it is not reproducible.

---

<a id="issue-7"></a>

## Issue 7 — `secret_hash` is the line-dependent dir-mode fingerprint

### Observed behaviour

ARVE sets `secret_hash` to the Gitleaks `Fingerprint`. In `dir` mode that is
`file:rule:startLine` — it contains **no part of the secret value**, because
ARVE also passes `--redact`, which strips the value from the report entirely.

Consequences in both directions:

- **Different secrets collide.** Two distinct secrets matched by the same rule on
  the same line share a fingerprint and collapse into one finding.
- **A changed secret does not.** A credential rotated *in place* keeps the same
  fingerprint, so the rotation is never observed.
- **An unchanged secret can look new.** Moving a secret to another line produces
  a different fingerprint.

### Code path

`PROJECT_CONTEXT.md` §3.4: `secret_hash = Gitleaks Fingerprint`; the engine runs
`dir` with `--redact`. Gitleaks builds the `dir`-mode fingerprint as
`file:rule:startLine` (in `git` mode, `commit:file:rule:startLine` — equally
line-dependent).

### Testbed evidence

**SEC-22 is the direct proof.** Two *different* synthetic credentials, both
matched by `generic-api-key`, on **one line** of `tools/sync_keys.py`:

```
ROTATION = {"primary_api_key": "<secret A>", "secondary_api_key": "<secret B>"}
```

Both gitleaks versions report **two findings** with **identical fingerprints**:

```
generic-api-key  tools/sync_keys.py:16  col 15   tools/sync_keys.py:generic-api-key:16
generic-api-key  tools/sync_keys.py:16  col 78   tools/sync_keys.py:generic-api-key:16
```

The only distinguishing field is `StartColumn`, which `NormalizedFinding` does
not carry — and which is independently unreliable on long lines (`LIM-03`:
reported as 29427 and 755 for a true column of 154444, differing by version).
**Expected result: 2 leaked credentials → 1 ARVE finding.** One is silently lost,
and only one gets rotated.

**SEC-27** proves the rotation case: a New Relic key in
`services/notifier-rust/notifier.toml` whose value is replaced in a later commit,
same file, same line. Reference `gitleaks git` reports two findings; ARVE sees
one finding that never changes state — not RESOLVED for the old key, not new for
the replacement.

**SEC-23** proves the opposite error: one credential in three files
(`.js`, `.yaml`, `.py`) yields **three** findings with three fingerprints. One
credential, three rotations' worth of noise.

### Scoring impact

Precision and recall distort in opposite directions and partly mask each other.
SEC-22 costs a true positive; SEC-23 inflates the count; SEC-27 produces a
finding whose *lifecycle* is wrong rather than its count — the worst kind for a
remediation tool, because it looks healthy.

The structural point: with `--redact` plus a line-based fingerprint, **no ARVE
finding identity derives from the secret itself**. Any future dedupe-by-credential
behaviour — the design question SEC-05 poses, where either answer is defensible —
cannot be implemented from the data currently stored.

---

<a id="issue-8"></a>

## Issue 8 — The dependency fingerprint omits the package version

### Observed behaviour

```
SHA256(engine | dependency | package | ecosystem | vuln_id | file_path)
```

**The version is not an input.** When one lockfile legitimately contains two
versions of the same package and one advisory covers both, the records produce an
identical fingerprint and collapse into a single finding.

### Code path

`PROJECT_CONTEXT.md` §3.4, dependency fingerprint definition; OSV mapper,
Phase 4A.

### Testbed evidence

**DEP-20.** One genuine pnpm lockfile,
`apps/partner-webhooks/pnpm-lock.yaml`, holding `minimist 1.2.5` as a direct
dependency and `minimist 0.0.8` pinned exactly by `mkdirp@0.5.1` (a real,
advisory-free parent). Both osv-scanner versions report **3** records:

| Package | Version | Advisory | Collapses? |
|---|---|---|---|
| minimist | 0.0.8 | GHSA-vh95-rmgr-6w4m | — only 0.0.8 is affected |
| minimist | **0.0.8** | **GHSA-xvch-5gv4-984h** | **with the row below** |
| minimist | **1.2.5** | **GHSA-xvch-5gv4-984h** | **with the row above** |

**Expected: 3 records → 2 ARVE findings.**

**The control that proves the fingerprint is otherwise sound: DEP-19.** The same
package and version (`minimist 1.2.0`) in *two different lockfiles* correctly
produces two findings, because `file_path` **is** an input. So this is a specific
omission, not general over-collapsing.

### Scoring impact

A silent under-count with no error and no indication a merge occurred, and
because the surviving finding carries *a* version, the result looks plausible.
Only a diff against the scanner's raw output reveals it.

The remediation consequence is the real cost: the two versions have **different
fixed versions** and arrive by **different paths** (one direct, one transitive),
so they are two separate pieces of work. One disappears. Multiple versions of one
transitive package in a single lockfile is routine in npm and pnpm trees, so the
effect on a real repository is likely larger than one finding.

---

<a id="issue-9"></a>

## Issue 9 — Scanner-upgrade hazards in the fingerprint inputs

### Observed behaviour

Two fingerprint inputs — `package_version` and `file_path` — are not stable
properties of the vulnerability. They are **outputs of a particular scanner
version**, and both change under routine maintenance. Nothing in ARVE pins or
monitors them, so an image bump silently rewrites finding identity.

This issue has no current symptom. It is a trap laid for the next upgrade, which
is exactly when it is cheapest to record and hardest to diagnose.

### Code path

`PROJECT_CONTEXT.md` §3.1 (pinned images) and §3.4 (fingerprint definitions).

### Testbed evidence

**(a) The version string changes with the scanner version.** `backend/requirements.txt`
pins `pyyaml==5.1`. Measured:

| osv-scanner | Reported name | Reported version |
|---|---|---|
| **1.9.2** — ARVE's pinned image | `pyyaml` | **`5.1`** |
| **2.5.1** — reference | `pyyaml` | **`5.1.0`** |

The day ARVE moves to a 2.x image, **every PyYAML finding's fingerprint changes**:
6 records resolve and immediately reopen, with no change in the repository. Note
the committed reference baseline already says `5.1.0` while ARVE would currently
report `5.1` — a diff against that baseline mismatches on this package today.

**(b) `file_path` is a fingerprint input, and which files exist depends on the
allow-list.** osv-scanner **2.5.1 reports `Newtonsoft.Json 12.0.1` twice** — from
`packages.lock.json` *and* from `LedgerExport.csproj` — where **1.9.2 reports it
once**. ARVE is unaffected today only because `.csproj` is skipped at ingestion.
Add `.csproj` to the allow-list — a reasonable thing to do for issue 1 — and the
same vulnerability becomes **two findings** with different `file_path` values.

So fixing an ingestion gap can inflate finding counts, and the two issues
interact.

### Scoring impact

No effect on today's numbers; potentially large on the next upgrade. A
resolve-and-reopen storm across an entire ecosystem is indistinguishable, in the
findings table, from a developer having fixed and reintroduced every dependency —
and it would arrive attached to an image bump nobody associates with finding
identity.

Worth deciding deliberately: whether version normalisation belongs in ARVE's
mapper rather than being inherited from the scanner, and whether the fingerprint
should key on something more stable than the path OSV happened to read.

---

## Reproducing any of this

```bash
# What ARVE's ingestion filter is PREDICTED to keep (issues 1-5)
python scripts/arve_filter_mirror.py

# Every number quoted above: 34 / 31 / 24, 49 / 50 / 41
python scripts/verify_plants.py

# Regression tests for the testbed's own tooling
python scripts/test_tooling.py
```

`expected-findings.json` carries a per-finding `arve_pipeline` block —
`ingestion`, `skip_reason`, `reaches_scanner`, `expected_arve_count` and
`known_arve_divergence` — so every claim above can be recomputed rather than
trusted. `scanner_limitations` (`LIM-01` … `LIM-03`) records scanner behaviour
that is **not** an ARVE issue and must not be filed as one.
