# Expected findings — answer key

Ground truth for the `arve-ledger-testbed` repository. Every flaw here was
planted deliberately and recorded at the moment it was planted.

- **17 planted findings**: `SEC-01` … `SEC-09` (Gitleaks) and `DEP-01` … `DEP-08`
  (OSV-Scanner).
- Machine-readable form: [`expected-findings.json`](expected-findings.json).
- **All credentials are synthetic**, randomly generated with the correct shape so
  scanners match them. None is valid for any real service.

| Field | Value |
|---|---|
| Advisory data verified | **2026-08-31**, against the live osv.dev API |
| Secrets verified | **2026-08-31**, gitleaks **8.30.1**, all 9 confirmed detected |
| Expected OSV-Scanner records | **30** across 8 packages (29 planted + 1 scanner over-match) |
| Expected Gitleaks findings | **10** at `HEAD`, **12** across full history |
| Git history | **13 commits** before the v1.1 expansion (earlier revisions of this file said 11), rebuilt reproducibly by `seed_history.py`; v1.1 appends after them |
| Answer-key schema | **1.1** — adds `file_type`, `scanner_verification` and `arve_pipeline` to every finding; see [§ ARVE pipeline view](#arve-pipeline-view-schema-11) |
| Scanner versions | ARVE-pinned **gitleaks 8.24.2 / osv-scanner 1.9.2** and reference **gitleaks 8.30.1 / osv-scanner 2.5.1**, all re-verified **2026-09-22** |
| Line numbers | ✅ **all 20 verified** against the committed content at the final commit |
| Reference baselines | `gitleaks-baseline.json`, `osv-baseline.json` — both committed |

> ### Why the advisory counts drift
> A vulnerable package carries *every* advisory published against it, not just
> the one it was chosen for. `lodash@4.17.11` alone accounts for 7 records. New
> CVEs land continuously, so the totals here will grow over time. Each `DEP-*`
> below names **one target advisory** — the one that exercises the behaviour the
> finding is testing — and the full 29-record inventory is listed in
> [§ Full expected OSV inventory](#full-expected-osv-inventory) so the diff can be
> made complete rather than approximate.

---

## Status

| Phase | Findings | State |
|---|---|---|
| Phase 2 | `DEP-01` … `DEP-08` | ✅ planted and recorded |
| Phase 3 | `SEC-01` … `SEC-09` | ✅ planted and recorded, all 9 verified detected |
| Phase 4 | history behaviour for `SEC-04`, `SEC-06` | ✅ built and verified |
| Phase 5 | line-number verification, scanner baselines | ✅ complete — baselines committed |
| v1.1 Phase 1 | schema 1.1: `file_type`, `scanner_verification`, `arve_pipeline` on all 17, plus negative controls, scanner limitations and the coverage matrix | ✅ complete |

---

# Group B — Vulnerable dependencies (OSV-Scanner, `finding_type: dependency`)

Two ecosystems, two lockfiles, both at nested paths. Neither is at the repository
root — that alone tests whether the scanner recurses instead of only checking the
top level.

**The noise floor is deliberately zero.** Every other package in both trees was
checked against osv.dev and returns no advisories, so *every* dependency finding
ARVE reports should correspond to something on this page. If it reports a package
not listed here, either the package picked up a new advisory since 2026-08-31 or
something is wrong.

---

## DEP-01 — direct PyPI dependency with a well-known advisory

**Planted:** `pyyaml==5.1` pinned as a direct dependency in the backend lockfile.

| | |
|---|---|
| File | `backend/requirements.txt` line **59** |
| Engine | `osv` |
| Package | `PyYAML` @ `5.1` (PyPI) |
| Target advisory | **GHSA-3pqx-4fqf-j49f** / **CVE-2019-20477** |
| Severity | `CRITICAL` |
| History only | no |
| Total records for this package | **6** (3 GHSA + 3 PYSEC aliases) |

**What this tests:** baseline direct-dependency detection in the primary
ecosystem. Deserialization of untrusted data — one of the most widely documented
Python advisories there is. If this is missed, the OSV integration is broken and
nothing else in Group B is meaningful.

**Note:** the three `PYSEC-*` records are alias duplicates of the three GHSA
records and carry **no CVSS vector and no GitHub severity string**. Whether ARVE
emits 6 findings or collapses alias groups into 3 is a design decision — but it
must be a deliberate one, and it must not emit `null` severity for the PYSEC
records. See `DEP-08` for the isolated version of this test.

---

## DEP-02 — vulnerable only as a transitive dependency

**Planted:** `certifi==2018.4.16`, which is **never named in `requirements.in`**.
It is pulled in by `httpx` and `httpcore`, neither of which constrains its
version, so an old pin survives indefinitely.

| | |
|---|---|
| File | `backend/requirements.txt` line **22** |
| Engine | `osv` |
| Package | `certifi` @ `2018.4.16` (PyPI) |
| Target advisory | **GHSA-xqr8-7jwr-rhp7** / **CVE-2023-37920** |
| Severity | `HIGH` |
| History only | no |
| Total records for this package | **4** |

**What this tests:** transitive resolution depth. The finding must be attributed
to `certifi` while the `# via httpcore / httpx` annotation shows it entered the
tree indirectly. **Both parents are advisory-free**, so this package's records are
attributable to nothing else.

**Note — a live edge case worth knowing about.** The osv.dev query API also
returns `PYSEC-2024-230` (CVE-2024-39689) for this package, but that advisory's
ECOSYSTEM range is `introduced: 2021.5.30`, so **2018.4.16 is not in range**. It
is excluded from the inventory below. The API appears to match loosely because
the record also carries a GIT range with `introduced: 0`. If OSV-Scanner reports
it in the Phase 5 baseline, this note is why — and ARVE reporting it is a
*scanner* behaviour, not an ARVE bug.

---

## DEP-03 — direct npm dependency with a high-severity advisory

**Planted:** `lodash@4.17.11` as a direct runtime dependency of the operator
console, genuinely used by `web/src/main.js`.

| | |
|---|---|
| File | `web/package-lock.json` line **72** (declared at `web/package.json` line 12) |
| Engine | `osv` |
| Package | `lodash` @ `4.17.11` (npm) |
| Target advisory | **GHSA-p6mc-m468-83gw** / **CVE-2020-8203** |
| Severity | `HIGH` |
| History only | no |
| Total records for this package | **7** |

**What this tests:** baseline detection in the *second* ecosystem, from a
lockfile at a nested path. This is the npm counterpart to `DEP-01`.

---

## DEP-04 — reachable only through another package's dependency tree

**Planted:** `follow-redirects@1.14.7`. It appears **only in
`web/package-lock.json`** and is absent from `web/package.json`. It enters the
tree solely as a dependency of `http-proxy@1.18.1`, which declares
`follow-redirects: ^1.0.0`.

| | |
|---|---|
| File | `web/package-lock.json` line **29** |
| Engine | `osv` |
| Package | `follow-redirects` @ `1.14.7` (npm) |
| Target advisory | **GHSA-pw2r-vq6v-hr8c** / **CVE-2022-0536** |
| Severity | `MEDIUM` (GitHub `moderate`) |
| History only | no |
| Total records for this package | **4**, all `moderate` |

**What this tests:** lockfile **graph** parsing. A scanner that only reads
`package.json` finds nothing here. The lockfile is genuine npm output and is
self-consistent — `npm install` reports "up to date" against it — so this is not
a hand-edited artifact.

**The parent `http-proxy@1.18.1` is itself advisory-free**, which is deliberate:
it contributes no records of its own, so anything reported here is unambiguously
the transitive child.

> **Correction recorded during the build.** `CVE-2022-0155` (GHSA-74fj-2j2h-c42q,
> HIGH) was originally chosen as this finding's target. It is **fixed in 1.14.7**
> and does not apply. The osv.dev query API returned it anyway on one run; range
> checking each advisory individually caught it. Target reassigned to
> CVE-2022-0536, which is genuinely in range.

---

## DEP-05 — one package carrying two distinct advisories

**Planted:** `minimist@1.2.0`, which has exactly two advisories and no more —
chosen precisely because the expected count is unambiguous.

| | |
|---|---|
| File | `web/package-lock.json` line **78** (declared at `web/package.json` line 16) |
| Engine | `osv` |
| Package | `minimist` @ `1.2.0` (npm) |
| Advisory 1 | **GHSA-vh95-rmgr-6w4m** / **CVE-2020-7598** — severity `MEDIUM` |
| Advisory 2 | **GHSA-xvch-5gv4-984h** / **CVE-2021-44906** — severity `CRITICAL` |
| History only | no |
| **Expected finding count** | **2 — not 1** |

**What this tests:** fingerprint uniqueness per `(package, advisory)`. One
package, one version, one lockfile line, two different advisories with two
different severities. A fingerprint keyed only on `(package, version)` collapses
these into one finding and **loses the CRITICAL one**, which is the failure this
plant exists to catch.

---

## DEP-06 — GitHub severity string `moderate`

**Planted:** `jquery@3.3.1`. All three of its advisories carry
`database_specific.severity: "MODERATE"` — there is no mixed-severity ambiguity
to hide behind.

| | |
|---|---|
| File | `web/package-lock.json` line **65** (declared at `web/package.json` line 11) |
| Engine | `osv` |
| Package | `jquery` @ `3.3.1` (npm) |
| Target advisory | **GHSA-6c3j-c64m-qhgq** / **CVE-2019-11358** |
| Severity | **`MEDIUM`** |
| History only | no |
| Total records for this package | **3**, all `moderate` |

**What this tests:** `normalize_severity`. GitHub emits the string `moderate`;
ARVE's canonical vocabulary has no such value — it must map to **`MEDIUM`**. A
normalizer that passes the string through unchanged, uppercases it to
`MODERATE`, or drops it to the default produces a visibly wrong severity on all
three records at once.

---

## DEP-07 — advisory with a GHSA ID but no CVE ID

**Planted:** `serialize-javascript@2.1.2`, used by `web/dev-server.js` to
serialize runtime config into the page.

| | |
|---|---|
| File | `web/package-lock.json` line **92** (declared at `web/package.json` line 17) |
| Engine | `osv` |
| Package | `serialize-javascript` @ `2.1.2` (npm) |
| Target advisory | **GHSA-5c6j-r48x-rmvq** |
| CVE | **none — must stay `null`** |
| Severity | `HIGH` |
| History only | no |
| Total records for this package | **2** |

**What this tests:** the `ghsa` field must populate and `cve` must stay **null**.
This package is well chosen for the test because its *other* advisory
(GHSA-hxcc-f52p-wc94) **does** carry `CVE-2020-7660` — so the same package, at
the same version, produces one finding with a CVE and one without. A normalizer
that copies the CVE across records, or that falls back to the GHSA ID as a
pseudo-CVE, is immediately visible.

**Failure modes this catches:** `cve` set to the string `"None"`, `""`, or the
GHSA ID; the finding dropped entirely because a CVE was assumed mandatory.

> **Correction recorded during the build.** This finding was originally assigned
> to `http-proxy@1.18.1` (GHSA-6x33-pw7p-hmpq, no CVE). That advisory is **fixed
> in 1.18.1** and does not apply — an early scan returned it spuriously.
> `http-proxy` was kept in the tree as the deliberately clean parent for
> `DEP-04`, and `DEP-07` was reassigned here.

---

## DEP-08 — advisory with no CVSS score at all

**Planted:** `stringstream@0.0.5`, used by `web/dev-server.js` to collect request
bodies for the access log.

| | |
|---|---|
| File | `web/package-lock.json` line **99** (declared at `web/package.json` line 18) |
| Engine | `osv` |
| Package | `stringstream` @ `0.0.5` (npm) |
| Target advisory | **GHSA-mf6x-7mm4-x2g7** / **CVE-2018-21270** |
| CVSS vector | **none — the OSV record's `severity` array is empty** |
| GitHub severity | `moderate` |
| Severity | **`MEDIUM`** |
| History only | no |
| Total records for this package | **1** — the only record, no alias siblings |

**What this tests:** the severity fallback path. There is no CVSS vector to parse,
so a normalizer that assumes `severity[0].score` always exists will throw or emit
`null`. The correct result is **`MEDIUM`**, reached via
`database_specific.severity: "moderate"`.

**Why this package specifically:** it is the only single-record, no-alias,
no-CVSS advisory available. Records with *genuinely* no severity signal at all
(`PYSEC-*`, `MAL-*`) always sit in an alias group beside a GHSA that does carry
CVSS, which makes the expected answer ambiguous — it would depend on whether ARVE
normalizes per-record or per-group. This plant has exactly one right answer.

**If you want the harder ambiguous case as well:** `PYSEC-2020-176`,
`PYSEC-2020-96` and `PYSEC-2021-142` are already present via `DEP-01` and have no
severity data whatsoever. They are the per-group-vs-per-record test, for free.

---

## Full expected OSV inventory

All **29** records OSV-Scanner should report, across 8 packages. Anything outside
this list is either a new advisory published after 2026-08-31 or a genuine
discrepancy worth investigating.

### PyPI — `backend/requirements.txt`

| Package | Version | OSV ID | GHSA | CVE | Severity | Finding |
|---|---|---|---|---|---|---|
| PyYAML | 5.1 | GHSA-3pqx-4fqf-j49f | GHSA-3pqx-4fqf-j49f | CVE-2019-20477 | CRITICAL | **DEP-01** |
| PyYAML | 5.1 | GHSA-6757-jp84-gxfx | GHSA-6757-jp84-gxfx | CVE-2020-1747 | CRITICAL | DEP-01 |
| PyYAML | 5.1 | GHSA-8q59-q68h-6hv4 | GHSA-8q59-q68h-6hv4 | CVE-2020-14343 | CRITICAL | DEP-01 |
| PyYAML | 5.1 | PYSEC-2020-176 | GHSA-3pqx-4fqf-j49f | CVE-2019-20477 | MEDIUM ¹ | DEP-01 |
| PyYAML | 5.1 | PYSEC-2020-96 | GHSA-6757-jp84-gxfx | CVE-2020-1747 | MEDIUM ¹ | DEP-01 |
| PyYAML | 5.1 | PYSEC-2021-142 | GHSA-8q59-q68h-6hv4 | CVE-2020-14343 | MEDIUM ¹ | DEP-01 |
| certifi | 2018.4.16 | GHSA-43fp-rhv2-5gv8 | GHSA-43fp-rhv2-5gv8 | CVE-2022-23491 | MEDIUM | DEP-02 |
| certifi | 2018.4.16 | GHSA-xqr8-7jwr-rhp7 | GHSA-xqr8-7jwr-rhp7 | CVE-2023-37920 | HIGH | **DEP-02** |
| certifi | 2018.4.16 | PYSEC-2022-42986 | GHSA-43fp-rhv2-5gv8 | CVE-2022-23491 | MEDIUM ¹ | DEP-02 |
| certifi | 2018.4.16 | PYSEC-2023-135 | GHSA-xqr8-7jwr-rhp7 | CVE-2023-37920 | MEDIUM ¹ | DEP-02 |

¹ No CVSS vector and no GitHub severity string — severity reached by fallback.

### npm — `web/package-lock.json`

| Package | Version | OSV ID | CVE | Severity | Finding |
|---|---|---|---|---|---|
| lodash | 4.17.11 | GHSA-29mw-wpgm-hmr9 | CVE-2020-28500 | MEDIUM | DEP-03 |
| lodash | 4.17.11 | GHSA-35jh-r3h4-6jhm | CVE-2021-23337 | HIGH | DEP-03 |
| lodash | 4.17.11 | GHSA-f23m-r3pf-42rh | CVE-2025-13465 | MEDIUM | DEP-03 |
| lodash | 4.17.11 | GHSA-jf85-cpcp-j695 | CVE-2019-10744 | CRITICAL | DEP-03 |
| lodash | 4.17.11 | GHSA-p6mc-m468-83gw | CVE-2020-8203 | HIGH | **DEP-03** |
| lodash | 4.17.11 | GHSA-r5fr-rjxr-66jc | CVE-2021-23337 | HIGH | DEP-03 |
| lodash | 4.17.11 | GHSA-xxjr-mmjv-4gpg | CVE-2025-13465 | MEDIUM | DEP-03 |
| follow-redirects | 1.14.7 | GHSA-cxjh-pqwp-8mfp | CVE-2024-28849 | MEDIUM | DEP-04 |
| follow-redirects | 1.14.7 | GHSA-jchw-25xp-jwwc | CVE-2023-26159 | MEDIUM | DEP-04 |
| follow-redirects | 1.14.7 | GHSA-pw2r-vq6v-hr8c | CVE-2022-0536 | MEDIUM | **DEP-04** |
| follow-redirects | 1.14.7 | GHSA-r4q5-vmmm-2653 | CVE-2026-40895 | MEDIUM | DEP-04 |
| minimist | 1.2.0 | GHSA-vh95-rmgr-6w4m | CVE-2020-7598 | MEDIUM | **DEP-05** |
| minimist | 1.2.0 | GHSA-xvch-5gv4-984h | CVE-2021-44906 | CRITICAL | **DEP-05** |
| jquery | 3.3.1 | GHSA-6c3j-c64m-qhgq | CVE-2019-11358 | MEDIUM | **DEP-06** |
| jquery | 3.3.1 | GHSA-gxr4-xjj5-5px2 | CVE-2020-11022 | MEDIUM | DEP-06 |
| jquery | 3.3.1 | GHSA-jpcq-cgw6-v4j6 | CVE-2020-11023 | MEDIUM | DEP-06 |
| serialize-javascript | 2.1.2 | GHSA-5c6j-r48x-rmvq | **none** | HIGH | **DEP-07** |
| serialize-javascript | 2.1.2 | GHSA-hxcc-f52p-wc94 | CVE-2020-7660 | HIGH | DEP-07 |
| stringstream | 0.0.5 | GHSA-mf6x-7mm4-x2g7 | CVE-2018-21270 | MEDIUM ² | **DEP-08** |

² No CVSS vector; severity from GitHub's `moderate` string.

### Packages deliberately kept clean

These are in the trees and must produce **no** findings. A report against any of
them is a false positive worth chasing.

`annotated-doc`, `annotated-types`, `anyio`, `click`, `colorama`, `fastapi`,
`h11`, `httpcore`, `httpx`, `idna`, `iniconfig`, `packaging`, `pluggy`,
`pydantic`, `pydantic-core`, `pygments`, `pytest`, `starlette`,
`typing-extensions`, `typing-inspection`, `uvicorn`, `eventemitter3`,
`http-proxy`, `requires-port`

---

# Group A — Secrets (Gitleaks, `finding_type: secret`)

**Every credential below is synthetic**, randomly generated with the correct
shape, and valid for no real service. Each one carries a
`TESTBED SEC-0N — intentional` comment beside it in the source; Gitleaks ignores
comments entirely, so this costs nothing in detectability.

**9 planted secrets produce 10 Gitleaks findings at `HEAD`** (an earlier
revision of this file said 11; the table below always listed 10). `SEC-02` and
`SEC-05` each yield two; `SEC-04` is absent from `HEAD`. Verified against
**gitleaks 8.30.1**, and re-verified 2026-09-22 against **8.24.2** (ARVE's pinned
version), which reports the identical set.

> ### Two shape constraints that silently break plants
> Both were found by running the scanner during planting rather than after, and
> both would have produced findings that look like ARVE bugs:
>
> 1. **`generic-api-key` needs the keyword and the value on the same line.**
>    `SEC-07` was originally written across three lines and was **not detected**.
>    Wrapping a long secret assignment for readability makes it invisible.
> 2. **AWS key IDs must use the real base32 alphabet (`A–Z`, `2–7`).** Gitleaks
>    rejects any `AKIA…` value containing `0`, `1`, `8` or `9`. `SEC-02`'s first
>    value had two `1`s and was **not detected**, at any entropy. Only 4 of 40
>    naively-random candidates were detected; 30 of 30 base32 candidates were.

---

## SEC-01 — Stripe secret key at `HEAD`

**Planted:** a Stripe live secret key as the hardcoded fallback for
`STRIPE_API_KEY`.

| | |
|---|---|
| File | `backend/app/config.py` line **35** |
| Engine | `gitleaks` |
| Rule | `stripe-access-token` |
| Severity | `HIGH` |
| History only | no |
| Expected findings | 1 |

**What this tests:** baseline detection at `HEAD`. A named-vendor rule on a
first-party source file — the easiest class of secret there is. **If this is
missed, the pipeline is broken** and nothing else in Group A means anything.

---

## SEC-02 — AWS credentials in a CI workflow

**Planted:** an AWS access key ID and secret access key set as environment
variables on the release-upload step.

| | |
|---|---|
| File | `.github/workflows/deploy.yml` lines **45** and **46** |
| Engine | `gitleaks` |
| Rules | `aws-access-token` (line 45), `generic-api-key` (line 46) |
| Severity | `HIGH` |
| History only | no |
| **Expected findings** | **2** |

**What this tests:** a non-Python path. Workflow YAML is sometimes excluded by
path filters, and a scanner configured to look only at application source will
miss it entirely.

**Shape note — this one is a trap.** The key ID uses the genuine AWS base32
alphabet (`A–Z`, `2–7`). Gitleaks rejects `AKIA…` values containing `0`, `1`,
`8` or `9` regardless of entropy, because real AWS key IDs cannot contain them.
A naively random 16-character suffix is undetectable roughly 90% of the time.

---

## SEC-03 — RSA private key

**Planted:** a genuine 2048-bit RSA private key, generated as a throwaway with
`openssl genrsa` and never used for anything.

| | |
|---|---|
| File | `backend/keys/webhook_signing.pem` line **5** |
| Engine | `gitleaks` |
| Rule | `private-key` |
| Severity | `HIGH` |
| History only | no |
| Expected findings | 1 |

**What this tests:** a distinct rule class — block detection on a PEM header
rather than a token regex or an entropy score. The PEM structure is valid and
passes `openssl rsa -check`, so the finding is not an artifact of a malformed
file. Note that `.gitignore` deliberately does **not** ignore `*.pem`.

The file carries a 3-line `TESTBED SEC-03` header before the PEM block — parsers
ignore anything before the `BEGIN` marker — which is why the finding lands on
line **5**, not line 1.

---

## SEC-04 — SFTP password, history only ⏳

**Planted:** the SFTP password for the bank settlement-file service account.

| | |
|---|---|
| File | `backend/app/settlement.py` line **16** — **history only** |
| Engine | `gitleaks` |
| Rule | `generic-api-key` |
| Severity | `HIGH` |
| **History only** | **yes** |
| Expected findings | 1 |

**What this tests:** **Git history scanning.** This is the single most important
structural test in Group A. At `HEAD` the file **does not exist** — a
working-tree scan finds nothing. The secret is reachable only by walking commits.

**Lifecycle:** added in commit 3 (`add nightly settlement file transfer`),
deleted in commit 7 (`clean up settlement config`). A scanner that only walks the
filesystem reports **zero** findings here and is wrong. A scanner that walks
history reports it and must **not** immediately mark it `RESOLVED` just because
`HEAD` is clean — the credential was committed and must be treated as exposed
until rotated.

**✅ Verified at build time.**

| Scan mode | Findings for `settlement.py` |
|---|---|
| `gitleaks dir .` (working tree) | **0** |
| `gitleaks git .` (history) | **1**, at line 16 in commit `5f9ec864` |

Introduced in `5f9ec864` *"add nightly settlement file transfer"*, removed in
`5c1f6a8f` *"clean up settlement config, the transfer moved to the platform job"*.

> **Why `seed_history.py` derives this value instead of storing it.** Writing the
> password as a literal in the build script would put it back at `HEAD` — a
> working-tree scan would find it there and this finding's entire purpose would
> be destroyed by the script meant to create it. It is derived deterministically
> from a fixed seed, so the history stays reproducible while the literal exists
> only inside the commits where it belongs. In those commits it is plain text,
> exactly as a real leaked credential would be.

---

## SEC-05 — the same secret in two files

**Planted:** one JWT signing key, byte-for-byte identical, in two different files.

| | |
|---|---|
| File | `backend/app/config.py` line **45** |
| Also at | `backend/tests/conftest.py` line **14** |
| Engine | `gitleaks` |
| Rule | `generic-api-key` |
| Severity | `HIGH` |
| History only | no |
| **Expected findings** | **2 from Gitleaks** — ARVE may legitimately emit 1 or 2 |

**What this tests:** **fingerprint behaviour.** Gitleaks reports **two**
findings, because it fingerprints per `(file, line, secret)`.

What ARVE does is a genuine design decision, and either answer is defensible:

- **Dedupe on `secret_hash` alone → 1 finding.** Models the truth that this is
  *one leaked credential* needing *one rotation*. But then fixing `config.py`
  alone leaves the finding OPEN with a stale file path.
- **Include the file path → 2 findings.** Each occurrence is tracked and closed
  independently. But rotating the key resolves two findings at once, and the
  count overstates the number of leaked credentials.

**The requirement is that the choice is deliberate and consistent** — not that
it matches a particular number. What must *not* happen is a nondeterministic
count between runs, or a fingerprint that changes when only one copy is removed.

---

## SEC-06 — a secret that moves line ⏳

**Planted:** the provider webhook signing secret, which changes line number
between two commits while the value stays identical.

| | |
|---|---|
| File | `backend/app/webhooks.py` line **22** (pre-refactor position) |
| Engine | `gitleaks` |
| Rule | `generic-api-key` |
| Severity | `HIGH` |
| History only | no |
| Expected findings | 1 |

**What this tests:** **line-independent `secret_hash` identity.** Introduced in
commit 5 at one line; the commit 6 refactor moves it to another. **The secret
value never changes.**

**Expected lifecycle:** the finding stays `OPEN` across both commits with a
**stable fingerprint**. A fingerprint that incorporates the line number will
report the finding as `RESOLVED` at commit 6 and then `REOPENED` — a false
lifecycle transition, and exactly the bug this plant exists to catch. In a real
deployment that noise trains people to ignore the tool.

**✅ Verified at build time.** A history scan reports this secret **twice**:

| Commit | Message | Line | Secret value |
|---|---|---|---|
| `4da4e7e2` | add provider webhook handler with signature verification | **43** | `whsec_…` |
| `dc9a9d69` | hoist webhook module constants to the top of the file | **22** | `whsec_…` **identical** |

The value is byte-identical in both. Only the position changed.

**Expected:** ONE finding, with a **stable fingerprint**, staying `OPEN` across
the move. A fingerprint incorporating the line number emits `RESOLVED` at the
refactor and then `REOPENED` — a false lifecycle transition on a secret that was
never fixed and never re-leaked. That is the noise that trains people to ignore
a security tool.

---

## SEC-07 — high-entropy key with no vendor prefix

**Planted:** a 64-character base64url key as `LEDGER_HMAC_KEY`, with no vendor
prefix of any kind.

| | |
|---|---|
| File | `backend/app/config.py` line **40** |
| Engine | `gitleaks` |
| Rule | `generic-api-key` |
| Severity | `HIGH` |
| History only | no |
| Expected findings | 1 |

**What this tests:** the **entropy** path rather than a named-vendor regex. No
rule can pattern-match this value; detection depends entirely on
`generic-api-key` finding a credential-ish keyword next to a high-entropy string.

**Shape note.** This was originally planted across three lines — a perfectly
natural way to format a long assignment — and was **not detected**. Gitleaks
requires the keyword and the value on the **same line**. It is now one line.

---

## SEC-08 — real-shaped credential in `.env.example`

**Planted:** a correctly-shaped SendGrid API token in the committed
`.env.example` template.

| | |
|---|---|
| File | `.env.example` line **23** |
| Engine | `gitleaks` |
| Rule | `sendgrid-api-token` |
| Severity | `MEDIUM` |
| History only | no |
| Expected findings | 1 |

**What this tests:** the `FALSE_POSITIVE` / `SUPPRESSED` lifecycle. This finding
is **ambiguous by design**.

**Verified:** gitleaks **does** report it — the `.example` filename does not
suppress it by default. So the ambiguity is not resolved by the scanner; it is
pushed to human triage. Someone must decide whether a correctly-shaped
credential in a template file is a real leak or documentation.

**This is the one finding where marking it `FALSE_POSITIVE` or `SUPPRESSED` is a
legitimate outcome.** The real test is what happens *next*: ARVE must carry that
triage state across rescans. If a suppressed finding reverts to `OPEN` on the
next scan, the lifecycle is broken and every future triage decision is worthless.

---

## SEC-09 — Slack webhook URL in Markdown

**Planted:** a Slack incoming-webhook URL inside a fenced code block in the
operational runbook.

| | |
|---|---|
| File | `docs/runbook.md` line **66** |
| Engine | `gitleaks` |
| Rule | `slack-webhook-url` |
| Severity | `MEDIUM` |
| History only | no |
| Expected findings | 1 |

**What this tests:** a **non-code path**. Documentation is routinely excluded
from scanning by extension filters, yet runbooks are one of the most common
places real webhook URLs leak, because they get pasted in as copy-paste-ready
commands — exactly as this one is.

---

## Expected Gitleaks output at `HEAD`

Ten findings, verified with gitleaks 8.30.1 and (2026-09-22) 8.24.2. Line
numbers were re-verified at the final commit in Phase 5.

| Rule | File | Line | Finding |
|---|---|---|---|
| `sendgrid-api-token` | `.env.example` | 23 | SEC-08 |
| `aws-access-token` | `.github/workflows/deploy.yml` | 45 | SEC-02 |
| `generic-api-key` | `.github/workflows/deploy.yml` | 46 | SEC-02 |
| `stripe-access-token` | `backend/app/config.py` | 35 | SEC-01 |
| `generic-api-key` | `backend/app/config.py` | 40 | SEC-07 |
| `generic-api-key` | `backend/app/config.py` | 45 | SEC-05 |
| `generic-api-key` | `backend/app/webhooks.py` | 22 | SEC-06 |
| `private-key` | `backend/keys/webhook_signing.pem` | 5 | SEC-03 |
| `generic-api-key` | `backend/tests/conftest.py` | 14 | SEC-05 |
| `slack-webhook-url` | `docs/runbook.md` | 66 | SEC-09 |

**`SEC-04` is not in this table** — it no longer exists at `HEAD`. It appears
only in a history scan.

### Expected Gitleaks output across full history

Twelve findings. The two extra beyond `HEAD` are the whole point of Phase 4:

| Rule | File | Line | Commit | Finding |
|---|---|---|---|---|
| `generic-api-key` | `backend/app/settlement.py` | 16 | `5f9ec864` | **SEC-04** — history only |
| `generic-api-key` | `backend/app/webhooks.py` | 43 | `4da4e7e2` | **SEC-06** — original position |

**Scanning note.** `gitleaks dir .` also scans `.venv/` and produces one
unrelated hit in `setuptools`. That directory is gitignored, so a repository
scan (`gitleaks git`) does not see it. Scan the Git repository, not the
filesystem, or the baseline will carry noise that is not part of this testbed.

---

# Reference scanner baselines

Both reference scanners were run against this repository and their reports are
committed. They exist to separate two failure modes that look identical from the
outside:

- a finding the reference tool **also** missed → **the testbed is wrong**, fix the plant
- a finding the reference tool **caught** but ARVE did not → **ARVE has a real bug**

Without them you cannot tell which system to debug.

| | |
|---|---|
| `gitleaks-baseline.json` | gitleaks **8.30.1**, `gitleaks git .` — **12 findings** (full history) |
| `osv-baseline.json` | osv-scanner **2.5.1**, `osv-scanner scan source --recursive .` — **30 records** |

## Did the reference tools miss anything? No.

**Every one of the 17 planted findings is reported by its reference scanner.**
There are no known-planted-but-undetected findings in this testbed.

| Group | Planted | Detected by reference tool |
|---|---|---|
| `SEC-01` … `SEC-09` | 9 | **9** (10 findings at `HEAD`, 12 across history) |
| `DEP-01` … `DEP-08` | 8 | **8** (29 planted records, all reported) |

That result was **not** free. Three plants were silently undetectable when first
written and were only caught because the scanners were run *during* planting
rather than after:

1. **SEC-07 was invisible.** Written as a wrapped three-line assignment — the
   natural way to format a long key — and matched nothing.
   `generic-api-key` requires the keyword and value on the **same line**.
2. **SEC-02's AWS key ID was invisible.** Gitleaks validates `AKIA…` values
   against the real base32 alphabet (`A–Z`, `2–7`) and rejects any containing
   `0`, `1`, `8` or `9`, at any entropy. Only **4 of 40** naively-random
   candidates were detected; **30 of 30** base32 candidates were.
3. **DEP-07 was pointed at a non-vulnerable package.** `http-proxy@1.18.1` was
   the original choice, but its advisory is *fixed in exactly that version*.
   Re-checking every advisory against its own affected ranges caught it.

Each of those would have surfaced during evaluation as "ARVE missed a finding"
when the truth was that there was nothing there to find.

## Scanner behaviour worth knowing before you diff

### One OSV over-match — expected, and not an ARVE bug

`osv-scanner` reports **PYSEC-2024-230** against `certifi@2018.4.16`. That
advisory's ECOSYSTEM range is `introduced: 2021.5.30`, so 2018.4.16 is **below
the introduced bound and not actually affected** — most likely matched because
the record also carries a GIT range with `introduced: 0`.

It is listed in the inventory so the diff comes out clean. **ARVE reporting it is
correct behaviour** — ARVE faithfully reflects its scanner, and *tools find the
evidence*. Do not "fix" ARVE to suppress it.

### PyPI version normalisation — a real fingerprinting hazard

`backend/requirements.txt` pins `pyyaml==5.1`. **What osv-scanner reports
depends on its version** (verified 2026-09-22):

| osv-scanner | Reported name | Reported version |
|---|---|---|
| **1.9.2** — ARVE's pinned image | `pyyaml` | **`5.1`** (verbatim) |
| **2.5.1** — reference, used for `osv-baseline.json` | `pyyaml` | **`5.1.0`** |

So ARVE, today, keys on `5.1`, while the committed reference baseline says
`5.1.0`. Any fingerprint built from `(package, version)` would resolve-and-reopen
every PyYAML finding the day ARVE upgrades its OSV image. This is not a bug in
either tool, but it must be handled deliberately — and a naive diff of ARVE
output against the reference baseline will not match on this one package. npm
versions are reported verbatim by both.

### Scan the repository, not the filesystem

`gitleaks dir .` on a working copy also walks `.venv/` and `web/node_modules/`
and produces unrelated hits. Both are gitignored, so `gitleaks git .` does not
see them. **SEC-04 is only reachable in `git` mode** — a `dir` scan reports 10
findings, a `git` scan reports 12.

## Why the committed baselines are redacted

`gitleaks-baseline.json` has its `Secret` and `Match` fields replaced with a
SHA-256 prefix. This is not tidiness — the raw report breaks the testbed in two
ways:

1. **It puts SEC-04's password back at `HEAD`.** That finding exists solely to be
   reachable through history. Committing the raw report would place the value in
   a file at `HEAD` and destroy it.
2. **It self-flags.** The raw report trips **17** of gitleaks' own rules, so
   every future scan would jump from 10 findings to 27 and drown the evaluation
   in the baseline describing itself.

Rule, file, line, commit, author, entropy and fingerprint are all preserved
untouched. The hash keeps findings correlatable — **SEC-06's identical value at
both of its lines is still provable from the baseline alone**:

```
line 22  sha256:17c4bb839cb93998
line 43  sha256:17c4bb839cb93998
```

`osv-baseline.json` likewise has the verbose advisory `details` prose stripped:
one advisory's example snippet contains a fake API key in an HTTP header, which
trips `generic-api-key`. Ids, aliases, severities, affected ranges and package
coordinates are all preserved.

**Verified: with both baselines committed, a full scan still reports exactly 10
findings at `HEAD`.** They add zero noise.

**This redacts a *report*, not a *plant*.** Every planted secret remains plain
text exactly where it was planted.

---

# ARVE pipeline view (schema 1.1)

Everything above answers *"is this flaw detectable?"*. This section answers a
different question: **"does it ever reach ARVE's scanners at all?"**

ARVE does not scan this repository as it sits on disk. It scans the subset its
ingestion `FileFilter` allows through, written to a workspace with **no `.git`
directory** (`PROJECT_CONTEXT.md` §2–3). A plant can therefore be missed for
three independent reasons, and telling them apart is the point of this section:

| Miss type | Cause | Whose bug |
|---|---|---|
| **Ingestion gap** | `FileFilter` skipped the file | ARVE Phase 2 |
| **Scanner gap** | the pinned scanner does not detect it | testbed plant, or scanner limitation |
| **Normalizer gap** | detected, then mangled/collapsed/dropped in mapping | ARVE Phase 4A |

The `ingestion` column is computed by
[`scripts/arve_filter_mirror.py`](scripts/arve_filter_mirror.py), a mirror of
ARVE's filter that **may drift from ARVE** — when they disagree, ARVE is right
and the mirror needs updating.

## What ARVE sees today

| ID | File type | Ingestion | ARVE findings | Divergence from this answer key |
|---|---|---|---|---|
| SEC-01 | python | INGESTED | 1 | severity → `MEDIUM` ¹ |
| SEC-02 | github-actions-yaml | INGESTED | 2 | severity → `MEDIUM` ¹ |
| **SEC-03** | pem | **SKIPPED** `unsupported_file_type` | **0** | **ingestion gap** — `.pem` is not in the extension allow-list |
| **SEC-04** | python | **ABSENT_AT_HEAD** | **0** | **history gap** — dir mode, no `.git` |
| SEC-05 | python | INGESTED | 2 | severity → `MEDIUM` ¹; two findings, because the dir-mode fingerprint `file:rule:line` differs per file |
| SEC-06 | python | INGESTED | 1 | severity → `MEDIUM` ¹; ARVE only ever sees HEAD (line 22), so **the line-move lifecycle test is not exercised** |
| SEC-07 | python | INGESTED | 1 | severity → `MEDIUM` ¹ |
| **SEC-08** | dotenv-template | **SKIPPED** `unsupported_file_type` | **0** | **ingestion gap** — `splitext('.env.example')` → `.example`, so the allow-list entry can never match. The SUPPRESSED-lifecycle test cannot run |
| SEC-09 | markdown | INGESTED | 1 | — |
| DEP-01 | pip-requirements | INGESTED | 1 | name `pyyaml`; version **`5.1`** on ARVE's osv 1.9.2 vs `5.1.0` on the reference 2.5.1 |
| DEP-02 | pip-requirements | INGESTED | 1 | both versions also report the `PYSEC-2024-230` over-match — correct behaviour |
| DEP-03 … DEP-08 | npm-package-lock | INGESTED | 1 each, **2 for DEP-05** | — |

¹ ARVE's gitleaks mapper hard-codes `MEDIUM` for every secret. The `severity` in
this answer key is the *intended* severity. Record it, do not "fix" it.

**Totals: 14 of 17 plants reach ARVE's scanners.** Two are lost at ingestion
(SEC-03, SEC-08) and one is history-only (SEC-04).

| Scan | Gitleaks findings | OSV records |
|---|---|---|
| `gitleaks git .` / full tree (reference baseline) | **12** | **30** |
| `gitleaks dir .` at `HEAD` | **10** | **30** |
| **ARVE-simulated** (pinned versions, ingested subset only) | **8** | **30** |

Both ingestion gaps are secrets, so the OSV number is unaffected — both
lockfiles are ingested.

## Scanner verification

Every finding now records whether **ARVE's pinned scanner version** detects it,
separately from the reference version, because rules and extractors differ
across versions.

| | gitleaks 8.24.2 (pinned) | gitleaks 8.30.1 (reference) |
|---|---|---|
| SEC-01 … SEC-09 | **9/9 detected** | **9/9 detected** |

| | osv-scanner 1.9.2 (pinned) | osv-scanner 2.5.1 (reference) |
|---|---|---|
| DEP-01 … DEP-08 | **8/8, 30 records** | **8/8, 30 records** |

The two versions of each tool report the identical set of findings on this
repository — the only difference is the PyYAML version string (DEP-01).

## Negative controls

Things that must produce **zero** findings. If a pinned scanner fires on one, it
moves to `known_false_positives` in `expected-findings.json` with the reason —
that is still useful precision data.

**NEG-01 — the AWS documentation example key ID.** Gitleaks allowlists values
ending in `EXAMPLE`, so this must never fire. It already appears in **four**
committed files, incidentally, as part of the instruction not to use it:
`PROJECT_CONTEXT.md:208`, `plan.md:28`, `KICKSTART_PROMPT.md:40`,
`NEW_PROJECT_START_README.md:315`. All four are INGESTED markdown.
**Verified 2026-09-22: 0 findings in gitleaks 8.24.2 and 8.30.1.**

`known_false_positives` is currently **empty**.

## Scanner limitations — not plants, not scored

Behaviour found while building v1.1. These are **not** planted findings and
**must not** be scored. They are recorded so nobody debugs ARVE over them.

| ID | Rule | Behaviour |
|---|---|---|
| **LIM-01** | `mapbox-api-token` | A Mapbox token in a URL (`...?access_token=pk...`) is **not** matched by the vendor rule — the rule needs the literal word `mapbox` immediately before the `=`. Only `generic-api-key` fires, so rule attribution is lost. Both versions. |
| **LIM-02** | `gcp-api-key` | A Google key followed by `&` (not the last query parameter) is **detected by no rule at all**, because `&` is not in the rule's terminator set. Google's own documented `?key=...&callback=...` order is invisible. Both versions. |
| **LIM-03** | any | `StartColumn` is wrong for a secret deep inside a very long single line, and **differs between versions** (true column 154382; 8.24.2 says 29365, 8.30.1 says 693). The line number is correct. **Not a scoring input** — ARVE's `NormalizedFinding` has no column field. |

`expected-findings.json` carries the exact strings tested, with the secret value
replaced by `{VALUE}` and its shape recorded, so the test can be re-run with a
fresh synthetic value without planting a secret in the answer key.

## Advisory drift since 2026-08-31

`lodash@4.17.11` (DEP-03) still has **7** records, but osv.dev has added CVE
aliases: `GHSA-35jh-r3h4-6jhm` and `GHSA-r5fr-rjxr-66jc` now alias both
CVE-2021-23337 **and** CVE-2026-4800, and `GHSA-f23m-r3pf-42rh` /
`GHSA-xxjr-mmjv-4gpg` alias both CVE-2025-13465 **and** CVE-2026-2950. The
inventory records the original alias for each. This is the world changing, not a
tool misbehaving.

---

# Group C — v1.1 secrets (`SEC-10` …)

New secret plants spread across file types, ecosystems and normalizer edge
cases. Every one records **where in ARVE's pipeline it is lost**, if it is lost:
an ingestion gap (the file never reaches a scanner), a scanner gap (the pinned
scanner does not detect it), or a normalizer gap (detected, then collapsed or
mangled in mapping).

Each was verified against **all four** scanner versions at the moment it was
planted — ARVE-pinned gitleaks **8.24.2** and reference **8.30.1** — and the
result is recorded per plant. Unless a plant says otherwise, both versions
report the identical rule, file and line.

---

## SEC-10 — GitHub token in Java source

**Planted:** a GitHub machine-user token for the private ops-config repository,
as the hardcoded fallback for `OPS_CONFIG_TOKEN`.

| | |
|---|---|
| File | `services/settlement-java/src/main/java/com/acmeledger/settlement/GatewayClient.java` line **25** |
| File type | `java` |
| Engine | `gitleaks` |
| Rule | `github-pat` |
| Severity | `HIGH` (ARVE will report `MEDIUM` — mapper hard-codes it) |
| ARVE ingestion | ✅ INGESTED |
| Expected findings | 1 (ARVE: 1) |

**What this tests:** a JVM source path. The file sits five directories deep
under `src/main/java`, which is where JVM code always lives and where shallow
path handling breaks.

**Verified:** detected by 8.24.2 and 8.30.1 at line 25, column 50. The Twilio
account SID on the neighbouring properties file is a real *shape* but not a
credential, and correctly produces nothing.

---

## SEC-11 — Twilio key in `application.properties` ⛔ ingestion gap

**Planted:** the Twilio API key used for settlement-failure SMS alerts, in the
Spring-style properties file.

| | |
|---|---|
| File | `services/settlement-java/src/main/resources/application.properties` line **12** |
| File type | `java-properties` |
| Engine | `gitleaks` |
| Rule | `twilio-api-key` |
| Severity | `HIGH` |
| ARVE ingestion | ⛔ **SKIPPED** `unsupported_file_type` |
| Expected findings | 1 on disk — **0 from ARVE** |

**What this tests:** **an ingestion gap, isolated.** Both gitleaks versions
detect this at line 12 when shown the file, so a miss here is *provably* ARVE's
Phase 2 filter and not a scanner limitation. `.properties` is not in the
extension allow-list, and `os.path.splitext` gives `.properties`, which matches
nothing.

`application.properties` is where JVM services conventionally keep credentials,
which makes it arguably the most valuable extension missing from the allow-list.

**Do not "fix" this by renaming the file.** Surfacing the gap is the point —
see `ARVE_ISSUES.md` issue 1.

---

## SEC-12 — Google API key inside a CSS `url()`

**Planted:** a Google Static Maps key in the `background-image` of the status
page's regional map.

| | |
|---|---|
| File | `apps/status-page/styles.css` line **48** |
| File type | `css` |
| Engine | `gitleaks` |
| Rule | `gcp-api-key` |
| Severity | `HIGH` |
| ARVE ingestion | ✅ INGESTED |
| Expected findings | 1 (ARVE: 1) |

**What this tests:** a credential inside a stylesheet — a file type nobody
thinks of as holding secrets, in a URL rather than an assignment.

**⚠ Shape constraint that silently breaks this plant.** The key **must be the
last query parameter**. `gcp-api-key` requires the value to be followed by a
quote, whitespace, semicolon or end of line. `&` is not in that set, so

```
?key=AIza...&callback=initMap      → detected by NO rule, in either version
?center=...&key=AIza..."           → detected
```

Google's own documented script-tag order is the undetectable one. Recorded as
`LIM-02` in `scanner_limitations`.

**Version difference worth knowing:** `gcp-api-key`'s entropy threshold rose
from **3** (8.24.2) to **4** (8.30.1). A random 35-character value clears both;
a low-entropy one would pass the pinned version and fail the reference.

---

## SEC-13 — Mapbox token in an inline `<script>`

**Planted:** a Mapbox public access token assigned to `mapboxgl.accessToken`,
exactly as Mapbox's own documentation shows it.

| | |
|---|---|
| File | `apps/status-page/index.html` line **37** |
| File type | `html` |
| Engine | `gitleaks` |
| Rule | `mapbox-api-token` |
| Severity | **`MEDIUM`** (deliberately not HIGH) |
| ARVE ingestion | ✅ INGESTED |
| Expected findings | 1 (ARVE: 1) |

**What this tests:** a vendor rule firing in HTML, and **severity that is not
uniform**. A Mapbox public token is referrer-restricted by design, so this is a
real leak but a milder one. ARVE currently reports `MEDIUM` for every secret, so
it will agree with this one **for the wrong reason** — which is exactly why
having a genuinely-MEDIUM secret in the set is useful once severity is fixed.

**⚠ The same token in a URL is invisible to this rule.** Written as
`?access_token=pk...` inside a `url()`, `mapbox-api-token` does **not** match —
the rule needs the literal word `mapbox` immediately before the `=`. Only
`generic-api-key` fires, so the vendor attribution is lost. Recorded as
`LIM-01`.

---

## SEC-14 — GitLab token in TypeScript

**Planted:** a GitLab `read_api` token in the admin console's deploy-status
widget.

| | |
|---|---|
| File | `apps/admin-ui/src/deployStatus.ts` line **15** |
| File type | `typescript` · Rule `gitlab-pat` · Severity `HIGH` |
| ARVE ingestion | ✅ INGESTED · Expected findings 1 (ARVE: 1) |

**What this tests:** the `.ts` extension. Deliberately an easy plant — its value
is file-type coverage, not difficulty. Detected by both versions at line 15.

---

## SEC-15 — npm token in `.npmrc` ⛔ ingestion gap

**Planted:** an npm registry auth token on the conventional
`//registry.npmjs.org/:_authToken=` line.

| | |
|---|---|
| File | `apps/admin-ui/.npmrc` line **6** |
| File type | `npmrc` · Rule `npm-access-token` · Severity `HIGH` |
| ARVE ingestion | ⛔ **SKIPPED** `unsupported_file_type` · 1 on disk, **0 from ARVE** |

**What this tests:** **dotfiles with no extension.** `os.path.splitext('.npmrc')`
returns `''` — for any dotfile the whole name is the stem. This is the same
behaviour that makes the `.env` entry in ARVE's allow-list unreachable, so this
plant and SEC-08 fail for one shared root cause.

An npm publish token is a supply-chain credential, which is what makes this
class of file worth ingesting.

---

## SEC-23 — one credential, three file types

**Planted:** one analytics collector write key, byte-identical in three files.

| | |
|---|---|
| Files | `apps/admin-ui/src/analyticsClient.js` line **11** (`javascript`) |
| | `ops/k8s/admin-ui-config.yaml` line **12** (`kubernetes-yaml`) |
| | `tools/analytics_export.py` line **17** (`python`) |
| Rule | `generic-api-key` · Severity `HIGH` |
| ARVE ingestion | ✅ all three INGESTED |
| **Expected findings** | **3** (ARVE: 3) |

**What this tests:** **SEC-05 widened.** SEC-05 puts one secret in two files of
the *same* type; this puts one secret in three *different* types. Gitleaks
reports three findings with three distinct fingerprints, because the dir-mode
fingerprint is `file:rule:line`.

So ARVE reports **3 findings for 1 leaked credential**. Rotating the key closes
three at once; fixing one file leaves two open pointing at stale paths. Either
choice is defensible — it has to be deliberate.

Read this next to **SEC-22**, where two *different* credentials collapse into
*one* fingerprint. The identity field is wrong in both directions at once.

---

## SEC-24 — admin key in a minified bundle

**Planted:** an Algolia **admin** key (not a search key) inlined into a
generated vendor bundle — which is how this leak really happens.

| | |
|---|---|
| File | `apps/admin-ui/public/vendor.min.js` line **1** |
| File type | `javascript-minified` · Rule `algolia-api-key` · Severity `HIGH` |
| ARVE ingestion | ✅ INGESTED · Expected findings 1 (ARVE: 1) |

**What this tests:** long-line handling. The file is a single **154,478-byte
line** and the secret sits at column **154444**. Both versions find it on line 1.

**The reported column is wrong, and the two versions disagree:**

| | Column |
|---|---|
| True position | **154444** |
| gitleaks 8.24.2 | 29427 |
| gitleaks 8.30.1 | 755 |

**This is not part of the plant's expected values and must not be scored.**
ARVE's `NormalizedFinding` has no column field, so the wrong value is dropped in
mapping rather than stored. Recorded as `LIM-03`.

**Naming matters:** gitleaks' global allowlist exempts named vendor bundles
(`jquery*`, `angular*`, `bootstrap*`, `plotly*`, `swagger-ui*`). Calling this
file `jquery.min.js` would have silently suppressed the finding.

---

## SEC-16 — Slack bot token in Go

| | |
|---|---|
| File | `services/reconciler-go/main.go` line **23** |
| File type | `go` · Rule `slack-bot-token` · Severity `HIGH` |
| ARVE ingestion | ✅ INGESTED · Expected findings 1 (ARVE: 1) |

**What this tests:** Go source. The `go.mod` beside it carries **DEP-11**, so
this one service exercises the secret and dependency paths together.

---

## SEC-17 — Hugging Face token on a Dockerfile `ENV` line

| | |
|---|---|
| File | `ops/Dockerfile` line **6** |
| File type | `dockerfile` · Rule `huggingface-access-token` · Severity `HIGH` |
| ARVE ingestion | ✅ INGESTED · Expected findings 1 (ARVE: 1) |

**What this tests:** the **filename** allow-list rather than the extension list.
`Dockerfile` has no extension at all — `splitext` gives `''`, exactly as for
`.npmrc` — but `dockerfile` is an allowed *filename*, so it is ingested while
SEC-15 is not. The two plants together show that the allow-list, not the
absence of an extension, decides.

A token on an `ENV` line also persists into every layer of the built image.

---

## SEC-18 — EC private key in a Kubernetes Secret ✅ the control for SEC-03

| | |
|---|---|
| File | `ops/k8s/secrets.yaml` line **12** |
| File type | `kubernetes-yaml` · Rule `private-key` · Severity `HIGH` |
| ARVE ingestion | ✅ INGESTED · Expected findings 1 (ARVE: 1) |

**What this tests:** **the same rule as SEC-03, in a file ARVE actually
ingests.** A genuine throwaway EC P-256 key, indented inside `stringData`.

| | File type | Ingestion | ARVE |
|---|---|---|---|
| SEC-03 | `.pem` | ⛔ SKIPPED | 0 |
| **SEC-18** | `.yaml` | ✅ INGESTED | 1 |

If ARVE reports SEC-18 but not SEC-03, the difference is **provably ingestion**
and not the `private-key` rule. Without this control, SEC-03's absence is
ambiguous.

The adjacent fake `CERTIFICATE` block correctly produces nothing.

---

## SEC-19 — Terraform Cloud token in `main.tf` ⛔ ingestion gap

| | |
|---|---|
| File | `ops/terraform/main.tf` line **17** |
| File type | `terraform` · Rule `hashicorp-tf-api-token` · Severity `HIGH` |
| ARVE ingestion | ⛔ **SKIPPED** `unsupported_file_type` · 1 on disk, **0 from ARVE** |

**What this tests:** **infrastructure-as-code.** Both versions detect it at line
17 when shown the file. `.tf` and `.tfvars` are both missing from the allow-list,
so the file type where cloud credentials concentrate is entirely invisible.

---

## SEC-20 — Shopify token in a shell script

| | |
|---|---|
| File | `ops/scripts/backup.sh` line **14** |
| File type | `shell` · Rule `shopify-access-token` · Severity `HIGH` |
| ARVE ingestion | ✅ INGESTED · Expected findings 1 (ARVE: 1) |

**What this tests:** operational glue, where long-lived tokens survive longest.
Pairs with SEC-26 below.

---

## SEC-26 — PyPI token under `ops/build/` ⛔ ingestion gap (directory filter)

| | |
|---|---|
| File | `ops/build/publish.sh` line **12** |
| File type | `shell` · Rule `pypi-upload-token` · Severity `HIGH` |
| ARVE ingestion | ⛔ **SKIPPED** `ignored_directory` · 1 on disk, **0 from ARVE** |

**What this tests:** **the directory filter, isolated.** SEC-20 and SEC-26 are
both `.sh` files with vendor-rule tokens. The *only* difference is one path
segment:

| | Path | Ingestion |
|---|---|---|
| SEC-20 | `ops/scripts/backup.sh` | ✅ INGESTED |
| **SEC-26** | `ops/**build**/publish.sh` | ⛔ SKIPPED `ignored_directory` |

The ignored-directory list (`build`, `dist`, `target`, `vendor`, `coverage`, …)
exists to skip *generated* output. But `build` also names hand-written release
tooling — and this file is tracked in Git, not generated. `.gitignore`
deliberately does not ignore `ops/build/`, so it really is committed.

The skip happens **before** the size and extension checks, so nothing later can
rescue it.

---

## SEC-21 — JWT in a SQL seed file

| | |
|---|---|
| File | `db/seed.sql` line **13** |
| File type | `sql` · Rule `jwt` · Severity `HIGH` |
| ARVE ingestion | ✅ INGESTED · Expected findings 1 (ARVE: 1) |

**What this tests:** a third *rule class*. Not a vendor prefix (SEC-10, SEC-14,
SEC-16 …) and not entropy-next-to-a-keyword (SEC-07, SEC-22, SEC-23), but
**document structure** — `header.payload.signature`, base64url.

The header and payload decode to real JSON; the signature is 32 random bytes, so
the token is correctly shaped and verifies against nothing.

---

## SEC-22 — two different secrets on one line 🔁 normalizer collapse

**Planted:** a rotation pair — two *different* 40-character credentials — in one
dict literal on a single line.

| | |
|---|---|
| File | `tools/sync_keys.py` line **16** (columns 15 and 78) |
| File type | `python` · Rule `generic-api-key` · Severity `HIGH` |
| ARVE ingestion | ✅ INGESTED |
| Gitleaks findings | **2** |
| **Expected ARVE findings** | **1 — the second credential is silently lost** |

**What this tests:** **`secret_hash` identity.** Both versions report two
findings, and both carry the *identical* fingerprint:

```
tools/sync_keys.py:generic-api-key:16     ← column 15
tools/sync_keys.py:generic-api-key:16     ← column 78
```

ARVE sets `secret_hash` to that fingerprint. Because it also passes `--redact`,
there is **no secret value** to disambiguate with, and `StartColumn` — the only
field that differs — is not carried on `NormalizedFinding` (and is unreliable
anyway, see `LIM-03`). So two leaked credentials become one finding, and only
one gets rotated.

**Do not "fix" this** by moving the secrets onto separate lines. The collapse is
the measurement. See `ARVE_ISSUES.md` issue 3.

Read together with **SEC-23**: one credential in three files becomes three
findings, while two credentials on one line become one. The identity field is
wrong in both directions.

---

## SEC-25 — Square token in a 1.2 MB fixture ⛔ ingestion gap (size limit)

| | |
|---|---|
| File | `db/fixtures/merchant_export.json` line **38901** |
| File type | `json-fixture` · Rule `square-access-token` · Severity `HIGH` |
| ARVE ingestion | ⛔ **SKIPPED** `file_too_large` · 1 on disk, **0 from ARVE** |

**What this tests:** **the size limit.** The file is **1,262,651 bytes** against
a **1,048,576-byte** cap — 214,075 bytes over.

| | |
|---|---|
| File size | 1,262,651 bytes |
| ARVE limit | 1,048,576 bytes |
| Extension | `.json` — allowed, but never reached |

The size check runs **before** the extension check, so being an allowed type
cannot rescue it. Large exports, database dumps and fixtures are exactly where
bulk credential leaks hide. The other 5,399 merchant records contain no
credential-shaped values and produce nothing.

---

## SEC-27 — a secret rotated in place 🔁 lifecycle

**Planted:** a New Relic ingest key whose value is **changed in place** in a
later commit — same file, same line, different value.

| | |
|---|---|
| File | `services/notifier-rust/notifier.toml` line **14** |
| File type | `toml` · Rule `new-relic-user-api-key` · Severity `HIGH` |
| ARVE ingestion | ✅ INGESTED |
| Reference `gitleaks git` | **2 findings** — pre- and post-rotation values |
| **Expected ARVE findings** | **1, continuously OPEN — the rotation is never observed** |

**What this tests:** the rotation lifecycle. **This divergence is expected
behaviour to record, not a defect in the plant:**

- ARVE scans **only HEAD**, so the old value does not exist for it.
- The dir-mode fingerprint `file:rule:line` is **identical** before and after,
  so even with history the two would share one identity.

A replaced credential is therefore indistinguishable from an untouched one. The
finding never transitions — it is not RESOLVED for the old key and not reopened
for the new one.

This completes a set of three:

| Plant | Change | Gitleaks sees | Consequence |
|---|---|---|---|
| **SEC-06** | same value, **line moves** | 2 fingerprints | looks like a *new* leak |
| **SEC-22** | different values, **same line** | 1 fingerprint | two leaks become *one* |
| **SEC-27** | **value replaced**, same line | 1 fingerprint at HEAD | rotation is *invisible* |

The pre-rotation value is derived from a fixed seed by `seed_history.py` and
never appears at HEAD. The rotation commit and its hash are added in Phase 5.

---

# Group D — v1.1 dependencies (`DEP-09` …)

Ten new ecosystems and lockfile formats. **Every lockfile is genuine
package-manager output**, produced by running the real tool in a throwaway
container — `yarn install`, `pnpm install --lockfile-only`, `go mod tidy`,
`cargo generate-lockfile`, `poetry lock`, `pip-compile`, `bundle lock`,
`dotnet restore --use-lock-file`, `gradle dependencies --write-locks`. Only
`pom.xml` is hand-written, because OSV reads it as a manifest rather than a
lockfile.

**The headline result: five of the twelve are invisible to ARVE**, and in every
case the pinned scanner parses the file perfectly well when allowed to see it.
That makes each of them a clean ingestion gap rather than a scanner limitation.

| ID | File | Package | Records | ARVE |
|---|---|---|---|---|
| DEP-09 | `services/settlement-java/pom.xml` | commons-text 1.9 | 1 | ✅ 1 |
| **DEP-10** | `services/payout-scheduler/gradle.lockfile` | snakeyaml 1.33 | 1 | ⛔ **0** |
| DEP-11 | `services/reconciler-go/go.mod` | golang.org/x/text 0.3.8 | 1 | ✅ 1 |
| **DEP-12** | `services/notifier-rust/Cargo.lock` | ansi_term 0.12.1 | 1 | ⛔ **0** |
| DEP-13 | `apps/admin-ui/yarn.lock` | json5 2.2.1 | 1 | ✅ 1 |
| DEP-14 | `apps/partner-webhooks/pnpm-lock.yaml` | node-fetch 2.6.0 | 2 | ✅ 2 |
| DEP-15 | `services/ledger-export-dotnet/packages.lock.json` | Newtonsoft.Json 12.0.1 | 1 | ✅ 1 |
| **DEP-16** | `tools/poetry.lock` | wheel 0.37.0 | 2 | ⛔ **0** |
| **DEP-17** | `tools/requirements-dev.txt` | jinja2 3.1.5 | 2 | ⛔ **0** |
| **DEP-18** | `apps/merchant-portal/Gemfile.lock` | addressable 2.7.0 | 2 | ⛔ **0** |
| DEP-19 | `apps/admin-ui/yarn.lock` | minimist 1.2.0 (= DEP-05) | 2 | ✅ 2 |
| DEP-20 | `apps/partner-webhooks/pnpm-lock.yaml` | minimist 0.0.8 **+** 1.2.5 | 3 | ⚠ **2** |

---

## DEP-09 — Maven manifest, read directly

`org.apache.commons:commons-text 1.9` — **CVE-2022-42889** (Text4Shell),
`CRITICAL`, 1 record, at `pom.xml` line **19**. ✅ INGESTED.

`pom.xml` is the one dependency source OSV reads as a *manifest*, so this proves
the Maven path independently of DEP-10.

**⚠ Both OSV versions resolve Maven transitively over the network** (via
deps.dev). commons-text 1.9 pulls `commons-lang3 3.11`, which has its own
advisory — so `commons-lang3` is pinned to **3.20.0** in `dependencyManagement`
purely to hold the noise floor at zero. **Without that pin this file reports 2
records, not 1.**

*Substitution:* log4j-core 2.14.1 was the original candidate. It carries **7**
advisories, two published in 2026 and still growing.

---

## DEP-10 — Gradle lockfile ⛔ ingestion gap

`org.yaml:snakeyaml 1.33` — CVE-2022-1471, `HIGH`, 1 record, line **4**.
⛔ SKIPPED `unsupported_file_type`.

Two JVM modules, different outcomes: `pom.xml` is ingested, `gradle.lockfile` is
not. The gap is the **filename allow-list**, not the ecosystem.

---

## DEP-11 — Go, with no severity data at all

`golang.org/x/text 0.3.8` — reported as **`GO-2026-5970`**, 1 record, `go.mod`
line **5**. ✅ INGESTED.

**The cleanest severity-fallback test in the suite.** The record has a CVE alias
but **no GHSA alias, no CVSS vector, no GitHub severity string and no ecosystem
severity** — so severity falls all the way through to the `MEDIUM` default.
DEP-08 still has a `moderate` string to fall back on; this one has nothing.

`go 1.27.1` is pinned to the current toolchain so no Go **stdlib** advisories
appear. *Version choice:* 0.3.7 would add two more records; 0.3.8 gives exactly
one.

**Note:** osv-scanner v1.9.2 also attempts `govulncheck` call analysis and logs
a non-fatal failure (its bundled Go is older than the `go` directive). The
record is still reported.

---

## DEP-12 — Rust, an ID that is neither CVE nor GHSA ⛔ ingestion gap

`ansi_term 0.12.1` — **`RUSTSEC-2021-0139`**, 1 record, `Cargo.lock` line **6**.
⛔ SKIPPED `unsupported_file_type`.

**This is an informational "unmaintained crate" notice, not an exploitable
vulnerability** — the record carries
`affected[].database_specific.informational == "unmaintained"`. It is the only
record in the testbed with **no CVE and no GHSA**, so ARVE must key it on the
RUSTSEC id alone and must not drop it for lacking both.

Whether unmaintained-crate notices should surface as security findings is a
product decision worth making deliberately. Every RUSTSEC advisory found without
a CVE or GHSA alias was of this informational kind — genuine RUSTSEC
vulnerabilities get mirrored to GHSA.

**The Rust gap is total:** `Cargo.toml` is ingested and `Cargo.lock` is not, so
the ecosystem is scanned as empty.

---

## DEP-13 — yarn classic lockfile

`json5 2.2.1` — CVE-2022-46175, `HIGH`, 1 record, line **5**. ✅ INGESTED.

*Substitution:* axios was the candidate — **29 advisories at 1.6.0, 30 at
1.7.4**, mostly from 2026 and still climbing.

---

## DEP-14 — pnpm lockfile v9.0

`node-fetch 2.6.0` — CVE-2022-0235 `HIGH` plus **GHSA-w7rc-rwvf-8q5r `LOW`**,
2 records, line **34**. ✅ INGESTED.

**A real risk worth testing:** osv-scanner v1.9.2 predates pnpm 9 considerably.
Had it failed to parse lockfileVersion 9.0, the plant would have been
undetectable for ARVE while working fine for the reference version. **Verified:
both parse it identically.**

GHSA-w7rc-rwvf-8q5r is the **only `LOW` record in the testbed** — the canonical
severity vocabulary now gets exercised end to end.

---

## DEP-15 — NuGet, ingested by accident

`Newtonsoft.Json 12.0.1` — CVE-2024-21907, `HIGH`, line **5**. ✅ INGESTED.

**Ingested by accident, not design:** `packages.lock.json` is not in the
filename allow-list, but `.json` is in the *extension* allow-list. That is the
only reason NuGet works where Cargo, Poetry and Bundler do not.

**⚠ Scanner-version divergence:** osv-scanner **2.5.1 reports this package
twice** — from `packages.lock.json` *and* from `LedgerExport.csproj` — while
**1.9.2 reports it once**. ARVE is unaffected today because `.csproj` is
skipped, but if the allow-list ever gained `.csproj`, the same vulnerability
would become **two** findings, since `file_path` is part of the fingerprint.

---

## DEP-16 — Poetry lockfile ⛔ ingestion gap

`wheel 0.37.0` — CVE-2022-40898 `HIGH` + `PYSEC-2022-43017` (alias duplicate, no
severity data), 2 records, line **4**. ⛔ SKIPPED.

**Python is where ARVE's ingestion is least consistent:** `requirements.txt` ✅,
`pyproject.toml` ✅, but `poetry.lock` and `Pipfile.lock` — the files that
actually pin versions — ⛔.

---

## DEP-17 — `requirements-dev.txt` ⛔ ingestion gap (exact-name matching)

`jinja2 3.1.5` — CVE-2025-27516 + `PYSEC-2026-1471`, 2 records, line **1**.
⛔ SKIPPED.

**Confirmed: osv-scanner v1.9.2 parses this filename perfectly well.** The miss
is entirely the allow-list, which matches the exact string `requirements.txt`.
Every `requirements-*.txt` variant — dev, test, ci, prod — is invisible, and
splitting dev dependencies out this way is a common layout.

*Version choice:* 3.1.4 gives 6 records; 3.1.5 gives 2. `markupsafe 3.0.3` is
advisory-free.

---

## DEP-18 — RubyGems ⛔ ingestion gap

`addressable 2.7.0` — CVE-2021-32740 + CVE-2026-35611, both `HIGH`, 2 records,
line **4**. ⛔ SKIPPED.

`public_suffix 4.0.7`, its only dependency, is advisory-free. *Packagist was
dropped:* the best candidate found (`guzzlehttp/psr7 1.8.1`) carries 6
advisories.

---

## DEP-19 — the same package version in a second lockfile ✅ positive control

`minimist 1.2.0` in `apps/admin-ui/yarn.lock` line **15** — the **identical**
package, version and advisory pair as **DEP-05** in `web/package-lock.json`.

Because `file_path` **is** an input to the dependency fingerprint, these must be
**2 findings distinct from DEP-05's 2** — four in total for one package version.

This is the positive control for DEP-20: it proves the fingerprint *does*
separate by file, which is what makes the missing version a specific defect
rather than general collapsing.

---

## DEP-20 — two versions of one package in one lockfile 🔁 normalizer collapse

`apps/partner-webhooks/pnpm-lock.yaml` holds **minimist 0.0.8** (pinned exactly
by `mkdirp@0.5.1`, a genuine advisory-free parent, line **23**) and **minimist
1.2.5** (direct, line 26).

| Version | Advisory | Severity |
|---|---|---|
| 0.0.8 | GHSA-vh95-rmgr-6w4m | MEDIUM |
| **0.0.8** | **GHSA-xvch-5gv4-984h** | **CRITICAL** |
| **1.2.5** | **GHSA-xvch-5gv4-984h** | **CRITICAL** |

(`vh95` is fixed in 1.2.3, so 1.2.5 carries only one.)

**OSV reports 3 records. ARVE should emit 2.** The two `GHSA-xvch-5gv4-984h`
rows differ *only* by version, and version is **not** an input to
`SHA256(engine | dependency | package | ecosystem | vuln_id | file_path)`.

This is not just a miscount. The two versions have **different fixed versions**
and arrive by **different paths** (one direct, one through `mkdirp`), so they are
two separate pieces of remediation work — and one of them silently disappears.
See `ARVE_ISSUES.md` issue 4.

---

# Group E — Negative controls (`NEG-01` …)

**These must produce zero findings.** They exist to measure precision, which
recall-only testing misses entirely: a scanner that reports everything scores
100% recall and is useless.

All six are **INGESTED**, so they are inside ARVE's view — they test the
scanners and the normalizer, not the filter. Verified 2026-09-22 against all
four scanner versions. `known_false_positives` is **empty**: nothing fired.

| ID | What | Where | Result |
|---|---|---|---|
| NEG-01 | AWS documentation example keys | 5 files | ✅ silent |
| NEG-02 | env-var references, no values | 3 files | ✅ silent |
| NEG-03 | low-entropy placeholders | `ops/scripts/env.sample.sh` | ✅ silent |
| NEG-04 | a **patched** lodash | `apps/admin-ui/yarn.lock` | ✅ silent |
| NEG-05 | vulnerable pin, **no lockfile** | `apps/status-page/package.json` | ✅ silent |
| NEG-06 | sha256 checksum near "hash" | `ops/scripts/verify_artifact.sh` | ✅ silent |

---

## NEG-01 — the AWS documentation example keys

Gitleaks allowlists `AKIA…EXAMPLE` values in its `aws-access-token` rule. The
value appears **five** times in this repository:

| File | Line | Origin |
|---|---|---|
| `PROJECT_CONTEXT.md` | 208 | incidental — the rule saying never to use it |
| `plan.md` | 28 | incidental |
| `KICKSTART_PROMPT.md` | 40 | incidental |
| `NEW_PROJECT_START_README.md` | 315 | incidental |
| **`docs/cloud-setup.md`** | **13–14** | **planted** — key ID *and* secret access key in a fenced ini block |

All five are ingested markdown and all five must stay silent. Contrast
**SEC-02**, a *synthetic* AWS key that uses the real base32 alphabet and **is**
detected — the difference is the allowlist, not the shape.

---

## NEG-02 — environment-variable references

`tools/env_check.py`, `apps/admin-ui/src/env.ts` and
`.github/workflows/admin-ui.yml` reference credentials by **name** only:
`os.environ.get("STRIPE_API_KEY")`, `import.meta.env.VITE_GITLAB_TOKEN`,
`${{ secrets.NPM_TOKEN }}`.

**Why this is a real test:** the variable names deliberately match planted
secrets elsewhere in the repo — `STRIPE_API_KEY` (SEC-01), `JWT_SIGNING_KEY`
(SEC-05), `SLACK_BOT_TOKEN` (SEC-16), `ANALYTICS_API_KEY` (SEC-23). A rule
keying on the keyword rather than the value fires here. Neither version does.

This is also the *correct* way to handle secrets, and it is everywhere in real
code. False positives on good practice are the fastest route to a tool being
ignored.

---

## NEG-03 — low-entropy placeholders

`ops/scripts/env.sample.sh` holds `API_KEY=changeme`,
`AUTH_TOKEN="<your-token-here>"`, and — more interestingly — two values with
**real vendor prefixes**: `sk_live_REPLACE_ME` and
`xoxb-000000000000-000000000000-REPLACE_ME`.

Only the shape of the remainder stops those matching. This is the exact
counterpart of **SEC-07**: that plant proves a *high*-entropy value next to a
credential keyword is caught; this proves a *low*-entropy one next to the same
keyword is not.

---

## NEG-04 — a patched version of a planted package

`lodash 4.18.1` in `apps/admin-ui/yarn.lock`, against `lodash 4.17.11` (DEP-03,
7 advisories) in `web/package-lock.json`. A finding here would mean version
ranges are ignored and packages are flagged by name.

> **The originally proposed control was rejected during verification.**
> `lodash 4.17.21` — the usual "safe" lodash — **still carries 3 live
> advisories** (GHSA-f23m-r3pf-42rh, GHSA-r5fr-rjxr-66jc, GHSA-xxjr-mmjv-4gpg).
> It would have been a vacuous control that quietly expected findings. 4.18.1 is
> the current latest, published 2026-04-01, and returns **0**. Its `resolved`
> hash and `integrity` were checked against the npm registry to confirm the
> lockfile is genuine resolution rather than a hand-edited version bump.

---

## NEG-05 — a vulnerable pin with no lockfile

`apps/status-page/package.json` pins **`lodash 4.17.11`** — the exact version
planted as DEP-03, with 7 advisories — and there is **no lockfile** in that
directory. OSV reports nothing.

This is the negative counterpart of **DEP-04**, which is reachable *only*
through a lockfile. Together they show that lockfile presence, not manifest
content, decides what OSV sees.

It also documents a genuine blind spot worth stating plainly: **a project with
no committed lockfile gets no dependency findings at all**, however old its pins
are.

---

## NEG-06 — a checksum next to the word "hash"

`ops/scripts/verify_artifact.sh` holds
`ARTIFACT_HASH="9f86d081…b0f00a08"` — 64 hex characters, high entropy, beside
`EXPECTED_HASH_ALGO`. Checksums are everywhere in release tooling.

**Result: silent in both versions** — but for a shallow reason worth recording.
`hash` is **not** in `generic-api-key`'s keyword list (`access`, `auth`, `api`,
`credential`, `creds`, `key`, `passwd`, `password`, `secret`, `token`), so the
value is never considered at all. That is precision by vocabulary, not by
understanding: renaming the variable to `ARTIFACT_KEY` would likely fire on a
value that is not a credential.
