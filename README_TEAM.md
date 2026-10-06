# README for the team — start here

This is the deliberately vulnerable repository we built so you can test a scanner
against something whose answers are already known.

You did not build it, so nothing here should require guessing. **This is the only
onboarding document.** It should take you from a fresh clone to a verified scan
without asking anyone. If something is missing, that is a bug in this file —
please say so rather than writing a second guide.

---

## 0. Before anything else: every credential here is fake

This repository contains things that look exactly like real leaked secrets — a
Stripe key, AWS credentials, private keys, tokens for GitHub, GitLab, Slack, npm,
Shopify, PyPI and more.

**Every one is synthetic.** Each was randomly generated with the correct *shape*
so scanners match it, and is valid for no real service. None has ever been live.
**Nothing needs to be reported, rotated or revoked.** The outdated packages are
pinned on purpose too.

> **Do not deploy this anywhere, and do not `npm install` / `pip install` it on a
> machine you care about.** Not because it will attack you — it will not — but
> because it deliberately installs old, genuinely vulnerable library versions.
> Use a container or a throwaway virtualenv.

---

## 1. What this testbed measures — and what it does not

**On the surface** this is a small double-entry payments ledger: FastAPI, SQLite,
seven endpoints, plus a handful of satellite services in other languages. The
application is deliberately boring. It exists to give planted flaws a *plausible
place to live* — the webhook endpoint exists so that a signing secret in the
codebase looks like ordinary engineering rather than an obviously planted flaw.

**Underneath** it is a scoring instrument. Every flaw was planted deliberately
and recorded in a machine-readable answer key *at the moment it was planted*, so
a scanner's output can be diffed against ground truth instead of eyeballed.

### The standing caveat — please repeat it whenever you quote a score

> **This testbed measures the Gitleaks + OSV-Scanner path only. It is never a
> measure of ARVE overall.**
>
> It says nothing about ARVE's triage, remediation, reporting, LLM explanation
> quality, sandbox security or performance. A score of "47/47" would mean *the
> secret and dependency path behaved as documented* — nothing more. There is
> deliberately **no SQL injection, XSS, path traversal, SSRF or broken access
> control** here, because those need SAST (Semgrep), which is not wired into ARVE
> yet. Planting them would test nothing and pollute the results.

---

## 2. The one idea this testbed is built around

A scanner benchmark usually asks *"did the tool find the flaw?"*. That question
is not useful for ARVE, because **ARVE never sees this repository as it exists on
disk.** It ingests a filtered subset of files into a workspace with **no `.git`
directory**, and scans that.

So a planted flaw can be missed for three completely different reasons, and
telling them apart is the whole point:

| Miss type | What happened | Whose problem | How you recognise it |
|---|---|---|---|
| **Ingestion gap** | the file never reached a scanner | **ARVE Phase 2** | the reference tool finds it; `arve_filter_mirror.py` says `SKIPPED` |
| **Scanner gap** | the scanner genuinely cannot detect it | the testbed, or the scanner | the reference tool *also* misses it |
| **Normalizer gap** | detected, then collapsed or mangled in mapping | **ARVE Phase 4A** | the scanner reports N, ARVE stores fewer |

**There are currently no known scanner gaps.** Every plant is detected by its
reference tool *and* by ARVE's own pinned scanner version when that scanner is
allowed to see the file. So in practice, any miss is an ingestion or normalizer
gap — and the testbed is arranged so you can prove which.

### Control pairs — how a gap is proven rather than asserted

Each pair is identical except for the one variable being tested. If ARVE reports
one and not the other, the cause is isolated:

| Pair | Identical | Differs only in | Proves |
|---|---|---|---|
| SEC-03 / **SEC-18** | `private-key` rule, real key | `.pem` vs `.yaml` | the extension allow-list, not the rule |
| SEC-20 / **SEC-26** | `.sh`, vendor token | `ops/scripts/` vs `ops/build/` | the ignored-directory filter |
| SEC-15 / **SEC-17** | no file extension at all | `.npmrc` vs `Dockerfile` | the filename allow-list |
| DEP-05 / **DEP-19** | same package+version+advisories | two different lockfiles | `file_path` *is* in the fingerprint — works |
| DEP-19 / **DEP-20** | same lockfile machinery | two files vs two versions | the version is *missing* from the fingerprint — breaks |
| SEC-22 / **SEC-23** | `generic-api-key` | 2 secrets 1 line vs 1 secret 3 files | `secret_hash` identity, failing in both directions |

---

## 3. Run it — five minutes

Requires **Docker** (for the scanners) and **Python 3.11+**. Nothing is installed
on your machine; the scanners run in throwaway containers.

### 3.1 Verify the whole testbed

```bash
python scripts/verify_plants.py
```

This is the **single source of truth for every number** in this repository. It:

1. materialises HEAD the way ARVE receives it (LF endings, no `.git`);
2. computes the subset ARVE's filter would ingest;
3. runs **all four** scanner versions in Docker;
4. diffs every run against `expected-findings.json`;
5. exits **non-zero** on any difference the answer key does not explain.

| Role | Image | Why this one |
|---|---|---|
| Gitleaks, **ARVE-pinned** | `ghcr.io/gitleaks/gitleaks:v8.24.2` | what ARVE actually runs |
| Gitleaks, reference | `ghcr.io/gitleaks/gitleaks:v8.30.1` | current release, produced the baseline |
| OSV-Scanner, **ARVE-pinned** | `ghcr.io/google/osv-scanner:v1.9.2` | what ARVE actually runs |
| OSV-Scanner, reference | `ghcr.io/google/osv-scanner:v2.5.1` | current release, produced the baseline |

Useful flags: `--quick` (pinned versions only), `--counts-only` (no scanning),
`--json out.json` (machine-readable results).

Secret values are never printed or written: gitleaks runs with `--redact`, and
only rule / file / line are shown.

### 3.2 What a pass looks like

```
ingestion [PREDICTED by scripts/arve_filter_mirror.py, not by ARVE]
  ok    70 of 88 files ingested, 18 skipped
            1 file_too_large
            1 ignored_directory
           16 unsupported_file_type

secrets (gitleaks)
  ok    8.24.2 dir at HEAD: 31 findings, exactly as expected
  ok    8.24.2 git full history: 34 findings, exactly as expected
  ok    8.24.2 ARVE-simulated [PREDICTED] (ingested subset): 24 findings, exactly as expected
  ok    8.30.1 dir at HEAD: 31 findings, exactly as expected
  ok    8.30.1 git full history: 34 findings, exactly as expected
  ok    8.30.1 ARVE-simulated [PREDICTED] (ingested subset): 24 findings, exactly as expected

dependencies (osv-scanner)
  ok    1.9.2 full tree: 49 records, exactly as expected
  ok    1.9.2 ARVE-simulated [PREDICTED]: 41 records, exactly as expected
  ok    2.5.1 full tree: 50 records, exactly as expected
  ok    2.5.1 ARVE-simulated [PREDICTED]: 41 records, exactly as expected

negative controls
  ok    8.24.2: all 16 must-stay-silent files are clean
  ok    8.30.1: all 16 must-stay-silent files are clean

line numbers
  ok    all 52 recorded locations match the committed content

OK: every plant, negative control and count matches the answer key
```

followed by the canonical counts block. **Every number quoted anywhere in this
file comes from that output.** If this document and the script ever disagree,
**the script is right** — that is exactly the drift these docs suffered before.

### 3.3 How to read a failure

The script names the difference rather than just failing:

```
  FAIL  8.24.2 dir at HEAD: 30 findings, expected 31
          missing:    ('ops/scripts/backup.sh', 14, 'shopify-access-token')
```

| What you see | What it means | What to do |
|---|---|---|
| `missing:` a plant | the file was edited, or a line moved | `git diff` that file; plants and line numbers are frozen (§4.3) |
| `unexpected:` a finding | something new got planted, or a scanner changed | if real, record it in the answer key — an unrecorded plant scores as a false positive |
| OSV `unexpected:` records | an advisory was published since 2026-09-22 | check the ID on osv.dev; advisory counts drift upward over time |
| OSV `version:` mismatch | a scanner changed how it renders a version | see the PyYAML hazard in §8 |
| a must-stay-silent file fired | a negative control broke | that is a precision regression worth reporting |
| line numbers fail | a recorded location no longer exists | a plant file was edited — revert it |

### 3.4 See what ARVE would ingest

```bash
python scripts/arve_filter_mirror.py             # verdict for every tracked file
python scripts/arve_filter_mirror.py path/to/file   # just these paths
python scripts/arve_filter_mirror.py --json      # machine-readable
```

> ⚠️ **This is a prediction, not a measurement.** The mirror re-implements ARVE's
> `FileFilter` from `PROJECT_CONTEXT.md` §3.3. **No ARVE run has confirmed it.**
> Everything labelled *ARVE-simulated* rests on it. **If a real ARVE scan
> disagrees, the mirror is wrong** — fix the mirror and the answer key, and record
> the difference, because it means `PROJECT_CONTEXT.md` §3.3 no longer describes
> ARVE.

### 3.5 Regression tests for the tooling itself

```bash
python scripts/test_tooling.py
```

Guards two things that already broke once: the commit-hash stamper in
`seed_history.py`, and baseline redaction (§8).

---

## 4. The repository map

### 4.1 Answer keys, baselines and scripts

| File | What it is |
|---|---|
| `expected-findings.json` | ★ **the answer key.** Machine-readable, schema 1.1. Diff against this |
| `EXPECTED_FINDINGS.md` | the same ground truth for humans, with the reasoning per plant |
| `ARVE_ISSUES.md` | nine issue-ready writeups of the pipeline gaps, with a status board |
| `PROJECT_CONTEXT.md` | what ARVE is and how it consumes this repo (a snapshot — do not quote its totals) |
| `plan.md` | build log: how the testbed was made, what was rejected, lessons |
| `gitleaks-baseline.json` | reference gitleaks 8.30.1, `git` mode, whole repo — secrets redacted |
| `osv-baseline.json` | reference osv-scanner 2.5.1, whole tree |
| `arve-simulated-baseline.json` | **pinned** versions over the **predicted** ingested subset |
| `scripts/verify_plants.py` | ★ verifies everything, prints the canonical counts |
| `scripts/arve_filter_mirror.py` | predicts ARVE's ingestion decisions |
| `scripts/test_tooling.py` | regression tests for the tooling |
| `seed_history.py` | rebuilds the planted Git history (§8) |

### 4.2 Where each ID lives

| Area | Plants |
|---|---|
| `backend/app/config.py` | SEC-01, SEC-05, SEC-07 |
| `backend/app/webhooks.py` | SEC-06 (moves line in history) |
| `backend/tests/conftest.py` | SEC-05 (second copy) |
| `backend/keys/webhook_signing.pem` | SEC-03 ⛔ |
| `backend/requirements.txt` | DEP-01, DEP-02 |
| `backend/app/settlement.py` | **SEC-04 — history only, not at HEAD** |
| `.github/workflows/deploy.yml` | SEC-02 (two findings) |
| `.env.example` | SEC-08 ⛔ |
| `docs/runbook.md` | SEC-09 |
| `web/package-lock.json` | DEP-03 … DEP-08 |
| `services/settlement-java/` | SEC-10, SEC-11 ⛔, DEP-09 |
| `services/payout-scheduler/` | DEP-10 ⛔ |
| `services/reconciler-go/` | SEC-16, DEP-11 |
| `services/notifier-rust/` | SEC-27 (rotated in place), DEP-12 ⛔ |
| `services/ledger-export-dotnet/` | DEP-15 |
| `apps/admin-ui/` | SEC-14, SEC-15 ⛔, SEC-23, SEC-24, DEP-13, DEP-19, NEG-02, NEG-04 |
| `apps/status-page/` | SEC-12, SEC-13, NEG-05 |
| `apps/partner-webhooks/` | DEP-14, DEP-20 |
| `apps/merchant-portal/` | DEP-18 ⛔ |
| `ops/` | SEC-17, SEC-18, SEC-19 ⛔, SEC-20, SEC-23, SEC-26 ⛔, NEG-03, NEG-06 |
| `db/` | SEC-21, SEC-25 ⛔ |
| `tools/` | SEC-22, SEC-23, DEP-16 ⛔, DEP-17 ⛔, NEG-02 |
| `docs/cloud-setup.md` | NEG-01 |

⛔ = predicted to be dropped by ARVE's ingestion filter.

The satellite services are **stubs**: plausible, small, and not expected to build
or run. Only `backend/` and `web/` actually run.

### 4.3 Files you must never edit

**Every file listed in §4.2 holds a plant, and its line numbers are frozen.**
The answer key records exact lines; editing a plant file invalidates the fixture
and `verify_plants.py` will fail on it.

Also frozen:

- **Existing IDs.** SEC-01…SEC-27, DEP-01…DEP-20, NEG-01…NEG-06 are assigned
  permanently. Next free: SEC-28, DEP-21, NEG-07.
- **Existing commits.** History is appended, never rewritten (§8).

New plants go in **new files**. The full frozen list is in `PROJECT_CONTEXT.md`
§5, which is the binding brief for anyone extending this repo.

---

## 5. Scoring a real ARVE run

Diff ARVE's output against `expected-findings.json`. Each finding carries `id`,
`engine`, `finding_type`, `severity`, `file_path`, `file_type`, `line_start`,
`rule_id` / `ghsa` / `cve`, `history_only`, plus:

- **`tests`** — one line on what this plant exists to check;
- **`arve_pipeline`** — `ingestion`, `skip_reason`, `reaches_scanner`,
  `expected_arve_count`, `known_arve_divergence`. **Predicted, not measured**;
- **`scanner_verification`** — per scanner version, measured;
- **`testbed`** — fixture detail: `expected_finding_count`, history blocks.

### 5.1 Keep these four counts separate

Collapsing them is the most common way to get a meaningless score. Run
`verify_plants.py` for the current values.

| # | Count | Source | Use it for |
|---|---|---|---|
| 1 | **gitleaks `git`** (full history) | measured | the upper bound — everything that exists |
| 2 | **gitleaks `dir`** (HEAD on disk) | measured | what a filesystem scan sees; history is gone |
| 3 | **ARVE-simulated** (ingested subset) | ⚠️ **predicted** | what ARVE should currently produce |
| 4 | **OSV records** | measured, per scanner version | dependencies; the two versions differ by one record |

Count 3 has a second number attached: the scanner reports one total over the
ingested subset, but **ARVE should store one fewer**, because SEC-22's two
distinct secrets collapse into a single fingerprint. Both numbers are printed.

### 5.2 Suggested grading order

1. **Coverage** — which plants did ARVE report? Start here.
2. **Attribution** — for each miss, is it ingestion, scanner or normalizer (§2)?
   A miss with a documented ingestion gap is *expected* and should not be scored
   as a detection failure.
3. **False positives** — anything reported that is not in the key. Check
   `packages_expected_clean` and `files_expected_no_secret_findings` first.
4. **Severity** — especially DEP-06 (`moderate` → `MEDIUM`), DEP-08 (no CVSS at
   all) and DEP-11 (no severity data of any kind → `MEDIUM` by default).
   ⚠️ ARVE's gitleaks mapper currently hard-codes `MEDIUM` for *every* secret, so
   it will disagree with the intended severity on most SEC-* plants. That is
   recorded, not a surprise.
5. **Field correctness** — DEP-07's `cve` must be genuinely `null`; DEP-12's ID
   is a RUSTSEC with no CVE *and* no GHSA.
6. **Counting** — DEP-05 and DEP-19 must each be 2; DEP-20 should be 2 of 3;
   SEC-23 should be 3; SEC-22 should be 1 of 2.
7. **Lifecycle** — rescan and confirm SEC-06 stays OPEN, a suppression on SEC-08
   survives, and SEC-27 does not silently absorb a rotation.

Items 1–3 are table stakes. **4–7 are where the real value is**, because they
test your normalisation and identity code rather than the scanners.

---

## 6. The debugging rule

> **If a plant is missed, check the baselines before touching any code.**

| Situation | Conclusion | Action |
|---|---|---|
| The reference tool **also** missed it | **the testbed is wrong** | tell us; the plant needs fixing |
| The reference tool **caught** it, ARVE did not | **the bug is ours** | check `arve_pipeline` first — it may be a known ingestion gap |
| The pinned version missed it but the reference caught it | a scanner-version difference | check `scanner_verification` for that plant |

This takes about thirty seconds and routinely saves a day. The three baselines
exist for exactly this:

- `gitleaks-baseline.json` and `osv-baseline.json` — what is **there**;
- `arve-simulated-baseline.json` — what ARVE can currently **see**.

Diff ARVE's own output against the third one.

---

## 7. Negative controls, known limitations, known false positives

### 7.1 Negative controls (NEG-01 … NEG-06) — these must produce nothing

Precision matters as much as recall: a scanner that reports everything scores
100% recall and is useless. All six are **ingested**, so they test the scanners
and the normalizer, not the filter.

| ID | What | Why it must stay silent |
|---|---|---|
| NEG-01 | AWS documentation example keys, in 5 files | allowlisted by the `aws-access-token` rule |
| NEG-02 | env-var *references* only, in 3 files | the correct way to handle secrets; the names deliberately match planted secrets |
| NEG-03 | low-entropy placeholders (`changeme`, `REPLACE_ME`) | two carry **real vendor prefixes** — only the value's shape stops them matching |
| NEG-04 | a **patched** lodash beside the vulnerable one | proves version ranges are respected, not name matching |
| NEG-05 | a vulnerable pin in `package.json` with **no lockfile** | OSV reads lockfiles, not manifests |
| NEG-06 | a sha256 checksum next to the word `hash` | high-entropy, credential-adjacent, not a credential |

### 7.2 Known scanner limitations (LIM-01 … LIM-03) — **never score these**

Recorded so nobody debugs ARVE over them. They are scanner behaviour, not ARVE
issues, and not plants.

| ID | Behaviour |
|---|---|
| **LIM-01** | A Mapbox token in a URL is **not** matched by `mapbox-api-token` — the rule needs the literal word `mapbox` immediately before the `=`. Only `generic-api-key` fires, so vendor attribution is lost |
| **LIM-02** | A Google API key followed by `&` is detected by **no rule at all**. Google's own documented `?key=…&callback=…` order is invisible to gitleaks |
| **LIM-03** | `StartColumn` is wrong for a secret deep in a very long line, and **differs between gitleaks versions**. The line number is correct. Not a scoring input — `NormalizedFinding` has no column field |

### 7.3 Known false positives

**Currently empty.** Nothing fired on a negative control in any of the four
scanner versions. If a pinned scanner ever does fire on one, it moves into
`known_false_positives` in the answer key *with the reason* — that is still
useful precision data.

One thing that looks like a false positive and is not: osv-scanner reports
`PYSEC-2024-230` against `certifi 2018.4.16`, whose affected range starts at
`2021.5.30`. It is a scanner over-match, it is listed in the inventory so your
diff comes out clean, and **ARVE reporting it is correct behaviour.** Do not
"fix" ARVE to suppress it.

---

## 8. Gotchas that would otherwise cost you a day

**① GitHub push protection will block this repository.**
It contains correctly-shaped GitHub, GitLab, Slack, npm, Shopify, Hugging Face
and PyPI tokens, and push protection blocks exactly those. You must either
bypass the block per secret ("used in tests") or disable secret scanning for this
repo. **ARVE ingests from GitHub, so the push has to succeed with every file
intact** — a partially pushed testbed silently invalidates every score.
Relatedly: this repo is intended to be **private**. It is a working catalogue of
realistic-looking credentials, and a public copy invites automated scrapers and
pointless abuse reports, even though nothing here is live.

**② `.git` must survive transfer, or SEC-04 is gone forever.**
If this reaches you as a zip or a pen drive without `.git`, SEC-04 and half of
SEC-06 and SEC-27 simply do not exist and nobody can find them. Clone it; do not
copy the folder. If the history is ever lost, `python seed_history.py --force`
rebuilds it (§8④).

**③ Scan the repository, not the filesystem.**
`gitleaks dir .` on a working copy also walks `.venv/` and `node_modules/` and
produces unrelated hits. More importantly it cannot see history. Use
`gitleaks git .` for the reference number.

**④ History is append-only. Never force-push.**
`seed_history.py --force` **deletes and recreates `.git`**. It is a disaster
recovery tool, not part of a normal workflow. Commits 1–10 rebuild
byte-identically — that range holds every commit hash the answer keys quote for
SEC-04 and SEC-06 — but commits 11 onward stage files that get edited, so their
hashes move, and SEC-27's two commits are re-stamped automatically.

Two details keep that guarantee true and are easy to break: the script pins
`core.autocrlf=input` (otherwise your Git line-ending setting changes every blob
and therefore every hash), and it embeds the original commit-1 `README.md`
instead of reading the working tree (otherwise editing the README rewrites
commit 1 and everything after it).

**⑤ The PyYAML version string changes with the scanner version.**
`requirements.txt` pins `pyyaml==5.1`. osv-scanner **1.9.2 reports `5.1`**;
**2.5.1 reports `5.1.0`**. ARVE keys on `5.1` today, while the committed
reference baseline says `5.1.0` — so a diff against that baseline mismatches on
this one package. If ARVE's OSV image is ever upgraded, **every PyYAML finding
resolves and reopens** with no change in the repository. See `ARVE_ISSUES.md`
issue 9. npm versions are reported verbatim by both.

**⑥ Baselines are redacted, and that is load-bearing.**
`Secret` and `Match` are replaced with a sha256 prefix. This is not tidiness: the
raw `git`-mode report contains SEC-04's and SEC-27's *history-only* values, and
committing it would put them back at HEAD and destroy both plants. Identical
hashes still prove identical values — SEC-06's value is provably the same at both
its lines straight from the baseline. `scripts/test_tooling.py` asserts this on
every run.

**⑦ Advisory counts drift upward over time.**
New CVEs land against old packages constantly. The counts were verified on
**2026-09-22**. *More* records than documented is almost certainly the world
changing — check the new IDs on osv.dev. *Fewer*, or different ones, is worth
investigating.

**⑧ Some "wrong-looking" numbers are correct.**
27 secrets produce more than 27 findings (several appear in multiple files, one
is rotated so history holds two values). 20 dependency plants produce far more
records, because a vulnerable package carries *every* advisory published against
it — `lodash` alone accounts for 7.

---

## 9. If something still does not add up

1. Did you run `python scripts/verify_plants.py`? It answers most questions.
2. Did you use `gitleaks git .` rather than `dir .`? (§8③)
3. Does `.git` exist in what you received? (§8②)
4. Is the thing you found in `expected_osv_inventory`,
   `packages_expected_clean`, or `scanner_limitations`?
5. Do the **baselines** contain it? That instantly tells you whether it is your
   tool or the testbed. (§6)
6. Is it simply a new advisory published since 2026-09-22? (§8⑦)

If it is still wrong after those, please flag it. **A genuine mistake in the
answer key is the worst possible outcome here**, because it makes every other
number untrustworthy. Say something rather than working around it.

---

### One-line summary

**Run `python scripts/verify_plants.py`. The number that matters is not how many
plants you find, but which of the four counts you are measuring against — because
the gap between "on disk" and "in ARVE's view" is ARVE's ingestion filter, not
your scanner, and proving which one you are looking at is the entire point of
this repository.**
