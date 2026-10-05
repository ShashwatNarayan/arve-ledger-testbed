# README for the team — start here

Hi. This is the deliberately vulnerable repository we agreed to build so you can
test your scanner against something whose answers are already known.

You did not build this, so nothing in here should require guessing. This document
explains what the project is, what is in every file, exactly what was planted,
where, how, and how to score your scanner against it.

**Read this file first. Everything else follows from it.**

---

## 0. Before anything else: the credentials are fake

This repository contains things that look exactly like real leaked secrets —
a Stripe key, AWS credentials, an RSA private key, a Slack webhook URL, an SFTP
password.

**Every single one is synthetic.** They were randomly generated to have the
correct *shape* so scanners match them. None is valid for any real service. None
has ever been live. Nothing needs to be reported, rotated, or revoked.

The same goes for the outdated packages — they are pinned on purpose.

> **Do not deploy this anywhere, and do not `npm install` / `pip install` it on a
> machine you care about.** Not because it will attack you — it will not — but
> because it deliberately installs old, genuinely vulnerable library versions.
> Use a container or a throwaway virtualenv.

---

## 1. What this project actually is

Two things at once.

**On the surface:** a small double-entry payments ledger API. Python + FastAPI +
SQLite on the backend, and one static HTML page as an "operator console". Seven
endpoints, no login system. It genuinely works — you can create an account,
deposit, withdraw, transfer between accounts, check a balance, list transactions,
and receive a signed webhook from a payment provider.

**Underneath:** a test fixture. The application is kept deliberately boring so
that all the interesting complexity lives in the planted vulnerabilities rather
than in the architecture. The app exists mainly to give the vulnerabilities a
*plausible place to live* — for example, the webhook endpoint exists so that
having a signing secret in the codebase looks like normal engineering rather than
an obviously planted flaw.

### What was deliberately NOT planted, and why

There is **no SQL injection, XSS, path traversal, SSRF, or broken access
control** in this repository.

That is not an oversight. Those flaws need a static-analysis tool (like Semgrep)
to find. Your scanner currently runs **Gitleaks** (secrets) and **OSV-Scanner**
(vulnerable dependencies). Planting flaws that neither tool can possibly detect
would just produce a pile of findings nobody can report, and would make the
results impossible to read. Everything planted here is something one of your two
tools can actually find.

If you later add Semgrep, this repo can be extended. For now the scope is exactly
matched to the two engines you have.

---

## 2. The short version — what your scanner should find

| | Count |
|---|---|
| Planted findings total | **47** |
| Hardcoded secrets (Gitleaks) | **27** → **31** findings at `HEAD`, **34** across full history |
| Vulnerable dependencies (OSV-Scanner) | **20** → **49** advisory records |
| Negative controls | **6** → must produce **nothing** |

**Three numbers, not one.** How many findings exist depends on *what you point
the scanner at*, and the difference is the most useful thing in this repository:

| Scan | Gitleaks | OSV | What it tells you |
|---|---|---|---|
| **Reference, `git` mode** — full history | **34** | **50** | the upper bound: everything that is there |
| **Reference, `dir` mode** — working tree at `HEAD` | **31** | **49** | what a filesystem scan sees; history is gone |
| **ARVE-simulated** — pinned versions, ingested files only | **24** | **41** | **what ARVE actually sees today** |

The gap between rows 2 and 3 is not scanner error. It is ARVE's ingestion filter
dropping files before any scanner runs. **12 plants are lost that way, and every
one of them is detected by ARVE's own pinned scanner when it is allowed to see
the file.** A thirteenth (SEC-04) exists only in history, which `dir` mode cannot
reach.

> **Do not count by hand.** Run `python scripts/verify_plants.py`. It runs all
> four scanner versions, diffs them against the answer key, exits non-zero on any
> unexplained difference, and prints every number quoted in this document. The
> totals in these docs used to be maintained by hand and drifted badly.

Two numbers look "wrong" at first glance and are correct:

- **27 secrets but 31–34 findings.** Several secrets appear in more than one
  place (SEC-23 is one credential in three files), one exists only in old
  commits, and one is rotated in place so history holds two values. See §6.
- **20 dependency plants but 49 records.** A vulnerable package carries *every*
  advisory published against it, not just the one it was chosen for. `lodash`
  alone accounts for 7. See §7.

---

## 3. Quick start

### Verify the whole thing in one command (start here)

```bash
python scripts/verify_plants.py
```

Runs all four scanner versions in Docker — ARVE-pinned **gitleaks 8.24.2** and
**osv-scanner 1.9.2**, reference **gitleaks 8.30.1** and **osv-scanner 2.5.1** —
in `git` mode, `dir` mode, and `dir` over only the files ARVE would ingest. It
diffs every run against `expected-findings.json` and exits non-zero on anything
the answer key does not explain. Nothing is installed on your machine and no
secret value is ever printed.

### Just scan it yourself

```bash
# Secrets — IMPORTANT: use `git`, not `dir`. See §9.
gitleaks git . --report-format json --report-path my-gitleaks.json

# Vulnerable dependencies
osv-scanner scan source --recursive . --format json --output-file my-osv.json

# What ARVE would actually ingest, before any scanner runs
python scripts/arve_filter_mirror.py
```

Then compare against `expected-findings.json`. See §8 for how.

### Actually run the app (optional — not needed for scanning)

```bash
python -m venv .venv
.venv/Scripts/activate            # Windows
# source .venv/bin/activate       # macOS / Linux
pip install -r backend/requirements.txt

cd backend
uvicorn app.main:app --reload     # http://127.0.0.1:8000  (docs at /docs)
```

And the web console, in a second terminal:

```bash
cd web
npm install
npm start                         # http://127.0.0.1:5173
```

`pip install` will pull genuinely outdated packages. That is intended — please do
it inside a virtualenv or container.

---

## 4. What is in which file

```
arve-ledger-testbed/
│
├── README_TEAM.md            ← you are here
├── README.md                 public-facing "this repo is intentionally broken" warning
│
├── EXPECTED_FINDINGS.md      ★ THE ANSWER KEY, human-readable
├── expected-findings.json    ★ THE ANSWER KEY, machine-readable (diff against this)
├── gitleaks-baseline.json    ★ what real Gitleaks found
├── osv-baseline.json         ★ what real OSV-Scanner found
│
├── plan.md                   how the testbed was built, phase by phase
├── seed_history.py           rebuilds the planted Git history from scratch
│
├── .env.example              config template          → SEC-08
├── .gitignore                (note: deliberately does NOT ignore *.pem or lockfiles)
├── .github/workflows/
│   └── deploy.yml            CI workflow              → SEC-02
├── docs/
│   └── runbook.md            ops runbook              → SEC-09
│
├── backend/
│   ├── requirements.in       direct dependencies only
│   ├── requirements.txt      compiled lockfile        → DEP-01, DEP-02
│   ├── keys/
│   │   └── webhook_signing.pem   RSA private key      → SEC-03
│   ├── app/
│   │   ├── main.py           app startup
│   │   ├── config.py         settings                 → SEC-01, SEC-05, SEC-07
│   │   ├── models.py         SQLite schema
│   │   ├── ledger.py         double-entry logic
│   │   ├── api.py            the seven endpoints
│   │   └── webhooks.py       HMAC verification        → SEC-06
│   └── tests/
│       └── conftest.py       test fixtures            → SEC-05 (second copy)
│
└── web/
    ├── package.json          declared dependencies
    ├── package-lock.json     resolved tree            → DEP-03 … DEP-08
    ├── dev-server.js         static server + /api proxy
    ├── index.html            the one page
    └── src/main.js           calls two endpoints
```

### What the v1.1 expansion added

```
ARVE_ISSUES.md                 ★ four issue-ready writeups of the pipeline gaps
PROJECT_CONTEXT.md             what ARVE is and how it consumes this repo
arve-simulated-baseline.json   ★ what ARVE's own scanners actually see
scripts/
  arve_filter_mirror.py        ★ mirrors ARVE's ingestion filter
  verify_plants.py             ★ verifies everything, prints the canonical counts

services/
  settlement-java/    Java + Maven      → SEC-10, SEC-11, DEP-09
  payout-scheduler/   Gradle            → DEP-10
  reconciler-go/      Go                → SEC-16, DEP-11
  notifier-rust/      Rust              → SEC-27, DEP-12
  ledger-export-dotnet/  .NET           → DEP-15
apps/
  admin-ui/           TypeScript + yarn → SEC-14, SEC-15, SEC-23, SEC-24, DEP-13, DEP-19, NEG-02, NEG-04
  status-page/        HTML + CSS        → SEC-12, SEC-13, NEG-05
  partner-webhooks/   pnpm              → DEP-14, DEP-20
  merchant-portal/    Ruby + bundler    → DEP-18
ops/
  Dockerfile          → SEC-17            k8s/       → SEC-18, SEC-23
  terraform/          → SEC-19            scripts/   → SEC-20, NEG-03, NEG-06
  build/              → SEC-26
db/
  seed.sql            → SEC-21            fixtures/  → SEC-25
tools/                Python tooling    → SEC-22, SEC-23, DEP-16, DEP-17, NEG-02
docs/cloud-setup.md   → NEG-01
```

**These services are stubs.** They are plausible and small, and they exist to
give each file type a realistic home. They are not expected to build or run —
only `backend/` and `web/` do that.

**A file that is NOT in the working tree but matters:**
`backend/app/settlement.py` — it was added in one commit and deleted in a later
one. It holds **SEC-04**. You will only see it if you scan Git history.

There are also two files from the original build brief —
`NEW_PROJECT_START_README.md` and `KICKSTART_PROMPT.md`. They are the
specification this repo was built from. Ignore them for scanning; they are kept
for provenance.

---

## 5. Every planted secret (Gitleaks)

Each one has a `# TESTBED SEC-0N — intentional` comment sitting right next to it
in the source, so a human reading the code can always tell it is deliberate.
Gitleaks ignores comments entirely, so this does not help or hinder detection.

| ID | What it is | Where | Rule | Severity |
|---|---|---|---|---|
| **SEC-01** | Stripe live secret key | `backend/app/config.py:35` | `stripe-access-token` | HIGH |
| **SEC-02** | AWS key ID + secret | `.github/workflows/deploy.yml:45` and `:46` | `aws-access-token`, `generic-api-key` | HIGH |
| **SEC-03** | RSA private key | `backend/keys/webhook_signing.pem:5` | `private-key` | HIGH |
| **SEC-04** | SFTP password | `backend/app/settlement.py:16` — **HISTORY ONLY** | `generic-api-key` | HIGH |
| **SEC-05** | JWT signing key, in **two** files | `backend/app/config.py:45` **and** `backend/tests/conftest.py:14` | `generic-api-key` | HIGH |
| **SEC-06** | Webhook secret that **moved line** | `backend/app/webhooks.py:22` (was `:43`) | `generic-api-key` | HIGH |
| **SEC-07** | 64-char key, no vendor prefix | `backend/app/config.py:40` | `generic-api-key` | HIGH |
| **SEC-08** | SendGrid token in a template file | `.env.example:23` | `sendgrid-api-token` | MEDIUM |
| **SEC-09** | Slack webhook URL | `docs/runbook.md:66` | `slack-webhook-url` | MEDIUM |

### The v1.1 secrets — 18 more, across 15 file types

Full reasoning for each is in [`EXPECTED_FINDINGS.md`](EXPECTED_FINDINGS.md).
⛔ marks a plant ARVE's ingestion filter drops before any scanner runs.

| ID | What it is | Where | Rule | ARVE |
|---|---|---|---|---|
| **SEC-10** | GitHub token | `services/settlement-java/…/GatewayClient.java:25` | `github-pat` | ✅ |
| **SEC-11** | Twilio API key | `…/application.properties:12` | `twilio-api-key` | ⛔ |
| **SEC-12** | Google Maps key in a CSS `url()` | `apps/status-page/styles.css:48` | `gcp-api-key` | ✅ |
| **SEC-13** | Mapbox token in an inline script | `apps/status-page/index.html:37` | `mapbox-api-token` | ✅ |
| **SEC-14** | GitLab token | `apps/admin-ui/src/deployStatus.ts:15` | `gitlab-pat` | ✅ |
| **SEC-15** | npm publish token | `apps/admin-ui/.npmrc:6` | `npm-access-token` | ⛔ |
| **SEC-16** | Slack bot token | `services/reconciler-go/main.go:23` | `slack-bot-token` | ✅ |
| **SEC-17** | Hugging Face token on `ENV` | `ops/Dockerfile:6` | `huggingface-access-token` | ✅ |
| **SEC-18** | EC private key in a k8s Secret | `ops/k8s/secrets.yaml:12` | `private-key` | ✅ |
| **SEC-19** | Terraform Cloud token | `ops/terraform/main.tf:17` | `hashicorp-tf-api-token` | ⛔ |
| **SEC-20** | Shopify token | `ops/scripts/backup.sh:14` | `shopify-access-token` | ✅ |
| **SEC-21** | JWT bearer token | `db/seed.sql:13` | `jwt` | ✅ |
| **SEC-22** | **two** secrets on one line | `tools/sync_keys.py:16` | `generic-api-key` ×2 | ⚠ 1 |
| **SEC-23** | one key in **three** file types | `.js:11`, `.yaml:12`, `.py:17` | `generic-api-key` ×3 | ✅ |
| **SEC-24** | Algolia admin key in a 154 KB bundle line | `apps/admin-ui/public/vendor.min.js:1` | `algolia-api-key` | ✅ |
| **SEC-25** | Square token in a 1.2 MB fixture | `db/fixtures/merchant_export.json:38901` | `square-access-token` | ⛔ |
| **SEC-26** | PyPI upload token | `ops/build/publish.sh:12` | `pypi-upload-token` | ⛔ |
| **SEC-27** | key **rotated in place** | `services/notifier-rust/notifier.toml:14` | `new-relic-user-api-key` | ✅ |

### The four that are aimed squarely at your normalizer

**SEC-22 — two different secrets, one line.** Gitleaks reports both, and both
get the *identical* fingerprint `tools/sync_keys.py:generic-api-key:16`, because
the dir-mode fingerprint is `file:rule:line` and `--redact` removes the values.
**Expect one finding, not two** — one real credential silently disappears.

**SEC-23 — one secret, three file types.** The same value in a `.js`, a `.yaml`
and a `.py` file produces **three** findings with three fingerprints. One
credential, three rotations' worth of noise. The opposite failure to SEC-22, from
the same field.

**SEC-27 — a key rotated in place.** Same file, same line, new value. A history
scan shows two findings; ARVE sees one that never changes state. **A rotated
credential is indistinguishable from an untouched one.**

**SEC-18 vs SEC-03 — the control pair.** Same `private-key` rule, same class of
secret. SEC-18 is in a `.yaml` file and is ingested; SEC-03 is a `.pem` and is
not. If ARVE reports one and not the other, the difference is provably ingestion
rather than the rule.

### What each one is actually testing

The first three are straightforward — they check the basics work. The last six
are the interesting ones, and they are aimed at **your** code rather than at
Gitleaks.

**SEC-01 — the canary.** A named-vendor rule on an obvious source file. If this
one is missed, something is broken at the plumbing level and no other result
means anything. Check this first.

**SEC-02 — non-code path.** Lives in CI workflow YAML, not application source. A
scanner configured to look only at `*.py` misses it. It produces **two** findings
(the key ID and the secret key, on adjacent lines).

**SEC-03 — a different rule class.** A real PEM block rather than a token regex
or an entropy score. It is a genuine, valid 2048-bit RSA key generated with
`openssl genrsa` — it just has never been used for anything.

**SEC-04 — history scanning. This is the big structural one.**
The file does not exist at `HEAD`. If you scan the working tree you will find
**nothing**. It is reachable only by walking commits. It was added in commit
`5f9ec86` *"add nightly settlement file transfer"* and removed in `5c1f6a8`
*"clean up settlement config"*.
Also worth checking: once found, your tool should **not** immediately mark it
resolved just because `HEAD` is clean. The credential was committed and pushed —
in the real world it is compromised until rotated, regardless of whether someone
deleted the file afterwards.

**SEC-05 — fingerprinting.** The exact same secret value, byte for byte, in two
different files. Gitleaks reports **two** findings because it identifies findings
by `(file, line, secret)`.
What *your* tool should do is a real design decision, and **either answer is
defensible**:
- dedupe on the secret value → **1** finding (models "one credential, one
  rotation" — but fixing one file leaves the finding open pointing at a stale path)
- include the file path → **2** findings (each is tracked and closed
  independently — but rotating the key closes two findings at once)

We are not saying which is right. What matters is that your tool does it
**deliberately and consistently**, and that the count does not change randomly
between runs.

**SEC-06 — stable identity across refactors.** The same secret appears at
**line 43** in commit `4da4e7e` and at **line 22** in commit `dc9a9d6`. The value
never changed; someone just moved the constant to the top of the file.
Your tool should report **one finding that stays open**. If its fingerprint
includes the line number, it will report the finding as *resolved* at the refactor
and then *reopened* — a completely false alarm about a secret that was never fixed
and never re-leaked. That kind of noise is exactly what teaches people to ignore a
security tool, which is why it is worth catching.

**SEC-07 — entropy, not pattern.** No vendor prefix, so no named rule can match
it. Detection depends entirely on spotting a credential-shaped keyword next to a
high-entropy string.

**SEC-08 — the deliberately ambiguous one.** A correctly-shaped SendGrid token
sitting in `.env.example`, a template file that is meant to be committed.
We checked: **Gitleaks does report it.** It is not filtered out by the `.example`
filename. So the tool does not resolve the ambiguity — a human has to.
This is the one finding where marking it a false positive or suppressing it is a
perfectly legitimate outcome. **The real test is what happens next:** if someone
marks it suppressed, does it stay suppressed on the next scan, or does it pop back
up as new? If triage decisions do not survive a rescan, nobody will ever bother
triaging.

**SEC-09 — documentation paths.** Inside a fenced code block in a Markdown file.
Docs are frequently excluded from scanning by file extension, yet runbooks are one
of the most common places webhook URLs genuinely leak, because people paste in
copy-paste-ready commands — exactly as this one is.

---

## 6. Why 27 secrets produce 31, 34 or 24 findings

This trips people up, so, explicitly:

| Scan | Findings | Why |
|---|---|---|
| **ARVE-simulated** (ingested files only) | **24** | the `HEAD` set minus the 7 secrets ARVE's ingestion filter drops |
| Working tree at `HEAD` | **31** | 27 secrets; several appear more than once (SEC-02 ×2, SEC-05 ×2, SEC-22 ×2, SEC-23 ×3), and SEC-04 does not exist at `HEAD` |
| Full Git history | **34** | the above, plus SEC-04 (+1), SEC-06 at its old line (+1), SEC-27's pre-rotation value (+1) |

If you get 31, you scanned the filesystem. If you get 34, you scanned history.
**34 is the reference number.** If you get 24, you are correctly simulating what
ARVE ingests — see §6a.

And one more number: **ARVE should store 23, not 24**, because SEC-22's two
distinct secrets share a fingerprint and collapse into one finding.

---

## 6a. The seven secrets ARVE never sees

Each of these is detected by ARVE's **own pinned scanner** (gitleaks 8.24.2)
when it is shown the file. They are lost earlier, at ingestion, for four
distinct reasons — which is why they are worth having:

| ID | File | Why it is dropped |
|---|---|---|
| SEC-03 | `backend/keys/webhook_signing.pem` | `.pem` is in no allow-list |
| SEC-08 | `.env.example` | `splitext` → `.example`, so the `.env.example` entry can never match |
| SEC-11 | `…/application.properties` | `.properties` is in no allow-list |
| SEC-15 | `apps/admin-ui/.npmrc` | dotfile → extension is `""` |
| SEC-19 | `ops/terraform/main.tf` | `.tf` is in no allow-list |
| SEC-25 | `db/fixtures/merchant_export.json` | 1.2 MB, over the 1 MiB size cap |
| SEC-26 | `ops/build/publish.sh` | path contains `build`, an ignored directory |

Plus **SEC-04**, which exists only in history and so is unreachable in `dir`
mode, and **five dependency lockfiles** (§7a). Run
`python scripts/arve_filter_mirror.py` to see the filter's verdict on every
file.

---

## 7. Every planted dependency (OSV-Scanner)

Two ecosystems, two lockfiles, and **neither is at the repository root**. That is
deliberate: it checks that your scanner recurses into subdirectories rather than
only looking at the top level.

| ID | Package | Ecosystem | Advisory | Severity | How it got there |
|---|---|---|---|---|---|
| **DEP-01** | `PyYAML 5.1` | PyPI | GHSA-3pqx-4fqf-j49f / CVE-2019-20477 | CRITICAL | direct |
| **DEP-02** | `certifi 2018.4.16` | PyPI | GHSA-xqr8-7jwr-rhp7 / CVE-2023-37920 | HIGH | **transitive only** |
| **DEP-03** | `lodash 4.17.11` | npm | GHSA-p6mc-m468-83gw / CVE-2020-8203 | HIGH | direct |
| **DEP-04** | `follow-redirects 1.14.7` | npm | GHSA-pw2r-vq6v-hr8c / CVE-2022-0536 | MEDIUM | **lockfile only** |
| **DEP-05** | `minimist 1.2.0` | npm | GHSA-vh95-rmgr-6w4m **+** GHSA-xvch-5gv4-984h | MEDIUM + CRITICAL | direct |
| **DEP-06** | `jquery 3.3.1` | npm | GHSA-6c3j-c64m-qhgq / CVE-2019-11358 | MEDIUM | direct |
| **DEP-07** | `serialize-javascript 2.1.2` | npm | GHSA-5c6j-r48x-rmvq | HIGH | direct |
| **DEP-08** | `stringstream 0.0.5` | npm | GHSA-mf6x-7mm4-x2g7 / CVE-2018-21270 | MEDIUM | direct |

### The v1.1 additions — six more ecosystems

Every lockfile below is **genuine package-manager output**, produced by running
the real tool in a throwaway container.

| ID | Package | Ecosystem / file | Records | ARVE sees it? |
|---|---|---|---|---|
| **DEP-09** | `commons-text 1.9` | Maven `pom.xml` | 1 | ✅ |
| **DEP-10** | `snakeyaml 1.33` | Maven `gradle.lockfile` | 1 | ⛔ |
| **DEP-11** | `golang.org/x/text 0.3.8` | Go `go.mod` | 1 | ✅ |
| **DEP-12** | `ansi_term 0.12.1` | crates.io `Cargo.lock` | 1 | ⛔ |
| **DEP-13** | `json5 2.2.1` | npm `yarn.lock` | 1 | ✅ |
| **DEP-14** | `node-fetch 2.6.0` | npm `pnpm-lock.yaml` v9 | 2 | ✅ |
| **DEP-15** | `Newtonsoft.Json 12.0.1` | NuGet `packages.lock.json` | 1 | ✅ |
| **DEP-16** | `wheel 0.37.0` | PyPI `poetry.lock` | 2 | ⛔ |
| **DEP-17** | `jinja2 3.1.5` | PyPI `requirements-dev.txt` | 2 | ⛔ |
| **DEP-18** | `addressable 2.7.0` | RubyGems `Gemfile.lock` | 2 | ⛔ |
| **DEP-19** | `minimist 1.2.0` | npm `yarn.lock` — same as DEP-05 | 2 | ✅ |
| **DEP-20** | `minimist 0.0.8` **+** `1.2.5` | npm `pnpm-lock.yaml` | 3 | ⚠ 2 |

---

## 7a. The five lockfiles ARVE never sees

**Whole ecosystems are scanned as empty.** In each case ARVE's pinned
osv-scanner parses the file perfectly well when shown it:

| Lockfile | Ecosystem | What ARVE ingests instead |
|---|---|---|
| `gradle.lockfile` | Maven/Gradle | `build.gradle` — a manifest OSV cannot resolve |
| `Cargo.lock` | crates.io | `Cargo.toml` — likewise |
| `poetry.lock` | PyPI | `pyproject.toml` — likewise |
| `requirements-dev.txt` | PyPI | nothing; only the exact name `requirements.txt` is allowed |
| `Gemfile.lock` | RubyGems | nothing |

OSV reads **lockfiles**, not manifests. Ingesting `Cargo.toml` while skipping
`Cargo.lock` means the Rust dependency tree is never examined at all.

Worth contrasting: `packages.lock.json` (DEP-15) **is** ingested — not because
NuGet is supported, but because the filename happens to end in `.json`.

### What each one is testing

**DEP-01 / DEP-03 — the canaries.** One per ecosystem. Ordinary direct
dependencies with famous advisories. If either is missed, lockfile parsing is
broken for that ecosystem.

**DEP-02 — transitive resolution.** `certifi` is **never named** in
`requirements.in`. It arrives only because `httpx` and `httpcore` depend on it,
and neither constrains the version, so an ancient pin survives. Both parents are
completely clean, so anything reported here can only be the transitive child.

**DEP-04 — dependency graph parsing.** `follow-redirects` appears **only in
`package-lock.json`** and is absent from `package.json`. It enters solely as a
dependency of `http-proxy`. A tool that reads only `package.json` finds nothing.
The lockfile is genuine npm output, not hand-edited — `npm install` reports "up to
date" against it. `http-proxy` itself is clean, again so the signal is unambiguous.

**DEP-05 — one package, two advisories → must be TWO findings.**
`minimist 1.2.0` has exactly two advisories and no more, which is why it was
chosen: the expected number is not arguable.
One is MEDIUM, the other is **CRITICAL**. If your tool identifies findings by
`(package, version)` it will collapse these into one — **and it will be the
CRITICAL one that disappears.** Findings must be identified per
`(package, advisory)`.

**DEP-06 — severity vocabulary.** GitHub publishes severity as the string
`moderate`. Most canonical severity scales do not have a "moderate" — they have
`MEDIUM`. All three of jQuery's advisories are `moderate`, so there is no
mixed-severity ambiguity to hide behind. If your normaliser passes the string
straight through, or uppercases it to `MODERATE`, or gives up and defaults, you
will see it clearly on all three at once.

**DEP-07 — an advisory with no CVE.** GHSA-5c6j-r48x-rmvq has a GHSA ID but **no
CVE ID at all**. Your `cve` field must come out **null** — not the string
`"None"`, not an empty string, not the GHSA ID copied across, and the finding must
not be dropped because a CVE was assumed mandatory.
This package is a good test because its *other* advisory **does** have a CVE
(CVE-2020-7660). So the same package at the same version yields one finding with a
CVE and one without. Any code that copies values between records shows up
immediately.

**DEP-08 — missing severity data.** The OSV record for this advisory has an
**empty `severity` array** — there is no CVSS vector to parse at all. Code that
assumes `severity[0]` exists will crash or emit null. The correct answer is
`MEDIUM`, reached by falling back to GitHub's `moderate` string.
This package has exactly one advisory and no alias duplicates, so there is exactly
one right answer.

---

## 8. How to actually score your scanner

### The two answer keys

**`expected-findings.json`** is the one to automate against. Structure:

```jsonc
{
  "schema_version": "1.1",
  "findings": [ ... 47 entries, one per planted finding ... ],
  "expected_osv_inventory": [ ... all 50 advisory records, each tagged with its file ... ],
  "negative_controls": [ ... 6 things that must produce NOTHING ... ],
  "known_false_positives": [ ... empty: nothing fired ... ],
  "scanner_limitations": [ ... 3 scanner quirks that are NOT scored ... ],
  "coverage_matrix": { ... plants by file type x engine x ingestion status ... },
  "packages_expected_clean": [ ... packages that must produce NOTHING ... ],
  "files_expected_no_secret_findings": [ ... 16 files that must stay silent ... ],
  "tooling_notes": [ ... what a history rebuild does and does not reproduce ... ],
  "normalization_notes": [ ... gotchas, see below ... ]
}
```

Each finding entry uses field names meant to line up with a normalised finding
format — `id`, `engine`, `finding_type`, `severity`, `file_path`, `line_start`,
`rule_id` / `ghsa` / `cve`, `history_only` — plus a `tests` field saying in one
line what that finding exists to check, and a `notes` field with the detail.

There is also a `testbed` sub-object on each entry with things that are about the
fixture rather than about the finding: `expected_finding_count` (how many findings
this single plant should produce), `total_records_for_package`, and for SEC-04 and
SEC-06 a `history` block with the exact commit hashes.

**`EXPECTED_FINDINGS.md`** is the same information written out for humans, with
the reasoning behind each choice. Read this one when a result surprises you.

### The baselines — please use these

`gitleaks-baseline.json` and `osv-baseline.json` are what the **real** tools
found when run against this repo. They exist to answer one question fast:

> Our scanner missed finding X. Is our scanner broken, or is the testbed wrong?

- **The reference tool also missed it** → the testbed is wrong. Tell us and we
  will fix the plant.
- **The reference tool caught it and yours did not** → the bug is in your code.

Without these you can burn days debugging the wrong system. For the record:
**all 47 plants are detected by their reference tool, and all 47 are also
detected by ARVE's pinned versions** when those are shown the file. There are no
known scanner gaps — every miss in ARVE's view is an ingestion or normalization
gap, which is the whole point.

There are now **three** baselines:

| File | Produced by | Scope |
|---|---|---|
| `gitleaks-baseline.json` | gitleaks **8.30.1**, `git` mode | whole repository, full history — **34** findings |
| `osv-baseline.json` | osv-scanner **2.5.1** | whole working tree — **50** records |
| `arve-simulated-baseline.json` | **pinned** 8.24.2 + 1.9.2 | **ingested files only** — **24** findings, **41** records |

The third one is the one to diff ARVE's own output against. The first two tell
you what is *there*; the third tells you what ARVE can currently *see*.

Advisory data verified **2026-09-22**.

### Suggested way to grade

1. **Coverage** — how many of the 17 did you find? Start here.
2. **False positives** — anything reported that is not in the key. Check it
   against `packages_expected_clean` (24 packages that must produce nothing).
3. **Severity accuracy** — especially DEP-06 (`moderate` → `MEDIUM`) and DEP-08
   (no CVSS at all → `MEDIUM`).
4. **Field correctness** — especially DEP-07's `cve` being genuinely null.
5. **Counting** — DEP-05 must be two findings; SEC-05's count must be
   intentional; SEC-02 is two.
6. **Lifecycle** — rescan and confirm SEC-06 stays open across its line move and
   that a suppression on SEC-08 survives.

Items 1–2 are table stakes. **Items 3–6 are where the real value is**, because
they test your own normalisation and identity code rather than the scanners.

---

## 9. Gotchas — please read before you file a bug

**① Scan the Git repository, not the filesystem.**
`gitleaks dir .` walks everything on disk, including `.venv/` and
`node_modules/`, which produces unrelated junk findings. More importantly it
reports **10** findings instead of **12**, because SEC-04 exists only in history.
Use `gitleaks git .`.

**② Ship the repository with its `.git` directory intact.**
If this reaches you as a zip or a pen drive with `.git` stripped out, SEC-04 and
half of SEC-06 are simply gone and cannot be found by anyone. If that has
happened, run `python seed_history.py --force` to rebuild the history (see §11).

**③ One OSV result is a scanner over-match, and that is expected.**
OSV-Scanner reports `PYSEC-2024-230` against `certifi 2018.4.16`. That advisory's
affected range actually starts at version `2021.5.30`, so 2018.4.16 is *below* the
range and not genuinely affected. It appears to match because the record also
carries a Git range starting from zero.
It is listed in the inventory so your diff comes out clean — that is why the
record count is **30** (29 planted + this one). **Your tool reporting it is
correct behaviour.** It is faithfully reflecting its scanner. Please do not "fix"
your tool to suppress it.

**④ PyYAML's version string changes shape.**
`requirements.txt` pins `pyyaml==5.1`, but OSV-Scanner reports the version as
**`5.1.0`**. If you build a finding identity from `(package, version)` it will key
on `5.1.0`, not the `5.1` written in the file. This is not a bug in either tool,
but two things follow: a naive text diff against the lockfile will not match, and
if your identity ever switched between the two forms it would resolve-and-reopen
every PyYAML finding. npm versions come through verbatim.

**⑤ The committed baselines have secret values redacted.**
In `gitleaks-baseline.json` the `Secret` and `Match` fields are replaced with a
SHA-256 prefix. This was necessary, not cosmetic — the raw report contains SEC-04's
password, and committing it would have put that secret back at `HEAD`, destroying
the one finding whose entire purpose is to be history-only. The raw report also
tripped 17 of Gitleaks' own rules on itself, which would have added phantom
findings to every future scan.
Everything you need is preserved: rule, file, line, commit, entropy, fingerprint.
Identical hashes still mean identical values — you can confirm SEC-06 has the same
secret at both of its lines straight from the baseline.
`osv-baseline.json` similarly has the long advisory prose stripped, because one
advisory's example text contains a fake API key that trips Gitleaks.

**⑥ Advisory counts drift upward over time.**
New CVEs get published against old packages constantly. The counts here were true
on **2026-08-31**. If you scan months later and see *more* records than documented,
that is almost certainly the world changing, not your tool misbehaving — check the
new advisory IDs against osv.dev. Fewer records, or different ones, is worth
investigating.

---

## 10. How the plants were made (and three that nearly failed silently)

Worth knowing, because it explains why some things are shaped the way they are.

**Everything was verified with the real scanners while it was being planted, not
afterwards.** That turned out to matter enormously. Three plants were written,
looked completely fine to a human, and detected **nothing**:

**SEC-07 was invisible because of line wrapping.** It was first written as a
neatly wrapped three-line assignment — the natural way to format a long key.
Gitleaks' `generic-api-key` rule needs the keyword and the value on the **same
line**. Zero findings until it was collapsed onto one line.

**SEC-02's AWS key was invisible because of its digits.** Gitleaks validates
`AKIA...` values against the real AWS base32 alphabet (`A–Z` and `2–7`) and
rejects anything containing `0`, `1`, `8` or `9` — at any entropy. The first
generated value had two `1`s in it. Testing showed only **4 of 40** naively random
candidates were detected, versus **30 of 30** using the correct alphabet.

**DEP-07 was originally pointed at a package that was not vulnerable.**
`http-proxy 1.18.1` was chosen for its no-CVE advisory — but that advisory is
*fixed in exactly that version*. The osv.dev query API returned it anyway on one
run. Re-checking every advisory against its own affected version ranges caught it.
(`http-proxy` was kept in the project as the deliberately clean parent for DEP-04.)

Each of these would have shown up on your side as *"the scanner missed a
finding"*, and you could have spent days debugging your code when the truth was
that there was nothing there to find. If you hit a miss, the baselines in §8 are
how you tell those two situations apart in about thirty seconds.

**One more, about `seed_history.py`:** SEC-04's password is *derived
deterministically from a fixed seed* rather than written into that script as a
literal. If it were a literal, it would sit at `HEAD` inside `seed_history.py`, a
working-tree scan would find it there, and SEC-04 would stop being history-only —
the build script would have quietly destroyed the very test it exists to create.
This is not obfuscation: inside the commits where the secret actually lives, it is
plain text, and Gitleaks matches it like any other.

---

## 11. The Git history, and rebuilding it

The history is part of the fixture. It spans about three months, with messages
written to read like ordinary development rather than like a test fixture —
`add nightly settlement file transfer`, `hoist webhook
module constants to the top of the file`, and so on.

The commits that matter structurally:

| Commit | Message | Why it matters |
|---|---|---|
| `5f9ec86` | add nightly settlement file transfer | **SEC-04 enters** |
| `4da4e7e` | add provider webhook handler with signature verification | **SEC-06 at line 43** |
| `dc9a9d6` | hoist webhook module constants to the top of the file | **SEC-06 moves to line 22** |
| `5c1f6a8` | clean up settlement config, the transfer moved to the platform job | **SEC-04 deleted** |
| `471c68d` | add notifier service config | **SEC-27 enters, pre-rotation value** |
| `b24991a` | rotate the notifier telemetry ingest key | **SEC-27 rotated in place — same line, new value** |

`seed_history.py` rebuilds all of this from scratch:

```bash
python seed_history.py --force      # --force required: it deletes and recreates .git
```

**Commits 1 through 10 come out with byte-identical hashes every time** — that
range holds every commit the answer keys quote, for SEC-04 and SEC-06 — so those
references stay valid across rebuilds. This was verified by rebuilding a scratch
clone and diffing. Commits 11 onward stage files that get edited (both answer
keys, the baselines, the script itself), so their hashes do move; SEC-27's two
commits sit in that range and are re-stamped into the answer key automatically.

Two details keep the guarantee true, and both are easy to break: the script pins
`core.autocrlf=input` (otherwise your Git line-ending setting changes every
blob), and it embeds the original commit-1 `README.md` rather than reading the
working tree (otherwise editing the README rewrites every hash after it).

It self-checks at the end, confirming SEC-04 is absent from the working tree but
present in history, that SEC-06 genuinely moved, and that SEC-27's pre-rotation
value exists only in history.

You should not need to run it. It is there so that if the history is ever lost —
zipped without `.git`, copied wrongly onto a pen drive — the fixture can be
restored exactly rather than approximately.

---

## 12. If something does not add up

Quick triage before raising it:

1. Did you use `gitleaks git .` rather than `gitleaks dir .`? (§9①)
2. Does `.git` exist in what you received? (§9②)
3. Is the thing you found in `expected_osv_inventory` or
   `packages_expected_clean`?
4. Does the **baseline** contain it? That instantly tells you whether it is your
   tool or the testbed. (§8)
5. Is it just a new advisory published since 2026-08-31? (§9⑥)

If it is still wrong after those, it is worth flagging — a genuine mistake in the
answer key is the worst possible outcome here, because it makes every other number
untrustworthy. Please do say something rather than working around it.

---

### One-line summary

**47 planted findings and 6 negative controls, all documented up front, all
confirmed detectable by ARVE's own pinned scanners. Run
`python scripts/verify_plants.py` to check everything at once. The number that
matters is not how many you find, but which of the three counts you are
measuring against — 34 in history, 31 on disk, 24 in ARVE's view — because the
gap between the last two is ARVE's ingestion filter, not your scanner.**
