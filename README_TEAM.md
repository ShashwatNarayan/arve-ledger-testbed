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
| Planted findings total | **17** |
| Hardcoded secrets (Gitleaks) | **9** → produce **10** findings at `HEAD`, **12** across full history |
| Vulnerable dependencies (OSV-Scanner) | **8** → produce **30** advisory records |

Two numbers look "wrong" at first glance and are correct:

- **9 secrets but 10–12 findings.** Two of the secrets appear in more than one
  place, and one exists only in old commits. Explained in §6.
- **8 dependency findings but 30 records.** A vulnerable package carries *every*
  advisory ever published against it, not just the one it was chosen for.
  `lodash` alone accounts for 7. Explained in §7.

---

## 3. Quick start

### Just scan it (you probably want this)

```bash
# Secrets — IMPORTANT: use `git`, not `dir`. See §9.
gitleaks git . --report-format json --report-path my-gitleaks.json

# Vulnerable dependencies
osv-scanner scan source --recursive . --format json --output-file my-osv.json
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

## 6. Why 9 secrets produce 10 or 12 findings

This trips people up, so, explicitly:

| Scan | Findings | Why |
|---|---|---|
| Working tree only | **10** | 9 secrets, but SEC-02 and SEC-05 each appear twice (+2), and SEC-04 does not exist at `HEAD` (−1) |
| Full Git history | **12** | the above, plus SEC-04 (+1), plus SEC-06 appearing at both its old and new line (+1) |

If you get 10, you scanned the filesystem. If you get 12, you scanned history.
**12 is the one you want** — see §9.

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
  "findings": [ ... 17 entries, one per planted finding ... ],
  "expected_osv_inventory": [ ... all 30 advisory records ... ],
  "packages_expected_clean": [ ... 24 packages that must produce NOTHING ... ],
  "normalization_notes": [ ... two gotchas, see below ... ]
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

Without these you can burn days debugging the wrong system. For the record: at
build time, **both reference tools detected all 17 planted findings**, so there
are no known gaps.

Versions used: **Gitleaks 8.30.1**, **OSV-Scanner 2.5.1**, advisory data as of
**2026-08-31**.

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

The history is part of the fixture. There are **12 commits** spread over about
three weeks, with messages written to read like ordinary development rather than
like a test fixture — `add nightly settlement file transfer`, `hoist webhook
module constants to the top of the file`, and so on.

The commits that matter structurally:

| Commit | Message | Why it matters |
|---|---|---|
| `5f9ec86` | add nightly settlement file transfer | **SEC-04 enters** |
| `4da4e7e` | add provider webhook handler with signature verification | **SEC-06 at line 43** |
| `dc9a9d6` | hoist webhook module constants to the top of the file | **SEC-06 moves to line 22** |
| `5c1f6a8` | clean up settlement config, the transfer moved to the platform job | **SEC-04 deleted** |

`seed_history.py` rebuilds all of this from scratch:

```bash
python seed_history.py --force      # --force required: it deletes and recreates .git
```

It is deterministic — commits 1 through 10 come out with **byte-identical hashes**
every time, so the commit references quoted above and in the answer keys stay
valid across rebuilds. It also self-checks at the end, confirming SEC-04 is absent
from the working tree but present in history, and that SEC-06 genuinely moved.

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

**17 planted findings, all documented up front, all confirmed detectable by the
real tools. Scan with `gitleaks git .` and `osv-scanner scan source --recursive
.`, diff against `expected-findings.json`, and use the committed baselines to tell
"our tool has a bug" apart from "the testbed is wrong".**
