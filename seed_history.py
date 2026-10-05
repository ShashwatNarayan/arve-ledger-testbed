#!/usr/bin/env python3
"""Rebuild the planted Git history for arve-ledger-testbed.

Several findings in this testbed exist *only in history*, so the commit sequence
is part of the fixture rather than an accident of how it was authored. This
script reconstructs that sequence deterministically.

What it produces
----------------
The original thirteen commits, followed by the v1.1 expansion commits. Three of
them matter structurally:

  * **SEC-04** (an SFTP password in ``backend/app/settlement.py``) is added in
    commit 4 and deleted in commit 8. At ``HEAD`` the file does not exist, so a
    working-tree scan finds nothing and only a history walk reports it.

  * **SEC-06** (the provider webhook secret in ``backend/app/webhooks.py``) is
    introduced in commit 6 at one line and moved to a different line by the
    refactor in commit 7. The secret *value* never changes, which is the point:
    a fingerprint that includes the line number will wrongly report the finding
    as RESOLVED and then REOPENED.

  * **SEC-27** (the New Relic ingest key in
    ``services/notifier-rust/notifier.toml``) is introduced with one value and
    *rotated in place* by a later commit -- same file, same line, new value.
    A history scan reports two findings; a HEAD-only scan reports one and never
    sees the rotation at all.

What is guaranteed to be reproducible
-------------------------------------
**Commits 1-10 come out byte-identical on every rebuild**, which is what
matters: every commit hash quoted in the answer keys (SEC-04's add/delete and
SEC-06's introduce/move) lives in that range. Two things are load-bearing for
that guarantee and are handled below:

  * ``core.autocrlf`` is pinned to ``input`` on the rebuilt repository, because
    the blobs -- and therefore the hashes -- otherwise depend on the machine's
    global Git configuration.
  * ``README.md`` is committed in commit 1, so the *original* commit-1 blob is
    embedded below as ``README_V1`` rather than read from the working tree.
    Without that, any later edit to ``README.md`` would silently change commit 1
    and every hash after it.

Commits 11 onward stage files that this project keeps editing (the two answer
keys, the baselines, this script), so their hashes follow the current content
and are *not* stable across content changes. No answer-key hash depends on them,
and ``stamp_commit_references()`` rewrites the SEC-27 references after a rebuild.

How it works
------------
Most files are added exactly once and never change, so they are staged straight
from the working tree. Only three artifacts need to differ from ``HEAD``, and
only those are embedded below as constants:

  * ``settlement.py``  -- does not exist at HEAD at all
  * ``webhooks.py``    -- the pre-refactor v1, with SEC-06 at its original line
  * ``config.py``      -- the pre-credentials v1, reading purely from the
                          environment

The current (final) contents of ``config.py`` and ``webhooks.py`` are read from
the working tree before anything is overwritten, then restored at their proper
commits. This means the script works from a fresh clone.

Usage
-----
    python seed_history.py --force

``--force`` is required because the script **deletes and recreates .git**.

INTENTIONALLY VULNERABLE TESTBED - see EXPECTED_FINDINGS.md.
"""

import argparse
import hashlib
import os
import re
import shutil
import string
import subprocess
from datetime import datetime, timedelta, timezone
from pathlib import Path

REPO = Path(__file__).resolve().parent

# ---------------------------------------------------------------------------
# Why SEC-04's value is derived rather than written out
# ---------------------------------------------------------------------------
# SEC-04 must be reachable ONLY by walking Git history -- that is the entire
# point of the finding. If the literal password appeared in this file it would
# also sit at HEAD, a working-tree scan would report it, and the test would be
# destroyed by the very script meant to create it.
#
# So the value is derived deterministically from the fixed seed below. It is
# stable across runs (the history is reproducible), it never appears as a
# literal at HEAD, and it is a perfectly ordinary high-entropy string once
# written into the commit -- Gitleaks matches it exactly as it would any other.
# This is not obfuscation of the planted secret: in the commits where it exists,
# it is plain text. It is avoidance of a second, unintended plant.
SEC04_SEED = "arve-ledger-testbed/SEC-04/settlement-sftp-service-account"

# SEC-27 is the same problem in a different shape. The PRE-ROTATION value must
# exist only inside the commits before the rotation: if it were a literal here
# it would sit at HEAD, and the finding this plant creates -- "the old key is
# reachable only through history" -- would be destroyed by this script. The
# post-rotation value is a normal planted secret and is read from the working
# tree, so the two can never drift apart.
SEC27_SEED = "arve-ledger-testbed/SEC-27/notifier-newrelic-ingest-pre-rotation"


def derive_secret(seed, length=28, alphabet=None):
    """Deterministically expand a seed into a high-entropy string."""
    alphabet = alphabet or (string.ascii_letters + string.digits)
    out = []
    counter = 0
    while len(out) < length:
        block = hashlib.sha256(f"{seed}:{counter}".encode()).digest()
        out.extend(alphabet[b % len(alphabet)] for b in block)
        counter += 1
    return "".join(out[:length])


def derive_sec27():
    """The pre-rotation New Relic key: NRAK- plus 27 upper-case alphanumerics."""
    return "NRAK-" + derive_secret(SEC27_SEED, 27, string.ascii_uppercase + string.digits)

# Commits are dated backwards from this point so `git log` looks like work done
# over a few weeks rather than all in one second.
FIRST_COMMIT_AT = datetime(2026, 7, 13, 9, 24, tzinfo=timezone.utc)

AUTHOR_NAME = os.environ.get("SEED_AUTHOR_NAME", "Shashwat Narayan")
AUTHOR_EMAIL = os.environ.get("SEED_AUTHOR_EMAIL", "shashwatn2802@gmail.com")


# ---------------------------------------------------------------------------
# Embedded file versions that differ from HEAD
# ---------------------------------------------------------------------------

# README.md is committed in COMMIT 1, so the commit-1 blob is pinned here rather
# than read from the working tree. Editing README.md at HEAD would otherwise
# change commit 1 and, with it, every commit hash the answer keys quote.
# The current README.md is restored at its proper commit further down.
README_V1 = '''# arve-ledger-testbed

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
'''

# backend/app/config.py as it stood before the credentials were hardcoded.
# Commit 1 gets this; commit 9 replaces it with the version carrying SEC-01,
# SEC-05 and SEC-07.
CONFIG_V1 = '''"""Application configuration.

Values are read from the environment. See `.env.example` for the full list.
"""

import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent

# Where the SQLite file lives. Relative to backend/ by default.
DATABASE_PATH = os.environ.get("LEDGER_DATABASE_PATH", str(BASE_DIR / "ledger.db"))

# ISO-4217 code applied to accounts created without an explicit currency.
DEFAULT_CURRENCY = os.environ.get("LEDGER_DEFAULT_CURRENCY", "USD")

# Ledger amounts are held as integer minor units (cents) to avoid float drift.
# This caps a single movement so a fat-fingered request cannot post a
# nonsensical amount.
MAX_TRANSACTION_MINOR = int(os.environ.get("LEDGER_MAX_TRANSACTION_MINOR", "100000000"))

# Payment provider settings.
PROVIDER_NAME = os.environ.get("LEDGER_PROVIDER_NAME", "acme-payments")
WEBHOOK_SIGNING_KEY_PATH = os.environ.get(
    "LEDGER_WEBHOOK_SIGNING_KEY_PATH", str(BASE_DIR / "keys" / "webhook_signing.pem")
)

# Credentials, read from the environment.
STRIPE_API_KEY = os.environ.get("STRIPE_API_KEY", "")
LEDGER_HMAC_KEY = os.environ.get("LEDGER_HMAC_KEY", "")
JWT_SIGNING_KEY = os.environ.get("JWT_SIGNING_KEY", "")
'''

# backend/app/webhooks.py as first written, before module constants were
# hoisted to the top of the file. SEC-06 sits low in the file here; the commit 7
# refactor moves it up. The secret value is identical in both versions.
WEBHOOKS_V1 = '''"""Payment provider webhook handling.

The provider signs every callback body with a shared secret and sends the
result in the `X-Provider-Signature` header as `t=<unix>,v1=<hex digest>`.
We recompute the digest and compare it in constant time.
"""

import hashlib
import hmac
import os
import time

from . import ledger


class WebhookError(Exception):
    """Raised when a callback cannot be accepted."""


def _parse_signature_header(header):
    """Split `t=...,v1=...` into its parts."""
    if not header:
        raise WebhookError("missing signature header")

    parts = {}
    for chunk in header.split(","):
        key, _, value = chunk.strip().partition("=")
        if key and value:
            parts[key] = value

    if "t" not in parts or "v1" not in parts:
        raise WebhookError("malformed signature header")
    return parts


# Reject callbacks whose timestamp is further away than this, so a captured
# request cannot be replayed days later.
SIGNATURE_TOLERANCE_SECONDS = 300

# Shared secret the provider signs callback bodies with. Falls back to the
# staging value issued by acme-payments so local callbacks verify out of the box.
# TESTBED SEC-06 - intentional, see EXPECTED_FINDINGS.md
PROVIDER_WEBHOOK_SECRET = os.environ.get("PROVIDER_WEBHOOK_SECRET", "__SEC06__")


def _signing_secret():
    """Return the shared secret used to sign provider callbacks."""
    return PROVIDER_WEBHOOK_SECRET


def compute_signature(timestamp, payload):
    """Return the hex digest the provider should have sent."""
    signed_payload = f"{timestamp}.".encode() + payload
    return hmac.new(
        _signing_secret().encode(), signed_payload, hashlib.sha256
    ).hexdigest()


def verify_signature(header, payload):
    """Check a callback's signature, raising WebhookError if it does not hold."""
    parts = _parse_signature_header(header)

    try:
        timestamp = int(parts["t"])
    except ValueError:
        raise WebhookError("malformed signature timestamp")

    if abs(time.time() - timestamp) > SIGNATURE_TOLERANCE_SECONDS:
        raise WebhookError("signature timestamp outside tolerance")

    expected = compute_signature(timestamp, payload)
    if not hmac.compare_digest(expected, parts["v1"]):
        raise WebhookError("signature mismatch")
    return True


def handle_event(event):
    """Apply a verified provider event to the ledger.

    Only settlement credits are actioned. Anything else is acknowledged and
    ignored so the provider stops retrying it.
    """
    event_type = event.get("type")
    data = event.get("data") or {}

    if event_type != "payment.settled":
        return {"status": "ignored", "type": event_type}

    account_id = data.get("account_id")
    amount = data.get("amount")
    if not account_id or not isinstance(amount, int):
        raise WebhookError("event is missing account_id or amount")

    ledger.deposit(account_id, amount, reference=event.get("id"))
    return {"status": "applied", "type": event_type, "account_id": account_id}
'''

# backend/app/settlement.py -- carries SEC-04. Added in commit 4, deleted in
# commit 8, so it exists nowhere in the working tree at HEAD.
SETTLEMENT = '''"""Nightly settlement file transfer.

The bank drops a settlement file on their SFTP server every night at 02:00 UTC.
We pull it, parse it, and reconcile it against the ledger the next morning.
"""

import os
from datetime import datetime, timedelta, timezone

SETTLEMENT_HOST = os.environ.get("SETTLEMENT_SFTP_HOST", "sftp.acme-settlement.example")
SETTLEMENT_PORT = int(os.environ.get("SETTLEMENT_SFTP_PORT", "22"))
SETTLEMENT_USER = os.environ.get("SETTLEMENT_SFTP_USER", "acme_ledger_svc")

# Bank-issued service account. Rotated quarterly by the payments team.
# TESTBED SEC-04 - intentional, see EXPECTED_FINDINGS.md
SETTLEMENT_SFTP_PASSWORD = os.environ.get("SETTLEMENT_SFTP_PASSWORD", "__SEC04__")

REMOTE_DIR = "/outbound/settlement"
LOCAL_DIR = os.environ.get("SETTLEMENT_LOCAL_DIR", "./settlement")


def expected_filename(for_date=None):
    """Bank names files SETTLE_YYYYMMDD.csv, dated the previous business day."""
    day = for_date or (datetime.now(timezone.utc).date() - timedelta(days=1))
    return f"SETTLE_{day.strftime('%Y%m%d')}.csv"


def connection_settings():
    """Return the parameters the SFTP client needs."""
    return {
        "host": SETTLEMENT_HOST,
        "port": SETTLEMENT_PORT,
        "username": SETTLEMENT_USER,
        "password": SETTLEMENT_SFTP_PASSWORD,
        "remote_dir": REMOTE_DIR,
    }


def parse_settlement_row(line):
    """Parse one CSV row into a reconcilable record.

    Format: reference,account_id,amount_minor,settled_at
    """
    parts = [p.strip() for p in line.split(",")]
    if len(parts) != 4:
        raise ValueError(f"malformed settlement row: {line!r}")

    reference, account_id, amount, settled_at = parts
    return {
        "reference": reference,
        "account_id": account_id,
        "amount": int(amount),
        "settled_at": settled_at,
    }


def load_settlement_file(path):
    """Read a settlement file, skipping the header row."""
    with open(path, encoding="utf-8") as handle:
        rows = [line for line in handle.read().splitlines() if line.strip()]
    return [parse_settlement_row(line) for line in rows[1:]]
'''


# ---------------------------------------------------------------------------
# Git helpers
# ---------------------------------------------------------------------------

def git(*args, **kwargs):
    """Run a git command in the repo, raising on failure."""
    return subprocess.run(
        ["git", *args], cwd=REPO, check=True, capture_output=True, text=True, **kwargs
    )


def commit(index, message, when):
    """Create one commit with a fixed author and committer date."""
    stamp = when.strftime("%Y-%m-%dT%H:%M:%S%z")
    env = {
        **os.environ,
        "GIT_AUTHOR_NAME": AUTHOR_NAME,
        "GIT_AUTHOR_EMAIL": AUTHOR_EMAIL,
        "GIT_COMMITTER_NAME": AUTHOR_NAME,
        "GIT_COMMITTER_EMAIL": AUTHOR_EMAIL,
        "GIT_AUTHOR_DATE": stamp,
        "GIT_COMMITTER_DATE": stamp,
    }
    subprocess.run(
        ["git", "commit", "-m", message],
        cwd=REPO, check=True, capture_output=True, text=True, env=env,
    )
    print(f"  {index:>2}. {message}")


def add(*paths):
    for path in paths:
        git("add", "--all", "--", path)


def staged():
    """True when the index differs from HEAD, i.e. there is something to commit."""
    result = subprocess.run(["git", "diff", "--cached", "--quiet"], cwd=REPO,
                            capture_output=True)
    return result.returncode != 0


def write(relative_path, content):
    target = REPO / relative_path
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(content, encoding="utf-8")


def read(relative_path):
    return (REPO / relative_path).read_text(encoding="utf-8")


def extract_toml_value(text, key):
    """Return the quoted value of `key = "..."` from a TOML file."""
    match = re.search(rf'^\s*{re.escape(key)}\s*=\s*"([^"]+)"', text, re.MULTILINE)
    if not match:
        raise SystemExit(f"could not find {key} in the TOML file")
    return match.group(1)


def extract_secret(text, marker):
    """Pull the quoted literal out of the line following a TESTBED marker.

    Keeps the planted secrets in exactly one place -- the working tree -- so this
    script can never drift out of sync with what was actually planted.
    """
    lines = text.splitlines()
    for i, line in enumerate(lines):
        if marker in line:
            for candidate in lines[i:i + 3]:
                if '", "' in candidate:
                    return candidate.rsplit('", "', 1)[1].split('"')[0]
    raise SystemExit(f"could not extract the secret for {marker}")


# ---------------------------------------------------------------------------
# Commit-reference stamping
# ---------------------------------------------------------------------------
# The answer keys quote commit hashes for SEC-04 and SEC-06. Those hashes are
# only knowable AFTER the history is built, and any edit to a file committed
# early (README.md sits in commit 1) changes every hash downstream. Writing them
# by hand therefore guarantees they go stale.
#
# So they are stamped here instead, from the history that was just built, and
# committed at the very end. Because the referenced commits all sit earlier in
# the sequence, adding this final commit cannot change them.
#
# NOTE: `git log -1 <hash>` is NOT a valid way to check a hash is current --
# unreachable objects from previous rebuilds linger in the object database and
# resolve happily. Use `git merge-base --is-ancestor <hash> HEAD`.

ANCHORS = [
    "add nightly settlement file transfer",
    "clean up settlement config, the transfer moved to the platform job",
    "add provider webhook handler with signature verification",
    "hoist webhook module constants to the top of the file",
    "use staging credentials as local fallbacks",
    "add deploy workflow and on-call runbook",
    # v1.1: SEC-27's two commits. Unlike the anchors above these are NOT stable
    # across rebuilds, because they sit after commits that stage the answer keys
    # -- which is exactly why they are stamped rather than written by hand.
    "add notifier service config",
    "rotate the notifier telemetry ingest key",
]

STAMPED_FILES = [
    "EXPECTED_FINDINGS.md",
    "expected-findings.json",
    "README_TEAM.md",
]

# gitleaks-baseline.json is deliberately NOT stamped. It is a generated report,
# and in `git` mode every finding carries the commit it was found in, so after a
# rebuild its hashes are stale by definition. Rewriting them would be a lie about
# which run produced the file. Regenerate the baselines after a rebuild instead:
#
#     python scripts/verify_plants.py      # confirm the plants still line up
#
# and re-run whatever produced the baselines. The same applies to
# arve-simulated-baseline.json.
GENERATED_NOT_STAMPED = ["gitleaks-baseline.json", "osv-baseline.json",
                         "arve-simulated-baseline.json"]

# Commit hashes the answer keys quote as a statement about the PAST rather than
# as a pointer into the current branch. A rebuild is expected to orphan these.
HISTORICAL_REFERENCES = [
    # tooling_notes: where the backspace bug in this script was introduced
    "b8333656",
]


def _subject(ref):
    r = subprocess.run(["git", "log", "-1", "--format=%s", ref],
                       cwd=REPO, capture_output=True, text=True)
    return None if r.returncode else r.stdout.strip()


def stamp_commit_references():
    """Rewrite stale commit hashes in the answer keys to the ones just built."""
    current = {}
    for msg in ANCHORS:
        h = git("log", "--format=%H", "--all", "--grep", msg, "-1").stdout.strip()
        if h:
            current[msg] = h

    # Find every hash currently written into the stamped files and work out
    # which commit message it referred to, so it can be remapped.
    replacements = {}
    for name in STAMPED_FILES:
        path = REPO / name
        if not path.exists():
            continue
        for token in set(re.findall(r"\b[0-9a-f]{7,40}\b",
                                    path.read_text(encoding="utf-8"))):
            if token in replacements:
                continue
            subject = _subject(token)
            if subject in current and not current[subject].startswith(token):
                new = current[subject]
                replacements[token] = new[:len(token)]

    if not replacements:
        print("  no stale commit references found")
        return False

    changed = []
    for name in STAMPED_FILES:
        path = REPO / name
        if not path.exists():
            continue
        original = path.read_text(encoding="utf-8")
        # Substitute WHOLE tokens only. A plain str.replace would rewrite the
        # 7-char prefix inside a 40-char hash and produce a hybrid that points
        # at no commit at all.
        text = re.sub(r"\b[0-9a-f]{7,40}\b",
                      lambda m: replacements.get(m.group(0), m.group(0)),
                      original)
        if text != original:
            path.write_text(text, encoding="utf-8")
            changed.append(name)

    for old, new in sorted(replacements.items()):
        print(f"  {old} -> {new}")
    return bool(changed)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--force", action="store_true",
        help="required: this DELETES .git and rebuilds the history from scratch",
    )
    args = parser.parse_args()

    if not (REPO / "backend" / "app" / "api.py").exists():
        raise SystemExit("run this from the repository root")

    if not args.force:
        raise SystemExit(
            "This deletes .git and rebuilds every commit.\n"
            "Re-run with --force if that is what you want."
        )

    # Capture the final versions before anything is overwritten, so the script
    # works from a fresh clone where only HEAD exists.
    final_config = read("backend/app/config.py")
    final_webhooks = read("backend/app/webhooks.py")
    final_readme = read("README.md")
    final_notifier = read("services/notifier-rust/notifier.toml")

    # SEC-04 is derived, never stored here. SEC-06 legitimately lives at HEAD,
    # so it is read back out of the working tree -- that keeps the planted value
    # in exactly one place and stops this script drifting out of sync with it.
    sec04 = derive_secret(SEC04_SEED)
    sec06 = extract_secret(final_webhooks, "TESTBED SEC-06")
    if sec06 == "__SEC06__":
        raise SystemExit("SEC-06 placeholder was not substituted")
    if len(set(sec04)) < 15:
        raise SystemExit("derived SEC-04 has too little variety to trip entropy rules")

    settlement = SETTLEMENT.replace("__SEC04__", sec04)
    webhooks_v1 = WEBHOOKS_V1.replace("__SEC06__", sec06)

    if webhooks_v1 == final_webhooks:
        raise SystemExit("webhooks v1 is identical to HEAD -- SEC-06 would not move")

    # SEC-27: same idea as SEC-04. The pre-rotation value is derived, the
    # post-rotation value is read from the working tree, and notifier v1 is the
    # HEAD file with the one value swapped back.
    sec27_old = derive_sec27()
    sec27_new = extract_toml_value(final_notifier, "newrelic_api_key")
    if not sec27_new.startswith("NRAK-"):
        raise SystemExit(f"SEC-27 value at HEAD looks wrong: {sec27_new[:5]!r}...")
    if sec27_old == sec27_new:
        raise SystemExit("SEC-27 pre- and post-rotation values are identical")
    notifier_v1 = final_notifier.replace(sec27_new, sec27_old)
    if notifier_v1 == final_notifier:
        raise SystemExit("SEC-27 rotation would be a no-op")

    # Remotes live inside .git, which is about to be deleted. Save them so a
    # rebuild does not silently detach this repo from GitHub.
    saved_remotes = []
    if (REPO / ".git").exists():
        listing = subprocess.run(["git", "remote", "-v"], cwd=REPO,
                                 capture_output=True, text=True)
        for line in listing.stdout.splitlines():
            if line.endswith("(fetch)"):
                parts = line.split()
                saved_remotes.append((parts[0], parts[1]))

    git_dir = REPO / ".git"
    if git_dir.exists():
        print("removing existing .git")
        shutil.rmtree(git_dir, ignore_errors=True)

    git("init", "--quiet", "--initial-branch=main")
    git("config", "user.name", AUTHOR_NAME)
    git("config", "user.email", AUTHOR_EMAIL)
    # Load-bearing for reproducibility: with core.autocrlf=true (the Git for
    # Windows default) the working tree holds CRLF and blobs are normalised on
    # the way in; with it false, CRLF would be committed verbatim and every
    # hash would change. Pinning `input` normalises on commit and never
    # converts on checkout, so the blobs -- and the hashes -- are the same on
    # every platform regardless of the machine's global configuration.
    git("config", "core.autocrlf", "input")

    at = FIRST_COMMIT_AT
    step = 0

    def nxt(days, hours):
        nonlocal at, step
        at = at + timedelta(days=days, hours=hours)
        step += 1
        return step, at

    print("\nbuilding history:")

    # 1 -- clean skeleton, no planted findings
    write("backend/app/config.py", CONFIG_V1)
    write("README.md", README_V1)
    add(".gitignore", "README.md",
        "backend/app/__init__.py", "backend/app/config.py", "backend/app/models.py")
    i, when = nxt(0, 0)
    commit(i, "initial project skeleton", when)

    # 2 -- the ledger itself
    add("backend/app/ledger.py", "backend/app/api.py", "backend/app/main.py")
    i, when = nxt(1, 3)
    commit(i, "add double-entry ledger core and the seven endpoints", when)

    # 3 -- DEP-01, DEP-02 enter
    add("backend/requirements.in", "backend/requirements.txt")
    i, when = nxt(2, 1)
    commit(i, "pin backend dependencies with pip-compile", when)

    # 4 -- SEC-04 enters history
    write("backend/app/settlement.py", settlement)
    add("backend/app/settlement.py")
    i, when = nxt(1, 5)
    commit(i, "add nightly settlement file transfer", when)

    # 5 -- DEP-03 .. DEP-08 enter
    add("web/package.json", "web/package-lock.json", "web/index.html",
        "web/src/main.js", "web/dev-server.js")
    i, when = nxt(3, 2)
    commit(i, "add operator console with dev proxy", when)

    # 6 -- SEC-06 introduced at its original line; SEC-03 lands alongside it
    write("backend/app/webhooks.py", webhooks_v1)
    add("backend/app/webhooks.py", "backend/keys/webhook_signing.pem")
    i, when = nxt(2, 4)
    commit(i, "add provider webhook handler with signature verification", when)

    # 7 -- SEC-06 moves line. Same value, new position.
    write("backend/app/webhooks.py", final_webhooks)
    add("backend/app/webhooks.py")
    i, when = nxt(1, 6)
    commit(i, "hoist webhook module constants to the top of the file", when)

    # 8 -- SEC-04 leaves the working tree but stays in history
    (REPO / "backend" / "app" / "settlement.py").unlink()
    git("add", "--all", "--", "backend/app/settlement.py")
    i, when = nxt(4, 2)
    commit(i, "clean up settlement config, the transfer moved to the platform job", when)

    # 9 -- SEC-01, SEC-05, SEC-07, SEC-08
    write("backend/app/config.py", final_config)
    add("backend/app/config.py", "backend/tests/conftest.py", ".env.example")
    i, when = nxt(2, 1)
    commit(i, "use staging credentials as local fallbacks", when)

    # 10 -- SEC-02, SEC-09
    add(".github/workflows/deploy.yml", "docs/runbook.md")
    i, when = nxt(3, 3)
    commit(i, "add deploy workflow and on-call runbook", when)

    # 11 -- the answer key and the build spec
    add("EXPECTED_FINDINGS.md", "expected-findings.json", "plan.md",
        "seed_history.py", "NEW_PROJECT_START_README.md", "KICKSTART_PROMPT.md")
    i, when = nxt(1, 2)
    commit(i, "document the planted findings and how the testbed was built", when)

    # 12 -- reference scanner baselines. Both are redacted: the raw gitleaks
    # report would put SEC-04's password back at HEAD and self-flag 17 times.
    if (REPO / "gitleaks-baseline.json").exists():
        add("gitleaks-baseline.json", "osv-baseline.json")
        i, when = nxt(2, 1)
        commit(i, "add reference scanner baselines for gitleaks and osv-scanner", when)

    # 13 -- handover guide for whoever evaluates a scanner against this repo.
    # The current README.md is restored here: commit 1 carries README_V1, so any
    # later edit to the README lands in this commit rather than rewriting the
    # hashes the answer keys quote.
    if (REPO / "README_TEAM.md").exists():
        write("README.md", final_readme)
        add("README_TEAM.md", "README.md")
        i, when = nxt(1, 4)
        commit(i, "add evaluation guide for the scanner team", when)

    # ---- v1.1 expansion ---------------------------------------------------
    # Everything below was APPENDED after the thirteen commits above; none of
    # them was rewritten. The sequence mirrors the commits made while planting,
    # so a rebuilt repository tells the same story as the live one.
    #
    # Only notifier.toml needs a version that differs from HEAD (SEC-27's
    # pre-rotation value); everything else is staged straight from the working
    # tree. A step whose paths are all missing, or that stages nothing new, is
    # skipped rather than committed empty -- that keeps the script usable on a
    # checkout where the v1.1 files have not been created yet.
    write("services/notifier-rust/notifier.toml", notifier_v1)

    v11 = [
        ("2026-09-22T22:58:22", "record how the ingestion filter sees each planted finding",
         ["PROJECT_CONTEXT.md", "scripts/arve_filter_mirror.py"]),
        ("2026-09-22T23:00:28", "write up the four pipeline gaps the testbed exposes",
         ["ARVE_ISSUES.md"]),
        ("2026-09-23T09:12:00", "add settlement service skeleton",
         ["services/settlement-java/src"]),
        ("2026-09-23T14:40:00", "add public status page",
         ["apps/status-page/index.html", "apps/status-page/styles.css"]),
        ("2026-09-24T10:05:00", "add admin console deploy status widget",
         ["apps/admin-ui/.npmrc", "apps/admin-ui/public", "apps/admin-ui/src/analyticsClient.js",
          "apps/admin-ui/src/deployStatus.ts"]),
        ("2026-09-24T16:20:00", "send console usage events to the analytics collector",
         ["ops/k8s/admin-ui-config.yaml", "tools/analytics_export.py"]),
        ("2026-09-25T11:30:00", "add settlement reconciler service",
         ["services/reconciler-go/main.go"]),
        ("2026-09-25T18:02:00", "add container image and cluster manifests",
         ["ops/Dockerfile", "ops/k8s/secrets.yaml"]),
        ("2026-09-26T09:45:00", "manage terraform cloud workspaces from the repo",
         ["ops/terraform"]),
        ("2026-09-26T15:15:00", "add nightly merchant catalogue backup",
         ["ops/scripts/backup.sh"]),
        ("2026-09-27T12:00:00", "add library release publish script",
         ["ops/build/publish.sh"]),
        ("2026-09-27T17:30:00", "add local database seed and merchant export fixture",
         ["db"]),
        ("2026-09-28T10:20:00", "add staging key sync helper",
         ["tools/sync_keys.py"]),
        # SEC-27 enters here carrying its PRE-ROTATION value.
        ("2026-09-28T14:55:00", "add notifier service config",
         ["services/notifier-rust/notifier.toml"]),
        ("2026-09-28T19:10:00", "document the new secret plants in the answer key",
         ["EXPECTED_FINDINGS.md", "expected-findings.json"]),
        ("2026-09-29T09:30:00", "pin settlement service dependencies",
         ["services/settlement-java/pom.xml"]),
        ("2026-09-29T13:10:00", "add payout scheduler module",
         ["services/payout-scheduler"]),
        ("2026-09-29T17:45:00", "pin reconciler dependencies",
         ["services/reconciler-go/go.mod", "services/reconciler-go/go.sum"]),
        ("2026-09-30T10:15:00", "add notifier crate and lockfile",
         ["services/notifier-rust/Cargo.toml", "services/notifier-rust/Cargo.lock",
          "services/notifier-rust/src"]),
        ("2026-09-30T15:20:00", "pin admin console dependencies",
         ["apps/admin-ui/package.json", "apps/admin-ui/yarn.lock", "apps/admin-ui/src/settings.ts"]),
        ("2026-10-01T09:40:00", "add partner webhook fan-out service",
         ["apps/partner-webhooks"]),
        ("2026-10-01T14:25:00", "add dotnet ledger export tool",
         ["services/ledger-export-dotnet"]),
        ("2026-10-01T18:05:00", "add developer tooling dependencies",
         ["tools/pyproject.toml", "tools/poetry.lock", "tools/requirements-dev.in",
          "tools/requirements-dev.txt"]),
        ("2026-10-02T11:00:00", "add merchant portal skeleton",
         ["apps/merchant-portal"]),
        ("2026-10-02T16:30:00", "document the new dependency plants in the answer key",
         ["EXPECTED_FINDINGS.md", "expected-findings.json"]),
        ("2026-10-03T09:15:00", "add cloud account setup notes",
         ["docs/cloud-setup.md"]),
        ("2026-10-03T11:40:00", "check required environment variables at startup",
         ["tools/env_check.py", "apps/admin-ui/src/env.ts"]),
        ("2026-10-03T15:05:00", "build the admin console in CI",
         [".github/workflows/admin-ui.yml"]),
        ("2026-10-04T10:30:00", "add sample env file and artifact verification script",
         ["ops/scripts/env.sample.sh", "ops/scripts/verify_artifact.sh"]),
        ("2026-10-04T14:50:00", "add status page preview script",
         ["apps/status-page/package.json"]),
        ("2026-10-04T18:20:00", "record the negative controls in the answer key",
         ["EXPECTED_FINDINGS.md", "expected-findings.json"]),
    ]

    for stamp, message, paths in v11:
        present = [p for p in paths if (REPO / p).exists()]
        if not present:
            continue
        add(*present)
        if not staged():
            continue
        step += 1
        commit(step, message, datetime.fromisoformat(stamp).replace(tzinfo=timezone.utc))

    # SEC-27's rotation: same file, same line, new value, its own commit.
    if (REPO / "services/notifier-rust/notifier.toml").exists():
        write("services/notifier-rust/notifier.toml", final_notifier)
        add("services/notifier-rust/notifier.toml")
        if staged():
            step += 1
            commit(step, "rotate the notifier telemetry ingest key",
                   datetime(2026, 10, 5, 9, 25, tzinfo=timezone.utc))

    # Anything produced after the plants -- verification tooling, regenerated
    # baselines, refreshed docs -- lands in one final commit.
    tail = ["scripts/verify_plants.py", "gitleaks-baseline.json", "osv-baseline.json",
            "arve-simulated-baseline.json", "README_TEAM.md", "README.md",
            "EXPECTED_FINDINGS.md", "expected-findings.json", "plan.md",
            "PROJECT_CONTEXT.md", "ARVE_ISSUES.md", "seed_history.py"]
    present = [p for p in tail if (REPO / p).exists()]
    if present:
        add(*present)
        if staged():
            step += 1
            commit(step, "refresh the answer keys and baselines for the v1.1 expansion",
                   datetime(2026, 10, 5, 16, 40, tzinfo=timezone.utc))

    # ---- stamp the real commit hashes into the answer keys ----------------
    print("\nstamping commit references:")
    if stamp_commit_references():
        add(*[f for f in STAMPED_FILES if (REPO / f).exists()])
        i, when = nxt(0, 2)
        commit(i, "update answer key with final commit references", when)

    # ---- verify the structural invariants ---------------------------------
    print("\nverifying:")

    tracked = git("ls-files").stdout.split()
    assert "backend/app/settlement.py" not in tracked, \
        "SEC-04 is still tracked at HEAD"
    print("  ok  SEC-04 absent from the working tree at HEAD")

    in_history = git("log", "--all", "--oneline", "--", "backend/app/settlement.py").stdout
    assert in_history.strip(), "SEC-04 is not in history either"
    print(f"  ok  SEC-04 present in {len(in_history.strip().splitlines())} historical commits")

    v1_line = next(n for n, l in enumerate(webhooks_v1.splitlines(), 1)
                   if "PROVIDER_WEBHOOK_SECRET = os.environ.get" in l)
    head_line = next(n for n, l in enumerate(final_webhooks.splitlines(), 1)
                     if "PROVIDER_WEBHOOK_SECRET = os.environ.get" in l)
    assert v1_line != head_line, "SEC-06 did not move"
    print(f"  ok  SEC-06 moved from line {v1_line} to line {head_line}, value unchanged")

    # SEC-27: the pre-rotation value must be reachable ONLY through history, and
    # the rotation must not move the line -- that is what makes ARVE's
    # file:rule:line fingerprint identical before and after.
    notifier_path = REPO / "services" / "notifier-rust" / "notifier.toml"
    if notifier_path.exists():
        assert sec27_old not in notifier_path.read_text(encoding="utf-8"), \
            "SEC-27 pre-rotation value is still at HEAD"
        assert sec27_old not in read("seed_history.py"), \
            "SEC-27 pre-rotation value leaked into this script as a literal"
        print("  ok  SEC-27 pre-rotation value absent from HEAD and from this script")

        old_line = next(n for n, l in enumerate(notifier_v1.splitlines(), 1) if sec27_old in l)
        new_line = next(n for n, l in enumerate(final_notifier.splitlines(), 1) if sec27_new in l)
        assert old_line == new_line, "SEC-27 rotation moved the line; it must stay in place"
        print(f"  ok  SEC-27 rotated in place at line {new_line}, value changed")

        rotation = git("log", "--all", "--oneline", "--grep",
                       "rotate the notifier telemetry ingest key").stdout.strip()
        assert rotation, "SEC-27 rotation commit is missing"
        touching = git("log", "--all", "--oneline", "--",
                       "services/notifier-rust/notifier.toml").stdout.strip().splitlines()
        assert len(touching) >= 2, "SEC-27 needs an introducing commit and a rotating commit"
        print(f"  ok  SEC-27 touched by {len(touching)} commits (introduced, then rotated)")

    # Every commit hash quoted in the answer keys must be an ANCESTOR OF HEAD.
    # Checking that `git log -1 <hash>` succeeds is not enough: unreachable
    # objects from earlier rebuilds still resolve.
    quoted = set()
    for name in STAMPED_FILES:
        path = REPO / name
        if path.exists():
            quoted |= set(re.findall(r"\b[0-9a-f]{7,40}\b",
                                     path.read_text(encoding="utf-8")))
    # Hashes the answer keys quote ON PURPOSE as history rather than as a live
    # reference: they describe the pre-rebuild repository and are expected to
    # stop being ancestors once the history is rebuilt.
    historical = set(re.findall(r"\b[0-9a-f]{7,40}\b",
                                " ".join(HISTORICAL_REFERENCES)))
    stale = []
    for h in quoted:
        if h in historical or any(ref.startswith(h) or h.startswith(ref)
                                  for ref in historical):
            continue
        if _subject(h) is None:
            continue  # not a commit at all, just a hex string
        r = subprocess.run(["git", "merge-base", "--is-ancestor", h, "HEAD"],
                           cwd=REPO, capture_output=True)
        if r.returncode:
            stale.append(h)
    assert not stale, (
        "answer key quotes commits that are not on this branch: "
        f"{sorted(stale)}\n"
        "If the history was just rebuilt, these are references the stamper could "
        "not map back to a commit message. Fix the reference or add it to "
        "HISTORICAL_REFERENCES if it deliberately points at the old history.")
    print(f"  ok  all {len(quoted) - len(historical & quoted)} live commit references "
          "are ancestors of HEAD")
    if GENERATED_NOT_STAMPED:
        print("  note the baselines record the commits of the run that produced them;"
              "\n       regenerate them after a rebuild rather than stamping them")

    count = len(git("log", "--oneline").stdout.strip().splitlines())
    print(f"  ok  {count} commits on main")

    status = git("status", "--porcelain").stdout.strip()
    untracked = [l for l in status.splitlines() if l.startswith("??")]
    if untracked:
        print(f"  note {len(untracked)} untracked path(s): "
              + ", ".join(l[3:] for l in untracked[:5]))

    for name, url in saved_remotes:
        subprocess.run(["git", "remote", "add", name, url], cwd=REPO,
                       capture_output=True)
        print(f"  ok  restored remote {name} -> {url}")

    if saved_remotes:
        print("\n  NOTE: the history was rebuilt, so every commit hash is new."
              "\n  If this branch was already pushed, the next push needs"
              "\n  --force-with-lease.")

    print("\ndone. `git log --oneline` to review.")


if __name__ == "__main__":
    main()
