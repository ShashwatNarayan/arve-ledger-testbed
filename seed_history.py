#!/usr/bin/env python3
"""Rebuild the planted Git history for arve-ledger-testbed.

Several findings in this testbed exist *only in history*, so the commit sequence
is part of the fixture rather than an accident of how it was authored. This
script reconstructs that sequence deterministically.

What it produces
----------------
Eleven commits whose messages read like ordinary development. Two of them matter
structurally:

  * **SEC-04** (an SFTP password in ``backend/app/settlement.py``) is added in
    commit 4 and deleted in commit 8. At ``HEAD`` the file does not exist, so a
    working-tree scan finds nothing and only a history walk reports it.

  * **SEC-06** (the provider webhook secret in ``backend/app/webhooks.py``) is
    introduced in commit 6 at one line and moved to a different line by the
    refactor in commit 7. The secret *value* never changes, which is the point:
    a fingerprint that includes the line number will wrongly report the finding
    as RESOLVED and then REOPENED.

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


def derive_secret(seed, length=28):
    """Deterministically expand a seed into a high-entropy alphanumeric string."""
    alphabet = string.ascii_letters + string.digits
    out = []
    counter = 0
    while len(out) < length:
        block = hashlib.sha256(f"{seed}:{counter}".encode()).digest()
        out.extend(alphabet[b % len(alphabet)] for b in block)
        counter += 1
    return "".join(out[:length])

# Commits are dated backwards from this point so `git log` looks like work done
# over a few weeks rather than all in one second.
FIRST_COMMIT_AT = datetime(2026, 7, 13, 9, 24, tzinfo=timezone.utc)

AUTHOR_NAME = os.environ.get("SEED_AUTHOR_NAME", "Shashwat Narayan")
AUTHOR_EMAIL = os.environ.get("SEED_AUTHOR_EMAIL", "shashwatn2802@gmail.com")


# ---------------------------------------------------------------------------
# Embedded file versions that differ from HEAD
# ---------------------------------------------------------------------------

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
        git("add", "--", path)


def write(relative_path, content):
    target = REPO / relative_path
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(content, encoding="utf-8")


def read(relative_path):
    return (REPO / relative_path).read_text(encoding="utf-8")


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
]

STAMPED_FILES = [
    "EXPECTED_FINDINGS.md",
    "expected-findings.json",
    "README_TEAM.md",
    "gitleaks-baseline.json",
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
        text = re.sub(r"[0-9a-f]{7,40}",
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

    # 13 -- handover guide for whoever evaluates a scanner against this repo
    if (REPO / "README_TEAM.md").exists():
        add("README_TEAM.md", "README.md")
        i, when = nxt(1, 4)
        commit(i, "add evaluation guide for the scanner team", when)

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

    # Every commit hash quoted in the answer keys must be an ANCESTOR OF HEAD.
    # Checking that `git log -1 <hash>` succeeds is not enough: unreachable
    # objects from earlier rebuilds still resolve.
    quoted = set()
    for name in STAMPED_FILES:
        path = REPO / name
        if path.exists():
            quoted |= set(re.findall(r"\b[0-9a-f]{7,40}\b",
                                     path.read_text(encoding="utf-8")))
    stale = []
    for h in quoted:
        if _subject(h) is None:
            continue  # not a commit at all, just a hex string
        r = subprocess.run(["git", "merge-base", "--is-ancestor", h, "HEAD"],
                           cwd=REPO, capture_output=True)
        if r.returncode:
            stale.append(h)
    assert not stale, f"answer key quotes commits not on this branch: {stale}"
    print(f"  ok  all {len(quoted)} quoted commit references are ancestors of HEAD")

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
