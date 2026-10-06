#!/usr/bin/env python3
"""Regression tests for the testbed's own tooling.

Run with:  python scripts/test_tooling.py

These guard two things that silently broke before, both of which are invisible
to a casual reading of the code:

1. `seed_history.py`'s commit-hash stamper. Its substitution pattern once
   contained literal BACKSPACE bytes (0x08) where the source should have read
   backslash-b. A terminal erases the preceding character when it prints a
   backspace, so `cat`, `grep`, an editor and even `inspect.getsource` all
   displayed a correct-looking regex. The pattern matched nothing, the rewrite
   quietly did nothing, and the function still printed the mappings it had
   computed -- so the logs looked right too. It survived from the original build
   until a rebuild first needed to re-stamp a hash.

   The lesson: a unit test that asserts the *mapping* would have passed. Only a
   test that asserts the FILE CONTENT ACTUALLY CHANGED catches this.

2. Baseline redaction. gitleaks' raw git-mode report contains SEC-04's and
   SEC-27's history-only secret values. Committing one unredacted would put
   those values back at HEAD and destroy the plants.
"""

import importlib.util
import json
import subprocess
import sys
import tempfile
import unicodedata
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
FAILURES = []


def load_seed_history():
    spec = importlib.util.spec_from_file_location("seed_history", REPO / "seed_history.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def check(name, condition, detail=""):
    if condition:
        print(f"  ok    {name}")
    else:
        print(f"  FAIL  {name}")
        if detail:
            print(f"          {detail}")
        FAILURES.append(name)


# ---------------------------------------------------------------------------
# 1. The stamper must actually rewrite the file
# ---------------------------------------------------------------------------

def test_stamping_rewrites_the_file():
    """Stamp a stale hash and assert the file on disk changed.

    This is the test that would have caught the backspace bug. Asserting only
    that the old->new mapping is computed passes even when the rewrite is a
    no-op, which is exactly how the bug hid.
    """
    print("\nstamp_commit_references() rewrites the file")
    seed = load_seed_history()
    message = "add notifier service config"

    with tempfile.TemporaryDirectory() as tmp:
        sandbox = Path(tmp)
        run = lambda *a: subprocess.run(["git", *a], cwd=sandbox, check=True,
                                        capture_output=True, text=True)
        run("init", "--quiet", "--initial-branch=main")
        run("config", "user.name", "test")
        run("config", "user.email", "test@example.com")
        (sandbox / "seed.txt").write_text("x\n", encoding="utf-8")
        run("add", "seed.txt")
        run("commit", "-q", "-m", message)
        real_hash = run("rev-parse", "HEAD").stdout.strip()

        # A stale 8-character hash that is NOT the real one, written the way the
        # answer keys write it.
        stale = "0" * 8 if not real_hash.startswith("0" * 8) else "1" * 8
        key = sandbox / "answer-key.json"
        original = json.dumps({"introduced_commit": stale,
                               "note": f"planted in commit {stale}"}, indent=2)
        key.write_text(original, encoding="utf-8")

        # Point the module at the sandbox.
        seed.REPO = sandbox
        seed.ANCHORS = [message]
        seed.STAMPED_FILES = ["answer-key.json"]
        seed.HISTORICAL_REFERENCES = []

        # The stale hash must resolve to the anchor's subject for the stamper to
        # map it, so alias it to the real commit first.
        run("tag", "-f", "stale-alias", real_hash)
        original_subject = seed._subject
        seed._subject = lambda ref: (message if ref == stale else original_subject(ref))
        try:
            changed = seed.stamp_commit_references()
        finally:
            seed._subject = original_subject

        after = key.read_text(encoding="utf-8")
        check("returns True when it rewrote something", changed is True)
        check("FILE CONTENT CHANGED (the regression)", after != original,
              "the stamper reported a mapping but left the file untouched - "
              "this is the exact backspace-byte failure")
        check("stale hash is gone", stale not in after)
        check("new hash is present", real_hash[:8] in after,
              f"expected {real_hash[:8]} in the rewritten file")
        check("both occurrences rewritten", after.count(real_hash[:8]) == 2,
              f"found {after.count(real_hash[:8])}, expected 2")


def test_source_has_no_control_characters():
    """No source file may contain control bytes that terminals render invisibly."""
    print("\nsource files contain no invisible control characters")
    offenders = []
    for path in sorted(REPO.glob("*.py")) + sorted((REPO / "scripts").glob("*.py")):
        data = path.read_bytes()
        for index, byte in enumerate(data):
            if byte < 0x20 and byte not in (0x09, 0x0A, 0x0D):
                name = unicodedata.name(chr(byte), f"0x{byte:02x}")
                offenders.append(f"{path.name} byte {index}: {name}")
    check("no control bytes in any Python source", not offenders, "; ".join(offenders[:5]))


# ---------------------------------------------------------------------------
# 2. Baselines must never carry a history-only secret
# ---------------------------------------------------------------------------

def test_baselines_are_redacted():
    """Derive the history-only values and prove no baseline contains them."""
    print("\nbaselines are redacted")
    seed = load_seed_history()
    sec04 = seed.derive_secret(seed.SEC04_SEED)
    sec27_old = seed.derive_sec27()
    notifier = (REPO / "services/notifier-rust/notifier.toml")
    sec27_new = seed.extract_toml_value(notifier.read_text(encoding="utf-8"),
                                        "newrelic_api_key") if notifier.exists() else None

    values = {"SEC-04": sec04, "SEC-27 pre-rotation": sec27_old}
    if sec27_new:
        values["SEC-27 post-rotation"] = sec27_new

    for name in ["gitleaks-baseline.json", "osv-baseline.json", "arve-simulated-baseline.json"]:
        path = REPO / name
        if not path.exists():
            continue
        text = path.read_text(encoding="utf-8")
        for label, value in values.items():
            check(f"{name} does not contain the {label} value", value not in text)

    path = REPO / "gitleaks-baseline.json"
    if path.exists():
        findings = json.loads(path.read_text(encoding="utf-8"))
        unredacted = [f for f in findings
                      if not str(f.get("Secret", "")).startswith("sha256:")
                      or not str(f.get("Match", "")).startswith("sha256:")]
        check(f"all {len(findings)} gitleaks-baseline findings redacted", not unredacted,
              f"{len(unredacted)} findings still carry a raw value")

    path = REPO / "arve-simulated-baseline.json"
    if path.exists():
        findings = json.loads(path.read_text(encoding="utf-8"))["gitleaks"]["findings"]
        unredacted = [f for f in findings if not str(f.get("Secret", "")).startswith("sha256:")]
        check(f"all {len(findings)} ARVE-simulated findings redacted", not unredacted)


def test_history_only_values_absent_from_head():
    """The whole point of SEC-04 and SEC-27's old value: not present at HEAD."""
    print("\nhistory-only values are absent from HEAD")
    seed = load_seed_history()
    for label, value in (("SEC-04", seed.derive_secret(seed.SEC04_SEED)),
                         ("SEC-27 pre-rotation", seed.derive_sec27())):
        found = subprocess.run(["git", "grep", "-l", value], cwd=REPO,
                               capture_output=True, text=True).stdout.strip()
        check(f"{label} value is not in any tracked file at HEAD", not found, found)


def main():
    print("tooling regression tests")
    test_stamping_rewrites_the_file()
    test_source_has_no_control_characters()
    test_baselines_are_redacted()
    test_history_only_values_absent_from_head()
    print()
    if FAILURES:
        print(f"FAILED: {len(FAILURES)} check(s) - {', '.join(FAILURES)}")
        return 1
    print("OK: all tooling regression tests pass")
    return 0


if __name__ == "__main__":
    sys.exit(main())
