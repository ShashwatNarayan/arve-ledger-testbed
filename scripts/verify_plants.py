#!/usr/bin/env python3
"""Verify every planted finding against expected-findings.json, and emit the counts.

This script is the SINGLE SOURCE OF TRUTH for every number quoted in
README_TEAM.md, EXPECTED_FINDINGS.md and plan.md. Those documents used to carry
hand-maintained totals, and they drifted: the commit count was variously written
as 11, 12 and 13, and the HEAD finding count as both 10 and 11. Run this instead
of counting by hand.

What it does
------------
1. Materialises the repository at HEAD the way ARVE receives it -- a file tree
   with LF endings and **no .git** -- and, from that, the subset ARVE's
   ingestion filter would keep (via scripts/arve_filter_mirror.py).
2. Runs all four scanner versions in Docker:

     gitleaks 8.24.2 (ARVE pinned)   dir over the full tree, dir over the
     gitleaks 8.30.1 (reference)     ingested subset, and git over the repo
     osv-scanner 1.9.2 (ARVE pinned) over the full tree and the ingested subset
     osv-scanner 2.5.1 (reference)

   The `dir` run over ONLY the ingested files is the ARVE simulation.

   **That one is a PREDICTION, not a measurement.** The ingested subset comes
   from scripts/arve_filter_mirror.py, a hand-written mirror of ARVE's
   FileFilter. No ARVE run has confirmed it. Everything else here is measured:
   which rule fires, in which file, at which line, for each scanner version. If
   a real ARVE scan disagrees with the predicted numbers, **the mirror is wrong**
   and both it and the answer key need updating -- not ARVE.
3. Diffs every run against expected-findings.json and exits non-zero on any
   difference that the answer key does not already explain.

Secrets are never written or printed: gitleaks runs with --redact, and only
rule / file / line are ever shown.

Usage
-----
    python scripts/verify_plants.py                 # verify and print the counts
    python scripts/verify_plants.py --counts-only   # skip scanning, print expectations
    python scripts/verify_plants.py --json out.json # also write the results as JSON
    python scripts/verify_plants.py --quick         # pinned versions only (faster)

Requires Docker. Nothing is installed on the host.
"""

import argparse
import io
import json
import shutil
import subprocess
import sys
import tarfile
import tempfile
from collections import Counter
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "scripts"))
from arve_filter_mirror import evaluate  # noqa: E402

GITLEAKS = {"8.24.2": "ghcr.io/gitleaks/gitleaks:v8.24.2",
            "8.30.1": "ghcr.io/gitleaks/gitleaks:v8.30.1"}
OSV = {"1.9.2": "ghcr.io/google/osv-scanner:v1.9.2",
       "2.5.1": "ghcr.io/google/osv-scanner:v2.5.1"}
PINNED_GITLEAKS, REFERENCE_GITLEAKS = "8.24.2", "8.30.1"
PINNED_OSV, REFERENCE_OSV = "1.9.2", "2.5.1"


# --------------------------------------------------------------------------
# Workspace
# --------------------------------------------------------------------------

def materialise(dest):
    """Write HEAD to `dest` with LF endings, the way a GitHub tarball arrives."""
    blob = subprocess.run(["git", "-c", "core.autocrlf=false", "archive", "HEAD"],
                          cwd=REPO, capture_output=True, check=True).stdout
    with tarfile.open(fileobj=io.BytesIO(blob)) as tar:
        tar.extractall(dest)


def split_ingested(tree, dest):
    """Copy only the files ARVE's FileFilter would ingest. Returns the verdicts."""
    verdicts = []
    for path in sorted(tree.rglob("*")):
        if not path.is_file():
            continue
        rel = path.relative_to(tree).as_posix()
        status, reason = evaluate(rel, path.stat().st_size)
        verdicts.append({"path": rel, "status": status, "skip_reason": reason})
        if status == "INGESTED":
            target = dest / rel
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(path, target)
    return verdicts


# --------------------------------------------------------------------------
# Scanners
# --------------------------------------------------------------------------

def run_gitleaks(version, target, mode="dir"):
    target = str(Path(target).resolve())
    mount = "/repo" if mode == "git" else "/code"
    with tempfile.TemporaryDirectory() as out:
        result = subprocess.run(
            ["docker", "run", "--rm", "--network=none",
             "-v", f"{target}:{mount}:ro", "-v", f"{out}:/output",
             GITLEAKS[version], mode, mount, "--report-format", "json",
             "--report-path", "/output/r.json", "--redact", "--exit-code", "0"],
            capture_output=True, text=True, encoding="utf-8", errors="replace")
        report = Path(out) / "r.json"
        if not report.exists():
            raise SystemExit(f"gitleaks {version} ({mode}) failed:\n{result.stderr[-1500:]}")
        data = json.loads(report.read_text(encoding="utf-8"))
    return [{"rule": d["RuleID"], "file": d["File"].split(mount.lstrip('/') + "/", 1)[-1].lstrip("/"),
             "line": d["StartLine"], "commit": (d.get("Commit") or "")[:8]} for d in data]


def run_osv(version, target):
    target = str(Path(target).resolve())
    with tempfile.TemporaryDirectory() as out:
        args = (["--format", "json", "--output", "/output/r.json", "-r", "/code"]
                if version.startswith("1.") else
                ["scan", "source", "--recursive", "/code", "--format", "json",
                 "--output-file", "/output/r.json"])
        result = subprocess.run(
            ["docker", "run", "--rm", "-v", f"{target}:/code:ro", "-v", f"{out}:/output",
             OSV[version], *args], capture_output=True, text=True,
            encoding="utf-8", errors="replace")
        report = Path(out) / "r.json"
        if not report.exists():
            raise SystemExit(f"osv-scanner {version} failed (rc={result.returncode}):\n{result.stderr[-1500:]}")
        data = json.loads(report.read_text(encoding="utf-8"))
    records = []
    for res in data.get("results") or []:
        source = res["source"]["path"].replace("/code/", "")
        for package in res.get("packages") or []:
            info = package["package"]
            for vuln in package.get("vulnerabilities") or []:
                records.append({"file": source, "package": info["name"],
                                "version": info["version"], "id": vuln["id"],
                                "ecosystem": info.get("ecosystem")})
    return records


# --------------------------------------------------------------------------
# Expectations, derived from the answer key
# --------------------------------------------------------------------------

def secret_expectations(key):
    """(file, line, rule) counters for HEAD, for full history, and for ARVE's view."""
    head, history, arve = Counter(), Counter(), Counter()
    for f in key["findings"]:
        if f["engine"] != "gitleaks":
            continue
        ingested = f["arve_pipeline"]["ingestion"] == "INGESTED"
        spots = [(f["file_path"], f["line_start"], f["rule_id"])]
        for loc in f["testbed"].get("additional_locations", []):
            spots.append((loc.get("file_path", f["file_path"]),
                          loc["line"], loc.get("rule", f["rule_id"])))
        for spot in spots:
            if not f["history_only"]:
                head[spot] += 1
                if ingested:
                    arve[spot] += 1
            history[spot] += 1
        for loc in f["testbed"].get("history_extra_locations", []):
            history[(loc["file_path"], loc["line"], loc["rule_id"])] += 1
    return head, history, arve


def dependency_expectations(key, scanner):
    """(file, package, id) -> version, for the records this scanner version reports."""
    expected = {}
    for record in key["expected_osv_inventory"]:
        if not (record.get("reported_by") or {}).get(scanner, True):
            continue
        version = (record.get("version_by_scanner") or {}).get(scanner, record["package_version"])
        expected[(record["file_path"], record["package_name"].lower(), record["osv_id"])] = version
    return expected


def compare_counter(observed, expected):
    obs = Counter((f["file"], f["line"], f["rule"]) for f in observed)
    return sorted((obs - expected).elements()), sorted((expected - obs).elements())


def compare_osv(observed, expected):
    obs = {(r["file"], r["package"].lower(), r["id"]): r["version"] for r in observed}
    unexpected = sorted(k for k in obs if k not in expected)
    missing = sorted(k for k in expected if k not in obs)
    wrong_version = sorted((k, expected[k], obs[k]) for k in obs if k in expected and obs[k] != expected[k])
    return unexpected, missing, wrong_version


# --------------------------------------------------------------------------
# Reporting
# --------------------------------------------------------------------------

class Report:
    def __init__(self):
        self.problems = []
        self.lines = []

    def ok(self, text):
        self.lines.append(f"  ok    {text}")

    def fail(self, text, detail=()):
        self.problems.append(text)
        self.lines.append(f"  FAIL  {text}")
        for item in detail:
            self.lines.append(f"          {item}")

    def section(self, title):
        self.lines.append(f"\n{title}")

    def dump(self):
        print("\n".join(self.lines))


def check_set(report, label, observed, expected):
    extra, missing = compare_counter(observed, expected)
    if not extra and not missing:
        report.ok(f"{label}: {len(observed)} findings, exactly as expected")
        return True
    report.fail(f"{label}: {len(observed)} findings, expected {sum(expected.values())}",
                [f"unexpected: {e}" for e in extra] + [f"missing:    {m}" for m in missing])
    return False


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--json", metavar="PATH", help="write the full result as JSON")
    parser.add_argument("--counts-only", action="store_true",
                        help="print the expected counts without running any scanner")
    parser.add_argument("--quick", action="store_true",
                        help="run only the ARVE-pinned scanner versions")
    args = parser.parse_args()

    key = json.loads((REPO / "expected-findings.json").read_text(encoding="utf-8"))
    head_exp, history_exp, arve_exp = secret_expectations(key)

    counts = {
        "planted_findings": key["planted_finding_count"]["total"],
        "secrets": key["planted_finding_count"]["secrets"],
        "dependencies": key["planted_finding_count"]["dependencies"],
        "negative_controls": len(key["negative_controls"]),
        "gitleaks_at_head": key["expected_gitleaks_finding_count_at_head"],
        "gitleaks_full_history": key["expected_gitleaks_finding_count_full_history"],
        "gitleaks_via_arve_ingestion": key["expected_gitleaks_finding_count_via_arve_ingestion"],
        "arve_findings_after_normalization": key["expected_arve_finding_count_after_normalization"],
        "osv_records_pinned": key["expected_osv_record_count_by_scanner"]["osv_1_9_2"],
        "osv_records_reference": key["expected_osv_record_count_by_scanner"]["osv_2_5_1"],
        "osv_records_via_arve_ingestion": key["expected_osv_record_count_via_arve_ingestion"],
        "commits": int(subprocess.run(["git", "rev-list", "--count", "HEAD"], cwd=REPO,
                                      capture_output=True, text=True).stdout.strip() or 0),
    }

    if args.counts_only:
        print_counts(counts, key)
        return 0

    report = Report()
    workspace = Path(tempfile.mkdtemp(prefix="arve-verify-"))
    try:
        tree, ingested = workspace / "full", workspace / "ingested"
        tree.mkdir(); ingested.mkdir()
        materialise(tree)
        verdicts = split_ingested(tree, ingested)
        skipped = [v for v in verdicts if v["status"] == "SKIPPED"]

        report.section("ingestion [PREDICTED by scripts/arve_filter_mirror.py, not by ARVE]")
        report.ok(f"{len(verdicts) - len(skipped)} of {len(verdicts)} files ingested, "
                  f"{len(skipped)} skipped")
        by_reason = Counter(v["skip_reason"] for v in skipped)
        for reason, n in sorted(by_reason.items()):
            report.lines.append(f"          {n:>3} {reason}")

        gitleaks_versions = [PINNED_GITLEAKS] if args.quick else list(GITLEAKS)
        osv_versions = [PINNED_OSV] if args.quick else list(OSV)
        results = {"gitleaks": {}, "osv": {}}

        report.section("secrets (gitleaks)")
        for version in gitleaks_versions:
            full = run_gitleaks(version, tree, "dir")
            arve = run_gitleaks(version, ingested, "dir")
            git = run_gitleaks(version, REPO, "git")
            results["gitleaks"][version] = {"head": full, "arve": arve, "history": git}
            check_set(report, f"{version} dir at HEAD", full, head_exp)
            check_set(report, f"{version} git full history", git, history_exp)
            check_set(report, f"{version} ARVE-simulated [PREDICTED] (ingested subset)", arve, arve_exp)

        report.section("dependencies (osv-scanner)")
        for version in osv_versions:
            scanner = "osv_1_9_2" if version.startswith("1.") else "osv_2_5_1"
            full = run_osv(version, tree)
            arve = run_osv(version, ingested)
            results["osv"][version] = {"full": full, "arve": arve}
            expected = dependency_expectations(key, scanner)
            unexpected, missing, wrong = compare_osv(full, expected)
            if not unexpected and not missing and not wrong:
                report.ok(f"{version} full tree: {len(full)} records, exactly as expected")
            else:
                report.fail(f"{version} full tree: {len(full)} records, expected {len(expected)}",
                            [f"unexpected: {u}" for u in unexpected]
                            + [f"missing:    {m}" for m in missing]
                            + [f"version:    {k} expected {e}, got {g}" for k, e, g in wrong])
            ingested_paths = {v["path"] for v in verdicts if v["status"] == "INGESTED"}
            arve_expected = {k: v for k, v in expected.items() if k[0] in ingested_paths}
            u2, m2, w2 = compare_osv(arve, arve_expected)
            if not u2 and not m2 and not w2:
                report.ok(f"{version} ARVE-simulated [PREDICTED]: {len(arve)} records, exactly as expected")
            else:
                report.fail(f"{version} ARVE-simulated [PREDICTED]: {len(arve)} records, expected {len(arve_expected)}",
                            [f"unexpected: {u}" for u in u2] + [f"missing:    {m}" for m in m2])

        report.section("negative controls")
        silent = set(key.get("files_expected_no_secret_findings", []))
        for version in gitleaks_versions:
            noisy = sorted({f["file"] for f in results["gitleaks"][version]["history"]} & silent)
            if noisy:
                report.fail(f"{version}: files that must produce nothing reported findings",
                            noisy)
            else:
                report.ok(f"{version}: all {len(silent)} must-stay-silent files are clean")

        report.section("line numbers")
        bad = verify_line_numbers(key, tree)
        if bad:
            report.fail(f"{len(bad)} recorded line numbers do not match the committed content", bad)
        else:
            report.ok(f"all {count_line_anchors(key)} recorded locations match the committed content")

        report.dump()
        print_counts(counts, key)

        if args.json:
            Path(args.json).write_text(json.dumps(
                {"counts": counts, "ingestion": verdicts, "results": results,
                 "problems": report.problems}, indent=2), encoding="utf-8")
            print(f"\nwrote {args.json}")

        if report.problems:
            print(f"\nFAILED: {len(report.problems)} unexplained difference(s)")
            return 1
        print("\nOK: every plant, negative control and count matches the answer key")
        return 0
    finally:
        shutil.rmtree(workspace, ignore_errors=True)


def count_line_anchors(key):
    total = 0
    for f in key["findings"]:
        total += 1 + len([l for l in f["testbed"].get("additional_locations", []) if "line" in l])
    return total


def verify_line_numbers(key, tree):
    """Every recorded line must exist in the committed file (history-only plants excepted)."""
    problems = []
    for f in key["findings"]:
        if f["history_only"]:
            continue
        spots = [(f["file_path"], f["line_start"])]
        for loc in f["testbed"].get("additional_locations", []):
            if "line" in loc:
                spots.append((loc.get("file_path", f["file_path"]), loc["line"]))
        for path, line in spots:
            target = tree / path
            if not target.exists():
                problems.append(f"{f['id']}: {path} does not exist at HEAD")
                continue
            lines = target.read_text(encoding="utf-8", errors="replace").splitlines()
            if not 1 <= line <= len(lines):
                problems.append(f"{f['id']}: {path}:{line} is outside the file ({len(lines)} lines)")
    return problems


def print_counts(counts, key):
    print("\n" + "=" * 68)
    print("CANONICAL COUNTS - quote these, do not count by hand")
    print("=" * 68)
    print(f"  planted findings                    {counts['planted_findings']}"
          f"  ({counts['secrets']} secrets + {counts['dependencies']} dependencies)")
    print(f"  negative controls                   {counts['negative_controls']}")
    print(f"  commits on main                     {counts['commits']}")
    print("\n  gitleaks findings            [MEASURED]")
    print(f"    git (full history)                {counts['gitleaks_full_history']}")
    print(f"    dir at HEAD                       {counts['gitleaks_at_head']}")
    print("\n  osv-scanner records          [MEASURED]")
    print(f"    osv 1.9.2 (ARVE pinned)           {counts['osv_records_pinned']}")
    print(f"    osv 2.5.1 (reference)             {counts['osv_records_reference']}"
          "   (also reports Newtonsoft.Json from the .csproj)")
    print("\n  ARVE's view                  [PREDICTED by the filter mirror -")
    print("                                 no ARVE run has confirmed it]")
    print(f"    gitleaks, ingested subset         {counts['gitleaks_via_arve_ingestion']}")
    print(f"    after normalization               {counts['arve_findings_after_normalization']}"
          "   (SEC-22's two secrets collapse to one)")
    print(f"    osv, ingested subset              {counts['osv_records_via_arve_ingestion']}")
    print("\n  If a real ARVE run disagrees with the predicted numbers, the mirror")
    print("  is wrong: fix scripts/arve_filter_mirror.py and the answer key, and")
    print("  record the difference. It means PROJECT_CONTEXT.md 3.3 is out of date.")
    print("=" * 68)


if __name__ == "__main__":
    sys.exit(main())
