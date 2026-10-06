#!/usr/bin/env python3
"""Mirror of ARVE's ingestion FileFilter.evaluate().

THIS IS A MIRROR, NOT THE REAL THING, AND ITS OUTPUT IS A PREDICTION.

It re-implements `backend/app/ingestion/filters/file_filter.py` from the ARVE
repository (ShashwatNarayan/arve) using the exact lists and evaluation order
recorded in PROJECT_CONTEXT.md section 3.3.

**No ARVE run has ever confirmed what this file says.** Every "ARVE-simulated"
number in the answer keys, and the whole of arve-simulated-baseline.json, rests
on it. ARVE is under active development, so this copy can drift; it also encodes
assumptions that were never executed against the real code, such as the
extension being lower-cased before lookup.

If a real ARVE scan disagrees with this mirror, **this file is wrong**. Fix it
and the answer key to match observed ARVE behaviour, and record the difference --
a disagreement is itself worth keeping, because it means PROJECT_CONTEXT.md
section 3.3 no longer describes ARVE. When ARVE's filter changes, update the
lists below and re-run scripts/verify_plants.py. Never "fix" a plant to suit
this file.

Evaluation order, per path (normalised to '/'):
  1. any DIRECTORY segment in IGNORED_DIRECTORIES      -> SKIPPED ignored_directory
  2. size > MAX_FILE_SIZE_BYTES                         -> SKIPPED file_too_large
  3. lower-cased filename in ALLOWED_FILENAMES, or path
     matches WORKFLOW_PATTERN                           -> INGESTED
  4. extension in BINARY_OR_MEDIA_EXTENSIONS            -> SKIPPED binary_or_media_file
  5. extension in ALLOWED_EXTENSIONS                    -> INGESTED
  6. otherwise                                          -> SKIPPED unsupported_file_type

The extension is computed with os.path.splitext, exactly as ARVE does, which
means `.env.example` -> '.example', `.env` / `.npmrc` -> '' and so on. The
'.env' and '.env.example' entries in ALLOWED_EXTENSIONS are kept verbatim even
though splitext can never produce the second one -- that is the ARVE behaviour
being recorded.

Usage:
  python scripts/arve_filter_mirror.py                 # every tracked file
  python scripts/arve_filter_mirror.py --root DIR      # walk DIR on disk instead
  python scripts/arve_filter_mirror.py --json          # machine-readable
  python scripts/arve_filter_mirror.py PATH [PATH...]  # specific paths
"""

import argparse
import json
import os
import re
import subprocess
import sys
from pathlib import Path

IGNORED_DIRECTORIES = {
    ".git", "node_modules", "venv", ".venv", "__pycache__", "dist", "build",
    "target", "coverage", "vendor", ".cache", ".idea", ".vscode",
}

MAX_FILE_SIZE_BYTES = 1_048_576

ALLOWED_FILENAMES = {
    "package.json", "package-lock.json", "yarn.lock", "pnpm-lock.yaml",
    "requirements.txt", "pyproject.toml", "pipfile", "pom.xml", "build.gradle",
    "go.mod", "cargo.toml", "dockerfile", "docker-compose.yml",
    "docker-compose.yaml", "makefile", ".gitignore",
}

WORKFLOW_PATTERN = re.compile(r"^\.github/workflows/.*\.(yml|yaml)$")

ALLOWED_EXTENSIONS = {
    ".py", ".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".java", ".go", ".rs",
    ".c", ".h", ".cpp", ".hpp", ".php", ".rb", ".kt", ".swift", ".cs", ".ex",
    ".exs", ".scala", ".html", ".css", ".scss", ".sass", ".less", ".vue",
    ".svelte", ".astro", ".json", ".yaml", ".yml", ".toml", ".env",
    ".env.example", ".sql", ".graphql", ".gql", ".sh", ".bash", ".ps1", ".md",
    ".markdown",
}

BINARY_OR_MEDIA_EXTENSIONS = {
    ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".webp", ".mp4", ".mov",
    ".avi", ".mp3", ".wav", ".zip", ".tar", ".gz", ".7z", ".rar", ".pdf",
    ".doc", ".docx", ".xls", ".xlsx", ".exe", ".dll", ".so", ".dylib", ".bin",
    ".woff", ".woff2", ".ttf", ".eot", ".pyc", ".pyo", ".pyd", ".db", ".sqlite",
    ".sqlite3", ".log",
}

INGESTED = "INGESTED"
SKIPPED = "SKIPPED"


def evaluate(path, size_bytes):
    """Return (status, skip_reason) for one repository-relative path."""
    normalized = path.replace("\\", "/").lstrip("/")
    segments = normalized.split("/")
    directories, filename = segments[:-1], segments[-1]

    if any(segment in IGNORED_DIRECTORIES for segment in directories):
        return SKIPPED, "ignored_directory"

    if size_bytes > MAX_FILE_SIZE_BYTES:
        return SKIPPED, "file_too_large"

    if filename.lower() in ALLOWED_FILENAMES or WORKFLOW_PATTERN.match(normalized):
        return INGESTED, None

    extension = os.path.splitext(filename)[1].lower()

    if extension in BINARY_OR_MEDIA_EXTENSIONS:
        return SKIPPED, "binary_or_media_file"

    if extension in ALLOWED_EXTENSIONS:
        return INGESTED, None

    return SKIPPED, "unsupported_file_type"


def tracked_files(root):
    out = subprocess.run(["git", "ls-files", "-z"], cwd=root, check=True,
                         capture_output=True).stdout.decode("utf-8")
    return [p for p in out.split("\0") if p]


def walked_files(root):
    for dirpath, _, filenames in os.walk(root):
        for name in filenames:
            full = Path(dirpath) / name
            yield full.relative_to(root).as_posix()


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("paths", nargs="*", help="repo-relative paths (default: git ls-files)")
    parser.add_argument("--root", default=None, help="walk this directory instead of git ls-files")
    parser.add_argument("--json", action="store_true", help="emit JSON")
    parser.add_argument("--ingested-only", action="store_true", help="print only INGESTED paths")
    args = parser.parse_args(argv)

    root = Path(args.root or Path(__file__).resolve().parent.parent)
    if args.paths:
        paths = args.paths
    elif args.root:
        paths = sorted(walked_files(root))
    else:
        paths = tracked_files(root)

    results = []
    for path in paths:
        full = root / path
        size = full.stat().st_size if full.exists() else 0
        status, reason = evaluate(path, size)
        results.append({"path": path, "status": status, "skip_reason": reason,
                        "size_bytes": size})

    if args.ingested_only:
        for r in results:
            if r["status"] == INGESTED:
                print(r["path"])
    elif args.json:
        json.dump(results, sys.stdout, indent=2)
        print()
    else:
        for r in results:
            print(f"{r['status']:<9} {r['skip_reason'] or '':<22} {r['path']}")
        skipped = sum(r["status"] == SKIPPED for r in results)
        print(f"\n{len(results) - skipped} ingested, {skipped} skipped, {len(results)} total")
    return 0


if __name__ == "__main__":
    sys.exit(main())
