# Kickstart prompt

Paste this into Claude Code from inside `C:\projects\arve-ledger-testbed`.

---

```text
Read NEW_PROJECT_START_README.md in this directory completely before doing
anything else. It is the build spec for this repository — follow it as a spec,
not as inspiration.

Summary of what you are building: a deliberately vulnerable payments-ledger API
that serves as a testbed for ARVE, a security scanning engine my team is
building. ARVE currently integrates Gitleaks (secrets) and OSV-Scanner
(vulnerable dependencies). This repo exists so we can measure how well ARVE
detects things whose answers we already know.

Three rules that override your normal instincts:

1. Keep the application trivially simple. Seven endpoints, ~15 source files,
   SQLite, no auth system. The complexity budget belongs entirely to the
   vulnerability matrix, not the architecture. If you find yourself adding a
   feature that isn't in the spec's feature list, stop.

2. Only plant flaws that Gitleaks or OSV-Scanner can actually detect. No SQL
   injection, XSS, or access-control bugs — those need Semgrep, which is not
   connected yet, so planting them would test nothing.

3. Do not obfuscate anything. These two scanners are exact-match detectors, not
   analyzers. A hidden secret is just an undetectable secret. Difficulty comes
   from where things live, from Git history, and from stressing ARVE's own
   normalizer — never from cleverness.

Work in this order:

  1. Confirm the plan with me before writing code — specifically the exact
     package versions you intend to use for the DEP-* findings. Verify each one
     against osv.dev first and tell me what you found; do not trust the
     candidate list in the spec without checking, and do not use famous
     documented example credentials like AKIAIOSFODNN7EXAMPLE, since scanners
     allowlist those by default.
  2. Build the app and plant the findings.
  3. Update EXPECTED_FINDINGS.md and expected-findings.json as you go, never
     afterwards. An unplanted-but-documented or planted-but-undocumented finding
     makes the whole evaluation meaningless.
  4. Write seed_history.py to reproduce the required commit sequence, then run
     it. Commit messages must read like ordinary development.
  5. Verify every line number in the answer key after the final commit.
  6. Run gitleaks and osv-scanner locally, commit both baseline reports, and
     tell me any planted finding that the reference tools themselves missed.

Every credential you write must be synthetic and non-functional, but correctly
shaped so the scanners match it. Start by reading the spec, then come back to me
with the dependency versions you verified and your build plan.
```
