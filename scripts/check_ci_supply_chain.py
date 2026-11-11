#!/usr/bin/env python3
"""Narrow offline GitHub Actions supply-chain regression guard.

Approved action SHAs require a deliberate reviewed update with upstream
verification. This is not a workflow sandbox or proof of supply-chain trust.
"""
from __future__ import annotations

from pathlib import Path
import re
import sys

ROOT = Path(__file__).resolve().parents[1]
EXPECTED = {
    "actions/checkout": "3d3c42e5aac5ba805825da76410c181273ba90b1",  # v7.0.1
    "actions/setup-python": "6d4fd22b20465ccc0f7354476588e8df7c9ca0e0",  # v7.1.0
}
ACTION = re.compile(r"(?m)^[ \t]*-[ \t]+uses:[ \t]+([^#\s]+)")
CHECKOUT_WITH = re.compile(
    r"(?m)^      - uses: actions/checkout@[0-9a-f]{40}[^\n]*\n"
    r"        with:\n          persist-credentials: false(?:\n|$)"
)


def verify_workflow(text: str) -> list[str]:
    """Check this repository's small, review-controlled workflow contract."""
    issues: list[str] = []
    refs = ACTION.findall(text)
    expected = [f"{name}@{sha}" for name, sha in EXPECTED.items()]
    if refs != expected:
        issues.append("unexpected, missing, unpinned, or reordered external actions")
    if not CHECKOUT_WITH.search(text):
        issues.append("checkout must explicitly disable credential persistence")
    if not re.search(r"(?m)^permissions:\n  contents: read[ \t]*$", text):
        issues.append("workflow must declare read-only contents permission")
    if re.search(r"(?m)^[ \t]+[a-z-]+:[ \t]+write[ \t]*$", text) or "write-all" in text:
        issues.append("workflow must not request write-scoped permissions")
    if re.search(r"\b(?:pull_request_target|workflow_run)\b", text):
        issues.append("privileged pull-request or workflow-run triggers prohibited")
    if re.search(r"(?i)\bsecrets\s*(?:\.|\[)|\bid-token:[ \t]*write\b", text):
        issues.append("workflow must not request secrets or OIDC credentials")
    return issues


def main() -> int:
    path = ROOT / ".github" / "workflows" / "ci.yml"
    try:
        issues = verify_workflow(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError) as exc:
        print(f"[CI GUARD] unable to read workflow: {exc}", file=sys.stderr)
        return 1
    if issues:
        for issue in issues:
            print(f"[CI GUARD] FAIL: {issue}", file=sys.stderr)
        return 1
    print("[CI GUARD] PASS: reviewed SHA pins, no checkout credentials, read-only permissions")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
