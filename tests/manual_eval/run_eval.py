"""Manual calibration harness: scan the malicious fixtures (and optional real-world corpus).

Usage:
    python tests/manual_eval/run_eval.py            # scan malicious fixtures
    python tests/manual_eval/run_eval.py --corpus   # also scan cloned real-world corpus
"""

from __future__ import annotations

import sys
from pathlib import Path

from skilltotal.collector import detect_component
from skilltotal.engine import analyze_directory

HERE = Path(__file__).parent


def scan(label: str, path: Path) -> None:
    comp = detect_component(path, str(path))
    r = analyze_directory(path, comp)
    caps = ", ".join(sorted(c.value for c in r.capabilities)) or "-"
    print(f"\n=== {label}  [{comp.type}]  {r.risk_level.value.upper()} {r.risk_score}/100 ===")
    print(f"  capabilities: {caps}")
    print(f"  findings ({len(r.findings)}):")
    for f in r.findings:
        print(f"    [{f.severity.value:8}] {f.id:24} ev={len(f.evidence):<2} {f.title}")
    if r.needs_review:
        print(f"  needs_review ({len(r.needs_review)}):")
        for n in r.needs_review[:8]:
            print(f"    - {n.title}")


def main() -> None:
    mal = HERE / "malicious"
    print("############## MALICIOUS FIXTURES ##############")
    for sub in sorted(mal.iterdir()):
        if sub.is_dir():
            scan(f"malicious/{sub.name}", sub)

    if "--corpus" in sys.argv:
        corpus = HERE / "corpus"
        if not corpus.exists():
            print("\n(no corpus/ — run fetch_corpus.py first)")
            return
        print("\n############## REAL-WORLD CORPUS ##############")
        for group in sorted(corpus.iterdir()):
            if not group.is_dir():
                continue
            # Monorepos expose components under <group>/src/*; otherwise each immediate
            # subdirectory of the group is its own component.
            srcdir = group / "src"
            if srcdir.is_dir():
                targets = [c for c in sorted(srcdir.iterdir()) if c.is_dir()]
            else:
                targets = [c for c in sorted(group.iterdir()) if c.is_dir() and c.name != ".git"]
            for t in targets:
                scan(f"corpus/{group.name}/{t.name}", t)


if __name__ == "__main__":
    main()
