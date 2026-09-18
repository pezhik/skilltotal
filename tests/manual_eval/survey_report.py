"""Turn a full-registry survey (survey_registry.py) into the published study.

Two outputs from one dataset: ``docs/mcp-registry-survey.md`` for people and
``docs/mcp-registry-survey.json`` for anyone who wants to recompute it. Stdlib only.

What this deliberately does NOT publish matters as much as what it does. Capability figures
(what a component *can* do) proved stable across four rulesets and are reported. Secret- and
sensitive-path counts are not: a sample of those hits in this population was dominated by
values published on purpose — an analytics project key, an on-chain address, a vendor's public
constant — rather than leaks. Printing such a count as "N components ship credentials" would be
a false public statement about named projects, so the number is withheld and the reason is
stated in the document itself.
"""

from __future__ import annotations

import argparse
import json
import re
from collections import Counter
from datetime import datetime, timezone
from fractions import Fraction
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parents[2]
OUT_PREFIX_DEFAULT = str(_REPO_ROOT / "docs" / "mcp-registry-survey")
_LEVELS = ("low", "medium", "high", "critical")
# OWASP Agentic Skills classes a static scan can evidence (AST06-AST10 need runtime or registry
# observation, so no rule maps to them). Names come from docs/owasp-agentic-skills-mapping.md.
# A component counts once per class, however many of its findings map to it.
_OWASP_LABEL: dict[str, str] = {
    "AST01": "AST01 Malicious Skills",
    "AST02": "AST02 Supply Chain Compromise",
    "AST03": "AST03 Over-Privileged Skills",
    "AST04": "AST04 Insecure Metadata",
    "AST05": "AST05 Unsafe Deserialization",
}
_UNREACHABLE = "repository or package no longer reachable"
# Rules are listed by how many components carry them. The markdown shows the head of the list; the
# JSON carries every rule, because the point of publishing it is that someone can recompute it.
_TOP_RULES_SHOWN = 15

# Capability ids in the order a reader cares about: reach first, then local power.
_CAP_LABEL: dict[str, str] = {
    "mcp_tools_detected": "exposes MCP tools",
    "network_egress": "can reach the network",
    "shell_execution": "can execute shell commands",
    "filesystem_read": "reads the filesystem",
    "filesystem_write": "writes the filesystem",
    "install_time_execution": "runs code at install time",
    "delegated_authentication": "uses delegated (OAuth/OIDC) authentication",
    "dynamic_code_execution": "evaluates code dynamically",
    "scoped_identity": "uses a scoped, short-lived identity",
    "prompt_surface_risk": "carries a prompt-injection surface",
}

_SKIP_BUCKETS: tuple[tuple[str, tuple[str, ...]], ...] = (
    (_UNREACHABLE, ("not found", "could not read")),
    ("larger than the size bound", ("toolarge", "exceeds")),
    ("slower than the time bound", ("timeout",)),
    ("access denied", ("authentication", "permission")),
)


def bucket_skip(reason: str) -> str:
    """Group a raw skip reason into a category a reader can act on."""
    low = (reason or "").lower()
    for label, needles in _SKIP_BUCKETS:
        if any(needle in low for needle in needles):
            return label
    return "other"


def load(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line]


def summarize(rows: list[dict]) -> dict:
    """Population statistics only — no per-component detail reaches the output."""
    ok = [r for r in rows if r["status"] == "ok"]
    skipped = [r for r in rows if r["status"] != "ok"]

    owners: Counter = Counter()
    for row in rows:
        match = re.match(r"https://github\.com/([^/]+)/", row["source"])
        if match:
            owners[match.group(1).lower()] += 1
    git_total = sum(owners.values())

    return {
        "population": len(rows),
        "scanned": len(ok),
        "skipped": len(skipped),
        "skip_reasons": dict(Counter(bucket_skip(r.get("reason", "")) for r in skipped)),
        "by_ecosystem": {
            eco: {
                "total": sum(1 for r in rows if r["ecosystem"] == eco),
                "scanned": sum(1 for r in ok if r["ecosystem"] == eco),
            }
            for eco in sorted({r["ecosystem"] for r in rows})
        },
        "risk_level": {lvl: sum(1 for r in ok if r.get("risk_level") == lvl) for lvl in _LEVELS},
        "malicious_indicators": sum(1 for r in ok if r.get("malicious")),
        "rulesets": dict(sorted(Counter(str(r["ruleset_version"]) for r in ok
                                        if "ruleset_version" in r).items())),
        "capabilities": {
            cap: sum(1 for r in ok if cap in r.get("capabilities", [])) for cap in _CAP_LABEL
        },
        "owasp": {
            cls: sum(1 for r in ok if cls in set(r.get("owasp") or ())) for cls in _OWASP_LABEL
        },
        # Components per rule, not matches per rule: a component that trips one rule in forty files
        # is still one component, and dict.fromkeys collapses any repeat within a row.
        "top_rules": dict(
            Counter(rule for r in ok for rule in dict.fromkeys(r.get("rules") or ())).most_common()
        ),
        "registry_shape": {
            "git_sources": git_total,
            "distinct_owners": len(owners),
            "largest_owner_share": (
                _share(owners.most_common(1)[0][1], git_total) if git_total else 0.0
            ),
            "top10_owner_share": _share(
                sum(c for _, c in owners.most_common(10)), git_total
            ) if git_total else 0.0,
        },
    }


def _share(part: int, whole: int) -> float:
    return round(100 * part / whole, 1) if whole else 0.0


def pct(part: int, whole: int) -> str:
    return share_label(100 * part / whole, part) if whole else "n/a"


def share_label(share: float, count: int) -> str:
    """A share to one decimal, except that a non-zero count never prints as 0.0%.

    Four critical components out of fifteen thousand round to 0.0%, which reads as "none". The
    count beside it is exact; the label must not contradict it.
    """
    if count and round(share, 1) == 0:
        return "<0.1%"
    return f"{share:.1f}%"


def partition_shares(counts: list[int], whole: int, target: float = 100.0) -> list[float]:
    """Round shares to one decimal so they sum exactly to ``target`` (largest-remainder method).

    Rounding each share on its own gave a risk column of 97.2 + 0.9 + 1.6 + 0.2 = 99.9, which
    reads as an error on a page whose argument is rigour. Hamilton's method takes each share's
    floor and hands the leftover tenths to the largest fractional remainders, so every value is
    the floor or the ceiling of its exact share -- never more than 0.1 away -- and the column adds
    up by construction. Ties go to the earlier index. The web renderer implements the same rule,
    and a shared vector in both test suites keeps the two from drifting.
    """
    if not whole or not counts:
        return [0.0 for _ in counts]
    exact = [Fraction(1000 * c, whole) for c in counts]  # tenths of a percent, exact
    floors = [int(x) for x in exact]
    units = round(target * 10) - sum(floors)
    if units < 0:
        raise ValueError("target is below the sum of floors; pass the rounded true total")
    order = sorted(range(len(counts)), key=lambda i: (-(exact[i] - floors[i]), i))
    for i in order[:units]:
        floors[i] += 1
    return [f / 10 for f in floors]


def render_markdown(s: dict, meta: dict) -> str:
    n = s["scanned"]
    shape = s["registry_shape"]
    entries = meta["registry_entries"]
    out: list[str] = []
    add = out.append

    # The population can be an earlier snapshot than the scan: re-running a better engine over
    # the SAME 17,535 entries is what makes two reports comparable, so say both dates when they
    # differ rather than let a reader reconcile the count against today's registry.
    snapshot = meta.get("population_snapshot") or meta["generated"]
    when = (
        f"scanned on {meta['generated']} against the registry as of {snapshot}"
        if snapshot != meta["generated"]
        else f"run on {meta['generated']}"
    )
    add("# The MCP registry, measured")
    add("")
    add(
        f"A deterministic static scan of every distinct component in the public MCP registry — "
        f"{s['population']:,} of them — {when} with SkillTotal "
        f"{meta['engine']} (ruleset {meta['ruleset']})."
    )
    add("")
    add("## How to read this")
    add("")
    add(
        "Every figure below describes a **capability**: something a component is able to do, "
        "derived only from the code it ships. A capability is not a vulnerability. A server that "
        "runs shell commands may exist precisely to run shell commands. What the numbers show is "
        "the reach an agent inherits when it hands work to one of these components."
    )
    add("")
    add("## Population")
    add("")
    add(
        f"The registry lists a server per published *version*, so its {entries:,} entries "
        f"collapse to **{s['population']:,} distinct components**. Aggregating the raw list "
        f"would count a single package many times over."
    )
    add("")
    add("| | |")
    add("|---|---|")
    add(f"| Distinct components | {s['population']:,} |")
    add(f"| Scanned | **{s['scanned']:,}** ({pct(s['scanned'], s['population'])}) |")
    add(f"| Not scanned | {s['skipped']:,} ({pct(s['skipped'], s['population'])}) |")
    add("")
    add("Nothing was dropped silently — every exclusion is counted:")
    add("")
    add("| Why a component was not scanned | Components | Share of population |")
    add("|---|---:|---:|")
    skip_rows = sorted(s["skip_reasons"].items(), key=lambda kv: -kv[1])
    skip_target = round(100 * s["skipped"] / s["population"], 1) if s["population"] else 0.0
    skip_shares = dict(zip(
        [label for label, _ in skip_rows],
        partition_shares([count for _, count in skip_rows], s["population"], skip_target),
        strict=True,
    ))
    for label, count in skip_rows:
        add(f"| {label} | {count:,} | {skip_shares[label]:.1f}% |")
    add("")
    add("| Ecosystem | Scanned | Listed | Coverage |")
    add("|---|---:|---:|---:|")
    for eco, data in sorted(s["by_ecosystem"].items(), key=lambda kv: -kv[1]["total"]):
        add(f"| {eco} | {data['scanned']:,} | {data['total']:,} | "
            f"{pct(data['scanned'], data['total'])} |")
    add("")
    add("## What these components can do")
    add("")
    add(f"Share of the {n:,} scanned components carrying each capability:")
    add("")
    add("| Capability | Components | Share |")
    add("|---|---:|---:|")
    for cap, label in _CAP_LABEL.items():
        count = s["capabilities"].get(cap, 0)
        if not count:
            continue  # a 0.0% row would read as a finding of absence, which a scan cannot make
        add(f"| {label} | {count:,} | **{pct(count, n)}** |")
    add("")
    owasp = {k: v for k, v in s.get("owasp", {}).items() if v}
    if owasp:
        add("## OWASP Agentic Skills Top 10")
        add("")
        add(
            "Every rule that has an honest static fit carries its OWASP class, so the same scan "
            "answers which classes this population actually exhibits. A class appears here when a "
            "component carries at least one finding mapped to it; a component can appear in "
            "several. Classes with no evidence in this population are left out rather than printed "
            "as zero. A class counts the rules mapped to it, not a verdict: the rules under "
            "*Malicious Skills* include exfiltration paths and evasion idioms that a legitimate "
            "tool can carry, and no component in this population carries a malicious indicator."
        )
        add("")
        add("| Class | Components | Share |")
        add("|---|---:|---:|")
        for cls, count in sorted(owasp.items(), key=lambda kv: -kv[1]):
            add(f"| {_OWASP_LABEL[cls]} | {count:,} | {pct(count, n)} |")
        add("")
    top_rules = s.get("top_rules") or {}
    if top_rules:
        shown = min(_TOP_RULES_SHOWN, len(top_rules))
        add("## Which rules fired")
        add("")
        add(
            f"{len(top_rules)} rules matched something in this population; the {shown} most "
            f"frequent are below, and the count for every rule is in the JSON beside this file. "
            f"A rule firing describes what the code does, not what it intends — most of the "
            f"traffic here is capability rules, which add nothing to the risk score. That is "
            f"precisely why the risk table below is so much flatter than the capability table "
            f"above. `skilltotal rules list` documents every id."
        )
        add("")
        add("| Rule | Components | Share |")
        add("|---|---:|---:|")
        for rule, count in list(top_rules.items())[:shown]:
            add(f"| `{rule}` | {count:,} | {pct(count, n)} |")
        add("")
    add("## Risk levels")
    add("")
    add(
        "SkillTotal scores risky constructs and malicious indicators; a capability on its own "
        "contributes zero to the score, and so does a secret the component ships, which the "
        "engine reports separately as an exposure. The risk distribution is therefore far flatter "
        "than the capability table above, and that difference is the point."
    )
    add("")
    add("| Level | Components | Share |")
    add("|---|---:|---:|")
    risk_shares = partition_shares([s["risk_level"][lvl] for lvl in _LEVELS], n)
    for lvl, shr in zip(_LEVELS, risk_shares, strict=True):
        add(f"| {lvl} | {s['risk_level'][lvl]:,} | {share_label(shr, s['risk_level'][lvl])} |")
    add(f"| carrying a malicious indicator | {s['malicious_indicators']:,} | "
        f"{pct(s['malicious_indicators'], n)} |")
    add("")
    add("## The registry itself")
    add("")
    add(f"- {entries:,} entries resolve to {s['population']:,} distinct components.")
    add(f"- {skip_shares.get(_UNREACHABLE, 0.0):.1f}% of the population points at a repository "
        f"or package that is gone or private.")
    add(f"- {shape['git_sources']:,} components are hosted on GitHub across "
        f"{shape['distinct_owners']:,} owners — yet one owner accounts for "
        f"**{shape['largest_owner_share']}%** of them, and the ten largest for "
        f"{shape['top10_owner_share']}%.")
    add("")
    add("## What this report does not claim")
    add("")
    add(
        "**No count of leaked credentials.** The engine does detect embedded secrets and that "
        "signal ships in the product, but a sample of the hits in this population was dominated "
        "by values published on purpose: analytics project keys that vendors document as safe to "
        "expose, on-chain addresses, and public vendor constants. A raw count would measure "
        "*shape* rather than exposure, and presenting it as a number of leaks would be a false "
        "statement about named projects. A figure will appear here once it can be given with a "
        "precision estimate from a labelled sample."
    )
    add("")
    add(
        "**No claim that any component is safe.** A malicious indicator is a match against a "
        "published rule for a known attack shape: decode-and-execute, hidden Unicode, "
        "instructions planted for the agent, auto-run hooks, credentials sent out. A count of "
        "zero means no component matched one, not that none is harmful: code fetched at run time "
        "is out of a static scan's sight, and so is an attack no rule describes yet."
    )
    add("")
    add("**No component is named.** These are population statistics.")
    add("")
    add("## Method")
    add("")
    add(f"- Engine {meta['engine']}, ruleset {meta['ruleset']} — deterministic regex and AST "
        f"analysis. The component is never executed and no LLM is involved, so the run "
        f"reproduces.")
    rulesets = s.get("rulesets", {})
    if len(rulesets) > 1:
        # Say which rows came from which ruleset rather than let one version label a mixed run.
        parts = ", ".join(f"{n:,} with ruleset {rs}" for rs, n in rulesets.items())
        add(f"- Scanned components by ruleset: {parts}. The later ruleset re-scanned only the "
            f"components whose result its changes could affect, plus those that exceeded a bound "
            f"on the first pass.")
    add(f"- Population: `{meta['registry_url']}` as of {snapshot}, deduplicated by source.")
    add(f"- Two bounds, both disclosed above: {meta['clone_mb']} MB per fetch and "
        f"{meta['timeout']}s of wall clock per component.")
    add("- Harness: `tests/manual_eval/survey_registry.py`. This report: "
        "`tests/manual_eval/survey_report.py`. Both ship in this repository.")
    # Partition tables (risk levels, skip reasons) use partition_shares so each column sums to its
    # total by construction; the convention is stated because one figure per table may sit a tenth
    # from its independently-rounded value.
    add("- Shares are rounded to one decimal place so that each table sums exactly to its total "
        "(largest-remainder method); a share can therefore sit up to 0.1 point from its "
        "unrounded value. The counts beside them are exact.")
    return "\n".join(out) + "\n"


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Render the MCP-registry survey into a report.")
    ap.add_argument("survey", help="JSONL produced by survey_registry.py")
    ap.add_argument("--out-prefix", default=OUT_PREFIX_DEFAULT)
    ap.add_argument("--engine", required=True)
    ap.add_argument("--ruleset", required=True, type=int)
    ap.add_argument("--registry-entries", required=True, type=int)
    ap.add_argument("--clone-mb", type=int, default=50)
    ap.add_argument("--timeout", type=int, default=60)
    ap.add_argument(
        "--population-snapshot", default="",
        help="date (YYYY-MM-DD) the registry population was captured; defaults to the run date",
    )
    ap.add_argument(
        "--scanned", default="",
        help="date (YYYY-MM-DD) the survey itself ran; defaults to today. The report says "
             "'scanned on <date>', so re-rendering an existing dataset the next day must not "
             "move that date onto the render.",
    )
    args = ap.parse_args(argv)

    summary = summarize(load(Path(args.survey)))
    generated = args.scanned or datetime.now(timezone.utc).strftime("%Y-%m-%d")
    meta = {
        "generated": generated,
        "population_snapshot": args.population_snapshot or generated,
        "engine": args.engine,
        "ruleset": args.ruleset,
        "registry_entries": args.registry_entries,
        "registry_url": "https://registry.modelcontextprotocol.io/v0/servers",
        "clone_mb": args.clone_mb,
        "timeout": args.timeout,
    }
    Path(args.out_prefix + ".json").write_text(
        json.dumps({"metadata": meta, "summary": summary}, indent=2) + "\n", encoding="utf-8"
    )
    Path(args.out_prefix + ".md").write_text(render_markdown(summary, meta), encoding="utf-8")
    print(f"wrote {args.out_prefix}.md and .json ({summary['scanned']} scanned)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
