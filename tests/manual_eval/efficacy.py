"""Offline detection-efficacy benchmark: recall / precision / coverage matrix.

Walks ``tests/eval_corpus/{positive,negative}/<AST-class>/<technique>/<variant>/``, runs the
*static* engine on each sample (offline, deterministic — the same engine call as
``calibrate.py``), and computes:

- **recall** — fraction of positive (malicious) samples the engine flags, overall + per OWASP
  class + per technique. "Flagged" uses the SAME rule as the offline detection floor
  (``tests/test_offline_calibration.py::_is_detected``): a malicious verdict OR risk high/critical.
- **precision / false positives** — negative (benign-but-tricky) samples wrongly flagged.
- **coverage matrix** — {OWASP class} x {language} positive-sample counts. The language axis is
  *honest* about deferred languages: Go/Rust/Java/Ruby/PHP appear with their real counts (often
  zero), because semantic exec/network/deserialization detection for them is a documented gap
  (see ``docs/language-scope.md``).

Zero network, zero runtime deps. Importable as an API (used by ``tests/test_efficacy_floor.py``
and the ops Tier-2 gate) and runnable as a script that writes ``docs/efficacy-report.{md,json}``.

Usage:
    python tests/manual_eval/efficacy.py [--corpus <dir>] [--out docs/efficacy-report]
"""

from __future__ import annotations

import argparse
import json
from dataclasses import dataclass, field
from pathlib import Path

from skilltotal import ENGINE_VERSION, RULESET_VERSION, engine
from skilltotal.collector import detect_component

CORPUS_ROOT = Path(__file__).resolve().parent.parent / "eval_corpus"

# Synthesized exfil findings that must never fire on a benign sample (precision invariants,
# mirroring tests/test_offline_calibration.py::test_benign_fp_shape_is_not_elevated).
_EXFIL_FINDING_IDS = ("ST-COMBO-EXFIL", "ST-FLOW-TRIFECTA")

# File suffix -> language label, for the coverage matrix's language axis.
_LANG_BY_SUFFIX = {
    ".py": "python", ".pyw": "python", ".pyi": "python",
    ".js": "node", ".mjs": "node", ".cjs": "node", ".jsx": "node",
    ".ts": "node", ".tsx": "node",
    ".sh": "shell", ".bash": "shell", ".zsh": "shell",
    ".go": "go", ".rs": "rust", ".java": "java", ".rb": "ruby", ".php": "php",
}
# Non-code carriers (manifests / instruction surfaces / data) that don't pin a language.
_CARRIER = "manifest/text"


@dataclass(frozen=True)
class Sample:
    """One eval-corpus sample: a component directory with a label encoded in its path."""

    path: Path
    polarity: str  # "positive" (should detect) | "negative" (should stay clean)
    owasp: str     # AST class from the path, e.g. "AST01"
    technique: str
    variant: str
    language: str  # primary code language in the sample, or "manifest/text"


@dataclass
class Result:
    sample: Sample
    detected: bool
    has_malicious: bool
    risk_level: str
    finding_ids: tuple[str, ...]
    exfil_fired: bool


@dataclass
class Metrics:
    positives: int = 0
    negatives: int = 0
    true_positives: int = 0          # positives correctly flagged
    false_negatives: list[str] = field(default_factory=list)  # positive samples missed (labels)
    false_positives: list[str] = field(default_factory=list)  # negative samples wrongly flagged
    recall_by_technique: dict[str, float] = field(default_factory=dict)
    recall_by_class: dict[str, float] = field(default_factory=dict)
    coverage_matrix: dict[str, dict[str, int]] = field(default_factory=dict)  # class -> lang -> n

    @property
    def recall(self) -> float:
        return self.true_positives / self.positives if self.positives else 1.0

    @property
    def precision(self) -> float:
        denom = self.true_positives + len(self.false_positives)
        return self.true_positives / denom if denom else 1.0

    @property
    def fp_rate(self) -> float:
        return len(self.false_positives) / self.negatives if self.negatives else 0.0


def _language_of(sample_dir: Path) -> str:
    """Primary code language of a sample, by the most common code suffix; carrier if none."""
    counts: dict[str, int] = {}
    for f in sample_dir.rglob("*"):
        if f.is_file():
            lang = _LANG_BY_SUFFIX.get(f.suffix.lower())
            if lang:
                counts[lang] = counts.get(lang, 0) + 1
    if not counts:
        return _CARRIER
    return max(counts, key=lambda k: counts[k])


def _label(sample: Sample) -> str:
    return f"{sample.polarity}/{sample.owasp}/{sample.technique}/{sample.variant}"


def discover(root: Path = CORPUS_ROOT) -> list[Sample]:
    """Find every sample under ``root/{positive,negative}/<class>/<technique>/<variant>/``.

    The leaf ``<variant>`` directory is the component root scanned by the engine. Labels
    (polarity, OWASP class, technique, variant, language) are derived entirely from the path,
    so there is no separate manifest to keep in sync.
    """
    samples: list[Sample] = []
    for polarity in ("positive", "negative"):
        base = root / polarity
        if not base.is_dir():
            continue
        for class_dir in sorted(p for p in base.iterdir() if p.is_dir()):
            for tech_dir in sorted(p for p in class_dir.iterdir() if p.is_dir()):
                for variant_dir in sorted(p for p in tech_dir.iterdir() if p.is_dir()):
                    samples.append(
                        Sample(
                            path=variant_dir,
                            polarity=polarity,
                            owasp=class_dir.name,
                            technique=tech_dir.name,
                            variant=variant_dir.name,
                            language=_language_of(variant_dir),
                        )
                    )
    return samples


def evaluate(samples: list[Sample]) -> list[Result]:
    """Run the static engine on each sample (offline) and capture the verdict."""
    results: list[Result] = []
    for s in samples:
        report = engine.analyze_directory(s.path, detect_component(s.path, source=str(s.path)))
        verdict = report.verdict or {}
        has_mal = bool(verdict.get("has_malicious_indicators"))
        elevated = report.risk_level.value in ("high", "critical")
        ids = tuple(sorted({f.id for f in report.findings}))
        results.append(
            Result(
                sample=s,
                detected=has_mal or elevated,
                has_malicious=has_mal,
                risk_level=report.risk_level.value,
                finding_ids=ids,
                exfil_fired=any(i in ids for i in _EXFIL_FINDING_IDS),
            )
        )
    return results


def compute_metrics(results: list[Result]) -> Metrics:
    m = Metrics()
    tech_total: dict[str, int] = {}
    tech_hit: dict[str, int] = {}
    class_total: dict[str, int] = {}
    class_hit: dict[str, int] = {}
    for r in results:
        s = r.sample
        if s.polarity == "positive":
            m.positives += 1
            tech_total[s.technique] = tech_total.get(s.technique, 0) + 1
            class_total[s.owasp] = class_total.get(s.owasp, 0) + 1
            m.coverage_matrix.setdefault(s.owasp, {})
            m.coverage_matrix[s.owasp][s.language] = (
                m.coverage_matrix[s.owasp].get(s.language, 0) + 1
            )
            if r.detected:
                m.true_positives += 1
                tech_hit[s.technique] = tech_hit.get(s.technique, 0) + 1
                class_hit[s.owasp] = class_hit.get(s.owasp, 0) + 1
            else:
                m.false_negatives.append(_label(s))
        else:  # negative — a benign FP is a malicious verdict, an exfil combo, or high/critical
            m.negatives += 1
            if r.has_malicious or r.exfil_fired or r.risk_level in ("high", "critical"):
                m.false_positives.append(_label(s))
    m.recall_by_technique = {
        t: round(tech_hit.get(t, 0) / n, 4) for t, n in sorted(tech_total.items())
    }
    m.recall_by_class = {
        c: round(class_hit.get(c, 0) / n, 4) for c, n in sorted(class_total.items())
    }
    return m


def run(root: Path = CORPUS_ROOT) -> tuple[list[Result], Metrics]:
    results = evaluate(discover(root))
    return results, compute_metrics(results)


def to_dict(metrics: Metrics) -> dict:
    return {
        "engine_version": ENGINE_VERSION,
        "ruleset_version": RULESET_VERSION,
        "positives": metrics.positives,
        "negatives": metrics.negatives,
        "recall": round(metrics.recall, 4),
        "precision": round(metrics.precision, 4),
        "fp_rate": round(metrics.fp_rate, 4),
        "false_negatives": metrics.false_negatives,
        "false_positives": metrics.false_positives,
        "recall_by_class": metrics.recall_by_class,
        "recall_by_technique": metrics.recall_by_technique,
        "coverage_matrix": metrics.coverage_matrix,
    }


def to_markdown(metrics: Metrics) -> str:
    d = to_dict(metrics)
    lines = [
        "# SkillTotal detection-efficacy report",
        "",
        f"Engine {d['engine_version']} · ruleset {d['ruleset_version']} · offline corpus.",
        "",
        f"- **recall: {d['recall'] * 100:.1f}%** ({metrics.true_positives}/{metrics.positives} "
        "malicious samples flagged)",
        f"- **precision: {d['precision'] * 100:.1f}%** · false-positive rate "
        f"{d['fp_rate'] * 100:.1f}% ({len(metrics.false_positives)}/{metrics.negatives} benign "
        "samples wrongly flagged)",
        "",
        "## Recall by OWASP class",
        "",
        "| class | recall |",
        "|---|---|",
    ]
    lines += [f"| {c} | {v * 100:.0f}% |" for c, v in d["recall_by_class"].items()]
    lines += ["", "## Recall by technique", "", "| technique | recall |", "|---|---|"]
    lines += [f"| {t} | {v * 100:.0f}% |" for t, v in d["recall_by_technique"].items()]
    lines += ["", "## Coverage matrix (positive samples: class x language)", ""]
    langs = sorted({lang for row in d["coverage_matrix"].values() for lang in row})
    if langs:
        lines.append("| class | " + " | ".join(langs) + " |")
        lines.append("|---|" + "---|" * len(langs))
        for c in sorted(d["coverage_matrix"]):
            row = d["coverage_matrix"][c]
            lines.append(f"| {c} | " + " | ".join(str(row.get(lang, 0)) for lang in langs) + " |")
    lines += [
        "",
        "> Languages with no semantic exec/network/deserialization detection (Go, Rust, Java, "
        "Ruby, PHP) are a documented gap — see `docs/language-scope.md`.",
        "",
    ]
    if metrics.false_negatives:
        lines += ["## Missed (false negatives)", ""] + [f"- {x}" for x in metrics.false_negatives]
    return "\n".join(lines) + "\n"


def main() -> None:
    ap = argparse.ArgumentParser(description="Offline detection-efficacy benchmark.")
    ap.add_argument("--corpus", type=Path, default=CORPUS_ROOT)
    ap.add_argument("--out", type=Path, help="output prefix; writes <prefix>.json and .md")
    args = ap.parse_args()

    _, metrics = run(args.corpus)
    if args.out:
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.with_suffix(".json").write_text(
            json.dumps(to_dict(metrics), indent=2), encoding="utf-8"
        )
        args.out.with_suffix(".md").write_text(to_markdown(metrics), encoding="utf-8")
    print(to_markdown(metrics))


if __name__ == "__main__":
    main()
