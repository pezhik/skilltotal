"""Analysis orchestrator — the reusable core entry point.

This module ties collection, indexing, scanning, capability extraction, and scoring
together into a single :class:`~skilltotal.models.Report`. Future web/SaaS products are
expected to import :func:`analyze_directory` (pure, no process I/O) directly; the CLI uses
:func:`analyze` which also handles source collection and cleanup.
"""

from __future__ import annotations

import os
import re
from collections.abc import Callable, Iterable
from dataclasses import replace
from datetime import datetime, timezone
from pathlib import Path

from skilltotal import REPORT_SCHEMA_VERSION, RULESET_VERSION, __version__, bounded_json
from skilltotal.agent_skill import skill_capability_mismatch
from skilltotal.autorun import autorun_commands
from skilltotal.baseline import apply_suppressions
from skilltotal.capabilities import extract_capabilities
from skilltotal.collector import collect
from skilltotal.combinations import post_classification, pre_classification
from skilltotal.file_index import (
    MAX_FILE_BYTES,
    SKIP_BUILD_OUTPUT,
    SKIP_DEPENDENCIES,
    SKIP_DIRS,
    SKIP_VENDORED,
    SKIP_VIRTUALENV,
    FileIndex,
    IndexedFile,
    agent_prompt_dirs,
    is_build_output_path,
    is_ci_path,
    is_data_corpus_path,
    is_doc_path,
    is_example_path,
    is_regular_file,
    is_test_path,
    skill_dirs,
)
from skilltotal.loaded_code import BARE_MODULE as _BARE_MODULE
from skilltotal.loaded_code import LOADING_SUFFIXES as _LOADING_SUFFIXES
from skilltotal.loaded_code import MAX_LOADED_FILES, follow_skipped_references
from skilltotal.loaded_code import MODULE_SUFFIXES as _MODULE_SUFFIXES
from skilltotal.loaded_code import RELATIVE_MODULE as _RELATIVE_MODULE
from skilltotal.loaded_code import bundled_module_file as _bundled_module_file
from skilltotal.loaded_code import module_file as _module_file
from skilltotal.models import (
    NOTHING_READ,
    OWN_OUTPUTS_SKIPPED,
    SKIPPED_FOLDERS,
    UNANALYZED_INSTALL_SCRIPT,
    UNANALYZED_LOADED_CODE,
    Component,
    Evidence,
    Finding,
    NeedsReview,
    Report,
    RiskLevel,
    Severity,
    ThreatClass,
    finding_counts,
)
from skilltotal.owasp import owasp_for
from skilltotal.parallel import run_scanners
from skilltotal.rules import get_rules, unknown_rule_hint
from skilltotal.scanners import SCANNERS
from skilltotal.scanners.base import MAX_EVIDENCE_PER_FINDING, aggregated_review
from skilltotal.scanners.mcp import is_mcp_listing
from skilltotal.scoring import compute_score, is_own_provider_read, risk_level
from skilltotal.traits import build_trait_profile
from skilltotal.typosquatting import TYPOSQUAT_FINDING_ID, package_name_typosquatting

# Component types produced by fetching a PUBLISHED artifact from a package registry (collector.
# _collect_archive). Everything else — a git clone, a local directory, an uploaded project — keeps
# its sources, so its build output is a duplicate rather than the only shipped code.
_PUBLISHED_PACKAGE_TYPES = frozenset({"npm_package", "python_package"})


def analyze(
    source: str,
    *,
    suppress: set[str] | None = None,
    ignore_rules: Iterable[str] | None = None,
    exclude: Iterable[str] | None = None,
    inline_ignores: bool = False,
    progress: Callable[[str], None] | None = None,
) -> Report:
    """Resolve ``source`` (path or URL), analyze it, and return a Report."""
    with collect(source) as ctx:
        report = analyze_directory(
            ctx.root,
            ctx.component,
            suppress=suppress,
            ignore_rules=ignore_rules,
            exclude=exclude,
            inline_ignores=inline_ignores,
            progress=progress,
        )
        if ctx.note:
            report.needs_review.append(
                NeedsReview(category="source", title="Scan target normalized", reason=ctx.note)
            )
        if ctx.skipped_entries:
            report.needs_review.append(_skipped_entries_note(ctx.skipped_entries))
        if ctx.distribution_note:
            report.needs_review.append(NeedsReview(
                category="coverage", title="One distribution of the release scanned",
                reason=ctx.distribution_note))
        if ctx.mirror_note:
            report.needs_review.append(NeedsReview(
                category="source", title="Fetched through a registry mirror",
                reason=ctx.mirror_note))
        return report


def analyze_directory(
    root: Path,
    component: Component,
    *,
    suppress: set[str] | None = None,
    ignore_rules: Iterable[str] | None = None,
    exclude: Iterable[str] | None = None,
    inline_ignores: bool = False,
    progress: Callable[[str], None] | None = None,
) -> Report:
    """Analyze an already-local component directory. Pure: no stdout, no exit.

    ``suppress`` is an optional set of baseline fingerprints to drop before scoring.
    ``ignore_rules`` drops whole rule ids; ``exclude`` is a list of path globs to skip.
    ``inline_ignores`` honors ``skilltotal:ignore`` markers in the scanned files. Only the owner of
    the code may turn it on (``scan`` of a local checkout, as in CI): in a package someone else
    wrote, the marker is the author's own comment, and one line of it would silence the finding
    that should stop the install.
    ``progress``, if given, is called with a short line at each stage (files read, each scanner),
    so a caller can show that a long scan is moving; the engine itself never prints.
    """
    if progress is not None:
        progress("Reading files")
    # A published package artifact ships its build output and NOT its sources, so dist/ and build/
    # must be scanned there; in a repository they duplicate source that is checked in beside them.
    published = component.type in _PUBLISHED_PACKAGE_TYPES
    # What npm runs on install is read whatever its shape, minified or not: it is the attack.
    install_scripts = _install_script_files(Path(root))
    # So is the code the package runs when it is imported or its command is run: a main file padded
    # with one long comment until it looked minified was skipped, and its payload with it.
    index = FileIndex.build(
        Path(root), exclude=exclude, skip_build_output=not published, always_index=install_scripts,
        keep_minified=_entry_point_files(Path(root)),
    )
    # Code the component loads by a literal path from a folder the walk passed over (its own
    # `lib/env/`, `src/vendor/`, ...) is read too: it runs whatever folder it is filed under.
    index, unloaded = follow_skipped_references(index)

    findings: list[Finding] = []
    needs_review: list[NeedsReview] = []
    indexed = {f.relpath for f in index.files}
    for relpath, script in install_scripts.items():
        if relpath not in indexed:
            needs_review.append(_unanalyzed_install_script(Path(root), relpath, script))
    if index.minified:
        shown = ", ".join(index.minified[:5])
        more = f" (+{len(index.minified) - 5} more)" if len(index.minified) > 5 else ""
        needs_review.append(
            NeedsReview(
                category="coverage",
                title="Minified bundle not analyzed",
                reason=(
                    f"{len(index.minified)} bundled/minified script(s) were skipped because a "
                    f"finding in them could not carry checkable file/line evidence, and their "
                    f"inlined dependencies are not this component's own code: {shown}{more}"
                ),
            )
        )
    needs_review.extend(_unread_notes(index))
    if index.own_outputs:
        needs_review.append(aggregated_review(
            category="coverage",
            title=OWN_OUTPUTS_SKIPPED,
            places=[(p, None) for p in index.own_outputs],
            what="file(s) are reports or baselines SkillTotal wrote (SARIF, JSON report, baseline)",
            advice="Each parsed in full as JSON of exactly that shape, which runs nothing; their "
                   "rule descriptions quote detection patterns, so they were not scanned.",
        ))
    if unloaded:
        needs_review.append(_unloaded_note(unloaded))
    skipped_note = _skipped_folders_note(index)
    if skipped_note is not None:
        needs_review.append(skipped_note)
    # A script npm runs at install that is too large already has a note of its own.
    large = [p for p in index.large if p not in install_scripts]
    if large:
        needs_review.append(aggregated_review(
            category="coverage",
            title="Files too large to analyze",
            places=[(p, None) for p in large],
            what=f"text file(s) larger than {MAX_FILE_BYTES // (1024 * 1024)} MiB were not read",
            advice="Nothing in them was checked.",
        ))
    unanalyzed = _unanalyzed_code(index)
    if unanalyzed:
        needs_review.append(_unanalyzed_note(unanalyzed))
    skipped_code = _skipped_code_files(index)
    def checked(number: int) -> None:
        if progress is not None:
            progress(f"Scanning {len(index.files)} files: check {number} of {len(SCANNERS)}")

    # Side by side in worker processes when the component is large and the entry point allows it;
    # the results are used in SCANNERS order either way (see skilltotal.parallel).
    regex_only: set[str] = set()
    for result in run_scanners(index, SCANNERS, checked):
        findings.extend(result.findings)
        needs_review.extend(result.needs_review)
        regex_only.update(result.regex_only_files)

    findings, suppressed_count = apply_suppressions(findings, suppress or set())
    # Reported apart from the inline markers' share, so the report can say what the baseline hid.
    baseline_count = suppressed_count if suppress else None
    ignore_set = {r for r in ignore_rules} if ignore_rules else set()
    if ignore_set:
        # Drop early so ignored base findings don't feed the synthesized rules below.
        findings = [f for f in findings if f.id not in ignore_set]
    if inline_ignores:
        findings, inline_count, refused, unknown_ids = _apply_inline_ignores(findings, index)
        suppressed_count += inline_count
        needs_review.extend(_unknown_marker_ids_notes(unknown_ids))
        if refused:
            needs_review.append(NeedsReview(
                category="suppression",
                title="Inline ignore does not apply to malicious indicators",
                reason=(
                    "A skilltotal:ignore marker sits on the evidence of "
                    + ", ".join(sorted(refused)) + ". A marker is written into the component, so "
                    "whoever wrote the component could use it to hide its own malicious "
                    "indicator; these findings stay. To accept one, record it in a baseline "
                    "(--write-baseline) or set it to warn under [policy] in .skilltotal.toml."
                ),
            ))

    # Demote evidence that does not represent executed/agent-facing behavior to needs_review
    # (never scored). Sibling gates, applied in order:
    #   1. test code   - not executed by consumers
    #   2. documentation/prose - READMEs, changelogs, ignore-files: descriptive, not behavior
    #   3. data/eval corpus - inert reference data (eval_datasets/poisoning.yaml, fixtures/*.json):
    #      a sample attack is a detector test vector, not behavior (code there is still scored)
    #   4. example/demo/benchmark scaffolding - illustrates the component, not its behavior
    #   5. CI/CD pipeline config - runs on the project's build service, not the consumer's machine
    #   6. structured-data prompt evidence - an injection phrase in a data blob is inert
    #   7. Python/shell code-context - a pattern that only appears inside a string literal/comment
    #      is a literal or doc example (e.g. a scanner's own rule definitions), not behavior
    # The layers that judge a file by its PATH (1-5 and build output) never demote what npm runs at
    # install time: a dropper that postinstall runs from dist/ or tests/ is the attack, whatever
    # the folder suggests. The content layers (6, 7) still apply to it.
    install_files = frozenset(install_scripts)
    findings, test_review = _hold_out(install_files, _split_test_evidence, findings, index)
    needs_review.extend(test_review)
    # Skills, subagents and commands: their markdown is read by the agent, not by a person.
    relpaths = [f.relpath for f in index.files]
    findings, doc_review = _hold_out(
        install_files, _split_doc_evidence, findings,
        skill_dirs(relpaths) | agent_prompt_dirs(relpaths),
        autorun_commands(index).frontmatter_lines,
    )
    needs_review.extend(doc_review)
    findings, corpus_review = _hold_out(install_files, _split_data_corpus_evidence, findings)
    needs_review.extend(corpus_review)
    findings, example_review = _hold_out(install_files, _split_example_evidence, findings)
    needs_review.extend(example_review)
    findings, ci_review = _hold_out(install_files, _split_ci_evidence, findings)
    needs_review.extend(ci_review)
    findings, structured_data_review = _split_structured_data_evidence(
        findings, _command_lines(index), index
    )
    needs_review.extend(structured_data_review)
    findings, code_ctx_review = _split_code_context_evidence(findings, index, regex_only)
    needs_review.extend(code_ctx_review)
    findings, provider_review = _split_own_provider_reads(findings, component)
    needs_review.extend(provider_review)
    if published:
        findings, build_review = _hold_out(install_files, _split_build_output_evidence, findings)
        needs_review.extend(build_review)
    else:
        findings, env_review = _split_unpublished_env_evidence(findings)
        needs_review.extend(env_review)

    # Cap evidence only now: a scanner collects every match, the splits above move tests, docs and
    # strings out, and what is left is what a report shows.
    findings = [_cap_evidence(f) for f in findings]
    capabilities = extract_capabilities(findings)

    # Synthesized combination findings: emergent risk from co-occurring signals (credential
    # read + egress, install hook + payload, ...). The registry in skilltotal.combinations is the
    # single ordered source of truth; the calibrated detection logic lives in scoring.py. Pre-
    # classification combinations run over the base findings; order is load-bearing (the exfil
    # combo must precede the trifecta, which is suppressed once the stronger combo has fired).
    # `fired` tracks which combinations fired, for that suppression and for the post-phase below.
    fired: set[str] = set()
    for combination in pre_classification():
        synthesized = combination.synth(findings, capabilities, component, fired, index)
        if synthesized is not None:
            findings.append(synthesized)
            fired.add(combination.id)

    # Agent Skill: declared allowed-tools vs. what the bundled code actually does (deterministic
    # undeclared-capability check). Synthesized here, after capabilities.
    mismatch = skill_capability_mismatch(component, index, capabilities)
    if mismatch is not None:
        findings.append(mismatch)

    # Supply chain: npm/PyPI package name one or two edits from a popular package (typosquatting).
    # Synthesized here off component identity; deterministic, evidence-anchored to the manifest.
    typosquat = package_name_typosquatting(component, index)
    if typosquat is not None:
        findings.append(typosquat)

    if ignore_set:
        # Drop again after synthesis so ignored synthesized ids (e.g. ST-COMBO-EXFIL) are honored.
        findings = [f for f in findings if f.id not in ignore_set]

    _assign_threat_classes(findings)

    # Post-classification combinations run after threat classes are final — e.g. convergence,
    # which counts the now-classified malicious indicators. A non-empty result is already
    # classified (RISKY_CONSTRUCT) on construction, so it needs no re-projection. Honor
    # ignore_set at append, as the base findings were dropped above.
    for combination in post_classification():
        synthesized = combination.synth(findings, capabilities, component, fired, index)
        if synthesized is not None and synthesized.id not in ignore_set:
            findings.append(synthesized)
            fired.add(combination.id)

    # Attach OWASP Agentic Skills Top 10 categories last, once every finding (incl. synthesized
    # ones) is present. Pure metadata projection — never affects the score.
    _assign_owasp(findings)

    score = compute_score(findings)
    level = risk_level(score)

    # Behavioral trait fingerprint + standards crosswalk. Pure projection over the final
    # finding set (incl. synthesized combinations); descriptive, never affects the score.
    traits = build_trait_profile(findings)

    report = Report(
        component=component,
        risk_score=score,
        risk_level=level,
        summary=_summary(level, score, findings, capabilities, needs_review),
        verdict=_verdict(
            findings, level, unanalyzed, nothing_read=not index.files, skipped_code=skipped_code
        ),
        capabilities=capabilities,
        traits=traits,
        findings=_sort_findings(findings),
        needs_review=needs_review,
        metadata=_metadata(index, findings, suppressed_count, baseline_count),
    )
    return report


# Rule id -> threat class, from the single source of truth (RuleSpec via the registry).
_THREAT_CLASS_BY_ID = {r.id: r.threat_class for r in get_rules()}

# Rule id -> Python code-context policy, for rules that need string/comment demotion.
_CODE_CTX_POLICY = {r.id: r.code_context for r in get_rules() if r.code_context != "any"}


def _assign_threat_classes(findings: list[Finding]) -> None:
    """Project each rule's declared threat_class onto its findings (one chokepoint)."""
    for f in findings:
        f.threat_class = _THREAT_CLASS_BY_ID.get(f.id, f.threat_class)


def _assign_owasp(findings: list[Finding]) -> None:
    """Project each rule's OWASP Agentic Skills Top 10 categories onto its findings."""
    for f in findings:
        f.owasp = owasp_for(f.id)


# Source languages whose behavior (shell, network, file access, dynamic code) no scanner reads yet.
# Secrets, sensitive paths, hidden Unicode and manifest checks still run on these files; the gap is
# behavior. Without saying so, a Go server that shells out and posts a credential file scored "low"
# with nothing to tell the reader why. A suffix that can also mean something other than code with
# shell, network or file access is left out: `.m` (often MATLAB), `.jl` (JSON Lines) and `.fs`
# (shaders); shell, PowerShell and batch files are read by the shell scanners. `.pl` stays: it is
# Perl far more often than Prolog, and Prolog code is not analyzed either, so the note holds for
# both and only the language it names could be off.
_UNANALYZED_LANGUAGES = {
    ".go": "Go",
    ".rs": "Rust",
    ".java": "Java",
    ".rb": "Ruby",
    ".php": "PHP",
    **dict.fromkeys((".c", ".h", ".cc", ".cpp", ".cxx", ".hpp", ".hh", ".hxx"), "C/C++"),
    ".cs": "C#",
    ".swift": "Swift",
    ".kt": "Kotlin",
    ".kts": "Kotlin",
    ".scala": "Scala",
    ".dart": "Dart",
    ".lua": "Lua",
    ".pl": "Perl",
    ".pm": "Perl",
    ".ex": "Elixir",
    ".exs": "Elixir",
    ".groovy": "Groovy",
    ".hs": "Haskell",
    ".clj": "Clojure",
    ".cljs": "Clojure",
    ".cljc": "Clojure",
    ".erl": "Erlang",
    ".hrl": "Erlang",
    ".r": "R",
    ".zig": "Zig",
}


# npm runs these on every install of the package, before anyone looks at it.
_NPM_INSTALL_SCRIPTS = ("preinstall", "install", "postinstall")


def _install_script_files(root: Path) -> dict[str, str]:
    """Files ``package.json`` runs at install time, as ``{relpath: script name}``.

    Any word of a ``preinstall`` / ``install`` / ``postinstall`` command that names a file inside
    the component is that file (``node setup.js``, ``sh ./scripts/x.sh``, ``./bin/fetch``), found
    the way Node finds it (``node .`` runs the package's ``main``, ``node install`` runs
    ``install.js``). So are the package's own modules those files load with a literal relative
    ``require``/``import``, transitively: a two-line ``postinstall`` that requires a minified
    ``lib/x.min.js`` runs that bundle too. Parsing only: nothing is run.

    A ``package.json`` that is a link is not read: it can point at any file on the machine.

    The component's own ``package.json`` comes first; then those of packages inside it (a
    workspace member, a vendored package), whose install scripts npm runs when they are installed
    from the repository. A package under a test, example, documentation, corpus or CI path is a
    fixture of that kind, not something the component installs, and stays with its folder's rules.
    """
    base = root.resolve()
    queue: list[tuple[Path, str]] = []
    for manifest in _package_manifests(root):
        try:
            data = bounded_json.loads(manifest.read_text(encoding="utf-8", errors="replace"))
        except (OSError, ValueError):
            continue
        scripts = data.get("scripts") if isinstance(data, dict) else None
        if not isinstance(scripts, dict):
            continue
        package = manifest.parent.resolve()
        for script in _NPM_INSTALL_SCRIPTS:
            command = scripts.get(script)
            if not isinstance(command, str):
                continue
            for word in _install_command_words(package, command):
                target = _module_file(base, package, word)
                if target is not None:
                    queue.append((target, script))
    found: dict[str, str] = {}
    while queue and len(found) < _MAX_INSTALL_FILES:
        target, script = queue.pop(0)
        relpath = target.relative_to(base).as_posix()
        if relpath in found:
            continue
        found[relpath] = script
        if target.suffix.lower() not in _LOADING_SUFFIXES:
            continue
        try:
            if target.stat().st_size > MAX_FILE_BYTES:
                continue  # unread; reported as not analyzed
            text = target.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        for match in _RELATIVE_MODULE.finditer(text):
            loaded = _module_file(base, target.parent, match.group(2))
            if loaded is not None:
                queue.append((loaded, script))
        for match in _BARE_MODULE.finditer(text):
            loaded = _bundled_module_file(base, target.parent, match.group(2))
            if loaded is not None:
                queue.append((loaded, script))
    return found


def _install_command_words(package: Path, command: str) -> list[str]:
    """The words of an install command that may name a file of ``package``, once each.

    Each is looked up on disk, which takes milliseconds, so a 20,000-word command took minutes.
    A word with no path separator and no dot names a file only through a top-level entry of
    the package (``node install`` runs ``install.js``); any other bare word is a command or an
    argument and is not looked up. At most ``_MAX_INSTALL_WORDS`` words are.
    """
    try:
        names = {name.casefold() for name in os.listdir(package)}
    except OSError:
        names = set()
    words: list[str] = []
    seen: set[str] = set()
    for word in re.split(r"[\s;&|<>()]+", command):
        word = word.strip("\"'`")
        if not word or word.startswith("-") or word in seen:
            continue
        seen.add(word)
        if not any(c in word for c in "/\\."):
            folded = word.casefold()
            if folded not in names and not any(folded + s in names for s in _MODULE_SUFFIXES):
                continue
        words.append(word)
        if len(words) >= _MAX_INSTALL_WORDS:
            break
    return words


# An install command names a file or two; this only bounds a padded one.
_MAX_INSTALL_WORDS = 64
# An install-time dropper is a handful of files; this only bounds a pathological require graph.
_MAX_INSTALL_FILES = 200
# Packages inside a component: how deep and how many are read (a monorepo has tens).
_MAX_PACKAGE_DEPTH = 6
_MAX_PACKAGES = 100


# How many entry points of the component's own package.json are read whatever their shape.
_MAX_ENTRY_POINTS = 32


def _entry_point_files(root: Path) -> set[str]:
    """The files the component's own ``package.json`` names as what runs: ``main``, ``module``,
    ``browser`` (a string), every ``bin`` and the file targets of ``exports``, found the way Node
    finds them and only inside the component. These are read even when they look minified, like
    the install scripts: they are the code that runs, so their shape cannot exempt them (security
    review, 2026-10-15: a padded main file hid an exfiltration from the scan and from guard).
    """
    manifest = root / "package.json"
    if not is_regular_file(manifest):
        return set()
    try:
        data = bounded_json.loads(manifest.read_text(encoding="utf-8", errors="replace"))
    except (OSError, ValueError):
        return set()
    if not isinstance(data, dict):
        return set()
    specs: list[str] = []
    for key in ("main", "module", "browser"):
        if isinstance(data.get(key), str):
            specs.append(data[key])
    bins = data.get("bin")
    specs += [bins] if isinstance(bins, str) else [
        v for v in bins.values() if isinstance(v, str)] if isinstance(bins, dict) else []

    def targets(node: object, depth: int = 0) -> None:
        if depth > 6 or len(specs) >= _MAX_ENTRY_POINTS * 2:
            return
        if isinstance(node, str):
            specs.append(node)
        elif isinstance(node, dict):
            for value in node.values():
                targets(value, depth + 1)
        elif isinstance(node, list):
            for value in node:
                targets(value, depth + 1)

    targets(data.get("exports"))
    base = root.resolve()
    found: set[str] = set()
    for spec in specs:
        if len(found) >= _MAX_ENTRY_POINTS:
            break
        if "*" in spec:  # a subpath pattern names many files, not one entry point
            continue
        target = _module_file(base, base, spec)
        if target is not None:
            found.add(target.relative_to(base).as_posix())
    return found


def _package_manifests(root: Path) -> list[Path]:
    """The ``package.json`` files whose install scripts count: the component's own, then those
    of packages inside it, outside skipped folders and outside test, example, documentation,
    corpus and CI paths. Links are not followed."""
    manifests: list[Path] = []
    if is_regular_file(root / "package.json"):
        manifests.append(root / "package.json")
    for dirpath, dirnames, filenames in os.walk(root):
        rel = Path(dirpath).relative_to(root).as_posix()
        depth = 0 if rel == "." else rel.count("/") + 1
        dirnames[:] = sorted(
            d for d in dirnames
            if d not in SKIP_DIRS and not (Path(dirpath) / d).is_symlink()
        ) if depth < _MAX_PACKAGE_DEPTH else []
        if rel == "." or "package.json" not in filenames:
            continue
        relpath = f"{rel}/package.json"
        if (is_test_path(relpath) or is_example_path(relpath) or is_doc_path(relpath)
                or is_data_corpus_path(relpath) or is_ci_path(relpath)):
            continue
        manifest = Path(dirpath) / "package.json"
        if is_regular_file(manifest):
            manifests.append(manifest)
            if len(manifests) > _MAX_PACKAGES:
                break
    return manifests


def _unanalyzed_install_script(root: Path, relpath: str, script: str) -> NeedsReview:
    try:
        too_large = (root / relpath).stat().st_size > MAX_FILE_BYTES
    except OSError:
        too_large = False
    why = (
        f"it is larger than {MAX_FILE_BYTES // (1024 * 1024)} MiB" if too_large
        else "it is not text the scanner reads, or it was excluded from the scan"
    )
    return NeedsReview(
        category="coverage",
        title=UNANALYZED_INSTALL_SCRIPT,
        reason=(
            f"package.json runs {relpath} at install time ({script}), and it was not analyzed: "
            f"{why}. Nothing in it was checked, so read it before installing."
        ),
        file=relpath,
    )


# Folders a report names when it did not read them: code someone else wrote (dependencies,
# vendored trees, virtual environments) or, in a repository, a build of the component's own.
_SKIPPED_FOLDER_KINDS = {
    SKIP_DEPENDENCIES: "dependencies",
    SKIP_VENDORED: "vendored code",
    SKIP_VIRTUALENV: "Python virtual environment",
    SKIP_BUILD_OUTPUT: "build output",
}


def _skipped_folders_note(index: FileIndex) -> NeedsReview | None:
    """Say which folders the walk passed over: a report must not read as covering them."""
    folders = [(rel, kind) for rel, kind in index.skipped_dirs if kind in _SKIPPED_FOLDER_KINDS]
    if not folders:
        return None
    shown = ", ".join(f"{rel}/ ({_SKIPPED_FOLDER_KINDS[kind]})" for rel, kind in folders[:5])
    more = f", and {len(folders) - 5} more" if len(folders) > 5 else ""
    return NeedsReview(
        category="coverage",
        title=SKIPPED_FOLDERS,
        reason=(
            f"{len(folders)} folder(s) were not read: {shown}{more}. They hold third-party code "
            "or a build of the component's own. Code the component loads from them by a literal "
            "path was read and checked; nothing else in them was."
        ),
        file=f"{folders[0][0]}/",
    )


def _unloaded_note(unloaded: list[str]) -> NeedsReview:
    """Code the component loads from a skipped folder that could not be read."""
    shown = ", ".join(unloaded[:5])
    more = f", and {len(unloaded) - 5} more" if len(unloaded) > 5 else ""
    return NeedsReview(
        category="coverage",
        title=UNANALYZED_LOADED_CODE,
        reason=(
            f"The component loads {len(unloaded)} file(s) from a folder the scan otherwise skips, "
            f"and they could not be read (larger than {MAX_FILE_BYTES // (1024 * 1024)} MiB, "
            f"unreadable, or past the {MAX_LOADED_FILES}-file limit): {shown}{more}. That code "
            "runs and nothing in it was checked."
        ),
        file=unloaded[0],
    )


def _unanalyzed_code(index: FileIndex) -> dict[str, int]:
    """Count shipped (non-test) source files per language whose behavior is not analyzed."""
    counts: dict[str, int] = {}
    for f in index.files:
        lang = _UNANALYZED_LANGUAGES.get(Path(f.relpath).suffix.lower())
        if lang and not is_test_path(f.relpath):
            counts[lang] = counts.get(lang, 0) + 1
    return dict(sorted(counts.items(), key=lambda kv: (-kv[1], kv[0])))


# Source code by suffix, for telling a skipped code file from skipped data or an asset: the
# languages the scanners read, plus those no scanner reads for behavior yet.
_CODE_SUFFIXES = frozenset(
    {
        ".py", ".pyw", ".js", ".mjs", ".cjs", ".jsx", ".ts", ".tsx", ".mts", ".cts",
        ".sh", ".bash", ".zsh", ".ps1", ".psm1", ".bat", ".cmd",
        *_UNANALYZED_LANGUAGES,
    }
)
_MINIFIED_INFIX = re.compile(r"[.-]min(?=\.[^.]+$)", re.IGNORECASE)


def _skipped_code_files(index: FileIndex) -> dict[str, int]:
    """Count the shipped (non-test) code files the scan did not read, by reason: ``too_large``
    (over MAX_FILE_BYTES, including a script npm runs at install, whatever its suffix) and
    ``minified`` (a bundle; see file_index._is_minified). A minified copy shipped next to its
    readable source (``x.min.js`` beside ``x.js``) was read in that source and is not counted."""
    indexed = {f.relpath for f in index.files}
    too_large = {
        p for p in index.large
        if (Path(p).suffix.lower() in _CODE_SUFFIXES or p in index.install_scripts)
        and not is_test_path(p)
    }
    for p in index.install_scripts - indexed:  # one in a skipped folder is not in index.large
        try:
            if (index.root / p).stat().st_size > MAX_FILE_BYTES:
                too_large.add(p)
        except OSError:
            continue
    minified = [
        p for p in index.minified
        if not is_test_path(p) and _MINIFIED_INFIX.sub("", p) not in indexed
    ]
    counts = {"too_large": len(too_large), "minified": len(minified)}
    return {reason: n for reason, n in counts.items() if n}


def _skipped_code_phrase(skipped: dict[str, int]) -> str:
    total = sum(skipped.values())
    reasons = " and ".join(
        f"{n} {'too large' if reason == 'too_large' else reason}" for reason, n in skipped.items()
    )
    return f"{total} code file{'s' if total != 1 else ''} not read ({reasons})"


def _language_list(unanalyzed: dict[str, int]) -> str:
    names = list(unanalyzed)
    return names[0] if len(names) == 1 else ", ".join(names[:-1]) + " and " + names[-1]


def _unanalyzed_note(unanalyzed: dict[str, int]) -> NeedsReview:
    files = ", ".join(f"{n} {lang}" for lang, n in unanalyzed.items())
    return NeedsReview(
        category="coverage",
        title="Code in languages not analyzed for behavior",
        reason=(
            f"{files} source file(s). Shell execution, network access, file access and dynamic "
            f"code in {_language_list(unanalyzed)} are not detected yet; checks for secrets, "
            f"sensitive paths and hidden Unicode did run. A low score does not cover this code."
        ),
    )


def _unread_notes(index: FileIndex) -> list[NeedsReview]:
    """What the walk found but did not read: files it could not open, links it did not follow,
    and the whole component when nothing in it could be analyzed. A file passed over in silence
    reads as checked and clean."""
    notes: list[NeedsReview] = []
    if index.unreadable:
        folders = any(p.endswith("/") for p in index.unreadable)
        notes.append(aggregated_review(
            category="coverage",
            title="Files could not be read",
            places=[(p, None) for p in index.unreadable],
            what=f"file(s){' and folder(s)' if folders else ''} could not be read",
            advice="Nothing in them was checked.",
        ))
    if index.links:
        notes.append(aggregated_review(
            category="coverage",
            title="Links not followed",
            places=[(p, None) for p in index.links],
            what="link(s) not followed (symbolic links or junctions)",
            advice="A link can point outside the component, so nothing it points to was read.",
        ))
    if not index.files:
        stats = index.stats
        kinds = [
            (stats.get("skipped_binary", 0), "binary"),
            (stats.get("skipped_large", 0), f"larger than {MAX_FILE_BYTES // (1024 * 1024)} MiB"),
            (stats.get("skipped_minified", 0), "minified"),
            (stats.get("skipped_source_map", 0), "source maps without code"),
            (stats.get("skipped_own_output", 0), "SkillTotal reports or baselines"),
            (len(index.unreadable), "unreadable"),
            (len(index.links), "links not followed"),
        ]
        found = ", ".join(f"{n} {kind}" for n, kind in kinds if n) or "it contains no files"
        notes.append(NeedsReview(
            category="coverage",
            title=NOTHING_READ,
            reason=(
                f"No file in this component could be analyzed ({found}), so this report "
                f"covers none of its content."
            ),
        ))
    return notes


def _skipped_entries_note(count: int) -> NeedsReview:
    entries, were = ("1 entry", "was") if count == 1 else (f"{count} entries", "were")
    return NeedsReview(
        category="coverage",
        title="Archive entries not extracted",
        reason=(
            f"{entries} of the archive {were} not extracted: symbolic and hard links, FIFOs and "
            f"devices are never written to disk, so nothing they point to was read."
        ),
    )


def _verdict(
    findings: list[Finding],
    level,
    unanalyzed: dict[str, int] | None = None,
    *,
    nothing_read: bool = False,
    skipped_code: dict[str, int] | None = None,
) -> dict:
    """Plain-language top-line answer, mapped to the two real user fears:

    1. "Is it malicious?" -> ``has_malicious_indicators`` (deliberate deception/stealth
       only: poisoning, obfuscated exec, prompt injection, hidden unicode). Kept narrow and
       high-confidence so we never label a legitimate-but-powerful component "malware".
    2. "Could it leak my data / get me compromised?" -> the severity tier, surfaced as
       "High risk" / "Critical risk" even with no malice (e.g. a clear-text credential+network
       exfiltration path). This keeps the headline consistent with the risk score instead of
       the confusing "critical, but not malware".

    Returns a single ``level`` (one of malicious | critical | high | medium | low), a
    human ``headline``, and up to three plain ``reasons``.
    """
    by_class = {c: 0 for c in ThreatClass}
    for f in findings:
        by_class[f.threat_class] += 1
    has_mal = by_class[ThreatClass.MALICIOUS_INDICATOR] > 0

    if has_mal:
        vlevel, headline = "malicious", "Malicious indicators found"
    elif level in (RiskLevel.CRITICAL, RiskLevel.HIGH):
        # Capabilities score 0, so a high score here comes from risky constructs: say "risk".
        vlevel = level.value
        headline = f"{level.value.capitalize()} risk - review before installing"
    elif level is RiskLevel.MEDIUM:
        vlevel, headline = "medium", "Some risk - review before installing"
    elif any(f.id == TYPOSQUAT_FINDING_ID for f in findings):
        # One mistyped name is how the impostor gets installed; the score of a typosquat says
        # nothing, since its code is usually a copy of the real package.
        vlevel, headline = "low", "Name resembles a popular package - check it before installing"
    elif by_class[ThreatClass.RISKY_CONSTRUCT] > 0:
        # A single risky construct scores in the low band, and it is still a finding to read:
        # "No significant risks found" over it said the opposite of the list below it.
        vlevel, headline = "low", "Low risk - review the findings before installing"
    elif by_class[ThreatClass.EXPOSURE] > 0:
        # A shipped credential does not raise the risk to the user, but the reader must not be
        # told "nothing here" about a package that carries a live key. Whether a value is live
        # the scan cannot tell (examples, defaults and public keys look the same), so the
        # headline names what was found and does not claim a leak.
        vlevel, headline = "low", "No malicious indicators - secret-like values found"
    elif by_class[ThreatClass.CAPABILITY] > 0:
        # Clean, but powerful: no malicious indicators and no risky constructs, yet the
        # component has real capabilities (shell/filesystem/network). Acknowledge them instead
        # of the dismissive "nothing here" so a capable tool reads correctly.
        vlevel, headline = "low", "No malicious indicators - review capabilities before installing"
    else:
        vlevel, headline = "low", "No significant risks found"

    if (unanalyzed or skipped_code) and vlevel == "low":
        # Never a reassuring headline over code nothing read: the level and score stay as they
        # are (unread code is not evidence of risk), only the wording stops implying "checked".
        # That covers code in a language no scanner reads for behavior, and code files that were
        # not read at all (too large, or a minified bundle).
        parts = []
        if unanalyzed:
            parts.append(
                f"{_language_list(unanalyzed)} code not checked for shell, network or file access"
            )
        if skipped_code:
            parts.append(_skipped_code_phrase(skipped_code))
        headline = "Partially analyzed - " + "; ".join(parts)
    if nothing_read and vlevel == "low":
        # Nothing was read, so nothing could be found: the level and score stay as they are, and
        # the headline does not word an empty scan as a clean one.
        headline = "Not analyzed - nothing in this component could be read"

    verdict = {
        "level": vlevel,
        "headline": headline,
        "has_malicious_indicators": has_mal,
        "reasons": _verdict_reasons(findings),
        "malicious_indicators": by_class[ThreatClass.MALICIOUS_INDICATOR],
        "risky_constructs": by_class[ThreatClass.RISKY_CONSTRUCT],
        "exposed_secrets": by_class[ThreatClass.EXPOSURE],
        "capabilities": by_class[ThreatClass.CAPABILITY],
    }
    if unanalyzed:
        verdict["unanalyzed_code"] = dict(unanalyzed)
    if skipped_code:
        verdict["unanalyzed_files"] = dict(skipped_code)
    return verdict


# Which findings explain a verdict first: what makes it malicious, then what is scored, then the
# rest. A capability is never the reason ahead of a risky construct, whatever its severity.
_REASON_ORDER = {
    ThreatClass.MALICIOUS_INDICATOR: 0,
    ThreatClass.RISKY_CONSTRUCT: 1,
    ThreatClass.EXPOSURE: 2,
    ThreatClass.CAPABILITY: 3,
}


def _verdict_reasons(findings: list[Finding], limit: int = 3) -> list[str]:
    """Top distinct finding titles (by threat class, then by severity) as plain reasons."""
    ordered = sorted(
        findings,
        key=lambda f: (_REASON_ORDER.get(f.threat_class, 4), -f.severity.rank),
    )
    reasons: list[str] = []
    for f in ordered:
        if f.title not in reasons:
            reasons.append(f.title)
        if len(reasons) >= limit:
            break
    return reasons


# Inline suppression marker: `# skilltotal:ignore` or `# skilltotal:ignore[ST-X, ST-Y]`
# (any comment syntax — #, //, <!-- -->). A bare marker ignores any rule on that line.
_INLINE_IGNORE_RE = re.compile(r"skilltotal:\s*ignore(?:\[([^\]]*)\])?", re.IGNORECASE)


def _apply_inline_ignores(
    findings: list[Finding], index: FileIndex
) -> tuple[list[Finding], int, set[str], dict[str, tuple[str, int]]]:
    """Drop evidence whose source line (or the line above) carries a skilltotal:ignore marker.

    Returns the kept findings; how many evidence occurrences were dropped (the report counts them
    as suppressed: an ignored finding is the owner's decision, not something never seen); the
    malicious-indicator rules a marker tried to silence, which are never dropped (the marker is in
    the component, and a component scanned as a local folder is not always the reader's own code,
    so its author could hide what it does, 2026-10-15); and the rule ids markers name that no rule
    has, each with where it was first seen (a misspelt id silences nothing, and the owner believes
    it does).
    """
    by_path = {f.relpath: f for f in index.files}
    known = frozenset(r.id for r in get_rules())
    unknown: dict[str, tuple[str, int]] = {}
    kept: list[Finding] = []
    dropped = 0
    refused: set[str] = set()
    for finding in findings:
        malicious = _THREAT_CLASS_BY_ID.get(finding.id) is ThreatClass.MALICIOUS_INDICATOR
        remaining = []
        for e in finding.evidence:
            if not _line_ignores(e, finding.id, by_path, known, unknown):
                remaining.append(e)
            elif malicious:
                remaining.append(e)
                refused.add(finding.id)
        dropped += len(finding.evidence) - len(remaining)
        if remaining:
            kept.append(_finding_with_evidence(finding, remaining))
    return kept, dropped, refused, unknown


def _line_ignores(
    evidence: Evidence, rule_id: str, by_path: dict[str, IndexedFile],
    known: frozenset[str] = frozenset(), unknown: dict[str, tuple[str, int]] | None = None,
) -> bool:
    """True when a marker on the evidence's line or the line above covers ``rule_id``. Ids a
    marker there names that are not in ``known`` are recorded in ``unknown``."""
    f = by_path.get(evidence.file)
    if f is None:
        return False
    for line_no in (evidence.line_start, evidence.line_start - 1):
        m = _INLINE_IGNORE_RE.search(f.line_text(line_no))
        if m is None:
            continue
        ids = m.group(1)
        if not ids:  # bare marker -> ignore whatever rule matched here
            return True
        wanted = {x.strip().upper() for x in ids.replace(";", ",").split(",") if x.strip()}
        if unknown is not None and known:
            for bad in sorted(wanted - known):
                unknown.setdefault(bad, (evidence.file, line_no))
        if rule_id.upper() in wanted:
            return True
    return False


def _unknown_marker_ids_notes(unknown: dict[str, tuple[str, int]]) -> list[NeedsReview]:
    """A note for each rule id a skilltotal:ignore marker names that no rule has."""
    known = sorted(r.id for r in get_rules())
    return [
        NeedsReview(
            category="config",
            title=f"Unknown rule id in skilltotal:ignore marker: {rule_id}",
            reason=(f"The marker names {rule_id}, which no rule has, so it suppresses nothing; "
                    f"{unknown_rule_hint(rule_id, known)}"),
            file=file,
            line=line,
        )
        for rule_id, (file, line) in sorted(unknown.items())
    ]


def _is_test_evidence(evidence: Evidence, by_path: dict[str, IndexedFile]) -> bool:
    """True if evidence is in test code — by path (test dirs/suffixes) or inline Rust tests.

    Rust unit tests live in the same .rs file as production code under `#[cfg(test)]` / `#[test]`,
    which the path-based ``is_test_path`` cannot see. That gated code is not compiled into the
    shipped artifact, so a credential there is a fixture, not behavior — demote it like any test.
    """
    if is_test_path(evidence.file):
        return True
    if evidence.match_offset is None:
        return False
    f = by_path.get(evidence.file)
    return f is not None and f.in_rust_test(evidence.match_offset)


def _split_test_evidence(
    findings: list[Finding],
    index: FileIndex,
) -> tuple[list[Finding], list[NeedsReview]]:
    """Keep only non-test evidence on findings; summarize test-only matches as review."""
    by_path = {f.relpath: f for f in index.files}
    kept: list[Finding] = []
    review: list[NeedsReview] = []
    for finding in findings:
        prod = [e for e in finding.evidence if not _is_test_evidence(e, by_path)]
        test = [e for e in finding.evidence if _is_test_evidence(e, by_path)]
        if prod:
            if len(prod) != len(finding.evidence):
                finding = Finding(
                    id=finding.id,
                    severity=finding.severity,
                    category=finding.category,
                    title=finding.title,
                    description=finding.description,
                    evidence=prod,
                    recommendation=finding.recommendation,
                )
            kept.append(finding)
        if test:
            files = sorted({e.file for e in test})
            review.append(
                NeedsReview(
                    category=finding.category,
                    title=f"{finding.title} (test code only)",
                    reason=(
                        f"{finding.id} matched only in test code "
                        f"({', '.join(files[:5])}); test code is not executed by consumers."
                    ),
                    file=files[0],
                    line=next((e.line_start for e in test if e.file == files[0]), None),
                )
            )
    return kept, review


def _hold_out(
    held_files: frozenset[str],
    split: Callable[..., tuple[list[Finding], list[NeedsReview]]],
    findings: list[Finding],
    *args: object,
) -> tuple[list[Finding], list[NeedsReview]]:
    """Run the path-based demotion ``split`` on the evidence outside ``held_files`` only.

    Evidence in a held file (one npm runs at install time) is behavior whatever folder it sits in,
    so it skips ``split`` and goes back into its finding where it was: the first location a report
    shows, and the hook quotes, does not move because other evidence was demoted.
    """
    held: dict[str, list[Evidence]] = {}
    rest: list[Finding] = []
    for finding in findings:
        mine = [e for e in finding.evidence if e.file in held_files]
        if mine:
            held[finding.id] = mine
        other = [e for e in finding.evidence if e.file not in held_files]
        if other:
            rest.append(_finding_with_evidence(finding, other))
    if not held:
        return split(findings, *args)
    kept, review = split(rest, *args)
    kept_by_id = {f.id: f for f in kept}
    merged: list[Finding] = []
    for finding in findings:
        base = kept_by_id.get(finding.id)
        evidence = [*(base.evidence if base else ()), *held.get(finding.id, ())]
        if not evidence:
            continue
        order = {id(e): i for i, e in enumerate(finding.evidence)}
        evidence.sort(key=lambda e: order.get(id(e), len(order)))
        merged.append(_finding_with_evidence(base or finding, evidence))
    return merged, review


def _finding_with_evidence(finding: Finding, evidence: list[Evidence]) -> Finding:
    """Return ``finding`` unchanged, or a copy with its evidence narrowed to ``evidence``."""
    if len(evidence) == len(finding.evidence):
        return finding
    return Finding(
        id=finding.id,
        severity=finding.severity,
        category=finding.category,
        title=finding.title,
        description=finding.description,
        evidence=evidence,
        recommendation=finding.recommendation,
        threat_class=finding.threat_class,
        owasp=finding.owasp,
    )


def _demoted_review(finding: Finding, demoted: list[Evidence], note: str) -> NeedsReview:
    files = sorted({e.file for e in demoted})
    return NeedsReview(
        category=finding.category,
        title=f"{finding.title} ({note})",
        reason=(
            f"{finding.id} matched only in {note} ({', '.join(files[:5])}); "
            "this context does not represent executed behavior."
        ),
        file=files[0],
        line=next((e.line_start for e in demoted if e.file == files[0]), None),
    )


def _split_doc_evidence(
    findings: list[Finding],
    skills: frozenset[str] = frozenset(),
    frontmatter: dict[str, int] | None = None,
) -> tuple[list[Finding], list[NeedsReview]]:
    """Demote evidence found only in human-facing documentation/metadata to needs_review.

    READMEs, changelogs, license/notice files, docs/ trees and ignore-files are never executed
    and are not an agent-instruction surface (those — SKILL.md, manifests — are excluded by
    ``is_doc_path``), so a pattern that appears only there is descriptive, not behavior.

    ``frontmatter`` maps markdown files whose frontmatter declares hooks or MCP servers (a
    subagent in ``agents/x.md``) to the last line of that frontmatter: those lines are commands
    the agent runs, whatever the file is named, so evidence on them is not documentation.
    """
    frontmatter = frontmatter or {}

    def is_doc(e: Evidence) -> bool:
        if e.line_end <= frontmatter.get(e.file, 0):
            return False
        return is_doc_path(e.file, skills)

    kept: list[Finding] = []
    review: list[NeedsReview] = []
    for finding in findings:
        prod = [e for e in finding.evidence if not is_doc(e)]
        docs = [e for e in finding.evidence if is_doc(e)]
        if prod:
            kept.append(_finding_with_evidence(finding, prod))
        if docs:
            review.append(_demoted_review(finding, docs, "documentation only"))
    return kept, review


def _split_own_provider_reads(
    findings: list[Finding], component: Component
) -> tuple[list[Finding], list[NeedsReview]]:
    """Demote a provider SDK's reads of its own provider's credential files to needs_review.

    Reading ~/.aws is what botocore and the AWS JavaScript SDK are for, and they build the path by
    joining it onto the home directory as often as they write it out. See
    ``scoring.is_own_provider_read`` for which packages count. Runs before synthesis, so the read
    cannot feed ST-COMBO-EXFIL either.
    """
    kept: list[Finding] = []
    review: list[NeedsReview] = []
    for finding in findings:
        own = [e for e in finding.evidence if is_own_provider_read(finding.id, e, component)]
        if not own:
            kept.append(finding)
            continue
        rest = [e for e in finding.evidence if not is_own_provider_read(finding.id, e, component)]
        if rest:
            kept.append(_finding_with_evidence(finding, rest))
        files = sorted({e.file for e in own})
        review.append(
            NeedsReview(
                category=finding.category,
                title=f"{finding.title} (the provider SDK's own credentials)",
                reason=(
                    f"{finding.id} matched where this package, an SDK or client of the provider "
                    f"those credentials belong to, reads them ({', '.join(files[:5])}); reading "
                    "them is what it is for, so it is not scored."
                ),
                file=files[0],
                line=next((e.line_start for e in own if e.file == files[0]), None),
            )
        )
    return kept, review


def _split_unpublished_env_evidence(
    findings: list[Finding],
) -> tuple[list[Finding], list[NeedsReview]]:
    """ST-ENV-SHIPPED only means anything for a released artifact.

    A `.env` sitting in a working tree or a git checkout is how the pattern is *supposed* to be
    used — the file is local and gitignored — so flagging it when someone scans a directory or a
    repository would fire on nearly every project and teach people to ignore the rule. The finding
    is about the file having escaped into a published package, which only the component type can
    tell us, and the component type is not visible to a scanner.
    """
    kept: list[Finding] = []
    review: list[NeedsReview] = []
    for f in findings:
        if f.id != "ST-ENV-SHIPPED":
            kept.append(f)
            continue
        files = ", ".join(dict.fromkeys(e.file for e in f.evidence))
        review.append(
            NeedsReview(
                category=f.category,
                title=f"Local .env file ({len(f.evidence)})",
                reason=(
                    "A .env file is present, but this component was not scanned as a published "
                    "package, and a local .env is normal and expected. Flagged for review, not "
                    f"scored: {files}."
                ),
                file=f.evidence[0].file,
            )
        )
    return kept, review


# Rules whose evidence is the EXISTENCE OF A FILE rather than code inside one. The demotion below
# exists because bundling inlines third-party code and destroys the path signals other layers rely
# on — reasoning that has nothing to say about a whole file the packer copied in. A `.env` under
# `build/` ships to every installer exactly like one at the root, so it stays scored.
_BUILD_OUTPUT_EXEMPT: frozenset[str] = frozenset({"ST-ENV-SHIPPED"})


def _split_build_output_evidence(
    findings: list[Finding],
) -> tuple[list[Finding], list[NeedsReview]]:
    """In a published package's build output, keep capability findings and demote risk claims.

    Build output is the only code a package ships, so it must be scanned — but a bundler inlines
    dependencies, tests, fixtures and template strings into the same file, and every other
    demotion layer here recognises those by their PATH (``tests/``, ``docs/``, ``examples/``).
    Bundling destroys exactly that signal, leaving those guards blind.

    So the line is drawn by what the evidence can still honestly support. A capability survives:
    the shipped artifact really can execute a shell or reach the network, whoever authored the
    code. A risk claim does not: whether a credential path is an exfiltration target or an entry
    in a security tool's own signature list, whether a secret is real or a generator's placeholder,
    whether an SSRF address is an attack or an assertion in a bundled test — all of that depends on
    context the bundle no longer carries. Measured on real packages, keeping them produced
    `critical` verdicts from a threat-feed's ``"*id_rsa*"`` pattern list, a
    ``JWT_ACCESS_SECRET: "test..."`` scaffold, and a bundled ``expect(...).toThrow()`` guarding
    against 169.254.169.254.

    Demoted evidence lands in needs_review, so it is disclosed rather than dropped, and it runs
    before synthesis so a demoted secret cannot feed ``ST-COMBO-EXFIL``.
    """
    kept: list[Finding] = []
    review: list[NeedsReview] = []
    for finding in findings:
        if finding.id in _BUILD_OUTPUT_EXEMPT:
            kept.append(finding)
            continue
        if _THREAT_CLASS_BY_ID.get(finding.id, ThreatClass.CAPABILITY) == ThreatClass.CAPABILITY:
            kept.append(finding)
            continue
        prod = [e for e in finding.evidence if not is_build_output_path(e.file)]
        built = [e for e in finding.evidence if is_build_output_path(e.file)]
        if prod:
            kept.append(_finding_with_evidence(finding, prod))
        if built:
            review.append(
                _demoted_review(finding, built, "inside a published package's build output")
            )
    return kept, review


def _split_data_corpus_evidence(
    findings: list[Finding],
) -> tuple[list[Finding], list[NeedsReview]]:
    """Demote evidence found only in inert data/eval/benchmark corpus files to needs_review.

    A pattern that appears only in reference data — a prompt-injection string in
    ``eval_datasets/poisoning.yaml``, a credential path in ``fixtures/sample.json`` — is a
    detector test vector or sample, not the component's executed behavior or agent-instruction
    surface. ``is_data_corpus_path`` is restricted to non-code files, so a real payload shipped
    as code in such a directory is still scanned and scored.
    """
    kept: list[Finding] = []
    review: list[NeedsReview] = []
    for finding in findings:
        prod = [e for e in finding.evidence if not is_data_corpus_path(e.file)]
        corpus = [e for e in finding.evidence if is_data_corpus_path(e.file)]
        if prod:
            kept.append(_finding_with_evidence(finding, prod))
        if corpus:
            review.append(_demoted_review(finding, corpus, "data/eval corpus only"))
    return kept, review


_STRUCTURED_DATA_SUFFIXES: tuple[str, ...] = (".json", ".yaml", ".yml", ".toml")
# MCP manifest filenames: a tool description here IS an agent-instruction surface, so an
# injection phrase in it must stay scored (not demoted as data). Kept in sync with scanners/mcp.
_MCP_MANIFEST_NAMES: frozenset[str] = frozenset(
    {"mcp.json", ".mcp.json", "mcp.config.json", "manifest.json", "server.json"}
)


def _is_structured_data_file(relpath: str) -> bool:
    name = relpath.lower().rsplit("/", 1)[-1]
    return name.endswith(_STRUCTURED_DATA_SUFFIXES) and name not in _MCP_MANIFEST_NAMES


# Findings demoted when their evidence sits in a structured-data (JSON/YAML/TOML) file — the value
# is inert data, not executed code or an agent-instruction surface:
#   - ST-PROMPT-INJECTION: an injection phrase in a JSON/YAML value is a scenario pack / config /
#     test vector, not a directive (MCP manifests excluded — tool descriptions steer the agent).
#   - ST-OBF-DECODE-EXEC: a decode-and-execute token in a YAML/JSON string is a keyword/pattern in
#     a security guardrail's own detection list (litellm ships one in a keyword YAML), not code that
#     runs — exactly like this scanner's own rule literals.
#   - ST-SENS-PATH: a credential-location token as a JSON/YAML string VALUE is inert data, not a
#     path being opened — botocore bundles the AWS API service models under `botocore/data/*.json`
#     where `"ec2KeyPair": "id_rsa"` is an API example value, not credential access. Real access is
#     `open("~/.aws/credentials")` in .py/.js, which is unaffected (efficacy positives are code).
_STRUCTURED_DATA_DEMOTABLE = frozenset(
    {"ST-PROMPT-INJECTION", "ST-OBF-DECODE-EXEC", "ST-SENS-PATH"}
)


def _command_lines(index: FileIndex) -> frozenset[tuple[str, int]]:
    """``(file, line)`` of every command string an agent or editor runs on its own (hooks, MCP
    launch commands, status lines, ...): see ``skilltotal.autorun``."""
    lines: set[tuple[str, int]] = set()
    for command in autorun_commands(index).commands:
        if command.is_http:
            continue
        f = command.file
        for piece in (*command.pieces, *command.env):
            first = f.line_of_offset(piece.start)
            last = f.line_of_offset(max(piece.start, piece.end - 1))
            lines.update((f.relpath, n) for n in range(first, last + 1))
    return frozenset(lines)


def _split_structured_data_evidence(
    findings: list[Finding],
    command_lines: frozenset[tuple[str, int]] = frozenset(),
    index: FileIndex | None = None,
) -> tuple[list[Finding], list[NeedsReview]]:
    """Demote code-pattern / injection evidence found in a structured-data file (JSON/YAML/TOML).

    A JSON/YAML value is data, not executable code or an agent-instruction surface.
    Agent-instruction surfaces (SKILL.md / AGENTS.md markdown, and MCP *manifests* whose tool
    descriptions steer the agent) are excluded via ``_is_structured_data_file``, so a live
    injection there still fires. Runs before synthesis, so a demoted match can't feed
    ST-FLOW-TRIFECTA / ST-CONVERGENCE. FPs: tandem (a defensive monitor's scenario JSON), litellm
    (its content-filter guardrail's keyword YAML).

    A value an agent or editor runs as a command (``command_lines``: a hook, an MCP server's
    launch command, a status line) is not inert data, so evidence on it is kept. Nor is a JSON
    file shaped as an MCP tool/prompt/resource listing whatever it is named (``tools.json``, a
    tools/list dump a server loads): the client hands every description in it to the model.
    """
    by_path = {f.relpath: f for f in index.files} if index is not None else {}
    listings: dict[str, bool] = {}

    def is_listing(relpath: str) -> bool:
        if relpath not in listings:
            f = by_path.get(relpath)
            listings[relpath] = False
            if f is not None and f.suffix == ".json":
                try:
                    listings[relpath] = is_mcp_listing(bounded_json.loads_cut(f.text)[0])
                except ValueError:
                    pass
        return listings[relpath]

    def is_data(e: Evidence) -> bool:
        if (e.file, e.line_start) in command_lines:
            return False
        return _is_structured_data_file(e.file) and not is_listing(e.file)

    kept: list[Finding] = []
    review: list[NeedsReview] = []
    for finding in findings:
        if finding.id not in _STRUCTURED_DATA_DEMOTABLE:
            kept.append(finding)
            continue
        real = [e for e in finding.evidence if not is_data(e)]
        data = [e for e in finding.evidence if is_data(e)]
        if real:
            kept.append(_finding_with_evidence(finding, real))
        if data:
            review.append(_demoted_review(finding, data, "a structured-data (JSON/YAML) value"))
    return kept, review


def _split_example_evidence(
    findings: list[Finding],
) -> tuple[list[Finding], list[NeedsReview]]:
    """Demote evidence found only in example/demo/benchmark scaffolding (incl. code) to
    needs_review. A 0.0.0.0 bind in ``examples/slack_example.py``, a demo API key in
    ``benchmark/test-project/``, or a credential path in ``.env.example`` is scaffolding that
    ships with the component to illustrate/measure it, not its primary behavior. Like test code,
    it is surfaced for review rather than scored, so a real payload hidden under examples/ is
    still reported. Runs after the data-corpus pass, before synthesized combos are computed, so
    scaffold evidence cannot drive ST-COMBO-EXFIL / ST-FLOW-TRIFECTA.
    """
    kept: list[Finding] = []
    review: list[NeedsReview] = []
    for finding in findings:
        prod = [e for e in finding.evidence if not is_example_path(e.file)]
        scaffold = [e for e in finding.evidence if is_example_path(e.file)]
        if prod:
            kept.append(_finding_with_evidence(finding, prod))
        if scaffold:
            review.append(
                _demoted_review(finding, scaffold, "example/demo/benchmark scaffolding only")
            )
    return kept, review


def _split_ci_evidence(
    findings: list[Finding],
) -> tuple[list[Finding], list[NeedsReview]]:
    """Demote evidence found only in CI/CD pipeline config to needs_review. A CI job runs on
    the project's build service, never on the consumer's machine — numpy's .circleci/config.yml
    writing its own ~/.ssh/config for a docs deploy is the project operating its own
    infrastructure, not component behavior. Runs before synthesized combos are computed, so a
    CI-only credential path cannot feed ST-COMBO-EXFIL. Install-time hooks (setup.py, npm
    postinstall) are not CI config and stay fully scored.
    """
    kept: list[Finding] = []
    review: list[NeedsReview] = []
    for finding in findings:
        prod = [e for e in finding.evidence if not is_ci_path(e.file)]
        ci = [e for e in finding.evidence if is_ci_path(e.file)]
        if prod:
            kept.append(_finding_with_evidence(finding, prod))
        if ci:
            review.append(_demoted_review(finding, ci, "CI/CD pipeline configuration only"))
    return kept, review


def _split_code_context_evidence(
    findings: list[Finding], index: FileIndex, regex_only: set[str] | frozenset[str] = frozenset()
) -> tuple[list[Finding], list[NeedsReview]]:
    """Demote regex matches inside a Python string literal/comment, per the rule's policy.

    A behavior/text detector matches its own pattern literals (and docstrings describing them)
    when scanning analyzer/security source; such `.py` matches are literals/examples, not
    executed behavior. Non-Python or non-regex (JSON/AST, no ``match_offset``) evidence is kept.
    """
    if not _CODE_CTX_POLICY:
        return findings, []
    by_path: dict[str, IndexedFile] = {f.relpath: f for f in index.files}
    kept: list[Finding] = []
    review: list[NeedsReview] = []
    for finding in findings:
        policy = _CODE_CTX_POLICY.get(finding.id)
        if policy is None:
            kept.append(finding)
            continue
        real = [
            e for e in finding.evidence
            if not _is_noncode_context(e, policy, by_path, finding.id, regex_only)
        ]
        demoted = [
            e for e in finding.evidence
            if _is_noncode_context(e, policy, by_path, finding.id, regex_only)
        ]
        if real:
            kept.append(_finding_with_evidence(finding, real))
        if demoted:
            review.append(
                _demoted_review(finding, demoted, "a non-executable string/comment context")
            )
    return kept, review


_AGENT_TEXT_RULES = frozenset(
    {"ST-PROMPT-INJECTION", "ST-MCP-TOOL-POISONING", "ST-MCP-SAMPLING-INJECTION"}
)
# Command rules whose match in a shell variable that is only ever printed is a hint, not a command.
_SHELL_HINT_RULES = frozenset({"ST-SHELL-PIPE-EXEC"})
# Policies under which only comments (and, for the second, Python docstrings) are non-code: the
# rule's real positives are value-strings, so string literals are never demoted for it.
_COMMENT_ONLY_POLICIES = frozenset({"comments", "comments_and_docstrings"})


def _is_noncode_context(
    e: Evidence, policy: str, by_path: dict[str, IndexedFile], rule_id: str = "",
    regex_only: set[str] | frozenset[str] = frozenset(),
) -> bool:
    """True if evidence ``e`` is a non-executable string/comment match that ``policy`` demotes.

    Python: a match inside a comment (any policy), a docstring (``comments_and_docstrings``) or a
    string literal (``strings_and_comments``/``strings_and_comments_all``).
    Shell: a match inside a ``#`` comment — so a ``# Usage: curl … | bash`` example line is a
    doc comment, not a runnable remote pipe-to-shell.
    C-family (.ts/.js/.go/.rs/…): a match inside a ``//`` or ``/* */`` comment — so a JSDoc line
    describing a threat (``* exfiltrate … to …``) is a description, not behavior. Under the
    ``strings_and_comments_all`` policy, C-family string literals are demoted too (a
    prompt-injection phrase held in a value-string is a pattern definition, not a live directive).
    """
    f = by_path.get(e.file)
    if f is None or e.match_offset is None:
        return False
    # A string a sink executes (`new Function("…")`, `exec("…")`) is code for every rule. A string
    # a model reads (a FastMCP tool docstring, a sampling prompt) is the directive itself for the
    # rules about text aimed at a model; for the others (a credential path an honest SSH tool's
    # docstring mentions) it is still a description.
    if f.string_is_executed(e.match_offset):
        return False
    if rule_id in _AGENT_TEXT_RULES and f.in_agent_facing_string(e.match_offset):
        return False
    # A command inside an `echo` / `Write-Host` argument is printed for a person to run, in every
    # language: an installer that prints `curl … | sh` as a hint does not pipe anything itself.
    if f.in_printed_command(e.match_offset):
        return True
    # The same command kept in a shell variable that the script only ever prints
    # (`uv_hint="curl … | sh"` then `echo "$uv_hint"`) is a hint too. A variable that is run
    # (`eval "$cmd"`, `bash -c "$cmd"`) keeps the match.
    if rule_id in _SHELL_HINT_RULES and f.in_shell_assigned_hint(e.match_offset):
        return True
    if f.suffix in (".py", ".pyw"):
        if f.in_comment(e.match_offset):
            return True
        # A docstring is a comment with the syntax of a string: `host="0.0.0.0"` in one is an
        # example. Opt-in, because for other rules a value-string in .py is the real signal.
        if policy == "comments_and_docstrings" and f.in_python_docstring(e.match_offset):
            return True
        # A file nested too deeply for the AST walk was read by regex alone: the credential path
        # a call reads is in a string there, and nothing else reports the call.
        return (policy in ("strings_and_comments", "strings_and_comments_all")
                and e.file not in regex_only and f.in_string(e.match_offset))
    everything = policy == "strings_and_comments_all"
    if f.is_shell_like:
        return f.in_shell_comment(e.match_offset) or (
            everything and f.in_shell_quoted(e.match_offset)
        )
    if f.in_sql_comment(e.match_offset):
        return True
    # For every rule that already treats string literals as non-code: a phrase inside a JS regex
    # literal is a pattern the code matches, and rendered HTML/JSX page text or a UI text attribute
    # (`placeholder="Paste ~/.codex/auth.json here"`) is prose for the person using the page.
    if policy not in _COMMENT_ONLY_POLICIES and (
        f.in_js_regex(e.match_offset)
        or f.in_rendered_markup_text(e.match_offset)
        or f.in_jsx_ui_attribute(e.match_offset)
    ):
        return True
    # Markdown prose states what a component does; a fenced block is what it actually ships.
    # A credential path in a sentence ("credentials live in ~/.aws/credentials") or an
    # illustrative key ("example values (Stripe's docs `sk_live_…`)") is documentation, and
    # treating it as behavior escalated real projects to `high` once a package's build output
    # supplied the network half of ST-COMBO-EXFIL. Prompt injection is exempt on purpose: there
    # the prose IS the directive, so demoting it would trade away the recall that matters most.
    # The same holds for tool poisoning in a skill's or subagent's frontmatter description.
    if f.in_markdown_prose(e.match_offset) or f.in_markdown_fenced_comment(e.match_offset):
        return policy != "strings_and_comments_all" and rule_id not in _AGENT_TEXT_RULES
    # C-family: demote matches in // and /* */ comments (a description in a code comment is not
    # behavior). String literals are demoted ONLY for the strings_and_comments_all policy
    # (ST-PROMPT-INJECTION); for every other rule a credential path passed as a string argument is
    # real access, so its C-family strings are kept.
    if f.in_c_comment(e.match_offset):
        return True
    return policy == "strings_and_comments_all" and f.in_c_string(e.match_offset)


_OCCURRENCES_SHOWN = re.compile(r" \(\d+ occurrence\(s\) shown as evidence\)\.$")


def _cap_evidence(f: Finding) -> Finding:
    if len(f.evidence) > MAX_EVIDENCE_PER_FINDING:
        f = replace(f, evidence=f.evidence[:MAX_EVIDENCE_PER_FINDING])
    # The scanner counted its matches before a baseline, an inline ignore or a demotion layer
    # removed some: the count in the description is the evidence that is left.
    m = _OCCURRENCES_SHOWN.search(f.description)
    if m is not None:
        shown = len(f.evidence)
        tail = f" ({shown} occurrence(s) shown as evidence)." if shown > 1 else ""
        description = f.description[: m.start()] + tail
        if description != f.description:
            f = replace(f, description=description)
    return f


def _sort_findings(findings: list[Finding]) -> list[Finding]:
    return sorted(findings, key=lambda f: (-f.severity.rank, f.id))


def _summary(level, score, findings, capabilities, needs_review) -> str:
    caps = ", ".join(sorted(c.value for c in capabilities)) or "none"
    risk, capability = finding_counts(findings)
    parts = [
        f"Risk level {level.value.upper()} (score {score}/100).",
        f"{risk} risk finding(s), {capability} capability finding(s) (not scored); "
        f"capabilities: {caps}.",
    ]
    if needs_review:
        parts.append(f"{len(needs_review)} item(s) require manual review.")
    return " ".join(parts)


def _metadata(
    index: FileIndex, findings: list[Finding], suppressed_count: int,
    baseline_count: int | None = None,
) -> dict:
    by_severity = {s.value: 0 for s in Severity}
    for f in findings:
        by_severity[f.severity.value] += 1
    # Only when a baseline was given: how many of the suppressed occurrences it accounted for.
    baseline = {} if baseline_count is None else {"baseline_suppressed_count": baseline_count}
    return {
        "skilltotal_version": __version__,
        "schema_version": REPORT_SCHEMA_VERSION,
        "ruleset_version": RULESET_VERSION,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "files_indexed": index.stats.get("indexed", 0),
        "files_skipped_binary": index.stats.get("skipped_binary", 0),
        "files_skipped_large": index.stats.get("skipped_large", 0),
        "scanners_run": [s.name for s in SCANNERS],
        "findings_by_severity": by_severity,
        "suppressed_count": suppressed_count,
        **baseline,
    }
