"""Dynamic code execution detection for Node.js.

Python dynamic execution is handled by the AST scanner
(:mod:`skilltotal.scanners.python_ast`).
"""

from __future__ import annotations

from skilltotal.file_index import FileIndex
from skilltotal.models import Capability, Severity
from skilltotal.scanners.base import (
    MAX_EVIDENCE_SCANNED,
    RuleSpec,
    Scanner,
    ScanResult,
    _collect_evidence,
    _finding_from_rule,
    alternation,
)
from skilltotal.scanners.node_fetch_exec import indirect_code_sink_spans

NODE_SUFFIXES = (".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs")

CATEGORY = "dynamic_code_execution"


class DynamicCodeScanner(Scanner):
    name = "dynamic_code"
    rules = [
        RuleSpec(
            id="ST-DYN-NODE",
            category=CATEGORY,
            severity=Severity.HIGH,
            title="Node.js dynamic code execution",
            description=(
                "Node.js dynamic execution primitives were detected "
                "(eval / new Function / the vm module's runners, written out or reached "
                "indirectly: `(0, eval)(x)`, `globalThis[\"eval\"](x)`, a renamed eval)."
            ),
            recommendation=(
                "Avoid evaluating dynamically constructed code; if unavoidable, ensure "
                "the input is a trusted constant and never derived from external data."
            ),
            capability=Capability.DYNAMIC_CODE_EXECUTION,
            # A `//` comment that mentions eval describes code rather than running it — the same
            # reasoning the exposure and shell rules already apply. Without this, a note like
            # "guarded string eval (no DOM types)" was reported as dynamic execution.
            code_context="comments",
            suffixes=NODE_SUFFIXES,
            node_interop=True,
            # `new Function("")` with an empty body runs nothing: bundled zod uses it to probe
            # whether the runtime allows code generation (CSP, jitless), so it is left out.
            pattern=alternation(
                r"\beval\s*\(",
                r"\bnew\s+Function\s*\((?!\s*(?:\"\"|''|``)\s*\))",
                r"\bvm\.runIn(?:NewContext|ThisContext)\s*\(",
            ),
        ),
    ]

    def scan(self, index: FileIndex) -> ScanResult:
        rule = self.rules[0]
        evidence = _collect_evidence(index, rule)
        seen = {(ev.file, ev.line_start, ev.line_end) for ev in evidence}
        # The same sinks spelled so that the pattern above does not read them: the indirect call
        # `(0, eval)(x)`, eval looked up on the global object by a spliced or bound name, a name
        # bound to eval, `vm.runInContext` / `new vm.Script`.
        for f in index.select(suffixes=NODE_SUFFIXES):
            if len(evidence) >= MAX_EVIDENCE_SCANNED:
                break
            for start, end in indirect_code_sink_spans(f):
                ev = f.evidence_for_span(start, end)
                key = (ev.file, ev.line_start, ev.line_end)
                if key not in seen:
                    seen.add(key)
                    evidence.append(ev)
        findings = [_finding_from_rule(rule, evidence)] if evidence else []
        return ScanResult(findings=findings)
