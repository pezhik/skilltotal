"""Component traits: a behavioral fingerprint projected over findings + a standards crosswalk.

A *trait* is a fundamental behavioral characteristic a component exhibits (it can execute
code, it reaches the network, it holds an embedded credential, it carries an untrusted
instruction surface, …). Traits are a higher-level, smaller vocabulary than the rule set:
many rules collapse into one trait, so the trait profile reads as a fingerprint rather than a
flat findings list.

This module is a pure projection layer, exactly like :mod:`skilltotal.capabilities` and
:mod:`skilltotal.owasp`: it never scans a file and never executes anything. It regroups the
evidence that findings already proved, keyed by trait, and attaches a machine-readable
crosswalk to three industry references for each trait:

* **CSA** — the Cloud Security Alliance "Secure Agentic System Design: A Trait-Based Approach"
  trait/pattern and its named risk;
* **MAESTRO** — the CSA MAESTRO threat-modeling layer(s) the trait maps to;
* **MITRE ATLAS** — the adversarial-ML tactic(s), where there is an honest fit.

Design boundaries (must hold):

* **Descriptive, never scored.** A single trait is like a :class:`~skilltotal.models.Capability`
  — informational, 0 weight. Risk still comes only from ``malicious_indicator`` /
  ``risky_construct`` findings (including the synthesized *emergent* trait-combinations
  ST-COMBO-EXFIL / ST-FLOW-TRIFECTA / ST-CONVERGENCE, which are already ``risky_construct``).
* **Component-only.** We only model traits that are statically determinable from files inside
  the component. CSA's runtime/architecture trait categories (Control & Orchestration, Trust
  models, Learning, broker availability) require deployment context we deliberately never
  inspect; they are intentionally *not* represented here rather than guessed.
* **Honest gaps.** Where a reference has no defensible fit for a trait, the field is an empty
  tuple — never a forced mapping. See ``docs/trait-crosswalk.md`` for the rationale.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

from skilltotal.models import Evidence, Finding

# Evidence kept per trait (traits aggregate many findings; mirror capabilities.py's cap).
MAX_EVIDENCE_PER_TRAIT = 25


class ComponentTrait(str, Enum):
    """A statically-determinable behavioral trait of a component.

    ``str`` subclass so it serializes to JSON directly (project convention).
    """

    # --- Single-behavior traits (one dimension of what the component can do) --------------
    TOOL_SURFACE = "tool_surface"
    EXECUTION_AUTHORITY = "execution_authority"
    FILESYSTEM_REACH = "filesystem_reach"
    NETWORK_EGRESS = "network_egress"
    NETWORK_EXPOSURE = "network_exposure"
    EMBEDDED_CREDENTIAL = "embedded_credential"
    DELEGATED_AUTHENTICATION = "delegated_authentication"
    UNTRUSTED_PERCEPTION = "untrusted_perception"
    METADATA_INTEGRITY = "metadata_integrity"
    SUPPLY_CHAIN_PROVENANCE = "supply_chain_provenance"
    UNSAFE_DESERIALIZATION = "unsafe_deserialization"
    CODE_OBFUSCATION = "code_obfuscation"
    # --- Emergent traits (a combination of behaviors — the synthesized risky-construct
    # findings; this is where CSA locates the real, non-obvious risk). ---------------------
    EXFIL_CORRELATION = "exfil_correlation"
    INSTRUCTION_EXFIL_FLOW = "instruction_exfil_flow"
    MALWARE_CONVERGENCE = "malware_convergence"


# MAESTRO layer reference (CSA MAESTRO threat-modeling framework). Names per the CSA paper.
MAESTRO_LAYERS: dict[str, str] = {
    "L1": "Foundation Models",
    "L2": "Data Operations",
    "L3": "Agent Frameworks",
    "L4": "Deployment & Infrastructure",
    "L5": "Evaluation & Observability",
    "L6": "Security & Compliance",
    "L7": "Agent Ecosystem",
}


@dataclass(frozen=True)
class TraitCrosswalk:
    """Human text + the three-standard crosswalk for one trait.

    ``maestro_layers`` are keys into :data:`MAESTRO_LAYERS`. ``atlas_tactics`` are MITRE ATLAS
    tactic names (empty where there is no honest fit). ``emergent`` marks the combination
    traits, whose backing findings are the synthesized risky-constructs.
    """

    title: str
    description: str
    csa_trait: str
    csa_risk: str
    maestro_layers: tuple[str, ...]
    atlas_tactics: tuple[str, ...]
    emergent: bool = False


# Trait -> its crosswalk. The MAESTRO layers for the CSA trait categories are taken from the
# paper's mapping table (section 3.6.1); Tool-Usage-derived traits are mapped to L3/L4 as a
# documented SkillTotal extension (the CSA table covered 6 of 7 categories, omitting Tool
# Usage). ATLAS tactics are populated only from the paper's explicit examples plus the direct
# Exfiltration tactic for the exfil combo; other traits honestly carry none.
TRAIT_CROSSWALK: dict[ComponentTrait, TraitCrosswalk] = {
    ComponentTrait.TOOL_SURFACE: TraitCrosswalk(
        title="Tool surface",
        description="Exposes callable tools/MCP tools that extend the agent's capabilities.",
        csa_trait="Tool Usage",
        csa_risk="Uncontrolled tool selection and sequencing",
        maestro_layers=("L3", "L4"),
        atlas_tactics=(),
    ),
    ComponentTrait.EXECUTION_AUTHORITY: TraitCrosswalk(
        title="Execution authority",
        description="Can execute shell commands or run dynamically-constructed code.",
        csa_trait="Tool Access Control / Direct Tool Access",
        csa_risk="Excessive ambient authority; uncontrolled tool selection and sequencing",
        maestro_layers=("L3", "L4"),
        atlas_tactics=(),
    ),
    ComponentTrait.FILESYSTEM_REACH: TraitCrosswalk(
        title="Filesystem reach",
        description="Reads from or writes to the local filesystem.",
        csa_trait="Tool Execution Context",
        csa_risk="Excessive ambient authority (blast radius on compromise)",
        maestro_layers=("L4",),
        atlas_tactics=(),
    ),
    ComponentTrait.NETWORK_EGRESS: TraitCrosswalk(
        title="Network egress",
        description="Opens outbound network connections to send or fetch data.",
        csa_trait="Interaction & Communication / Direct Communication",
        csa_risk="Amplified impact of trust exploitation in direct channels",
        maestro_layers=("L5", "L7"),
        atlas_tactics=(),
    ),
    ComponentTrait.NETWORK_EXPOSURE: TraitCrosswalk(
        title="Network exposure",
        description="Binds a listener or debug endpoint, exposing an inbound surface.",
        csa_trait="Interaction & Communication",
        csa_risk="Unauthorized or unintended access & data leakage",
        maestro_layers=("L4", "L7"),
        atlas_tactics=(),
    ),
    ComponentTrait.EMBEDDED_CREDENTIAL: TraitCrosswalk(
        title="Embedded credential access",
        description="Embeds a secret or reads credential/sensitive-path locations.",
        csa_trait="Tool Execution Context / Agent Service Identity",
        csa_risk="Insufficient permission granularity; credential rotation complexity",
        maestro_layers=("L4", "L6"),
        atlas_tactics=(),
    ),
    ComponentTrait.DELEGATED_AUTHENTICATION: TraitCrosswalk(
        title="Delegated authentication",
        description=(
            "Authenticates tool/API calls with the end user's delegated OAuth/OIDC credentials "
            "rather than a long-lived embedded service credential — a smaller blast radius."
        ),
        csa_trait="Tool Execution Context / User Delegated Credentials",
        csa_risk="Access-control boundary confusion (agent-level vs user-level operations)",
        maestro_layers=("L4", "L6"),
        atlas_tactics=(),
    ),
    ComponentTrait.UNTRUSTED_PERCEPTION: TraitCrosswalk(
        title="Untrusted perception surface",
        description=(
            "Carries an injectable instruction surface (prompt-injection phrasing or "
            "hidden/smuggled instructions) that untrusted input can drive."
        ),
        csa_trait="Perception & Context / Contextual Perception",
        csa_risk="Context manipulation and poisoning",
        maestro_layers=("L2", "L5"),
        atlas_tactics=("Adversarial Perception Attacks", "Model Poisoning"),
    ),
    ComponentTrait.METADATA_INTEGRITY: TraitCrosswalk(
        title="Metadata integrity risk",
        description=(
            "Metadata/declarations may mislead: tool poisoning or shadowing, or code that "
            "does more than the declared surface allows."
        ),
        csa_trait="Trust / Tool Poisoning",
        csa_risk="Trust inheritance through data",
        maestro_layers=("L6", "L7"),
        atlas_tactics=(),
    ),
    ComponentTrait.SUPPLY_CHAIN_PROVENANCE: TraitCrosswalk(
        title="Supply-chain provenance risk",
        description=(
            "Install/build-time hooks, remote-fetch-and-run, or a name that resembles a "
            "popular package (typosquatting)."
        ),
        csa_trait="General Protections / Supply Chain",
        csa_risk="Supply-chain compromise via install-time execution or name confusion",
        maestro_layers=("L4",),
        atlas_tactics=(),
    ),
    ComponentTrait.UNSAFE_DESERIALIZATION: TraitCrosswalk(
        title="Unsafe deserialization",
        description="Deserializes data with primitives that can execute code on load.",
        csa_trait="General Protections / Input Validation",
        csa_risk="Untrusted input driving code execution on deserialization",
        maestro_layers=("L2",),
        atlas_tactics=(),
    ),
    ComponentTrait.CODE_OBFUSCATION: TraitCrosswalk(
        title="Code obfuscation",
        description="Ships encoded/obfuscated or encrypted blobs that hide their content.",
        csa_trait="General Protections / Explainability",
        csa_risk="Opaque payloads defeating review and detection",
        maestro_layers=("L5",),
        atlas_tactics=(),
    ),
    ComponentTrait.EXFIL_CORRELATION: TraitCrosswalk(
        title="Sensitive-access + egress correlation",
        description=(
            "Reads credential/sensitive data AND can reach the network — a "
            "credential-exfiltration path when the two behaviors correlate."
        ),
        csa_trait="Tool Access Control / Broker-Mediated Access",
        csa_risk="Cross-request correlation blindness (read sensitive data then external comms)",
        maestro_layers=("L5",),
        atlas_tactics=("Exfiltration",),
        emergent=True,
    ),
    ComponentTrait.INSTRUCTION_EXFIL_FLOW: TraitCrosswalk(
        title="Instruction-driven exfiltration flow",
        description=(
            "An untrusted-instruction surface combined with file access and network egress — "
            "the 'lethal trifecta' for instruction-driven exfiltration."
        ),
        csa_trait="Perception & Context + Tool Access Control",
        csa_risk="Context manipulation escalated through tool egress",
        maestro_layers=("L2", "L5"),
        atlas_tactics=("Adversarial Perception Attacks", "Exfiltration"),
        emergent=True,
    ),
    ComponentTrait.MALWARE_CONVERGENCE: TraitCrosswalk(
        title="Malicious-indicator convergence",
        description="Multiple distinct malicious indicators co-occur in one component.",
        csa_trait="General Protections / Anomaly Detection",
        csa_risk="Convergent malicious behavior across independent indicators",
        maestro_layers=("L5",),
        atlas_tactics=(),
        emergent=True,
    ),
}


# Rule id -> the trait(s) it evidences. Empty tuple = the rule evidences no fingerprint trait
# on its own (kept explicit so the completeness test forces a deliberate decision per rule,
# exactly like OWASP_BY_RULE). A rule may map to several traits (e.g. a dangerous MCP tool is
# both a tool surface and execution authority).
_T = ComponentTrait
TRAIT_BY_RULE: dict[str, tuple[ComponentTrait, ...]] = {
    # Execution of code / commands.
    "ST-SHELL-PY": (_T.EXECUTION_AUTHORITY,),
    "ST-SHELL-NODE": (_T.EXECUTION_AUTHORITY,),
    "ST-CMDI-PY": (_T.EXECUTION_AUTHORITY,),
    "ST-CMDI-NODE": (_T.EXECUTION_AUTHORITY,),
    "ST-TAINT-SHELL-PY": (_T.EXECUTION_AUTHORITY,),
    "ST-TAINT-EXEC-PY": (_T.EXECUTION_AUTHORITY,),
    "ST-DYN-PY": (_T.EXECUTION_AUTHORITY,),
    "ST-DYN-NODE": (_T.EXECUTION_AUTHORITY,),
    "ST-PTH-EXEC": (_T.EXECUTION_AUTHORITY,),
    "ST-SHELL-EVASION": (_T.EXECUTION_AUTHORITY,),
    "ST-OBF-DECODE-EXEC": (_T.EXECUTION_AUTHORITY, _T.CODE_OBFUSCATION),
    "ST-OBF-DECODE-EXEC-PY": (_T.EXECUTION_AUTHORITY, _T.CODE_OBFUSCATION),
    "ST-OBF-DECODE-EXEC-SH": (_T.EXECUTION_AUTHORITY, _T.CODE_OBFUSCATION),
    # Filesystem.
    "ST-FS-PY-READ": (_T.FILESYSTEM_REACH,),
    "ST-FS-PY-WRITE": (_T.FILESYSTEM_REACH,),
    "ST-FS-NODE-READ": (_T.FILESYSTEM_REACH,),
    "ST-FS-NODE-WRITE": (_T.FILESYSTEM_REACH,),
    # Network.
    "ST-NET-PY": (_T.NETWORK_EGRESS,),
    "ST-NET-NODE": (_T.NETWORK_EGRESS,),
    "ST-EMAIL-BCC-EXFIL": (_T.NETWORK_EGRESS,),
    "ST-EXPOSE-BIND": (_T.NETWORK_EXPOSURE,),
    "ST-EXPOSE-DEBUG": (_T.NETWORK_EXPOSURE,),
    # Credentials / sensitive data.
    "ST-SECRET-EMBEDDED": (_T.EMBEDDED_CREDENTIAL,),
    "ST-AUTH-DELEGATED": (_T.DELEGATED_AUTHENTICATION,),
    "ST-SENS-PATH": (_T.EMBEDDED_CREDENTIAL,),
    "ST-SENS-PATH-PY": (_T.EMBEDDED_CREDENTIAL,),
    "ST-SENS-WORD": (_T.EMBEDDED_CREDENTIAL,),
    # Untrusted perception (prompt injection + hidden/smuggled instructions).
    "ST-PROMPT-INJECTION": (_T.UNTRUSTED_PERCEPTION,),
    "ST-PROMPT-WEAK": (_T.UNTRUSTED_PERCEPTION,),
    "ST-HIDDEN-UNICODE": (_T.METADATA_INTEGRITY, _T.UNTRUSTED_PERCEPTION),
    "ST-HIDDEN-UNICODE-AMBIG": (_T.METADATA_INTEGRITY, _T.UNTRUSTED_PERCEPTION),
    # Metadata integrity (poisoning / shadowing / falsified declaration).
    "ST-MCP-TOOL-POISONING": (_T.METADATA_INTEGRITY,),
    "ST-MCP-TOOL-SHADOWING": (_T.METADATA_INTEGRITY,),
    "ST-SKILL-CAP-MISMATCH": (_T.METADATA_INTEGRITY,),
    # Tool surface (MCP).
    "ST-MCP-DETECTED": (_T.TOOL_SURFACE,),
    "ST-MCP-OVERBROAD-SCOPE": (_T.TOOL_SURFACE,),
    "ST-MCP-AUTO-APPROVE": (_T.TOOL_SURFACE,),
    "ST-MCP-DANGEROUS-TOOL": (_T.TOOL_SURFACE, _T.EXECUTION_AUTHORITY),
    "ST-MCP-SERVER-EXEC": (_T.TOOL_SURFACE, _T.EXECUTION_AUTHORITY),
    # Deserialization.
    "ST-DESERIALIZE-PY": (_T.UNSAFE_DESERIALIZATION,),
    "ST-TAINT-DESERIAL-PY": (_T.UNSAFE_DESERIALIZATION,),
    # Supply chain.
    "ST-INSTALL-NPM": (_T.SUPPLY_CHAIN_PROVENANCE,),
    "ST-INSTALL-NPM-PREPARE": (_T.SUPPLY_CHAIN_PROVENANCE,),
    "ST-INSTALL-PY": (_T.SUPPLY_CHAIN_PROVENANCE,),
    "ST-SHELL-PIPE-EXEC": (_T.SUPPLY_CHAIN_PROVENANCE, _T.EXECUTION_AUTHORITY),
    "ST-TYPOSQUAT": (_T.SUPPLY_CHAIN_PROVENANCE,),
    # Obfuscation (passive encoded blobs; no direct execution).
    "ST-OBF-BASE64-BLOB": (_T.CODE_OBFUSCATION,),
    "ST-OBF-HEX": (_T.CODE_OBFUSCATION,),
    "ST-OBF-MINIFIED": (_T.CODE_OBFUSCATION,),
    "ST-ENCRYPTED-ARCHIVE": (_T.CODE_OBFUSCATION,),
    # Emergent combinations (synthesized risky-construct findings).
    "ST-COMBO-EXFIL": (_T.EXFIL_CORRELATION,),
    "ST-FLOW-TRIFECTA": (_T.INSTRUCTION_EXFIL_FLOW,),
    "ST-CONVERGENCE": (_T.MALWARE_CONVERGENCE,),
    "ST-INSTALL-DROPPER": (_T.SUPPLY_CHAIN_PROVENANCE, _T.EXECUTION_AUTHORITY),
}


def traits_for(rule_id: str) -> tuple[ComponentTrait, ...]:
    """Component trait(s) a rule id evidences (empty tuple if none/unknown)."""
    return TRAIT_BY_RULE.get(rule_id, ())


def extract_traits(findings: list[Finding]) -> dict[ComponentTrait, list[Evidence]]:
    """Project findings onto the trait fingerprint: trait -> the evidence that proves it.

    Pure regrouping of evidence the findings already carry — no re-scan. Every trait present is
    therefore evidence-backed by construction, mirroring :func:`capabilities.extract_capabilities`.
    """
    traits: dict[ComponentTrait, list[Evidence]] = {}
    for finding in findings:
        for trait in traits_for(finding.id):
            bucket = traits.setdefault(trait, [])
            for ev in finding.evidence:
                if len(bucket) >= MAX_EVIDENCE_PER_TRAIT:
                    break
                bucket.append(ev)
    return traits


def build_trait_profile(findings: list[Finding]) -> list[dict]:
    """Serialize the trait fingerprint for :meth:`Report.to_dict`.

    Returns one entry per exhibited trait — the trait id, its crosswalk (CSA / MAESTRO /
    ATLAS), and the backing evidence — ordered by the :class:`ComponentTrait` declaration
    order for deterministic output. Built engine-side (like ``verdict``/``metadata``) so the
    ``models`` module stays free of a dependency on this projection layer.
    """
    projected = extract_traits(findings)
    profile: list[dict] = []
    for trait in ComponentTrait:  # stable, declaration-ordered
        evidence = projected.get(trait)
        if not evidence:
            continue
        meta = TRAIT_CROSSWALK[trait]
        profile.append(
            {
                "trait": trait.value,
                "title": meta.title,
                "description": meta.description,
                "emergent": meta.emergent,
                "crosswalk": {
                    "csa_trait": meta.csa_trait,
                    "csa_risk": meta.csa_risk,
                    "maestro_layers": [
                        {"id": layer, "name": MAESTRO_LAYERS[layer]}
                        for layer in meta.maestro_layers
                    ],
                    "atlas_tactics": list(meta.atlas_tactics),
                },
                "evidence": [e.to_dict() for e in evidence],
            }
        )
    return profile
