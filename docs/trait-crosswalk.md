# Component traits & the standards crosswalk

SkillTotal projects its findings onto a small, higher-level vocabulary of **behavioral traits**
— a fingerprint of what a component *does* — and maps each trait to three industry references.
This is a pure projection layer (`skilltotal/traits.py`), exactly like `capabilities.py` and
`owasp.py`: no new detection, no execution, no re-scan. Traits are surfaced in the report's
`traits[]` array (report schema ≥ 1.5).

## Why traits (vs. a flat findings list)

A findings list answers "which dangerous APIs are present?". A trait fingerprint answers "what
behavioral characteristics does this component exhibit, and which *combinations* create emergent
risk?" — the framing of the Cloud Security Alliance's *Secure Agentic System Design: A
Trait-Based Approach*. Traits give the report a compact, classification-grade shape that speaks
the language auditors and compliance stakeholders already use.

## Invariants

- **Descriptive, never scored.** A single trait carries 0 weight (like a `Capability`). Risk
  comes only from `malicious_indicator` / `risky_construct` findings — including the *emergent*
  combination traits, which are backed by the synthesized risky-construct findings
  (`ST-COMBO-EXFIL`, `ST-FLOW-TRIFECTA`, `ST-CONVERGENCE`) that already score.
- **Component-only.** Only statically-determinable traits appear. CSA's runtime/architecture
  trait categories (Control & Orchestration, Trust models, Agent Learning, broker availability)
  require deployment context SkillTotal deliberately never inspects, so they are **not**
  represented here rather than guessed. They are a natural boundary for a future
  system-composition (hosted) analysis, not the offline component engine.
- **Honest gaps.** Where a reference has no defensible fit for a trait, the field is empty — a
  mapping is never forced. MAESTRO layers for Tool-Usage-derived traits (L3/L4) are a documented
  SkillTotal extension: the CSA MAESTRO mapping table covered 6 of its 7 trait categories and
  omitted Tool Usage.

## The taxonomy

`emergent = yes` marks a combination trait (backed by a synthesized risky-construct finding);
all others are single-behavior traits. MAESTRO layers reference the CSA MAESTRO framework; ATLAS
tactics reference MITRE ATLAS.

The three CSA **Tool Execution Context** traits form a blast-radius spectrum — how a component
authenticates its tool calls, from largest to smallest blast radius: `embedded_credential` (Agent
Service Identity — a long-lived static secret) → `delegated_authentication` (User Delegated
Credentials — scoped to the end user) → `scoped_identity` (Least-Privilege Service Identity — a
short-lived, assumed, narrowly-scoped credential).

| Trait | Emergent | CSA trait | CSA named risk | MAESTRO layer(s) | MITRE ATLAS tactic(s) |
|-------|----------|-----------|----------------|------------------|-----------------------|
| `tool_surface` | no | Tool Usage | Uncontrolled tool selection and sequencing | L3 Agent Frameworks, L4 Deployment & Infrastructure | - |
| `execution_authority` | no | Tool Access Control / Direct Tool Access | Excessive ambient authority; uncontrolled tool selection and sequencing | L3 Agent Frameworks, L4 Deployment & Infrastructure | - |
| `filesystem_reach` | no | Tool Execution Context | Excessive ambient authority (blast radius on compromise) | L4 Deployment & Infrastructure | - |
| `network_egress` | no | Interaction & Communication / Direct Communication | Amplified impact of trust exploitation in direct channels | L5 Evaluation & Observability, L7 Agent Ecosystem | - |
| `network_exposure` | no | Interaction & Communication | Unauthorized or unintended access & data leakage | L4 Deployment & Infrastructure, L7 Agent Ecosystem | - |
| `embedded_credential` | no | Tool Execution Context / Agent Service Identity | Insufficient permission granularity; credential rotation complexity | L4 Deployment & Infrastructure, L6 Security & Compliance | - |
| `delegated_authentication` | no | Tool Execution Context / User Delegated Credentials | Access-control boundary confusion (agent-level vs user-level operations) | L4 Deployment & Infrastructure, L6 Security & Compliance | - |
| `scoped_identity` | no | Tool Execution Context / Least-Privilege Service Identity | Agent proliferation / permission sprawl if scopes are not curated | L4 Deployment & Infrastructure, L6 Security & Compliance | - |
| `untrusted_perception` | no | Perception & Context / Contextual Perception | Context manipulation and poisoning | L2 Data Operations, L5 Evaluation & Observability | Adversarial Perception Attacks, Model Poisoning |
| `metadata_integrity` | no | Trust / Tool Poisoning | Trust inheritance through data | L6 Security & Compliance, L7 Agent Ecosystem | - |
| `supply_chain_provenance` | no | General Protections / Supply Chain | Supply-chain compromise via install-time execution or name confusion | L4 Deployment & Infrastructure | - |
| `unsafe_deserialization` | no | General Protections / Input Validation | Untrusted input driving code execution on deserialization | L2 Data Operations | - |
| `code_obfuscation` | no | General Protections / Explainability | Opaque payloads defeating review and detection | L5 Evaluation & Observability | - |
| `exfil_correlation` | yes | Tool Access Control / Broker-Mediated Access | Cross-request correlation blindness (read sensitive data then external comms) | L5 Evaluation & Observability | Exfiltration |
| `instruction_exfil_flow` | yes | Perception & Context + Tool Access Control | Context manipulation escalated through tool egress | L2 Data Operations, L5 Evaluation & Observability | Adversarial Perception Attacks, Exfiltration |
| `malware_convergence` | yes | General Protections / Anomaly Detection | Convergent malicious behavior across independent indicators | L5 Evaluation & Observability | - |

## Adding or changing a trait

`TRAIT_BY_RULE` in `skilltotal/traits.py` must have an entry for **every** rule id — the
completeness test (`tests/test_traits.py::test_every_rule_has_an_explicit_trait_decision`)
fails CI otherwise, so a new detection rule forces a deliberate trait decision (a trait tuple or
an explicit empty tuple). Every `ComponentTrait` must have a `TRAIT_CROSSWALK` entry with valid
MAESTRO layer keys. Because `traits[]` is part of the versioned report contract, adding a trait
field or changing the shape requires a `REPORT_SCHEMA_VERSION` bump and a `report.schema.json`
update (see [releasing.md](releasing.md)); adding a new trait *value* under the existing shape
does not.
