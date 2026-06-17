"""SkillTotal — AI Component Security Platform (core engine).

This package is the reusable core engine. Everything here is import-safe and free of
process-level side effects (no printing, no ``sys.exit``) *except* :mod:`skilltotal.cli`,
which is the thin I/O shell. Future web and enterprise products are intended to import
:func:`skilltotal.engine.analyze` directly.
"""

from skilltotal.models import (
    Capability,
    Component,
    Evidence,
    Finding,
    NeedsReview,
    Report,
    RiskLevel,
    Severity,
)

# --- Versioned contract (consumed by downstream products such as the web app) -----------
# ENGINE_VERSION: semver of the code / public API; pin this from a consumer.
# REPORT_SCHEMA_VERSION: shape of Report.to_dict(); bumps only on schema changes.
# RULESET_VERSION: integer counter of the detection ruleset; bumps when rules change, so a
#   consumer knows when re-scanning old reports may surface new findings.
__version__ = "0.16.6"
ENGINE_VERSION = __version__
REPORT_SCHEMA_VERSION = "1.3"
RULESET_VERSION = 17

__all__ = [
    "__version__",
    "ENGINE_VERSION",
    "REPORT_SCHEMA_VERSION",
    "RULESET_VERSION",
    "Capability",
    "Component",
    "Evidence",
    "Finding",
    "NeedsReview",
    "Report",
    "RiskLevel",
    "Severity",
]
