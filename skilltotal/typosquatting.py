"""Package-name typosquatting heuristic (npm / PyPI).

Flags a package whose name is one or two character edits away from a well-known popular package —
the classic supply-chain attack where a malicious package impersonates a trusted one
(``lodash`` -> ``loddash``, ``requests`` -> ``requets``). Like ``ST-SKILL-CAP-MISMATCH`` this is a
synthesized finding (see :mod:`skilltotal.engine`) keyed off the component *identity*, not file
content: deterministic, stdlib-only, no LLM, no execution. Evidence is anchored to the ``name``
declaration in the package manifest so the "no finding without evidence" invariant holds.

Conservative on purpose (to keep false positives at zero on benign corpora): exact matches and
scoped npm names are never flagged, short names are skipped, and the edit-distance threshold is
tight. The finding interprets the resemblance only — it never asserts the package *is* malicious.
"""

from __future__ import annotations

import re

from skilltotal.file_index import FileIndex, IndexedFile
from skilltotal.models import Component, Evidence, Finding, Severity, ThreatClass

TYPOSQUAT_FINDING_ID = "ST-TYPOSQUAT"

# Most-downloaded / most-typosquatted packages per ecosystem. A scanned package that exactly
# matches one of these is the real thing and is never flagged; a near-miss is. Curated, not
# exhaustive — refreshed alongside RULESET_VERSION. Stored canonicalized (see _canon_*).
_NPM_RAW = (
    "react", "react-dom", "react-router", "react-router-dom", "react-redux", "redux", "lodash",
    "axios", "express", "chalk", "commander", "debug", "request", "async", "moment", "vue",
    "webpack", "webpack-cli", "babel-core", "typescript", "eslint", "prettier", "jest", "mocha",
    "chai", "dotenv", "uuid", "classnames", "rxjs", "next", "jquery", "bootstrap", "underscore",
    "bluebird", "node-fetch", "cross-env", "rimraf", "glob", "semver", "yargs", "inquirer",
    "colors", "minimist", "body-parser", "cors", "mongoose", "ws", "ejs", "pug", "handlebars",
    "nodemon", "ts-node", "styled-components", "formik", "yup", "zod", "dayjs", "date-fns",
    "immer", "mobx", "tailwindcss", "postcss", "autoprefixer", "sass", "vite", "rollup", "esbuild",
    "jsonwebtoken", "bcrypt", "bcryptjs", "passport", "helmet", "morgan", "winston", "pino",
    "nodemailer", "sharp", "multer", "sequelize", "typeorm", "prisma", "knex", "mysql", "mysql2",
    "redis", "ioredis", "mongodb", "joi", "ajv", "fastify", "koa", "graphql", "react-query",
    "three", "chart.js", "prop-types", "core-js", "tslib", "openai", "anthropic", "langchain",
)
_PYPI_RAW = (
    "requests", "urllib3", "setuptools", "certifi", "charset-normalizer", "idna", "six",
    "python-dateutil", "numpy", "pandas", "boto3", "botocore", "pyyaml", "click", "flask",
    "django", "jinja2", "markupsafe", "werkzeug", "itsdangerous", "sqlalchemy", "wheel",
    "packaging", "attrs", "pytz", "cryptography", "cffi", "pycparser", "scipy", "matplotlib",
    "pillow", "fastapi", "pydantic", "starlette", "uvicorn", "gunicorn", "celery", "redis",
    "pymongo", "psycopg2", "psycopg2-binary", "aiohttp", "httpx", "beautifulsoup4", "lxml",
    "scrapy", "selenium", "openpyxl", "tqdm", "colorama", "rich", "typer", "pytest", "tox",
    "coverage", "faker", "hypothesis", "black", "flake8", "mypy", "pylint", "isort", "bandit",
    "pre-commit", "virtualenv", "poetry", "twine", "wrapt", "decorator", "toml", "tomli",
    "jsonschema", "pyjwt", "oauthlib", "anyio", "sniffio", "websockets", "grpcio", "protobuf",
    "tensorflow", "torch", "scikit-learn", "keras", "transformers", "nltk", "spacy",
    "opencv-python", "seaborn", "plotly", "statsmodels", "sympy", "networkx", "joblib",
    "markdown", "sphinx", "pygments", "paramiko", "ansible", "openai", "anthropic", "langchain",
)


def _canon_pypi(s: str) -> str:
    """PEP 503-style canonical name: lowercase with runs of ``-_.`` collapsed to a single ``-``."""
    return re.sub(r"[-_.]+", "-", s.strip().lower())


def _canon_npm(s: str) -> str:
    return s.strip().lower()


_POPULAR_NPM = frozenset(_canon_npm(x) for x in _NPM_RAW)
_POPULAR_PYPI = frozenset(_canon_pypi(x) for x in _PYPI_RAW)


def _levenshtein(a: str, b: str, max_d: int) -> int | None:
    """Levenshtein edit distance, bounded: returns the distance if ``<= max_d`` else ``None``."""
    la, lb = len(a), len(b)
    if abs(la - lb) > max_d:
        return None
    prev = list(range(lb + 1))
    for i in range(1, la + 1):
        cur = [i] + [0] * lb
        row_min = cur[0]
        ca = a[i - 1]
        for j in range(1, lb + 1):
            cost = 0 if ca == b[j - 1] else 1
            cur[j] = min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + cost)
            if cur[j] < row_min:
                row_min = cur[j]
        if row_min > max_d:
            return None
        prev = cur
    return prev[lb] if prev[lb] <= max_d else None


def package_name_typosquatting(component: Component, index: FileIndex) -> Finding | None:
    """Synthesize ST-TYPOSQUAT when an npm/PyPI package name closely resembles a popular package."""
    if component.type == "npm_package":
        popular, canon, eco = _POPULAR_NPM, _canon_npm, "npm"
    elif component.type == "python_package":
        popular, canon, eco = _POPULAR_PYPI, _canon_pypi, "PyPI"
    else:
        return None

    raw = (component.name or "").strip()
    if not raw or raw.startswith("@"):
        return None  # scoped npm names are namespace-protected — not a typosquat surface
    norm = canon(raw)
    if len(norm) < 5 or norm in popular:
        return None  # too short to disambiguate, or it IS the known package

    best: str | None = None
    best_d = 99
    for p in popular:
        d = _levenshtein(norm, p, max_d=2)
        if d is not None and 1 <= d < best_d:
            best, best_d = p, d
            if best_d == 1:
                break
    if best is None or (best_d == 2 and len(norm) < 6):
        return None  # nothing close, or an extra-conservative cutoff for shorter names

    ev = _name_evidence(index, component.type, raw)
    if ev is None:
        return None  # cannot anchor evidence -> never emit an un-evidenced Finding

    return Finding(
        id=TYPOSQUAT_FINDING_ID,
        severity=Severity.HIGH,
        category="supply_chain",
        title="Package name closely resembles a popular package (possible typosquatting)",
        description=(
            f"The {eco} package name '{raw}' is within {best_d} character edit(s) of the "
            f"widely-used package '{best}'. Name confusion (typosquatting) is a common "
            "supply-chain attack where a malicious package impersonates a trusted one. This flags "
            "the resemblance only — confirm the publisher and source are who you expect."
        ),
        evidence=[ev],
        recommendation=(
            "Confirm you are installing the intended package (exact name, publisher, repository). "
            "If you meant the popular package, fix the name; if this is a deliberate fork, "
            "document it."
        ),
        threat_class=ThreatClass.RISKY_CONSTRUCT,
    )


def _root_file(index: FileIndex, names: tuple[str, ...]) -> IndexedFile | None:
    """First root-level file matching one of ``names`` (case-insensitive), in priority order."""
    for want in names:
        for f in index.files:
            if "/" not in f.relpath and f.relpath.lower() == want.lower():
                return f
    return None


def _name_evidence(index: FileIndex, ctype: str, raw: str) -> Evidence | None:
    """Anchor evidence to the ``name`` declaration in the package manifest."""
    if ctype == "npm_package":
        manifest = _root_file(index, ("package.json",))
        pat = r'"name"\s*:\s*"([^"]*)"'
    else:
        manifest = _root_file(index, ("pyproject.toml", "setup.py"))
        pat = r'(?im)^\s*name\s*[=:]\s*["\']([^"\']*)["\']'
    if manifest is None:
        return None
    m = re.search(pat, manifest.text)
    if m:
        return manifest.evidence_for_span(m.start(1), m.end(1))
    return manifest.evidence_for_lines(1, 1)
