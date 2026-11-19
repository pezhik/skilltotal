"""Package-name typosquatting heuristic (npm / PyPI).

Flags a package whose name is one or two character edits away from a well-known popular package —
the classic supply-chain attack where a malicious package impersonates a trusted one
(``lodash`` -> ``loddash``, ``requests`` -> ``requets``). Like ``ST-SKILL-CAP-MISMATCH`` this is a
synthesized finding (see :mod:`skilltotal.engine`) keyed off the component *identity*, not file
content: deterministic, stdlib-only, no LLM, no execution. Evidence is anchored to the ``name``
declaration in the package manifest (``package.json``; ``pyproject.toml`` / ``setup.py``, else the
core metadata of an sdist's ``PKG-INFO`` or a wheel's ``*.dist-info/METADATA``) so the "no finding
without evidence" invariant holds.

Conservative on purpose (to keep false positives at zero on benign corpora): exact matches, popular
look-alikes (``_KNOWN_LEGIT_*``) and scoped npm names are never flagged, short names are skipped,
and the edit-distance threshold is tight. The finding interprets the resemblance only — it never
asserts the package *is* malicious.
"""

from __future__ import annotations

import re

from skilltotal.file_index import FileIndex, IndexedFile
from skilltotal.models import Component, Evidence, Finding, Severity, ThreatClass
from skilltotal.text_normalize import normalize_with_map

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
    "jsonschema", "pyjwt", "oauthlib", "authlib", "pynacl", "anyio", "sniffio", "websockets",
    "grpcio", "protobuf",
    "tensorflow", "torch", "scikit-learn", "keras", "transformers", "nltk", "spacy",
    "opencv-python", "seaborn", "plotly", "statsmodels", "sympy", "networkx", "joblib",
    "markdown", "sphinx", "pygments", "paramiko", "ansible", "openai", "anthropic", "langchain",
)


# Well-known packages that sit within the edit threshold of a name above but are popular projects in
# their own right: `vitest` is not a misspelt `vite`, `scapy` is not a misspelt `scipy`. They are
# exempt (never flagged), and are not themselves targets. Derived, not hand-picked: every name in
# the 10,000 most-downloaded packages of each registry (npm: npm-high-impact `topDownload`; PyPI:
# hugovk/top-pypi-packages; 2026-10 snapshots) that the heuristic would otherwise flag. A real
# typosquat cannot take one of these names: they are registered to the projects listed here.
# Refresh alongside the popular lists.
_KNOWN_LEGIT_NPM_RAW = (
    "color", "color2k", "colord", "commondir", "corser", "crypt", "crypto", "cypress", "dargs",
    "dashify", "enquirer", "esquery", "for-in", "format", "gaxios", "getenv", "global", "globby",
    "jshint", "keypress", "minimisted", "mquery", "mssql", "node-watch", "opener", "otplib",
    "oxlint", "preact", "prismjs", "radash", "rcedit", "react-dnd", "recast", "rehackt",
    "scrypt-js", "shimmer", "tslint", "uuidv7", "vitefu", "vitest",
)
_KNOWN_LEGIT_PYPI_RAW = (
    "aerich", "aioftp", "astrapy", "beaker", "beautifulsoup", "blake3", "bleach", "botorch",
    "cattrs", "certipy", "coredis", "cpplint", "crick", "darker", "djangoql", "djlint", "dydantic",
    "enrich", "fasta2a", "fastai", "fastar", "gradio", "grequests", "grpclib", "hiredis",
    "httpie", "httpr", "httpx2", "hyper", "itypes", "jaxlib", "manygo", "markdown2", "markitdown",
    "moocore", "moyopy", "nbsphinx", "niquests", "numpyro", "open3d", "opencc", "opendal",
    "openlit", "openmim", "openmm", "p-tqdm", "panda3d", "pandasql", "pandoc", "pathlib",
    "pottery", "psycopg", "psycopg-binary", "psycopg-c", "pyaml", "pygame", "pyjsparser",
    "pylama", "pynini", "pynvml", "pyperf", "pyqwest", "pyrect", "pysaml2", "pyshacl", "pytoml",
    "pytorch", "redfish", "redisvl", "rtoml", "ruyaml", "scanpy", "scapy", "scramp", "scrypt",
    "segments", "shyaml", "simpy", "sodapy", "spaces", "splink", "stqdm", "stumpy", "syrupy",
    "tablib", "tclint", "tcmlib", "tensorflowjs", "tombi", "tomli-w", "tomlkit", "tomlrt",
    "torchao", "torchax", "torchx", "typepy", "unicon", "unicorn", "usort", "vastai", "vyper",
    "willow", "x-transformers", "xoto3",
)


def _canon_pypi(s: str) -> str:
    """PEP 503-style canonical name: lowercase with runs of ``-_.`` collapsed to a single ``-``."""
    return re.sub(r"[-_.]+", "-", s.strip().lower())


def _canon_npm(s: str) -> str:
    return s.strip().lower()


_POPULAR_NPM = frozenset(_canon_npm(x) for x in _NPM_RAW)
_POPULAR_PYPI = frozenset(_canon_pypi(x) for x in _PYPI_RAW)
_KNOWN_LEGIT_NPM = frozenset(_canon_npm(x) for x in _KNOWN_LEGIT_NPM_RAW)
_KNOWN_LEGIT_PYPI = frozenset(_canon_pypi(x) for x in _KNOWN_LEGIT_PYPI_RAW)


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


# --- A name the component depends on or launches -------------------------------------------------
# The component's own name is judged by edit distance, against the look-alikes of the 10,000
# most-downloaded packages. A DEPENDENCY can be any of millions of names, and honest packages sit
# one edit from a popular one (`graphiql`, `pedantic`, `reactn`, `expresso`, `ptest`). So a
# dependency is flagged only for the ways a name is mistyped or disguised, never for a plain
# substitution, a letter added or dropped at either end, or a new letter in the middle:
#   swapped letters      axois, loadsh, reqeusts
#   doubled or undoubled fetchh, expres, pilow
#   a dropped inner letter of a long name   mongose, colorma
#   digits or letter pairs that read as letters   requ3sts, l0dash, rnongoose, nurnpy
#   look-alike or invisible characters     a Cyrillic letter, a zero-width space
#   separators           crossenv for cross-env
# Popular names that are dependency or launch targets but not in the lists above (adding them
# there would change the own-name check, whose exemptions were derived for those lists).
_DEPENDENCY_ONLY_NPM = ("electron", "mcp-remote", "supergateway", "puppeteer", "playwright")
_DEPENDENCY_ONLY_PYPI = (
    "python-dotenv", "fastmcp", "mcp-server-fetch", "mcp-server-git", "mcp-server-time",
    "mcp-server-sqlite",
)
# npm scopes that are imitated (`@modelcontextprotocoI/...`). A name INSIDE a real scope cannot be
# squatted, so only the scope is compared.
_KNOWN_SCOPES = ("modelcontextprotocol", "anthropic-ai", "aws-sdk", "google-cloud")
_TARGETS = {
    "npm": frozenset(p for p in (*_POPULAR_NPM, *_DEPENDENCY_ONLY_NPM) if len(p) >= 5),
    "pypi": frozenset(
        p for p in (*_POPULAR_PYPI, *(_canon_pypi(x) for x in _DEPENDENCY_ONLY_PYPI))
        if len(p) >= 5
    ),
}
_NOT_A_SQUAT = {
    "npm": _POPULAR_NPM | _KNOWN_LEGIT_NPM | frozenset(_DEPENDENCY_ONLY_NPM),
    "pypi": _POPULAR_PYPI | _KNOWN_LEGIT_PYPI
    | frozenset(_canon_pypi(x) for x in _DEPENDENCY_ONLY_PYPI),
}
_DIGIT_LETTERS = str.maketrans({"0": "o", "1": "l", "3": "e", "4": "a", "5": "s", "7": "t"})
_SEPARATORS = re.compile(r"[-_.]")
_MAX_DEPENDENCY_NAME = 80


def _one_edit_typo(name: str, target: str) -> str | None:
    """How ``name`` mistypes ``target`` in one keystroke, or None (see the list above)."""
    ln, lt = len(name), len(target)
    if ln == lt:
        diff = [i for i in range(ln) if name[i] != target[i]]
        if (len(diff) == 2 and diff[1] == diff[0] + 1
                and name[diff[0]] == target[diff[1]] and name[diff[1]] == target[diff[0]]):
            return "two letters swapped"
        return None
    longer, shorter = (name, target) if ln > lt else (target, name)
    if len(longer) != len(shorter) + 1:
        return None
    i = 0
    while i < len(shorter) and longer[i] == shorter[i]:
        i += 1
    if longer[i + 1:] != shorter[i:]:
        return None
    doubled = (i > 0 and longer[i] == longer[i - 1]) or (
        i + 1 < len(longer) and longer[i] == longer[i + 1]
    )
    if ln > lt:
        return "a letter doubled" if doubled else None
    if doubled and lt >= 6:
        return "a doubled letter written once"
    if lt >= 7 and 0 < i < lt - 1:
        return "a letter left out"
    return None


def _disguised_as(name: str, targets: frozenset[str]) -> tuple[str, str] | None:
    """A popular name that ``name`` reads as once its digits, letter pairs or look-alike
    characters are read the way the eye reads them."""
    if not name.isascii():
        plain = normalize_with_map(name)[0].lower()
        if plain != name and plain in targets:
            return plain, "look-alike or invisible characters"
        name = plain
    variants = {name.translate(_DIGIT_LETTERS), name.replace("1", "i").translate(_DIGIT_LETTERS)}
    for v in tuple(variants):
        variants.add(v.replace("rn", "m"))
        variants.add(v.replace("vv", "w"))
    variants.discard(name)
    for v in sorted(variants):
        if v in targets:
            return v, "digits or letter pairs that read as its letters"
    return None


def name_lookalike(raw: str, ecosystem: str) -> tuple[str, str] | None:
    """``(popular name, how)`` when a dependency or launched package is written like a popular
    package and is not one; ``ecosystem`` is ``"npm"`` or ``"pypi"``. See the block comment for
    what counts. A scoped npm name is compared by its scope only."""
    raw = raw.strip()
    if not raw or len(raw) > _MAX_DEPENDENCY_NAME:
        return None
    if ecosystem == "npm" and raw.startswith("@"):
        scope = raw[1:].split("/", 1)[0]
        # `I` for `l` only shows before the name is lower-cased.
        candidates = {scope.lower(), scope.replace("I", "l").lower()}
        if candidates & set(_KNOWN_SCOPES):
            return (None if scope.lower() in _KNOWN_SCOPES
                    else ("@" + scope.replace("I", "l").lower(), "a capital I for a small l"))
        for known in _KNOWN_SCOPES:
            for candidate in candidates:
                how = _one_edit_typo(candidate, known)
                if how:
                    return "@" + known, how
        found = _disguised_as(scope.lower(), frozenset(_KNOWN_SCOPES))
        return ("@" + found[0], found[1]) if found else None
    canon = _canon_pypi if ecosystem == "pypi" else _canon_npm
    name = canon(raw)
    targets, known = _TARGETS[ecosystem], _NOT_A_SQUAT[ecosystem]
    if len(name) < 5 or name in known:
        return None
    found = _disguised_as(name, targets)
    if found:
        return found
    if not name.isascii():
        return None
    for target in sorted(targets):
        if abs(len(target) - len(name)) > 1:
            continue
        how = _one_edit_typo(name, target)
        if how:
            return target, how
    bare = _SEPARATORS.sub("", name)
    british = name.replace("colour", "color")
    for target in sorted(targets):
        if bare == _SEPARATORS.sub("", target):
            return target, "the same letters with other separators"
        if british != name and british == target:
            return target, "another spelling of the same word"
    return None


# --- A well-known name aliased to another package ------------------------------------------------
# `"express": "npm:<other>@4"` installs <other> under the name `express`: the code and its reviewer
# read `require("express")` and something else answers. Aliases are honest far more often than not,
# and the honest ones say what they are: the same package at another version (`react-17:
# npm:react@17`), a fork under a scope (`npm:@acme/node-fetch`), a build of the same project whose
# name carries the original's (`lodash-es`, `rolldown-vite`, `wp-prettier`, `preact-compat`), or
# another well-known package (`underscore` -> `lodash`). What is left is a well-known name that
# stands for an unscoped package named after something else.
# Drop-in replacements that do not carry the original's name and are not in the lists above.
_KNOWN_REPLACEMENTS = frozenset({
    "inferno-compat", "nervjs", "anujs", "es-toolkit", "undici", "picocolors", "tinyglobby",
    "zepto", "cash-dom", "luxon", "ky", "got", "bun-types",
})
_ALIASED_NAMES = _POPULAR_NPM | frozenset(_DEPENDENCY_ONLY_NPM)
_NAME_WORD = re.compile(r"[a-z0-9]{3,}")


def alias_replaces_known_name(name: str, target: str) -> bool:
    """Whether the npm alias ``"name": "npm:target@..."`` puts an unrelated package behind a
    well-known name (see above). ``target`` is the package name without its version."""
    key, other = _canon_npm(name), _canon_npm(target)
    if key not in _ALIASED_NAMES or not other or len(other) > _MAX_DEPENDENCY_NAME:
        return False
    if other.startswith("@") or other in _NOT_A_SQUAT["npm"] or other in _KNOWN_REPLACEMENTS:
        return False
    bare_key, bare_other = _SEPARATORS.sub("", key), _SEPARATORS.sub("", other)
    if bare_key in bare_other or bare_other in bare_key:
        return False
    # A word of the name inside the other name: `react-dom` -> `preact-compat`.
    return not any(word in bare_other for word in _NAME_WORD.findall(key))


def package_name_typosquatting(component: Component, index: FileIndex) -> Finding | None:
    """Synthesize ST-TYPOSQUAT when an npm/PyPI package name closely resembles a popular package."""
    if component.type == "npm_package":
        popular, legit, canon, eco = _POPULAR_NPM, _KNOWN_LEGIT_NPM, _canon_npm, "npm"
    elif component.type == "python_package":
        popular, legit, canon, eco = _POPULAR_PYPI, _KNOWN_LEGIT_PYPI, _canon_pypi, "PyPI"
    else:
        return None

    raw = (component.name or "").strip()
    if not raw or raw.startswith("@"):
        return None  # scoped npm names are namespace-protected — not a typosquat surface
    norm = canon(raw)
    if len(norm) < 5 or norm in popular or norm in legit:
        return None  # too short to disambiguate, or it IS a known package (target or look-alike)

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
            "the resemblance only - confirm the publisher and source are who you expect."
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


def _wheel_metadata(index: FileIndex) -> IndexedFile | None:
    """A wheel's ``<name>-<version>.dist-info/METADATA``; a wheel has no pyproject.toml/setup.py."""
    for f in index.files:
        parts = f.relpath.split("/")
        if len(parts) == 2 and parts[0].lower().endswith(".dist-info") and parts[1] == "METADATA":
            return f
    return None


_NPM_NAME = re.compile(r'"name"\s*:\s*"([^"]*)"')
# `[^\S\n]*`, not `\s*`: from each of many blank lines `^\s*` ran over all the rest (quadratic).
_PY_MANIFEST_NAME = re.compile(r'(?im)^[^\S\n]*name\s*[=:]\s*["\']([^"\']*)["\']')
# Core metadata (an sdist's PKG-INFO, a wheel's METADATA): an RFC 822 `Name:` header.
_CORE_METADATA_NAME = re.compile(r"(?m)^Name:[ \t]*(\S+)[ \t]*\r?$")


def _name_evidence(index: FileIndex, ctype: str, raw: str) -> Evidence | None:
    """Anchor evidence to the ``name`` declaration in the package manifest.

    PyPI: ``pyproject.toml`` / ``setup.py`` when they declare it, else the core metadata every
    distribution carries (an sdist's root ``PKG-INFO``, a wheel's ``*.dist-info/METADATA``).
    """
    if ctype == "npm_package":
        candidates = [(_root_file(index, ("package.json",)), _NPM_NAME)]
    else:
        candidates = [
            (_root_file(index, ("pyproject.toml",)), _PY_MANIFEST_NAME),
            (_root_file(index, ("setup.py",)), _PY_MANIFEST_NAME),
            (_root_file(index, ("PKG-INFO",)), _CORE_METADATA_NAME),
            (_wheel_metadata(index), _CORE_METADATA_NAME),
        ]
    present = [(f, pat) for f, pat in candidates if f is not None]
    for manifest, pat in present:
        m = pat.search(manifest.text)
        if m:
            return manifest.evidence_for_span(m.start(1), m.end(1))
    return present[0][0].evidence_for_lines(1, 1) if present else None
