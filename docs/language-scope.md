# Language scope — what the engine analyzes, and the known gaps

SkillTotal is a **zero-dependency** static analyzer (Python stdlib only). Python ships an `ast`
parser in the stdlib; no other language does. So detection depth varies by language, and this page
states the boundary honestly rather than implying uniform coverage. See `docs/efficacy-report.md`
for the measured recall/precision and the per-language coverage matrix.

## In scope (semantic / high-confidence)

| Language | How | What is detected |
|---|---|---|
| **Python** (`.py`) | AST (`python_ast.py`) — alias/`from`-import aware, read-vs-write aware | shell/process exec, filesystem read/write, network egress, dynamic `eval`/`exec`/`compile`, unsafe deserialization, decode-and-exec, sensitive-path arguments, untrusted-input → exec/shell taint |
| **Node / TypeScript** (`.js`/`.mjs`/`.cjs`/`.jsx`/`.ts`/`.tsx`) | declarative regex scanners | `child_process`/exec libs, `fs` read/write, `fetch`/axios/http/mailers, `eval`/`Function`/`vm`, command injection, npm lifecycle hooks |
| **Shell** (`.sh`/`.bash`/`.zsh`) | regex scanners | `base64 -d \| bash`, `curl\|wget \| sh`, decode-and-exec, defense-evasion idioms |
| **MCP manifests** (JSON) + **agent instruction surfaces** (`SKILL.md`/`AGENTS.md`) | JSON + markdown parsing | dangerous tools, server exec, tool poisoning/shadowing, auto-approve, over-broad scope, prompt injection |

## Cross-language (apply to every file regardless of language)

Sensitive-path references, embedded secrets (known-prefix tokens / private keys), obfuscation
heuristics (base64/hex blobs, minification), hidden/deceptive Unicode (Trojan-Source / ASCII
smuggling), prompt-injection phrasing (de-obfuscated first), `.pth` startup persistence,
encrypted-archive staging, and package-name typosquatting (npm/PyPI identity).

## Deferred — known gap (NOT yet detected)

There is **no semantic exec / network / filesystem / deserialization / command-injection
detection** for **Go, Rust, Java, Ruby, PHP, C/C++**. Only the cross-language signals above apply
to them today. Concretely, a credential stealer written purely in, say, Go (`os/exec` +
`net/http`) or a Java `ObjectInputStream` deserialization sink would currently be flagged only if
it also trips a cross-language signal (a sensitive path, an embedded secret, obfuscation, a hidden
Unicode payload, a poisoned manifest, a typosquat name) — the language-specific exec/egress would
be missed, and the synthesized exfil combos (`ST-COMBO-EXFIL`, `ST-FLOW-TRIFECTA`) would not fire.

The coverage matrix in `docs/efficacy-report.md` shows these languages with their real (often
zero) positive-sample counts rather than hiding the gap.

**Why deferred:** a faithful semantic analyzer for these languages needs a real parser, which the
zero-dependency constraint rules out (Python’s is the only stdlib parser). The realistic path is
regex-based heuristic scanners mirroring the Node.js ones — tractable but a deliberate, separately
calibrated effort, not a quiet add-on.

## Roadmap (free OSS) + SkillTotal Cloud depth (paid)

Per the open-core boundary (`docs/open-core.md`), **all detection rules stay in the free OSS
engine** — so the language work below is OSS. The paid **SkillTotal Cloud** layer sits *above*
detection (deeper analysis and interpretation), it does not gate basic detection.

**Free OSS engine — basic multi-language detection (planned):**
1. Regex-based exec/network/deserialization scanners for **Go, Rust, Java** (the main non-Python/
   non-Node AI-component languages), mirroring the Node.js scanner pattern, so the exfil combos can
   fire there too. Java `ObjectInputStream` deserialization is the highest-priority single sink.
2. Then **Ruby, PHP**.
3. Each language ships with its own positive/negative samples in `tests/eval_corpus/` and must hold
   the recall floor (`tests/test_efficacy_floor.py`) and the false-positive floor before release.

**SkillTotal Cloud (paid) — multi-language depth, above the free detector:** cross-language
semantic / dataflow taint analysis, sandbox-confirmed exploitability of a flagged sink, and
interpretation/prioritization of multi-language findings. This is the “WHY it matters / WHAT
HAPPENS WHEN RUN” layer — a Cloud differentiator that never removes detection from the OSS engine.
