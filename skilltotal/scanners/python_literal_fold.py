"""Commands and code a Python file decodes from its own literals before running them.

``os.system(base64.b64decode("...").decode())``, ``os.popen("".join(chr(x) for x in [...]))``,
``subprocess.run(_dec([46, 70, ...]), shell=True)`` with a repeating-key XOR helper, and
``exec(payload[::-1])`` all hand a sink a text that is fully determined by literals in the file but
never written out in it. The folder below computes that text the way a reader with a pencil would:
it evaluates constants, concatenation, slices, ``chr``/``ord``, integer arithmetic, the standard
decoders, comprehensions over literal sequences and calls of small local helper functions. Nothing
of the analyzed file is executed or imported: only this module's own arithmetic runs, under a step
budget and a size cap.

A sink is reported only when its argument folds completely AND a decoding step was needed to get
there (XOR, character codes, a reversed string, base64/hex/rot13/zlib). A plain constant, a joined
argv or an f-string of literals is how honest code spells a command and is not reported here.
"""

from __future__ import annotations

import ast
import base64
import binascii
import codecs
import re
import zlib
from collections.abc import Callable

from skilltotal.file_index import IndexedFile
from skilltotal.models import Evidence
from skilltotal.scanners.base import MAX_EVIDENCE_SCANNED
from skilltotal.scanners.python_ast import (
    ALWAYS_SHELL_CALLS,
    _CallVisitor,
    _command_arg,
    _is_dynamic_builtin_call,
    _scope_assignments,
    _shell_true,
    walk_deep,
)

SINK_SHELL = "shell"
SINK_EXEC = "exec"

# One file's folding work in total, and the largest value it may build. A literal the size of a
# real payload folds in a few thousand steps; a file made to burn time stops here.
_MAX_STEPS = 60_000
_MAX_LEN = 100_000
_MAX_DEPTH = 24
_MAX_INT_BITS = 64
# How many character-code or XOR operations, and how long a reversed or decoded text, make a
# value "decoded" rather than spelled: `chr(10)` in a command line is a newline, not a disguise.
_MIN_CODE_OPS = 4
_MIN_DECODED_LEN = 6

_Value = str | bytes | int | list

# Cheap text gate: a file is parsed a second time only when it holds both a sink that is given
# something other than a string literal and a decoding step. Most files hold neither; parsing
# every file that merely names `subprocess` cost as much as the Python scanner itself.
_SINK_GATE = re.compile(
    # Called with something other than one string literal, or named without a call
    # (`run = os.system`).
    r"\b(?:exec|eval|system|popen|getoutput|getstatusoutput)\b"
    r"(?!\s*\(\s*[rbuRBU]{0,2}(?:\"[^\"\\\n]{0,400}\"|'[^'\\\n]{0,400}')\s*[,)])"
    r"|\bshell\s*=\s*True\b"
)
# An XOR is an operator between two values (`b ^ KEY`), which a `^` inside a regular expression
# (`"^abc"`, `[^x]`, `a|^b`) is not.
_DECODE_GATE = re.compile(
    r"\bchr\b|[\w\])]\s*\^\s*[\w(]|\[\s*::\s*-1\s*\]|\breversed\s*\("
    r"|b(?:16|32|64|85)decode|a85decode|fromhex|unhexlify|a2b_|rot_?13|decompress"
)

_B64 = {
    "base64.b64decode": base64.b64decode,
    "base64.standard_b64decode": base64.b64decode,
    "base64.urlsafe_b64decode": base64.urlsafe_b64decode,
    "base64.b32decode": base64.b32decode,
    "base64.b16decode": base64.b16decode,
    "base64.b85decode": base64.b85decode,
    "base64.a85decode": base64.a85decode,
    "binascii.unhexlify": binascii.unhexlify,
    "binascii.a2b_hex": binascii.unhexlify,
    "binascii.a2b_base64": binascii.a2b_base64,
    "bytes.fromhex": bytes.fromhex,
    "bytearray.fromhex": bytes.fromhex,
}
_TEXT_CODECS = frozenset({"utf-8", "utf8", "ascii", "latin-1", "latin1", "utf_8"})
_STR_METHODS = frozenset({"strip", "lstrip", "rstrip", "lower", "upper"})


class _Unfoldable(Exception):
    """The expression depends on something that is not a literal of the file."""


_FOLD_ERRORS = (
    _Unfoldable, ValueError, TypeError, IndexError, KeyError, OverflowError, ZeroDivisionError,
    binascii.Error, zlib.error, RecursionError, MemoryError, LookupError,
)


class LiteralFolder:
    """Evaluates an expression built from literals. ``names`` are the names of the current scope
    that are assigned exactly once, ``functions`` the module's function definitions, ``resolve``
    turns a call target into its dotted name with import aliases applied."""

    def __init__(
        self,
        resolve: Callable[[ast.expr], str | None],
        names: dict[str, ast.expr],
        functions: dict[str, ast.FunctionDef | ast.AsyncFunctionDef],
    ) -> None:
        self._resolve = resolve
        self._names = names
        self._functions = functions
        self._steps = 0
        self._code_ops = 0
        self._decoded = False

    def fold(self, node: ast.expr) -> tuple[_Value, bool] | None:
        """The value of ``node`` and whether a decoding step produced it, or None."""
        self._code_ops = 0
        self._decoded = False
        try:
            value = self._eval(node, {}, 0)
        except _FOLD_ERRORS:
            return None
        return value, self._decoded or self._code_ops >= _MIN_CODE_OPS

    # -- evaluation ----------------------------------------------------------------------------
    def _tick(self, cost: int = 1) -> None:
        self._steps += cost
        if self._steps > _MAX_STEPS:
            raise _Unfoldable

    def _sized(self, value: _Value) -> _Value:
        if isinstance(value, int):
            if value.bit_length() > _MAX_INT_BITS:
                raise _Unfoldable
        elif len(value) > _MAX_LEN:
            raise _Unfoldable
        return value

    def _eval(self, node: ast.expr, env: dict[str, _Value], depth: int) -> _Value:
        self._tick()
        if depth > _MAX_DEPTH:
            raise _Unfoldable
        if isinstance(node, ast.Constant):
            if isinstance(node.value, bool) or not isinstance(node.value, (str, bytes, int)):
                raise _Unfoldable
            return node.value
        if isinstance(node, ast.Name):
            if node.id in env:
                return env[node.id]
            bound = self._names.get(node.id)
            if bound is None:
                raise _Unfoldable
            return self._eval(bound, {}, depth + 1)
        if isinstance(node, (ast.List, ast.Tuple)):
            return self._sized([self._eval(e, env, depth + 1) for e in node.elts])
        if isinstance(node, ast.JoinedStr):
            parts = []
            for value in node.values:
                if isinstance(value, ast.FormattedValue):
                    if value.format_spec is not None or value.conversion != -1:
                        raise _Unfoldable
                    part = self._eval(value.value, env, depth + 1)
                    if not isinstance(part, (str, int)):
                        raise _Unfoldable
                    parts.append(str(part))
                else:
                    parts.append(str(self._eval(value, env, depth + 1)))
            return self._sized("".join(parts))
        if isinstance(node, ast.UnaryOp):
            operand = self._eval(node.operand, env, depth + 1)
            if not isinstance(operand, int):
                raise _Unfoldable
            if isinstance(node.op, ast.USub):
                return -operand
            if isinstance(node.op, ast.Invert):
                return ~operand
            if isinstance(node.op, ast.UAdd):
                return operand
            raise _Unfoldable
        if isinstance(node, ast.BinOp):
            return self._binop(node, env, depth)
        if isinstance(node, ast.Subscript):
            return self._subscript(node, env, depth)
        if isinstance(node, (ast.GeneratorExp, ast.ListComp)):
            return self._comprehension(node, env, depth)
        if isinstance(node, ast.Call):
            return self._call(node, env, depth)
        raise _Unfoldable

    def _binop(self, node: ast.BinOp, env: dict[str, _Value], depth: int) -> _Value:
        left = self._eval(node.left, env, depth + 1)
        right = self._eval(node.right, env, depth + 1)
        op = node.op
        if isinstance(op, ast.Add):
            if type(left) is not type(right):
                raise _Unfoldable
            return self._sized(left + right)  # type: ignore[operator]
        if isinstance(op, ast.Mult):
            if isinstance(left, int) and isinstance(right, int):
                return self._sized(left * right)
            seq, count = (left, right) if isinstance(right, int) else (right, left)
            if isinstance(seq, int) or not isinstance(count, int):
                raise _Unfoldable
            if count < 0 or len(seq) * count > _MAX_LEN:
                raise _Unfoldable
            return seq * count
        if not (isinstance(left, int) and isinstance(right, int)):
            raise _Unfoldable
        if isinstance(op, ast.BitXor):
            self._code_ops += 1
            return left ^ right
        if isinstance(op, ast.Sub):
            return self._sized(left - right)
        if isinstance(op, ast.Mod):
            return left % right
        if isinstance(op, ast.FloorDiv):
            return left // right
        if isinstance(op, ast.BitAnd):
            return left & right
        if isinstance(op, ast.BitOr):
            return left | right
        if isinstance(op, ast.RShift) and 0 <= right < _MAX_INT_BITS:
            return left >> right
        if isinstance(op, ast.LShift) and 0 <= right < _MAX_INT_BITS:
            return self._sized(left << right)
        raise _Unfoldable

    def _subscript(self, node: ast.Subscript, env: dict[str, _Value], depth: int) -> _Value:
        owner = self._eval(node.value, env, depth + 1)
        if isinstance(owner, int):
            raise _Unfoldable
        index = node.slice
        if isinstance(index, ast.Slice):
            bounds = []
            for part in (index.lower, index.upper, index.step):
                if part is None:
                    bounds.append(None)
                    continue
                value = self._eval(part, env, depth + 1)
                if not isinstance(value, int):
                    raise _Unfoldable
                bounds.append(value)
            self._tick(len(owner) // 64)
            if bounds[2] is not None and bounds[2] < 0 and len(owner) >= _MIN_DECODED_LEN + 2:
                self._decoded = True
            return owner[bounds[0] : bounds[1] : bounds[2]]
        position = self._eval(index, env, depth + 1)
        if not isinstance(position, int):
            raise _Unfoldable
        return owner[position]

    def _iterate(self, node: ast.expr, env: dict[str, _Value], depth: int) -> list:
        value = self._eval(node, env, depth + 1)
        if isinstance(value, int):
            raise _Unfoldable
        self._tick(len(value))
        return list(value)

    def _comprehension(
        self, node: ast.GeneratorExp | ast.ListComp, env: dict[str, _Value], depth: int
    ) -> list:
        if len(node.generators) != 1:
            raise _Unfoldable
        gen = node.generators[0]
        if gen.ifs or gen.is_async:
            raise _Unfoldable
        out: list = []
        for item in self._iterate(gen.iter, env, depth):
            inner = dict(env)
            self._bind(gen.target, item, inner)
            out.append(self._eval(node.elt, inner, depth + 1))
        return out

    def _bind(self, target: ast.expr, value: _Value, env: dict[str, _Value]) -> None:
        if isinstance(target, ast.Name):
            env[target.id] = value
            return
        if isinstance(target, (ast.Tuple, ast.List)) and isinstance(value, list) and len(
            target.elts
        ) == len(value):
            for sub, item in zip(target.elts, value, strict=True):
                self._bind(sub, item, env)
            return
        raise _Unfoldable

    def _call(self, node: ast.Call, env: dict[str, _Value], depth: int) -> _Value:
        if any(isinstance(a, ast.Starred) for a in node.args):
            raise _Unfoldable
        name = self._resolve(node.func)
        if name in _B64:
            data = self._eval(self._arg(node, 0), env, depth + 1)
            if isinstance(data, list):
                data = bytes(data)
            if isinstance(data, int):
                raise _Unfoldable
            self._tick(len(data) // 16)
            if name.endswith("fromhex"):
                if not isinstance(data, str):
                    raise _Unfoldable
                out = bytes.fromhex(data)
            else:
                out = _B64[name](data)
            return self._mark_decoded(out)
        if name in ("zlib.decompress", "gzip.decompress"):
            data = self._eval(self._arg(node, 0), env, depth + 1)
            if not isinstance(data, bytes):
                raise _Unfoldable
            wbits = 47 if name.startswith("gzip") else 15
            out = zlib.decompressobj(wbits).decompress(data, _MAX_LEN)
            self._tick(len(out) // 16)
            return self._mark_decoded(out)
        if name == "codecs.decode":
            return self._codec(self._eval(self._arg(node, 0), env, depth + 1),
                               self._eval(self._arg(node, 1), env, depth + 1))
        if name in self._functions and isinstance(node.func, ast.Name):
            return self._local_call(self._functions[name], node, env, depth)
        if isinstance(node.func, ast.Name):
            bound = self._names.get(node.func.id)
            if isinstance(bound, ast.Lambda) and node.func.id not in env:
                return self._lambda_call(bound, node, env, depth)
            return self._builtin(node.func.id, node, env, depth)
        if isinstance(node.func, ast.Attribute):
            return self._method(node.func, node, env, depth)
        raise _Unfoldable

    def _mark_decoded(self, out: bytes) -> bytes:
        if len(out) >= _MIN_DECODED_LEN:
            self._decoded = True
        return self._sized(out)

    @staticmethod
    def _arg(node: ast.Call, position: int) -> ast.expr:
        if len(node.args) <= position:
            raise _Unfoldable
        return node.args[position]

    def _codec(self, data: _Value, codec: _Value) -> _Value:
        if not isinstance(codec, str):
            raise _Unfoldable
        codec = codec.lower().replace("-", "_")
        if codec in ("rot13", "rot_13") and isinstance(data, str):
            self._tick(len(data) // 16)
            if len(data) >= _MIN_DECODED_LEN:
                self._decoded = True
            return codecs.decode(data, "rot13")
        if codec in ("hex", "hex_codec", "base64", "base64_codec") and isinstance(data, bytes):
            self._tick(len(data) // 16)
            return self._mark_decoded(codecs.decode(data, codec))
        raise _Unfoldable

    def _builtin(self, name: str, node: ast.Call, env: dict[str, _Value], depth: int) -> _Value:
        if node.keywords:
            raise _Unfoldable
        if name == "chr":
            code = self._eval(self._arg(node, 0), env, depth + 1)
            if not isinstance(code, int):
                raise _Unfoldable
            self._code_ops += 1
            return chr(code)
        if name == "ord":
            char = self._eval(self._arg(node, 0), env, depth + 1)
            if not isinstance(char, (str, bytes)) or len(char) != 1:
                raise _Unfoldable
            return ord(char)
        if name == "len":
            value = self._eval(self._arg(node, 0), env, depth + 1)
            if isinstance(value, int):
                raise _Unfoldable
            return len(value)
        if name in ("bytes", "bytearray"):
            items = self._iterate(self._arg(node, 0), env, depth)
            if not all(isinstance(i, int) for i in items):
                raise _Unfoldable
            return bytes(items)
        if name in ("list", "tuple"):
            return self._iterate(self._arg(node, 0), env, depth)
        if name == "str":
            value = self._eval(self._arg(node, 0), env, depth + 1)
            if not isinstance(value, (str, int)):
                raise _Unfoldable
            return str(value)
        if name == "int":
            value = self._eval(self._arg(node, 0), env, depth + 1)
            base = self._eval(node.args[1], env, depth + 1) if len(node.args) > 1 else 10
            if isinstance(value, int) and len(node.args) == 1:
                return value
            if not isinstance(value, str) or not isinstance(base, int):
                raise _Unfoldable
            return self._sized(int(value, base))
        if name == "reversed":
            items = self._iterate(self._arg(node, 0), env, depth)
            if len(items) >= _MIN_DECODED_LEN + 2:
                self._decoded = True
            return items[::-1]
        if name == "enumerate":
            items = self._iterate(self._arg(node, 0), env, depth)
            return [[i, item] for i, item in enumerate(items)]
        if name == "range":
            bounds = [self._eval(a, env, depth + 1) for a in node.args]
            if not bounds or len(bounds) > 3 or not all(isinstance(b, int) for b in bounds):
                raise _Unfoldable
            span = range(*bounds)  # type: ignore[arg-type]
            if len(span) > _MAX_LEN:
                raise _Unfoldable
            self._tick(len(span))
            return list(span)
        if name == "zip":
            columns = [self._iterate(a, env, depth) for a in node.args]
            return [list(row) for row in zip(*columns, strict=False)]
        if name == "map" and len(node.args) == 2:
            items = self._iterate(node.args[1], env, depth)
            mapper = node.args[0]
            out: list = []
            for item in items:
                self._tick()
                if isinstance(mapper, ast.Name) and mapper.id == "chr" and isinstance(item, int):
                    self._code_ops += 1
                    out.append(chr(item))
                elif isinstance(mapper, ast.Lambda):
                    out.append(self._apply_lambda(mapper, [item], depth))
                else:
                    raise _Unfoldable
            return out
        raise _Unfoldable

    def _method(
        self, func: ast.Attribute, node: ast.Call, env: dict[str, _Value], depth: int
    ) -> _Value:
        owner = self._eval(func.value, env, depth + 1)
        attr = func.attr
        if attr == "join" and isinstance(owner, (str, bytes)):
            items = self._iterate(self._arg(node, 0), env, depth)
            if not all(isinstance(i, type(owner)) for i in items):
                raise _Unfoldable
            # Checked before joining: a long separator between many items is built in one go.
            if sum(len(i) for i in items) + len(owner) * len(items) > _MAX_LEN:
                raise _Unfoldable
            return owner.join(items)  # type: ignore[arg-type]
        if attr == "decode" and isinstance(owner, bytes):
            codec = self._eval(node.args[0], env, depth + 1) if node.args else "utf-8"
            if isinstance(codec, str) and codec.lower() in _TEXT_CODECS:
                return owner.decode(codec, "replace")
            return self._codec(owner, codec)
        if attr == "encode" and isinstance(owner, str):
            codec = self._eval(node.args[0], env, depth + 1) if node.args else "utf-8"
            if isinstance(codec, str) and codec.lower() in _TEXT_CODECS:
                return owner.encode(codec, "replace")
            raise _Unfoldable
        if attr in _STR_METHODS and isinstance(owner, str) and not node.args:
            return getattr(owner, attr)()
        if attr == "replace" and isinstance(owner, str) and len(node.args) == 2:
            old = self._eval(node.args[0], env, depth + 1)
            new = self._eval(node.args[1], env, depth + 1)
            if not isinstance(old, str) or not isinstance(new, str):
                raise _Unfoldable
            self._tick(len(owner) // 16)
            # Checked before replacing: every occurrence may grow into a long replacement.
            if old and owner.count(old) * len(new) + len(owner) > _MAX_LEN:
                raise _Unfoldable
            if not old and (len(owner) + 1) * len(new) + len(owner) > _MAX_LEN:
                raise _Unfoldable
            return owner.replace(old, new)
        if attr == "split" and isinstance(owner, str) and len(node.args) <= 1:
            sep = self._eval(node.args[0], env, depth + 1) if node.args else None
            if sep is not None and not isinstance(sep, str):
                raise _Unfoldable
            return list(owner.split(sep))
        raise _Unfoldable

    # -- small local helpers ---------------------------------------------------------------------
    def _local_call(
        self,
        func: ast.FunctionDef | ast.AsyncFunctionDef,
        node: ast.Call,
        env: dict[str, _Value],
        depth: int,
    ) -> _Value:
        """A helper whose body is plain assignments and one return: `def _dec(x): k = b"..";
        return bytes(c ^ k[i % len(k)] for i, c in enumerate(x)).decode()`."""
        if isinstance(func, ast.AsyncFunctionDef) or node.keywords:
            raise _Unfoldable
        spec = func.args
        if spec.vararg or spec.kwarg or spec.kwonlyargs or spec.posonlyargs:
            raise _Unfoldable
        if len(node.args) > len(spec.args):
            raise _Unfoldable
        inner: dict[str, _Value] = {}
        defaults = [None] * (len(spec.args) - len(spec.defaults)) + list(spec.defaults)
        for i, param in enumerate(spec.args):
            if i < len(node.args):
                inner[param.arg] = self._eval(node.args[i], env, depth + 1)
            elif defaults[i] is not None:
                inner[param.arg] = self._eval(defaults[i], {}, depth + 1)
            else:
                raise _Unfoldable
        body = list(func.body)
        if body and isinstance(body[0], ast.Expr) and isinstance(body[0].value, ast.Constant):
            body = body[1:]  # docstring
        for stmt in body[:-1]:
            if not (
                isinstance(stmt, ast.Assign)
                and len(stmt.targets) == 1
                and isinstance(stmt.targets[0], ast.Name)
            ):
                raise _Unfoldable
            inner[stmt.targets[0].id] = self._eval(stmt.value, inner, depth + 1)
        if not body or not isinstance(body[-1], ast.Return) or body[-1].value is None:
            raise _Unfoldable
        return self._eval(body[-1].value, inner, depth + 1)

    def _lambda_call(
        self, func: ast.Lambda, node: ast.Call, env: dict[str, _Value], depth: int
    ) -> _Value:
        if node.keywords:
            raise _Unfoldable
        return self._apply_lambda(func, [self._eval(a, env, depth + 1) for a in node.args], depth)

    def _apply_lambda(self, func: ast.Lambda, values: list, depth: int) -> _Value:
        spec = func.args
        if spec.vararg or spec.kwarg or spec.kwonlyargs or spec.defaults or len(spec.args) != len(
            values
        ):
            raise _Unfoldable
        inner = {param.arg: value for param, value in zip(spec.args, values, strict=True)}
        return self._eval(func.body, inner, depth + 1)


def as_text(value: _Value) -> str | None:
    """A folded value as the text a sink would receive, or None for a number or a list."""
    if isinstance(value, bytes):
        return value.decode("utf-8", "replace")
    return value if isinstance(value, str) else None


def _once_assigned(body: list[ast.stmt]) -> dict[str, ast.expr]:
    """Names a scope assigns exactly once, with what they are assigned."""
    seen: dict[str, list[ast.expr]] = {}
    for value, names in _scope_assignments(body):
        for name in names:
            seen.setdefault(name, []).append(value)
    return {name: values[0] for name, values in seen.items() if len(values) == 1}


class _DecodedSinkVisitor(_CallVisitor):
    """Finds shell and exec sinks whose argument is decoded from literals of the file."""

    def __init__(self, file: IndexedFile):
        super().__init__(file)
        self.sinks: list[tuple[str, Evidence, str]] = []
        self._names: dict[str, ast.expr] = {}
        self._all_functions: dict[str, ast.FunctionDef | ast.AsyncFunctionDef] = {}
        self._folder: LiteralFolder | None = None

    def visit_Module(self, node: ast.Module) -> None:
        self._names = _once_assigned(node.body)
        for stmt in node.body:
            if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef)):
                self._all_functions[stmt.name] = stmt
        self._folder = LiteralFolder(self._dotted, self._names, self._all_functions)
        super().visit_Module(node)

    def _visit_function(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> None:
        saved = self._names
        # Module names stay visible; the function's own single assignments shadow them, and its
        # parameters hide a module name of the same spelling.
        local = {**saved, **_once_assigned(node.body)}
        for arg in [*node.args.posonlyargs, *node.args.args, *node.args.kwonlyargs]:
            local.pop(arg.arg, None)
        self._names = local
        if self._folder is not None:
            self._folder._names = local
        try:
            if isinstance(node, ast.FunctionDef):
                super().visit_FunctionDef(node)
            else:
                super().visit_AsyncFunctionDef(node)
        finally:
            self._names = saved
            if self._folder is not None:
                self._folder._names = saved

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self._visit_function(node)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        self._visit_function(node)

    def _add(self, rule_id: str, node: ast.AST) -> None:
        return  # the base visitor's own rules are reported by PythonAstScanner

    def _add_dynamic_import(self, node: ast.AST) -> None:
        return

    def _classify_call(self, name: str, node: ast.Call) -> None:
        if self._folder is None or len(self.sinks) >= MAX_EVIDENCE_SCANNED:
            return
        if name in ALWAYS_SHELL_CALLS or (name.startswith("subprocess.") and _shell_true(node)):
            kind, arg = SINK_SHELL, _command_arg(node)
        elif _is_dynamic_builtin_call(name, node) and name.rsplit(".", 1)[-1] != "compile":
            kind, arg = SINK_EXEC, (node.args[0] if node.args else None)
        else:
            return
        if arg is None or isinstance(arg, ast.Constant):
            return
        folded = self._folder.fold(arg)
        if folded is None or not folded[1]:
            return
        text = as_text(folded[0])
        if text is None or len(text.strip()) < _MIN_DECODED_LEN:
            return
        self.sinks.append((kind, self._evidence(node), text))


def python_decoded_sinks(f: IndexedFile) -> list[tuple[str, Evidence, str]]:
    """``(sink kind, evidence, decoded text)`` for every shell or exec call of a Python file whose
    argument the file decodes from its own literals. Parsing and constant arithmetic only: nothing
    of the file is run."""
    text = f.text
    if _SINK_GATE.search(text) is None or _DECODE_GATE.search(text) is None:
        return []
    try:
        tree = ast.parse(text, filename=f.relpath)
    except (SyntaxError, ValueError, RecursionError, MemoryError):
        return []

    def walk() -> list[tuple[str, Evidence, str]]:
        visitor = _DecodedSinkVisitor(f)
        visitor.visit(tree)
        return visitor.sinks

    try:
        return walk_deep(walk)
    except RecursionError:
        return []
