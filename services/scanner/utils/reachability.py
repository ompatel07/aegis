"""Reachability analysis for SCA (dependency) findings.

A dependency CVE only matters in proportion to whether the vulnerable package is
actually used. For each ecosystem this module answers two questions about a
package:

  * is_direct  — is it a DIRECT dependency (declared in the project's manifest)
                 or a transitive one pulled in by something else?
  * reachable  — is it REACHABLE: does any first-party source file import/use it?

This is import/usage-level reachability: a strong, honest static approximation of
true call-graph reachability. It does not claim to prove a vulnerable *function*
is invoked (that needs a per-function advisory DB); it proves the vulnerable
*module* is (or is not) wired into the codebase. An unused/transitive dependency
is de-prioritized; a directly-imported one is escalated — the same signal Snyk's
reachable-vulnerabilities feature sells, computed from source.

The analysis is best-effort and defensive: any parse failure degrades to
"unknown" (reachable=None) for that package rather than raising, so SCA never
fails because of it.
"""
from __future__ import annotations

import json
import os
import re

from logging_config import get_logger

log = get_logger("reachability")

# ── Ecosystems ────────────────────────────────────────────────────────────────
PYTHON = "python"
JAVASCRIPT = "javascript"
GO = "go"
JAVA = "java"

# Trivy dependency-scan Types → our ecosystem.
_TYPE_TO_ECOSYSTEM: dict[str, str] = {
    "pip": PYTHON, "poetry": PYTHON, "pipenv": PYTHON, "python-pkg": PYTHON, "uv": PYTHON,
    "npm": JAVASCRIPT, "yarn": JAVASCRIPT, "pnpm": JAVASCRIPT, "node-pkg": JAVASCRIPT, "bun": JAVASCRIPT,
    "gomod": GO, "gobinary": GO,
    "pom": JAVA, "gradle": JAVA, "jar": JAVA,
}

# Directories that never contain first-party source we should credit for reach.
_SKIP_DIRS = {
    ".git", "node_modules", "vendor", ".venv", "venv", "env", "__pycache__",
    "dist", "build", "target", ".next", "out", ".gradle", "site-packages",
    ".mypy_cache", ".pytest_cache", ".ruff_cache", "bower_components",
}

_MAX_FILE_BYTES = 2_000_000

# PyPI project name → the module(s) it is imported as, where they differ.
_PY_PKG_TO_MODULES: dict[str, list[str]] = {
    "pyyaml": ["yaml"],
    "beautifulsoup4": ["bs4"],
    "pillow": ["pil"],
    "python-dateutil": ["dateutil"],
    "scikit-learn": ["sklearn"],
    "opencv-python": ["cv2"],
    "msgpack-python": ["msgpack"],
    "protobuf": ["google"],
    "setuptools": ["setuptools", "pkg_resources"],
    "python-jose": ["jose"],
    "pycryptodome": ["crypto"],
    "typing-extensions": ["typing_extensions"],
}


def ecosystem_for_type(trivy_type: str | None) -> str | None:
    """Map a Trivy result Type onto our ecosystem, or None if unsupported."""
    return _TYPE_TO_ECOSYSTEM.get((trivy_type or "").lower())


def _pep503(name: str) -> str:
    """Normalize a Python distribution name (PEP 503): lowercase, runs of -_. -> -."""
    return re.sub(r"[-_.]+", "-", (name or "").strip().lower())


class ReachabilityIndex:
    """A one-shot import/dependency index for a project tree."""

    def __init__(self) -> None:
        # ecosystem -> set of normalized direct-dependency names
        self.direct: dict[str, set[str]] = {PYTHON: set(), JAVASCRIPT: set(), GO: set(), JAVA: set()}
        # ecosystem -> whether we found a manifest at all (so we can tell
        # "transitive" apart from "we couldn't read directness").
        self.has_manifest: dict[str, bool] = {PYTHON: False, JAVASCRIPT: False, GO: False, JAVA: False}
        # import indexes: key -> sorted list of relative source files
        self._py: dict[str, set[str]] = {}    # top-level module -> files
        self._js: dict[str, set[str]] = {}    # package specifier root -> files
        self._go: dict[str, set[str]] = {}    # full import path -> files
        self._java: dict[str, set[str]] = {}  # imported FQCN -> files

    # ── lookup ────────────────────────────────────────────────────────────────
    def annotate(self, ecosystem: str, pkg: str) -> dict:
        """Return reachability metadata for a package: reachable / reachable_files
        / is_direct. `reachable` is None when we cannot determine it."""
        files = self._reachable_files(ecosystem, pkg)
        reachable = None if files is None else len(files) > 0
        is_direct = self._is_direct(ecosystem, pkg)
        return {
            "reachable": reachable,
            "reachable_files": (files or [])[:20],
            "reachable_file_count": (len(files) if files is not None else None),
            "is_direct": is_direct,
            "reachability_ecosystem": ecosystem,
        }

    def _is_direct(self, ecosystem: str, pkg: str) -> bool | None:
        if not self.has_manifest.get(ecosystem):
            return None
        return _norm_pkg(ecosystem, pkg) in self.direct[ecosystem]

    def _reachable_files(self, ecosystem: str, pkg: str) -> list[str] | None:
        try:
            if ecosystem == PYTHON:
                return self._py_reach(pkg)
            if ecosystem == JAVASCRIPT:
                return sorted(self._js.get(pkg.lower(), set()))
            if ecosystem == GO:
                return self._go_reach(pkg)
            if ecosystem == JAVA:
                return self._java_reach(pkg)
        except Exception as exc:  # noqa: BLE001 — never fail SCA on reachability
            log.debug("reachability.lookup_failed", ecosystem=ecosystem, pkg=pkg, error=str(exc))
        return None

    def _py_reach(self, pkg: str) -> list[str]:
        key = _pep503(pkg)
        candidates = set(_PY_PKG_TO_MODULES.get(key, []))
        candidates.add(key.replace("-", "_"))
        candidates.add(key.replace("-", ""))
        hits: set[str] = set()
        for mod in candidates:
            hits |= self._py.get(mod, set())
        return sorted(hits)

    def _go_reach(self, module: str) -> list[str]:
        module = (module or "").strip()
        hits: set[str] = set()
        for path, files in self._go.items():
            if path == module or path.startswith(module + "/"):
                hits |= files
        return sorted(hits)

    def _java_reach(self, pkg: str) -> list[str]:
        # Trivy reports "group:artifact"; the groupId is usually a package prefix.
        group = (pkg or "").split(":", 1)[0].strip().lower()
        if not group:
            return []
        hits: set[str] = set()
        for fqcn, files in self._java.items():
            if fqcn.lower() == group or fqcn.lower().startswith(group + "."):
                hits |= files
        return sorted(hits)


def _norm_pkg(ecosystem: str, pkg: str) -> str:
    if ecosystem == PYTHON:
        return _pep503(pkg)
    if ecosystem == JAVASCRIPT:
        return (pkg or "").strip().lower()
    if ecosystem == JAVA:
        return (pkg or "").strip().lower()
    return (pkg or "").strip()  # go: module path, case-sensitive


# ── Index construction ────────────────────────────────────────────────────────
def build_index(root: str) -> ReachabilityIndex:
    """Walk the project once, parsing manifests (direct deps) and source imports."""
    idx = ReachabilityIndex()
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in _SKIP_DIRS and not d.startswith(".git")]
        for name in filenames:
            path = os.path.join(dirpath, name)
            rel = os.path.relpath(path, root).replace(os.sep, "/")
            try:
                _dispatch(idx, path, rel, name)
            except OSError:
                continue
            except Exception as exc:  # noqa: BLE001 — one bad file must not abort
                log.debug("reachability.parse_failed", file=rel, error=str(exc))
    return idx


def _read(path: str) -> str | None:
    if os.path.getsize(path) > _MAX_FILE_BYTES:
        return None
    with open(path, encoding="utf-8", errors="ignore") as fh:
        return fh.read()


def _dispatch(idx: ReachabilityIndex, path: str, rel: str, name: str) -> None:
    lower = name.lower()
    ext = os.path.splitext(lower)[1]

    # Manifests (direct dependencies).
    if lower.startswith("requirements") and lower.endswith(".txt"):
        _parse_requirements(idx, _read(path))
    elif lower == "pyproject.toml":
        _parse_pyproject(idx, _read(path))
    elif lower == "pipfile":
        _parse_pipfile(idx, _read(path))
    elif lower == "package.json":
        _parse_package_json(idx, _read(path))
    elif lower == "go.mod":
        _parse_go_mod(idx, _read(path))
    elif lower == "pom.xml":
        _parse_pom(idx, _read(path))
    elif lower.endswith(".gradle") or lower.endswith(".gradle.kts"):
        _parse_gradle(idx, _read(path))

    # Source imports (reachability).
    if ext == ".py":
        _parse_py_imports(idx, _read(path), rel)
    elif ext in (".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx"):
        _parse_js_imports(idx, _read(path), rel)
    elif ext == ".go":
        _parse_go_imports(idx, _read(path), rel)
    elif ext == ".java":
        _parse_java_imports(idx, _read(path), rel)


# ── Manifest parsers (direct deps) ────────────────────────────────────────────
_REQ_NAME = re.compile(r"^([A-Za-z0-9][A-Za-z0-9._-]*)")


def _parse_requirements(idx: ReachabilityIndex, text: str | None) -> None:
    if text is None:
        return
    idx.has_manifest[PYTHON] = True
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith(("#", "-", "git+", "http")):
            continue
        m = _REQ_NAME.match(line)
        if m:
            idx.direct[PYTHON].add(_pep503(m.group(1)))


def _parse_pyproject(idx: ReachabilityIndex, text: str | None) -> None:
    if text is None:
        return
    try:
        import tomllib
    except ModuleNotFoundError:  # pragma: no cover — py<3.11
        return
    try:
        data = tomllib.loads(text)
    except Exception:  # noqa: BLE001
        return
    idx.has_manifest[PYTHON] = True
    for dep in (data.get("project", {}) or {}).get("dependencies", []) or []:
        m = _REQ_NAME.match(str(dep).strip())
        if m:
            idx.direct[PYTHON].add(_pep503(m.group(1)))
    poetry = ((data.get("tool", {}) or {}).get("poetry", {}) or {}).get("dependencies", {}) or {}
    for name in poetry:
        if name.lower() != "python":
            idx.direct[PYTHON].add(_pep503(name))


def _parse_pipfile(idx: ReachabilityIndex, text: str | None) -> None:
    if text is None:
        return
    try:
        import tomllib
    except ModuleNotFoundError:  # pragma: no cover
        return
    try:
        data = tomllib.loads(text)
    except Exception:  # noqa: BLE001
        return
    idx.has_manifest[PYTHON] = True
    for section in ("packages", "dev-packages"):
        for name in (data.get(section, {}) or {}):
            idx.direct[PYTHON].add(_pep503(name))


def _parse_package_json(idx: ReachabilityIndex, text: str | None) -> None:
    if text is None:
        return
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        return
    idx.has_manifest[JAVASCRIPT] = True
    for section in ("dependencies", "devDependencies", "optionalDependencies", "peerDependencies"):
        for name in (data.get(section, {}) or {}):
            idx.direct[JAVASCRIPT].add(name.strip().lower())


_GOMOD_REQ_LINE = re.compile(r"^\s*([^\s]+)\s+v\S+(\s+//\s*indirect)?\s*$")


def _parse_go_mod(idx: ReachabilityIndex, text: str | None) -> None:
    if text is None:
        return
    idx.has_manifest[GO] = True
    in_block = False
    for raw in text.splitlines():
        line = raw.strip()
        if line.startswith("require ("):
            in_block = True
            continue
        if in_block and line == ")":
            in_block = False
            continue
        candidate = line
        if line.startswith("require "):
            candidate = line[len("require "):].strip()
        elif not in_block:
            continue
        m = _GOMOD_REQ_LINE.match(candidate)
        if m and not m.group(2):  # group(2) present == "// indirect"
            idx.direct[GO].add(m.group(1))


def _parse_pom(idx: ReachabilityIndex, text: str | None) -> None:
    if text is None:
        return
    import xml.etree.ElementTree as ET

    try:
        root = ET.fromstring(text)
    except ET.ParseError:
        return
    idx.has_manifest[JAVA] = True

    def _local(tag: str) -> str:
        return tag.rsplit("}", 1)[-1]

    for dep in root.iter():
        if _local(dep.tag) != "dependency":
            continue
        group = artifact = None
        for child in dep:
            if _local(child.tag) == "groupId":
                group = (child.text or "").strip()
            elif _local(child.tag) == "artifactId":
                artifact = (child.text or "").strip()
        if group and artifact:
            idx.direct[JAVA].add(f"{group}:{artifact}".lower())


_GRADLE_DEP = re.compile(
    r"""(?:implementation|api|compile|runtimeOnly|testImplementation|classpath)\s*"""
    r"""[\('"]+([A-Za-z0-9_.\-]+):([A-Za-z0-9_.\-]+)(?::[^'"]*)?['"]"""
)


def _parse_gradle(idx: ReachabilityIndex, text: str | None) -> None:
    if text is None:
        return
    idx.has_manifest[JAVA] = True
    for group, artifact in _GRADLE_DEP.findall(text):
        idx.direct[JAVA].add(f"{group}:{artifact}".lower())


# ── Source import parsers (reachability) ──────────────────────────────────────
def _parse_py_imports(idx: ReachabilityIndex, text: str | None, rel: str) -> None:
    if text is None:
        return
    import ast

    try:
        tree = ast.parse(text)
    except SyntaxError:
        return
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                _add(idx._py, alias.name.split(".")[0], rel)
        elif isinstance(node, ast.ImportFrom):
            if node.level == 0 and node.module:  # skip relative imports
                _add(idx._py, node.module.split(".")[0], rel)


_JS_IMPORT = re.compile(
    r"""(?:require\(\s*|import\s*\(\s*|(?:import|export)[^'"]*?from\s*|import\s+)['"]([^'"]+)['"]"""
)


def _parse_js_imports(idx: ReachabilityIndex, text: str | None, rel: str) -> None:
    if text is None:
        return
    for spec in _JS_IMPORT.findall(text):
        if not spec or spec.startswith((".", "/")):
            continue  # local module
        if spec.startswith("@"):
            parts = spec.split("/")
            pkg = "/".join(parts[:2]) if len(parts) >= 2 else spec
        else:
            pkg = spec.split("/")[0]
        _add(idx._js, pkg.lower(), rel)


_GO_IMPORT_BLOCK = re.compile(r"import\s*\(([\s\S]*?)\)")
_GO_IMPORT_SINGLE = re.compile(r'import\s+(?:[\w.]+\s+)?"([^"]+)"')
_GO_PATH = re.compile(r'"([^"]+)"')


def _parse_go_imports(idx: ReachabilityIndex, text: str | None, rel: str) -> None:
    if text is None:
        return
    for block in _GO_IMPORT_BLOCK.findall(text):
        for path in _GO_PATH.findall(block):
            _add(idx._go, path, rel)
    for path in _GO_IMPORT_SINGLE.findall(text):
        _add(idx._go, path, rel)


_JAVA_IMPORT = re.compile(r"import\s+(?:static\s+)?([A-Za-z0-9_.]+?)(?:\.\*)?\s*;")


def _parse_java_imports(idx: ReachabilityIndex, text: str | None, rel: str) -> None:
    if text is None:
        return
    for fqcn in _JAVA_IMPORT.findall(text):
        # Store the package portion (drop the trailing ClassName if present).
        parts = fqcn.split(".")
        pkg = ".".join(parts[:-1]) if len(parts) > 1 and parts[-1][:1].isupper() else fqcn
        _add(idx._java, pkg, rel)
        _add(idx._java, fqcn, rel)


def _add(index: dict[str, set[str]], key: str, rel: str) -> None:
    if key:
        index.setdefault(key, set()).add(rel)
