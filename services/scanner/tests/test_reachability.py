"""Unit tests for import/usage-level reachability analysis.

Each ecosystem gets a tiny synthetic project: a manifest (direct deps) plus a
source file that imports some of them. We assert direct-vs-transitive and
reachable-vs-unreachable are computed correctly — the signal that drives
SCA prioritization.
"""
from __future__ import annotations

from utils import reachability
from utils.reachability import GO, JAVA, JAVASCRIPT, PYTHON


def _write(root, rel, content):
    p = root / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(content, encoding="utf-8")


# ── Python ────────────────────────────────────────────────────────────────────
def test_python_direct_and_reachable(tmp_path):
    _write(tmp_path, "requirements.txt", "Flask==0.12.0\nPyYAML==5.1\nunused-lib==1.0\n")
    _write(tmp_path, "app.py", "import flask\nimport yaml\nfrom os import path\n")

    idx = reachability.build_index(str(tmp_path))

    flask = idx.annotate(PYTHON, "flask")
    assert flask["reachable"] is True and flask["is_direct"] is True
    assert "app.py" in flask["reachable_files"]

    # PyPI name differs from import name (PyYAML -> yaml): still reachable + direct.
    pyyaml = idx.annotate(PYTHON, "PyYAML")
    assert pyyaml["reachable"] is True and pyyaml["is_direct"] is True

    # Declared but never imported -> direct but unreachable.
    unused = idx.annotate(PYTHON, "unused-lib")
    assert unused["is_direct"] is True and unused["reachable"] is False

    # Not in the manifest at all -> transitive + unreachable.
    trans = idx.annotate(PYTHON, "some-transitive-dep")
    assert trans["is_direct"] is False and trans["reachable"] is False


def test_python_pyproject_direct(tmp_path):
    _write(
        tmp_path,
        "pyproject.toml",
        '[project]\nname = "x"\ndependencies = ["requests>=2.0", "click"]\n',
    )
    _write(tmp_path, "main.py", "import requests\n")
    idx = reachability.build_index(str(tmp_path))
    assert idx.annotate(PYTHON, "requests")["is_direct"] is True
    assert idx.annotate(PYTHON, "click")["is_direct"] is True
    assert idx.annotate(PYTHON, "click")["reachable"] is False  # declared, unused


# ── JavaScript ────────────────────────────────────────────────────────────────
def test_javascript_direct_and_reachable(tmp_path):
    _write(
        tmp_path,
        "package.json",
        '{"dependencies": {"lodash": "^4.0.0", "@scope/thing": "1.0.0"},'
        ' "devDependencies": {"jest": "^29"}}',
    )
    _write(
        tmp_path,
        "src/index.js",
        "const _ = require('lodash');\nimport x from '@scope/thing';\nimport './local';\n",
    )
    idx = reachability.build_index(str(tmp_path))

    lodash = idx.annotate(JAVASCRIPT, "lodash")
    assert lodash["reachable"] is True and lodash["is_direct"] is True
    assert "src/index.js" in lodash["reachable_files"]

    scoped = idx.annotate(JAVASCRIPT, "@scope/thing")
    assert scoped["reachable"] is True and scoped["is_direct"] is True

    # Declared dev dep, never imported -> direct but unreachable.
    jest = idx.annotate(JAVASCRIPT, "jest")
    assert jest["is_direct"] is True and jest["reachable"] is False


# ── Go ────────────────────────────────────────────────────────────────────────
def test_go_direct_transitive_and_reachable(tmp_path):
    _write(
        tmp_path,
        "go.mod",
        "module example.com/app\n\ngo 1.22\n\nrequire (\n"
        "\tgithub.com/foo/bar v1.2.3\n"
        "\tgithub.com/baz/qux v0.1.0 // indirect\n)\n",
    )
    _write(
        tmp_path,
        "main.go",
        'package main\n\nimport (\n\t"fmt"\n\t"github.com/foo/bar/sub"\n)\n\nfunc main() { fmt.Println(sub.X) }\n',
    )
    idx = reachability.build_index(str(tmp_path))

    bar = idx.annotate(GO, "github.com/foo/bar")
    assert bar["is_direct"] is True and bar["reachable"] is True  # matched by prefix
    assert "main.go" in bar["reachable_files"]

    qux = idx.annotate(GO, "github.com/baz/qux")
    assert qux["is_direct"] is False  # marked // indirect
    assert qux["reachable"] is False  # never imported


# ── Java ──────────────────────────────────────────────────────────────────────
def test_java_direct_and_reachable(tmp_path):
    _write(
        tmp_path,
        "pom.xml",
        "<project><dependencies>"
        "<dependency><groupId>org.apache.commons</groupId>"
        "<artifactId>commons-lang3</artifactId><version>3.12.0</version></dependency>"
        "</dependencies></project>",
    )
    _write(
        tmp_path,
        "src/Main.java",
        "import org.apache.commons.lang3.StringUtils;\nclass Main {}\n",
    )
    idx = reachability.build_index(str(tmp_path))

    lang3 = idx.annotate(JAVA, "org.apache.commons:commons-lang3")
    assert lang3["is_direct"] is True and lang3["reachable"] is True  # groupId prefix match
    assert "src/Main.java" in lang3["reachable_files"]


def test_no_manifest_means_unknown_directness(tmp_path):
    _write(tmp_path, "app.py", "import flask\n")
    idx = reachability.build_index(str(tmp_path))
    ann = idx.annotate(PYTHON, "flask")
    assert ann["reachable"] is True
    assert ann["is_direct"] is None  # no manifest -> can't tell direct vs transitive
