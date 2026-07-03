"""Metadata-only feature extraction for the false-positive classifier.

CRITICAL PRIVACY INVARIANT: not one of these features is derived from source
code. Everything here comes from a finding's metadata + the project's shape
(rule id, engine, severity, file *path* patterns, LOC count, dependency
directness, ...). No code, no snippets, no identifiers from the code. See
PRIVACY.md.
"""
from __future__ import annotations

import hashlib
import os
import re

# The ordered feature vector the model consumes.
FEATURE_NAMES = [
    "severity_ord",
    "file_path_depth",
    "lines_of_code",
    "is_in_test_file",
    "is_in_generated_file",
    "is_direct_dependency",
    "engine_hash",
    "rule_hash",
    "ext_hash",
    "language_hash",
    "cwe_hash",
    "owasp_hash",
    "size_bucket_ord",
]

_SEVERITY_ORD = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0, "informational": 0}
_SIZE_ORD = {"small": 0, "medium": 1, "large": 2}

_TEST_PAT = re.compile(r"(^|/)(tests?|__tests__|spec|specs|e2e)(/|$)|[._-](test|spec)\.", re.IGNORECASE)
_GENERATED_PAT = re.compile(
    r"(^|/)(dist|build|out|vendor|node_modules|generated|\.next|migrations)(/|$)|\.min\.|\.bundle\.|_pb2\.|\.pb\.go$",
    re.IGNORECASE,
)


def _hash(value: str | None, buckets: int) -> float:
    if not value:
        return 0.0
    h = int(hashlib.md5(value.encode("utf-8")).hexdigest(), 16)
    return float(h % buckets)


def is_test_path(path: str | None) -> bool:
    return bool(path and _TEST_PAT.search(path))


def is_generated_path(path: str | None) -> bool:
    return bool(path and _GENERATED_PAT.search(path))


def featurize(rec: dict) -> list[float]:
    """Turn a feature record (metadata-only) into the model's numeric vector."""
    return [
        float(_SEVERITY_ORD.get(str(rec.get("severity", "")).lower(), 0)),
        float(rec.get("file_path_depth") or 0),
        float(rec.get("lines_of_code") or 0),
        1.0 if rec.get("is_in_test_file") else 0.0,
        1.0 if rec.get("is_in_generated_file") else 0.0,
        1.0 if rec.get("is_direct_dependency") else 0.0,
        _hash(rec.get("engine"), 16),
        _hash(rec.get("rule_id"), 256),
        _hash(rec.get("file_extension"), 32),
        _hash(rec.get("project_language"), 16),
        _hash(rec.get("cwe"), 64),
        _hash(rec.get("owasp_category"), 16),
        float(_SIZE_ORD.get(str(rec.get("project_size_bucket", "")).lower(), 1)),
    ]


# Actions that indicate the finding was a false positive (the positive class).
_FP_ACTIONS = {"marked_fp", "suppressed", "ignored"}


def label_to_binary(action: str) -> int:
    """1 = false positive, 0 = true positive (confirmed/fixed)."""
    return 1 if action in _FP_ACTIONS else 0


def record_from_finding(finding: dict, project: dict | None = None) -> dict:
    """Build a metadata-only feature record from a finding + optional project ctx."""
    project = project or {}
    path = finding.get("file_path") or ""
    meta = finding.get("metadata") or {}
    is_direct = meta.get("is_direct")
    return {
        "rule_id": finding.get("rule_id"),
        "engine": _enum(finding.get("engine")),
        "severity": _enum(finding.get("severity")),
        "file_extension": os.path.splitext(path)[1].lower() or None,
        "file_path_depth": path.count("/"),
        "project_language": project.get("language"),
        "project_size_bucket": project.get("size_bucket"),
        "lines_of_code": meta.get("nloc") or meta.get("clone_lines"),
        "cwe": finding.get("cwe_id"),
        "owasp_category": finding.get("owasp_category"),
        "is_in_test_file": is_test_path(path),
        "is_in_generated_file": is_generated_path(path),
        "is_direct_dependency": bool(is_direct) if is_direct is not None else False,
    }


def _enum(v) -> str | None:
    if v is None:
        return None
    return v.value if hasattr(v, "value") else str(v)
