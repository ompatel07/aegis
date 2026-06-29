"""Language and project-type detection.

Detection is twofold:
  * marker files (package.json, go.mod, ...) → project type + ecosystem,
  * file-extension census → primary language + language mix for rule selection.

This mirrors the orchestrator's Go detector so both services agree on language
names (lowercase, canonical).
"""
from __future__ import annotations

import os
from collections import Counter
from dataclasses import dataclass, field

# Marker file → (project_type, primary_language).
_MARKER_FILES: dict[str, tuple[str, str]] = {
    "package.json": ("node", "javascript"),
    "tsconfig.json": ("node", "typescript"),
    "go.mod": ("go", "go"),
    "requirements.txt": ("python", "python"),
    "pyproject.toml": ("python", "python"),
    "Pipfile": ("python", "python"),
    "pom.xml": ("maven", "java"),
    "build.gradle": ("gradle", "java"),
    "Gemfile": ("ruby", "ruby"),
    "Cargo.toml": ("cargo", "rust"),
    "composer.json": ("php", "php"),
}

# File extension → canonical language name.
_EXTENSION_MAP: dict[str, str] = {
    ".js": "javascript",
    ".jsx": "javascript",
    ".mjs": "javascript",
    ".cjs": "javascript",
    ".ts": "typescript",
    ".tsx": "typescript",
    ".py": "python",
    ".go": "go",
    ".java": "java",
    ".rb": "ruby",
    ".rs": "rust",
    ".php": "php",
    ".cs": "csharp",
    ".c": "c",
    ".h": "c",
    ".cpp": "cpp",
    ".cc": "cpp",
    ".kt": "kotlin",
    ".scala": "scala",
}

# Directories we never want to descend into during detection or analysis.
IGNORED_DIRS: frozenset[str] = frozenset(
    {
        ".git",
        "node_modules",
        "vendor",
        "dist",
        "build",
        "out",
        ".next",
        "__pycache__",
        ".venv",
        "venv",
        "target",
        ".idea",
        ".vscode",
        "coverage",
    }
)


@dataclass
class DetectionResult:
    primary_language: str | None
    languages: list[str] = field(default_factory=list)
    project_types: list[str] = field(default_factory=list)
    language_file_counts: dict[str, int] = field(default_factory=dict)
    marker_files: list[str] = field(default_factory=list)


def detect(root: str, max_files: int = 50_000) -> DetectionResult:
    """Detect languages/project types under `root`.

    Walks the tree once, ignoring vendored/build directories. Bounded by
    `max_files` so a hostile or huge repo cannot stall detection.
    """
    ext_counter: Counter[str] = Counter()
    found_markers: list[str] = []
    project_types: set[str] = set()
    marker_language_hits: Counter[str] = Counter()
    scanned = 0

    for dirpath, dirnames, filenames in os.walk(root):
        # Prune ignored directories in-place so os.walk skips them.
        dirnames[:] = [d for d in dirnames if d not in IGNORED_DIRS]

        for name in filenames:
            scanned += 1
            if scanned > max_files:
                break

            if name in _MARKER_FILES:
                ptype, lang = _MARKER_FILES[name]
                project_types.add(ptype)
                marker_language_hits[lang] += 1
                rel = os.path.relpath(os.path.join(dirpath, name), root)
                found_markers.append(rel)

            _, ext = os.path.splitext(name)
            lang = _EXTENSION_MAP.get(ext.lower())
            if lang:
                ext_counter[lang] += 1

        if scanned > max_files:
            break

    # Prefer the language with the most source files; fall back to marker hits.
    if ext_counter:
        primary = ext_counter.most_common(1)[0][0]
    elif marker_language_hits:
        primary = marker_language_hits.most_common(1)[0][0]
    else:
        primary = None

    languages = [lang for lang, _ in ext_counter.most_common()]

    return DetectionResult(
        primary_language=primary,
        languages=languages,
        project_types=sorted(project_types),
        language_file_counts=dict(ext_counter),
        marker_files=found_markers,
    )
