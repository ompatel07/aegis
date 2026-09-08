"""Post-process Trivy's SBOM output before we store or hand it to anyone (J1).

Trivy names the SBOM after the *path it scanned*. For us that path is an internal
checkout directory, which produces three problems in a document that goes to a
customer's auditor:

1. **The SPDX document is invalid.** Every package gets
   ``downloadLocation: "git+/tmp/aegis-checkout-1234"``, and the official SPDX
   validator (spdx-tools) rejects that as not a valid download location. Measured
   before this fix: 543 validation errors on one Python repo, 383 on one npm repo
   — every SPDX document we produced failed.
2. **It leaks our internal filesystem layout** into a downloadable artifact.
3. **It is simply false.** No npm package was downloaded from our scratch
   directory, so the field asserts something untrue about provenance.

We also add the SBOM's author. NTIA's minimum elements require the *author of the
SBOM data*, and Trivy fills in only ``tools`` (itself). Naming the tool is not
naming the author, so we add Aegis explicitly.

What we deliberately do NOT do: invent supplier names for components. Trivy does
not resolve them, and guessing a supplier from a registry namespace would be
fabricated provenance in an audit document. That gap is reported honestly in
docs/COMPLIANCE_ACCURACY_J1.md rather than papered over.
"""
from __future__ import annotations

import re
from typing import Any
from urllib.parse import urlsplit, urlunsplit

# SPDX's own sentinel for "we did not determine this". Spec-valid, and honest.
NOASSERTION = "NOASSERTION"

_SBOM_AUTHOR = "Aegis"

# A download location Trivy could plausibly emit that IS legitimate: a real URL,
# or an SPDX VCS locator whose target is a URL (git+https://…). Anything else —
# in practice `git+/local/path` — is replaced.
_VALID_DOWNLOAD = re.compile(
    r"^(NONE|NOASSERTION|(git|hg|svn|bzr)\+[a-z][a-z0-9+.-]*://|[a-z][a-z0-9+.-]*://)",
    re.IGNORECASE,
)


def _strip_credentials(url: str) -> str:
    """Remove any user:password@ from a URL. A clone URL should never carry a
    credential, but if one ever does, an SBOM is the last place it should land."""
    try:
        parts = urlsplit(url)
    except ValueError:
        return url
    if not parts.netloc or "@" not in parts.netloc:
        return url
    host = parts.netloc.rsplit("@", 1)[1]
    return urlunsplit((parts.scheme, host, parts.path, parts.query, parts.fragment))


def project_identity(repo_url: str | None, fallback: str = "project") -> str:
    """A stable, non-leaking name for the thing the SBOM describes.

    Prefers the repository URL (credentials stripped). Falls back to a neutral
    constant rather than the scan path — the whole point is to keep local paths
    out of the document."""
    if not repo_url:
        return fallback
    clean = _strip_credentials(repo_url.strip())
    return clean or fallback


def _namespace_slug(identity: str) -> str:
    """A URL-path-safe slug for the document namespace.

    The identity is usually a full clone URL; embedding one URL inside another
    produces a namespace like `https://aegis.dev/spdx/https://github.com/...`,
    which is ugly and confuses readers. Use host + path only."""
    try:
        parts = urlsplit(identity)
    except ValueError:
        parts = None
    if parts and parts.scheme and parts.netloc:
        raw = f"{parts.netloc}{parts.path}"
    else:
        raw = identity
    raw = re.sub(r"\.git$", "", raw.strip("/"))
    return re.sub(r"[^A-Za-z0-9._/-]", "-", raw) or "project"


def _looks_like_path(value: Any) -> bool:
    """True for the local-path shapes Trivy substitutes into name fields."""
    if not isinstance(value, str) or not value:
        return False
    return value.startswith(("/", "./", "../")) or bool(re.match(r"^[A-Za-z]:[\\/]", value))


def sanitize_cyclonedx(doc: dict, repo_url: str | None) -> dict:
    """Replace the scanned-path component name and record the SBOM author."""
    identity = project_identity(repo_url)
    md = doc.get("metadata")
    if isinstance(md, dict):
        comp = md.get("component")
        if isinstance(comp, dict) and _looks_like_path(comp.get("name")):
            comp["name"] = identity
        # NTIA element 6 — author of the SBOM data. Trivy records only itself as
        # a tool; the author is us.
        if not md.get("authors"):
            md["authors"] = [{"name": _SBOM_AUTHOR}]
    return doc


def sanitize_spdx(doc: dict, repo_url: str | None) -> dict:
    """Make the SPDX document valid and free of internal paths.

    Returns the same dict, mutated."""
    identity = project_identity(repo_url)

    if _looks_like_path(doc.get("name")):
        doc["name"] = identity

    # documentNamespace embeds the same path; rebuild it around the identity
    # while preserving the UUID Trivy generated (namespaces must stay unique).
    ns = doc.get("documentNamespace")
    if isinstance(ns, str) and ns:
        uuid_match = re.search(r"[0-9a-fA-F-]{36}$", ns)
        suffix = uuid_match.group(0) if uuid_match else ""
        doc["documentNamespace"] = f"https://aegis.dev/spdx/{_namespace_slug(identity)}-{suffix}".rstrip("-")

    ci = doc.get("creationInfo")
    if isinstance(ci, dict):
        creators = ci.get("creators")
        if isinstance(creators, list):
            org = f"Organization: {_SBOM_AUTHOR}"
            if org not in creators:
                creators.insert(0, org)

    for pkg in doc.get("packages") or []:
        if not isinstance(pkg, dict):
            continue
        # The root package Trivy synthesises for the scan target is named after
        # the path as well, not just the document.
        if _looks_like_path(pkg.get("name")):
            pkg["name"] = identity
        dl = pkg.get("downloadLocation")
        if not isinstance(dl, str) or not _VALID_DOWNLOAD.match(dl):
            pkg["downloadLocation"] = NOASSERTION
        # An externalRef whose locator is empty fails validation; an empty
        # reference carries no information, so drop it rather than fake one.
        refs = pkg.get("externalRefs")
        if isinstance(refs, list):
            kept = [r for r in refs if isinstance(r, dict) and str(r.get("referenceLocator") or "").strip()]
            if kept:
                pkg["externalRefs"] = kept
            else:
                pkg.pop("externalRefs", None)
    return doc


def sanitize(fmt: str, doc: dict, repo_url: str | None) -> dict:
    if fmt == "cyclonedx":
        return sanitize_cyclonedx(doc, repo_url)
    if fmt == "spdx":
        return sanitize_spdx(doc, repo_url)
    return doc
