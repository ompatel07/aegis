"""SBOM sanitiser tests (J1 Part A).

Trivy names its SBOM after the path it scanned. For us that is an internal
checkout directory, which made every SPDX document we produced fail the official
SPDX validator (measured: 543 errors on redash, 383 on NodeGoat, 8 on DVWA) and
put our filesystem layout into a document customers hand to auditors.

These tests pin the three properties that fix depends on: no local path survives,
the SPDX download location becomes a spec-valid sentinel, and the SBOM names its
author. The end-to-end proof against the real validators lives in
docs/COMPLIANCE_ACCURACY_J1.md; this file keeps the behaviour from regressing
without needing spdx-tools installed.
"""
from __future__ import annotations

import pytest

from utils import sbom_sanitize as S

REPO = "https://github.com/OWASP/NodeGoat"


def _spdx_doc() -> dict:
    """The shape Trivy actually emits, reduced to what the sanitiser touches."""
    return {
        "spdxVersion": "SPDX-2.3",
        "name": "/workspaces/_f1/NodeGoat",
        "documentNamespace": "http://trivy.dev/repository//workspaces/_f1/NodeGoat-084f254f-23b7-44ff-b521-29b84efd65d3",
        "creationInfo": {"creators": ["Organization: aquasecurity", "Tool: trivy-0.71.2"]},
        "packages": [
            {
                "name": "/workspaces/_f1/NodeGoat",
                "SPDXID": "SPDXRef-Repository-146e79686c1a2a40",
                "downloadLocation": "git+/workspaces/_f1/NodeGoat",
            },
            {
                "name": "abbrev",
                "versionInfo": "1.1.1",
                "downloadLocation": "git+/workspaces/_f1/NodeGoat",
                "externalRefs": [
                    {"referenceType": "purl", "referenceLocator": "pkg:npm/abbrev@1.1.1"},
                    {"referenceType": "advisory", "referenceLocator": ""},
                ],
            },
        ],
    }


def _cdx_doc() -> dict:
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.7",
        "metadata": {
            "timestamp": "2026-09-08T07:59:25+00:00",
            "tools": {"components": [{"name": "trivy", "version": "0.71.2"}]},
            "component": {"type": "application", "name": "/workspaces/_f1/NodeGoat"},
        },
        "components": [{"name": "abbrev", "version": "1.1.1", "purl": "pkg:npm/abbrev@1.1.1"}],
    }


# ── the leak ──────────────────────────────────────────────────────────────────

def test_spdx_removes_every_internal_path():
    import json
    out = json.dumps(S.sanitize("spdx", _spdx_doc(), REPO))
    assert "/workspaces/" not in out, "an internal checkout path survived into the SPDX document"


def test_cyclonedx_removes_internal_path():
    import json
    out = json.dumps(S.sanitize("cyclonedx", _cdx_doc(), REPO))
    assert "/workspaces/" not in out


def test_root_package_name_is_sanitised_not_only_the_document_name():
    """The document name and the synthesised root package both carry the path;
    fixing only the former leaves the leak in place."""
    doc = S.sanitize("spdx", _spdx_doc(), REPO)
    assert doc["name"] == REPO
    assert doc["packages"][0]["name"] == REPO


# ── SPDX validity ─────────────────────────────────────────────────────────────

def test_local_download_location_becomes_noassertion():
    doc = S.sanitize("spdx", _spdx_doc(), REPO)
    assert all(p["downloadLocation"] == S.NOASSERTION for p in doc["packages"])


def test_real_download_urls_are_preserved():
    """Only the invalid local-path form is replaced; a genuine URL must survive,
    otherwise we would be destroying real provenance to satisfy a validator."""
    doc = _spdx_doc()
    doc["packages"][1]["downloadLocation"] = "https://registry.npmjs.org/abbrev/-/abbrev-1.1.1.tgz"
    doc["packages"][0]["downloadLocation"] = "git+https://github.com/OWASP/NodeGoat.git"
    out = S.sanitize("spdx", doc, REPO)
    assert out["packages"][1]["downloadLocation"] == "https://registry.npmjs.org/abbrev/-/abbrev-1.1.1.tgz"
    assert out["packages"][0]["downloadLocation"] == "git+https://github.com/OWASP/NodeGoat.git"


def test_empty_external_refs_are_dropped_but_real_ones_kept():
    doc = S.sanitize("spdx", _spdx_doc(), REPO)
    refs = doc["packages"][1]["externalRefs"]
    assert len(refs) == 1
    assert refs[0]["referenceLocator"] == "pkg:npm/abbrev@1.1.1"


def test_namespace_does_not_nest_a_url_inside_a_url():
    doc = S.sanitize("spdx", _spdx_doc(), REPO)
    ns = doc["documentNamespace"]
    assert ns.count("://") == 1, f"namespace nests a second URL: {ns}"
    assert "084f254f-23b7-44ff-b521-29b84efd65d3" in ns, "the uniqueness suffix was dropped"


# ── NTIA element 6: author of the SBOM data ───────────────────────────────────

def test_cyclonedx_records_an_author():
    doc = S.sanitize("cyclonedx", _cdx_doc(), REPO)
    assert doc["metadata"]["authors"], "NTIA requires the author of the SBOM data"


def test_spdx_records_an_author_without_dropping_trivy():
    doc = S.sanitize("spdx", _spdx_doc(), REPO)
    creators = doc["creationInfo"]["creators"]
    assert any("Aegis" in c for c in creators)
    assert any("trivy" in c for c in creators), "the generating tool must still be attributed"


# ── credential safety ─────────────────────────────────────────────────────────

@pytest.mark.parametrize("url,expected", [
    ("https://x-token:ghp_secret@github.com/o/r", "https://github.com/o/r"),
    ("https://user:pw@gitlab.com/g/p.git", "https://gitlab.com/g/p.git"),
    ("https://github.com/o/r", "https://github.com/o/r"),
])
def test_credentials_never_reach_the_sbom(url, expected):
    """A clone URL should not carry a credential, but if one ever does, an SBOM
    is a downloadable artifact and the last place it should appear."""
    assert S.project_identity(url) == expected


def test_missing_repo_url_falls_back_to_a_neutral_name_not_the_path():
    doc = S.sanitize("spdx", _spdx_doc(), None)
    assert "/workspaces/" not in doc["name"]
    assert doc["name"] == "project"
