# Compliance Control Mappings

Aegis maps its findings to compliance-framework controls so a scan doubles as
**technical evidence** for an audit. The mapping pivots on two stable properties
every finding carries — its **CWE** (`cwe_id`) and **OWASP** category
(`owasp_category`) — plus the scanner **pillar** (security / deployment).

## How the mapping works

Each framework file (`frameworks/<framework>.yaml`) lists the controls Aegis can
provide evidence for. A control declares the finding signals that map to it:

```yaml
- id: CC6.1
  name: Logical & Physical Access Controls
  evidence:
    owasp: ["A01:2021", "A07:2021"]     # OWASP Top-10 2021 categories
    cwe:   ["CWE-284", "CWE-287"]        # CWE identifiers
    pillars: ["security"]
```

At report time each finding is attributed to every control whose `evidence`
matches its CWE **or** OWASP category. A control with ≥1 open (non-suppressed,
non-false-positive) finding is **Needs attention**; a control in scope with zero
open findings is **Passing (no exceptions found)**.

## Honest scope

Aegis performs **static application + dependency + secret + IaC analysis**. It
can therefore evidence the *technical / code-level* controls of a framework —
injection defenses, crypto usage, access-control patterns in code, dependency
CVEs, secret hygiene, deployment misconfig. It **cannot** attest to
organizational, physical, HR, or process controls (background checks, physical
security, vendor management, incident-response drills). Those are marked
`aegis_scope: out-of-scope` and appear in reports as *"requires external
evidence"* — never as passing.

**These mappings are a reviewed, defensible starting point, not a certification.**
A qualified auditor/assessor must validate scope and evidence before any formal
attestation. Every generated report carries this disclaimer.

## Frameworks

| File | Framework | Basis |
| --- | --- | --- |
| `frameworks/soc2.yaml` | SOC 2 | 2017 Trust Services Criteria |
| `frameworks/pci_dss.yaml` | PCI-DSS 4.0 | Requirements 2, 3, 4, 6, 8 |
| `frameworks/hipaa.yaml` | HIPAA Security Rule | §164.312 Technical Safeguards |
| `frameworks/iso27001.yaml` | ISO/IEC 27001:2022 | Annex A (8.x technical) |
| `frameworks/owasp_asvs.yaml` | OWASP ASVS 4.0 | L1/L2/L3 verification reqs |
| `frameworks/nist_csf.yaml` | NIST CSF 2.0 | Function/Category/Subcategory |

Generator: [`services/scanner/compliance/report.py`](../services/scanner/compliance/report.py).
Report samples + PDF pipeline: [`COMPLIANCE_REPORTS.md`](../COMPLIANCE_REPORTS.md).
