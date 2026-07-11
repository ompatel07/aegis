# Compliance Reports

Aegis turns a scan into **audit-ready technical evidence** across six frameworks.
Reports are generated from the same findings shown in the dashboard, mapped to
each framework's controls via CWE and OWASP category.

## Frameworks

| Framework | Version | Mapping file |
| --- | --- | --- |
| SOC 2 | 2017 Trust Services Criteria | [`compliance/frameworks/soc2.yaml`](compliance/frameworks/soc2.yaml) |
| PCI-DSS | 4.0 | [`compliance/frameworks/pci_dss.yaml`](compliance/frameworks/pci_dss.yaml) |
| HIPAA Security Rule | 45 CFR §164.312 | [`compliance/frameworks/hipaa.yaml`](compliance/frameworks/hipaa.yaml) |
| ISO/IEC 27001 | 2022 Annex A | [`compliance/frameworks/iso27001.yaml`](compliance/frameworks/iso27001.yaml) |
| OWASP ASVS | 4.0.3 (L1/L2/L3) | [`compliance/frameworks/owasp_asvs.yaml`](compliance/frameworks/owasp_asvs.yaml) |
| NIST CSF | 2.0 | [`compliance/frameworks/nist_csf.yaml`](compliance/frameworks/nist_csf.yaml) |

Mapping methodology + honest-scope statement: [`compliance/README.md`](compliance/README.md).

## What each report contains (5b–5g)

- **Executive summary** — compliance score (in-scope controls passing),
  controls needing attention, control coverage, scan grade.
- **Findings by control** — every in-scope control with its status
  (Passing / Needs attention / Requires external evidence) and the open findings
  attributed to it.
- **Remediation timeline** — failing controls ordered by an SLA derived from the
  worst open finding severity (critical 7d / high 30d / medium 90d / low 180d).
- **Audit-trail evidence** — the scan id, commit, and timestamp anchor the report
  to an immutable scan; findings carry file/line + rule provenance.
- **Historical trend** — score over successive scans (the generator accepts a
  series; the dashboard renders the sparkline).
- **Legal disclaimer** — every report states it is automated technical evidence,
  not a certification, and must be validated by a qualified assessor.

## Generating a report (5h)

```bash
# HTML (always available)
python -m compliance.report --framework soc2 \
    --findings scan_export.json --out soc2.html

# PDF (weasyprint)
python -m compliance.report --framework pci_dss \
    --findings scan_export.json --out pci_dss.pdf
```

`scan_export.json` is `{ "scan": {project, grade, commit}, "findings": [ … ] }` —
exactly the finding shape the API already emits (`cwe_id`, `owasp_category`,
`severity`, `is_false_positive`, `is_suppressed`, `title`, `file_path`).

**PDF pipeline.** `render_pdf()` uses **WeasyPrint** (`weasyprint` in the
scanner's `requirements.txt`). It is an optional import — HTML generation never
requires it, so the feature degrades gracefully where WeasyPrint's native libs
are unavailable.

**Scheduled reports + email delivery.** Report generation reuses the existing
notification dispatcher (`services/api/internal/notify`): an org can schedule a
framework report on scan-complete or on a cron cadence, and the rendered PDF is
delivered via the same email provider abstraction (log/Resend/SendGrid/SMTP)
used for scan alerts. The generator is the unit of work; the scheduler enqueues
`(org, framework, cadence)` and attaches the PDF.

## Scoring model

- A finding maps to a control when its CWE **or** OWASP category is listed in the
  control's `evidence`.
- `open` = not false-positive and not suppressed.
- In-scope control with ≥1 open finding → **Needs attention**; else **Passing**.
- Out-of-scope controls (organizational/physical/process) are reported as
  **Requires external evidence** — never counted as passing. This keeps the
  compliance score honest: Aegis attests only what static analysis can prove.

## Accuracy & review

The control↔CWE/OWASP relationships follow well-established mappings (OWASP
Top-10 ↔ CWE, ASVS ↔ CWE, and each framework's published technical requirements).
They are a **reviewed, defensible baseline** intended to accelerate an audit, not
replace an assessor's judgment. Scope decisions (`aegis_scope: out-of-scope`) are
deliberately conservative.
