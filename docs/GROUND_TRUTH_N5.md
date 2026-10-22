# Pass N5 — a STRONG bar that can fail, PHP measured, Java/Python gaps closed

## C. Holdout, recorded before any rule change

**Why.** N4's rule-gap list was read off the same corpora N5's rules would be measured
on, so recall on them after the fixes is inflated by construction. Held-out corpora are
fixed here, in a commit made before any N5 rule edit. **N5 writes rules only from the
tuning corpora's gap list. Part A's recall criterion is evaluated on held-out recall.**

**How the corpora were chosen.** I did not pick them. They were drawn by
`services/scanner/tools/draw_holdout.py`, which writes
`services/scanner/accuracy/holdout.json`:

1. **The pool** is every qualifying N4 corpus except those already used to write or change a rule:

   | excluded | why |
   |---|---|
   | Security Shepherd | N4 fixed the Java cookie rule on it; the `aegis-java-xss` precision work comes from its findings |
   | PyGoat | N4 fixed the Python cookie rule on it; the `shell=True` fix comes from it |
   | VulnerableApp | N4 promoted `aegis-java-weak-cipher` on its findings |
   | DVGA (Go) | N4 promoted two Go rules on its findings |
   | dvpwa | F1 ground truth; every pass since F1 gates on it |

2. **The seed** is N4's final commit, `b07254804600f5aa849bdb8d7d574c0d1c85de11`.
3. **The draw** shuffles the pool with that seed and holds corpora out in that order,
   until the held-out set has at least min(20, half the language's in-scope items).

| language | held out (commit) | in scope | tuning | in scope |
|---|---|--:|---|--:|
| **Java** | java-sec-code (`4711f4e186258c6e0dd5c3863e7c9592e7e9026a`) · dvja (`597ece1ab79ffffea7289d49b0c443bb2ebcbd16`) | 34 | VulnerableApp, Security Shepherd, JavaVulnerableLab, Javulna | 175 |
| **Python** | DSVW (`9ca3c9acf3defa0a6148d40e5f5cebeb5dcbb908`) · django.nV (`a48901f106da4888417339b7b44b8ed56b64c63f`) · lets-be-bad-guys (`7cbf11014bfc6dc9e199dc0b8a64e4597bc2338f`) | 38 | PyGoat, DVGraphQL, dvpwa | 34 |
| **Go** | damn-vulnerable-golang (`fad5655a69879d37010b40044a5d4f4d305ee916`) · go-test-bench (`92445700823205281369911a72b7127f18c8c9ed`) · GoVWA (`4058f79f31eeb4a36d8f1e64bba1f0c899646e6f`) · not-going-anywhere (`3ea1a49de1c399633e513f0348752b7f0098b7c1`) | 25 | DVGA (Go) | 10 |

**PHP.** N5 writes no PHP rule. The Part B corpora (bWAPP, Mutillidae II, XVWA) are
measured for the first time in N5, so they are held out by construction. DVWA is tuning:
earlier passes gated on it.

**JavaScript / TypeScript.** N5 writes no JS/TS rule. Their only ground-truth corpora,
NodeGoat and juice-shop, are F1/N1 ground truth that every pass since has gated rule
changes on, so they are tuning corpora.

**Baseline before any N5 change** (N4 rules, N4 scans):

| language | held-out recall | tuning recall |
|---|--:|--:|
| Java | 4/34 = 12% | 27/175 = 15% |
| Python | 8/38 = 21% | 10/34 = 29% |
| Go | 4/25 = 16% | 1/10 = 10% |

**What the holdout takes off N5's list.** These N4 rule-gap items sit in held-out
corpora, so N5 writes no rule from them:
- Java: 5 of the 6 *unannotated Spring handler parameter* items (java-sec-code). The
  brief's Part D names this gap, but Part C forbids it.
- Java: redirect (2).
- Python: raw `http.server` sources (DSVW), Django `DEBUG`, `@csrf_exempt`, redirect.

If a rule written from the tuning list catches one of these items, that is
generalisation, and it is counted.
