"""P3: hand triage of real-repository findings that no earlier pass recorded a verdict
for -- new rules (aegis-php-stored-xss) and findings that moved (the Python SQL rule now
reports at the execute call). Same shape as docs/ground_truth_n5/real_verdicts.py:
DEFAULT[(repo, rule)] covers every finding of that rule in that repo; EXCEPT keys
(repo, file-suffix, line, rule) override it.
"""
DEFAULT: dict = {}
EXCEPT: dict = {}
