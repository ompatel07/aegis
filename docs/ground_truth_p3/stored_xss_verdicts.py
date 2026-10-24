"""P3: verdicts for the 60 sampled aegis-php-stored-xss findings (stored_xss_sample.json,
drawn by sample_stored_xss.py; criteria fixed in docs/PRECISION_P3.md §C.0 before the
draw). Index -> (verdict, why). A TP is a value some user can write reaching the HTML
unescaped. Dolibarr also filters request input on write (its WAF rejects common script
payloads); the criteria credit only escaping on the way OUT, so every TP here is one the
WAF may in practice block -- the figure is an upper bound.

usage: python stored_xss_verdicts.py   (prints the tally and the Wilson interval)
"""
import math

ID = "an id / number / count / amount / date, or an internal value"
ESC = "escaped on the way out (getNomUrl escapes or strips; textwithtooltip escapes its tooltip)"
STATUS = "a status / enum label"
V = {
    0: ("FP", "dol_get_fiche_head(): tabs built from internal, translated labels"),
    1: ("FP", STATUS), 2: ("TP", "length_accounta($obj->subaccount): a user-entered accounting code, printed raw"),
    3: ("FP", ID), 4: ("FP", ESC), 5: ("FP", ESC), 6: ("FP", ESC), 7: ("FP", ESC), 8: ("FP", ID), 9: ("FP", ID),
    10: ("FP", ESC), 11: ("FP", ID), 12: ("FP", "selectDate(): a date widget"), 13: ("FP", ID),
    14: ("TP", "$objp->numr: a user-entered bank-statement number, printed raw into an attribute"),
    15: ("FP", ID), 16: ("FP", ID), 17: ("FP", ID), 18: ("FP", ID), 19: ("FP", ID), 20: ("FP", ID),
    21: ("FP", STATUS), 22: ("FP", ID),
    23: ("TP", "p.ref: a user-entered project ref, printed raw"),
    24: ("TP", "$obj->country: a country label from an admin-editable dictionary, printed raw"),
    25: ("FP", ID), 26: ("FP", ID), 27: ("FP", ID),
    28: ("TP", "dol_trunc($obj->label): a product label, truncated not escaped"),
    29: ("FP", "an installer's SQL error from Dolibarr's own migration scripts"),
    30: ("FP", STATUS), 31: ("FP", ID), 32: ("FP", ID), 33: ("FP", ID), 34: ("FP", ID), 35: ("FP", ID),
    36: ("FP", ID), 37: ("FP", ESC), 38: ("FP", STATUS), 39: ("FP", ESC), 40: ("FP", ID),
    41: ("TP", "getFullName(): a recruitment candidate's name (the public application form), not escaped"),
    42: ("FP", ID), 43: ("FP", ID), 44: ("FP", ID), 45: ("FP", ID),
    46: ("FP", "a CSV download (Content-Type: text/csv), not HTML"),
    47: ("FP", STATUS), 48: ("FP", ID), 49: ("FP", ID), 50: ("FP", ID), 51: ("FP", ID), 52: ("FP", ID),
    53: ("FP", ID), 54: ("FP", ID),
    55: ("UNCERTAIN", "TakePOS menu titles: translations, possibly a DB-sourced entry; not settled from the code"),
    56: ("FP", ESC), 57: ("FP", "a system notification-trigger label, not user-editable"),
    58: ("FP", "a module name"), 59: ("FP", ID),
}

if __name__ == "__main__":
    tp = sum(v == "TP" for v, _ in V.values())
    fp = sum(v == "FP" for v, _ in V.values())
    unc = sum(v == "UNCERTAIN" for v, _ in V.values())
    n, z = tp + fp, 1.959964
    p = tp / n
    d, c = 1 + z * z / n, p + z * z / (2 * n)
    r = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n))
    print(f"{len(V)} sampled: {tp} TP, {fp} FP, {unc} UNCERTAIN; precision {tp}/{n} = {p:.1%} "
          f"[{(c - r) / d:.1%}, {(c + r) / d:.1%}]")
