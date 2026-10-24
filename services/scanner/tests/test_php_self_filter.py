"""N2 Part C: a project-wide PHP_SELF input filter drops PHP_SELF as an XSS source --
and nothing else does.

Dolibarr's first complete scan produced 2,362 `aegis-php-xss` findings, effectively
all false: it filters PHP_SELF at bootstrap in an included file, which an
intraprocedural taint engine cannot see. Detecting that filter cut it to 24, of which
3 are genuine findings the flood had been burying.

The risk in this direction is the opposite of a false positive: a detector that fires
too eagerly SILENCES a real vulnerability class. TeamPass's
`public/install/upgrade.php` PHP_SELF XSS is a true positive, so the tests below pin
both directions.
"""
from __future__ import annotations

import os
import textwrap

from engines import semgrep_engine as E

# The shape Dolibarr uses: one included file that reads PHP_SELF and rejects the
# characters an attribute/tag breakout needs, invoked at file scope.
DOLIBARR_SHAPE = textwrap.dedent("""\
    <?php
    function testSqlAndScriptInject($val, $type)
    {
        $inj = 0;
        if ($type == 2) {
            $inj += preg_match('/[:;"\\'<>\\?\\(\\){}\\$%#]/', $val);
            $inj += preg_match('/\\\\.\\\\./', $val);
        }
        return $inj;
    }
    if (!defined('NOSCANPHPSELFFORINJECTION') && !empty($_SERVER["PHP_SELF"])) {
        $more = array($_SERVER["PHP_SELF"]);
        analyseVarsForSqlAndScriptsInjection($more, 2);
    }
    """)


def _write(tmp_path, rel: str, body: str) -> None:
    p = tmp_path / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(body, encoding="utf-8")


def test_detects_a_bootstrap_php_self_character_filter(tmp_path):
    _write(tmp_path, "htdocs/waf.inc.php", DOLIBARR_SHAPE)
    _write(tmp_path, "htdocs/page.php",
           '<?php print \'<form action="\'.$_SERVER["PHP_SELF"].\'">\';')
    assert E._php_self_globally_filtered(str(tmp_path)) == "htdocs/waf.inc.php"


def test_plain_php_self_use_is_not_a_filter(tmp_path):
    """The TeamPass/DVWA shape: PHP_SELF is read and echoed, never filtered."""
    _write(tmp_path, "public/install/upgrade.php", textwrap.dedent("""\
        <?php
        $protocol = 'https://';
        print '<a href="'.$protocol.$_SERVER['HTTP_HOST'].substr($_SERVER['PHP_SELF'], 0, 5).'">x</a>';
        """))
    assert E._php_self_globally_filtered(str(tmp_path)) is None


def test_a_filter_without_quote_or_angle_rejection_does_not_count(tmp_path):
    """Rejecting `..` alone stops path traversal, NOT an attribute breakout. A
    partial filter must not silence the XSS class."""
    _write(tmp_path, "boot.php", textwrap.dedent("""\
        <?php
        if (preg_match('/\\\\.\\\\./', $_SERVER["PHP_SELF"])) { die('no'); }
        doSomething();
        """))
    assert E._php_self_globally_filtered(str(tmp_path)) is None


def test_a_guard_defined_but_never_reached_does_not_count(tmp_path):
    """A function that checks PHP_SELF but is never called at file scope proves
    nothing about what runs before a page renders."""
    _write(tmp_path, "lib.php", textwrap.dedent("""\
        <?php
        function maybeCheck() {
            return preg_match('/[<>"\\']/', $_SERVER["PHP_SELF"]);
        }
        """))
    assert E._php_self_globally_filtered(str(tmp_path)) is None


def test_augmentation_drops_only_the_php_self_source(tmp_path):
    """The rule must lose PHP_SELF and KEEP every other source, so a $_GET-sourced
    XSS in the same application still fires."""
    import yaml

    _write(tmp_path, "htdocs/waf.inc.php", DOLIBARR_SHAPE)
    rules_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(E.__file__))),
                             "rules", "taint")
    out, adjustments = E._augmented_taint_dir(str(tmp_path), rules_dir)
    assert out, "expected an augmented rule directory"
    with open(os.path.join(out, "php.yaml"), encoding="utf-8") as fh:
        doc = yaml.safe_load(fh)
    xss = next(r for r in doc["rules"] if r["id"] == "aegis-php-xss")
    patterns = [str(p.get("pattern", "")) for s in xss["pattern-sources"]
                for p in s.get("pattern-either", [])]
    assert not any("PHP_SELF" in p for p in patterns), patterns
    for kept in ("$_GET[...]", "$_POST[...]", "$_COOKIE[...]"):
        assert any(kept == p for p in patterns), f"{kept} must survive: {patterns}"
    # The suppression is reported with its evidence -- never silent.
    assert adjustments and adjustments[0]["dropped_source"] == "$_SERVER['PHP_SELF']"
    assert adjustments[0]["evidence"] == "htdocs/waf.inc.php"
    assert "character-class filter" in adjustments[0]["reason"]


def test_no_filter_means_no_adjustment(tmp_path):
    rules_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(E.__file__))),
                             "rules", "taint")
    _write(tmp_path, "a.php", '<?php echo $_SERVER["PHP_SELF"];')
    out, adjustments = E._augmented_taint_dir(str(tmp_path), rules_dir)
    assert adjustments == []
    assert out is None
