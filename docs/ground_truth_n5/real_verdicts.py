"""Pass N5: hand triage of every security finding on the measured real-repository corpus
(V2's 15 at their recorded commits, N3's extended cmp-* repositories, spring-petclinic),
for the rules whose findings no earlier pass recorded a verdict for. Earlier verdicts
(N2b njsscan, N3 weakness rules) are reused where the finding is identical.

DEFAULT[(repo, rule)] applies to every finding of that rule in that repo; EXCEPT keys
(repo, file-suffix, line, rule) override it. A finding no entry covers is UNTRIAGED,
and an untriaged finding fails its language's precision criterion (utils/tier_bar.py).
Reasons are in docs/GROUND_TRUTH_N5.md §A.3.
"""
FP_ESC = "values pass through the project's escaper (DoliDB::escape, dol_escape_js) or an int cast; the rule does not model it"
FP_LOOKUP = "server data printed (a query result or configuration), not request data"
FP_INTERNAL_SQL = "SQL text built from internal identifiers or administrator configuration, no request input"
FP_SHELL_AS_SQL = "a shell command passed to a function named execute(); not SQL"
FP_DEV_TOOL = "developer tooling run by an operator with its own arguments; no attacker input"
FP_REDOS_LINEAR = "not catastrophic: each repetition needs a separator, so matching is linear"
UNC_REDOS_CLIENT = "catastrophic or unreadable (minified) shape, but the input is the browser's own data; no attacker input identified"
FP_ARRAY_FIND = "Array.prototype.find over an in-memory list, not a database query"

DEFAULT = {
    ("Dolibarr__dolibarr", "aegis-php-sql-injection"): ("FP", FP_ESC),
    ("Dolibarr__dolibarr", "aegis-php-xss"): ("FP", FP_ESC + "; or a translated / configured string"),
    ("FreshRSS__FreshRSS", "aegis-php-path-traversal"): ("FP", "the key is validated (hex format) or the path is built from a hash / MIME map"),
    ("librenms__librenms", "aegis-php-xss"): ("FP", FP_LOOKUP + "; or numbers (pagination) and URL-helper output"),
    ("cmp-django", "aegis-py-sql-string-construction"): ("FP", FP_INTERNAL_SQL + " (Django's own backends quote names with quote_name())"),
    ("cmp-ansible", "aegis-py-sql-string-construction"): ("FP", FP_DEV_TOOL),
    ("cmp-ansible", "aegis-py-shell-command-construction"): ("FP", FP_DEV_TOOL),
    ("cmp-kafka", "aegis-py-sql-string-construction"): ("FP", FP_SHELL_AS_SQL),
    ("getredash__redash", "aegis-py-sql-string-construction"): ("FP", FP_INTERNAL_SQL),
    ("librenms__librenms", "aegis-py-sql-string-construction"): ("FP", FP_INTERNAL_SQL),
    ("librenms__librenms", "aegis-py-shell-command-construction"): ("FP", "the command string is built internally from the poller's own job list"),
    ("nocodb__nocodb", "aegis-js-nosql-injection"): ("FP", FP_ARRAY_FIND),
    ("nocodb__nocodb", "aegis-js-redos-nested-quantifier"): ("FP", FP_REDOS_LINEAR),
    ("Dolibarr__dolibarr", "aegis-js-redos-nested-quantifier"): ("UNCERTAIN", UNC_REDOS_CLIENT),
    ("nilsteampassnet__TeamPass", "aegis-js-redos-nested-quantifier"): ("UNCERTAIN", UNC_REDOS_CLIENT),
    ("chatwoot__chatwoot", "aegis-js-redos-nested-quantifier"): ("FP", FP_REDOS_LINEAR),
    ("librenms__librenms", "aegis-js-redos-nested-quantifier"): ("FP", FP_REDOS_LINEAR),
    ("nopSolutions__nopCommerce", "aegis-js-redos-nested-quantifier"): ("FP", FP_REDOS_LINEAR),
    ("cmp-nest", "express_xss"): ("FP", "framework internals: an error message written by the streaming helper"),
    ("cmp-nest", "generic_header_injection"): ("FP", "a DI provider token, not an HTTP header"),
    ("cmp-nextauth", "generic_header_injection"): ("FP", "framework adapter copying a Response's own status and headers"),
    ("cmp-nextauth", "express_xss"): ("FP", "framework adapter writing a Response body it was handed"),
    ("cmp-terraform", "aegis-go-ssrf"): ("FP", "a test mock browser following its own test server's redirects"),
    ("cmp-vault", "aegis-go-xss"): ("FP", "websocket messages written to the CLI's stdout, not an HTTP response"),
    ("cmp-prisma", "aegis-js-sql-injection"): ("FP", "Prisma Studio's local query console executes queries by design"),
    ("cmp-prisma", "node_sqli_injection"): ("FP", "an integration-test fixture's setup SQL"),
    ("cmp-prisma", "express_xss"): ("FP", "a CLI writing to a stream, not an HTTP response"),
    ("cmp-prisma", "aegis-js-redos-nested-quantifier"): ("FP", FP_REDOS_LINEAR),
    ("cmp-prisma", "node_sha1"): ("FP", "a test computing a buffer checksum"),
    ("cmp-react", "generic_header_injection"): ("FP", "Map.set in the compiler, not an HTTP header"),
    ("cmp-react", "express_xss"): ("FP", "a JSON response (Content-type: application/json)"),
    ("cmp-react", "aegis-js-xss"): ("FP", "JSON.stringify of a source map written as JSON"),
    ("cmp-react", "aegis-js-redos-nested-quantifier"): ("FP", FP_REDOS_LINEAR),
    ("cmp-react", "node_md5"): ("FP", "a cache / content hash, not a security use"),
    ("cmp-react", "node_sha1"): ("FP", "a cache / content hash, not a security use"),
    ("cmp-react", "generic_path_traversal"): ("TP", "a dev fixture server reads join(dir, request.url): traversal as written"),
    ("cmp-react", "join_resolve_path_traversal"): ("TP", "a dev / bench server reads join(dir, request.url): traversal as written"),
    ("cmp-vault", "aegis-js-ssrf"): ("FP", "a service worker re-issuing the page's own same-origin request"),
    ("cmp-vault", "aegis-js-redos-nested-quantifier"): ("FP", FP_REDOS_LINEAR),
    ("cmp-vault", "aegis-js-nosql-injection"): ("FP", "Mirage, the UI test suite's in-memory mock server"),
}
EXCEPT = {
    ("Dolibarr__dolibarr", "core/lib/website.lib.php", 565, "aegis-php-xss"): ("TP", "REQUEST_URI-derived $currenturi printed unencoded"),
    ("Dolibarr__dolibarr", "install/inc.php", 666, "aegis-php-xss"): ("TP", "REQUEST_URI printed unencoded in the installer"),
    ("Dolibarr__dolibarr", "adherents/card.php", 1064, "aegis-php-xss"): ("TP", "HTTP_REFERER printed unescaped into an attribute"),
    ("Dolibarr__dolibarr", "adherents/card.php", 1388, "aegis-php-xss"): ("TP", "HTTP_REFERER printed unescaped into an attribute"),
    ("Dolibarr__dolibarr", "pastetools/filter/common.js", 24, "aegis-js-redos-nested-quantifier"): ("FP", FP_REDOS_LINEAR),
    ("nilsteampassnet__TeamPass", "install/upgrade.php", 281, "aegis-php-xss"): ("TP", "PHP_SELF (attacker-controllable path) printed into an attribute"),
    ("nilsteampassnet__TeamPass", "install/upgrade.php", 553, "aegis-php-xss"): ("TP", "PHP_SELF (attacker-controllable path) printed into a link"),
    ("cmp-django", "contrib/auth/hashers.py", 665, "aegis-py-weak-hash-credential"): ("TP", "Django's legacy salted-MD5 password hasher: md5 of a password"),
    ("getredash__redash", "bin/release_manager.py", 73, "aegis-py-tls-verification-disabled"): ("TP", "release upload with TLS verification switched off"),
}
