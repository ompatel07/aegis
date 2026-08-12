<?php
// Test fixtures for rules/taint/php.yaml — consumed by `semgrep --test`.
//
// Each rule has a positive case (annotation: the rule MUST fire on the next line)
// and a sanitized negative case (annotation: it must NOT fire). Mirrors the
// Python/JS/Go/Java fixtures. Never scanned in production (--config loads only
// *.yaml as rules).

// ── SQL injection ────────────────────────────────────────────────────────────
function sqli_bad($conn) {
    $id = $_GET["id"];
    // ruleid: aegis-php-sql-injection
    return mysqli_query($conn, "SELECT * FROM users WHERE id = " . $id);
}

function sqli_bad_method($conn) {
    $id = $_POST["id"];
    // ruleid: aegis-php-sql-injection
    return $conn->query("SELECT * FROM users WHERE id = " . $id);
}

function sqli_ok_prepared($conn) {
    $id = $_GET["id"];
    $stmt = $conn->prepare("SELECT * FROM users WHERE id = ?");
    $stmt->bind_param("i", $id);
    // ok: aegis-php-sql-injection
    return $stmt->execute();
}

function sqli_ok_cast($conn) {
    $id = intval($_GET["id"]);
    // ok: aegis-php-sql-injection
    return mysqli_query($conn, "SELECT * FROM users WHERE id = " . $id);
}

// ── Reflected XSS ────────────────────────────────────────────────────────────
function xss_bad() {
    $name = $_GET["name"];
    // ruleid: aegis-php-xss
    echo "<h1>Hello " . $name . "</h1>";
}

function xss_ok() {
    $name = $_GET["name"];
    // ok: aegis-php-xss
    echo "<h1>Hello " . htmlspecialchars($name, ENT_QUOTES) . "</h1>";
}

// ── OS command injection ─────────────────────────────────────────────────────
function cmd_bad() {
    $host = $_GET["host"];
    // ruleid: aegis-php-command-injection
    system("ping -c 1 " . $host);
}

function cmd_bad_shell_exec() {
    $host = $_REQUEST["host"];
    // ruleid: aegis-php-command-injection
    return shell_exec("nslookup " . $host);
}

function cmd_ok() {
    $host = $_GET["host"];
    // ok: aegis-php-command-injection
    system("ping -c 1 " . escapeshellarg($host));
}

// ── Path traversal / LFI ─────────────────────────────────────────────────────
function path_bad() {
    $page = $_GET["page"];
    // ruleid: aegis-php-path-traversal
    include "/var/www/pages/" . $page;
}

function path_bad_read() {
    $file = $_GET["file"];
    // ruleid: aegis-php-path-traversal
    return file_get_contents("/var/data/" . $file);
}

function path_ok() {
    $file = $_GET["file"];
    $safe = basename($file);
    // ok: aegis-php-path-traversal
    return file_get_contents("/var/data/" . $safe);
}

// ── LDAP injection ───────────────────────────────────────────────────────────
function ldap_bad($conn) {
    $user = $_GET["user"];
    $filter = "(uid=" . $user . ")";
    // ruleid: aegis-php-ldap-injection
    return ldap_search($conn, "dc=example,dc=com", $filter);
}

function ldap_ok($conn) {
    $user = $_GET["user"];
    $filter = "(uid=" . ldap_escape($user, "", LDAP_ESCAPE_FILTER) . ")";
    // ok: aegis-php-ldap-injection
    return ldap_search($conn, "dc=example,dc=com", $filter);
}
