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

function xss_ok_json() {
    // An AJAX/JSON endpoint echoing json_encode() is a JSON response, not HTML —
    // not reflected XSS.
    $id = $_POST["id"];
    $row = get_row($id);
    // ok: aegis-php-xss
    echo json_encode($row);
}

function xss_still_bad_after_transform() {
    // A benign string transform must NOT clear taint — still reflected XSS.
    $name = $_GET["name"];
    // ruleid: aegis-php-xss
    echo "<h1>" . trim($name) . "</h1>";
}

// ── Stored XSS (P3): a DB read is stored data, not reflected request data ─────
function stored_xss_bad($link) {
    $res = mysqli_query($link, "SELECT bio FROM users WHERE id = 1");
    $row = mysqli_fetch_assoc($res);
    // ok: aegis-php-xss
    // ruleid: aegis-php-stored-xss
    echo "<p>" . $row["bio"] . "</p>";
}

function stored_xss_keyed_by_request_bad($pdo) {
    // the request only CHOSE the row; what is printed is the stored value
    $st = $pdo->prepare("SELECT name FROM users WHERE id = ?");
    $st->execute([$_GET["id"]]);
    $user = $st->fetch();
    // ok: aegis-php-xss
    // ruleid: aegis-php-stored-xss
    echo "<h1>" . $user["name"] . "</h1>";
}

function stored_xss_object_api_bad($mysqli) {
    $obj = $mysqli->query("SELECT title FROM posts")->fetch_object();
    // ruleid: aegis-php-stored-xss
    print $obj->title;
}

function stored_xss_escaped_ok($link) {
    $row = mysqli_fetch_assoc(mysqli_query($link, "SELECT bio FROM users"));
    // ok: aegis-php-stored-xss
    echo "<p>" . htmlspecialchars($row["bio"], ENT_QUOTES) . "</p>";
}

function stored_xss_numeric_ok($link) {
    $row = mysqli_fetch_assoc(mysqli_query($link, "SELECT n FROM counts"));
    // ok: aegis-php-stored-xss
    echo "<td>" . intval($row["n"]) . "</td>";
}

function reflected_not_stored($link) {
    // request data printed directly: reflected, and NOT also reported as stored
    // ok: aegis-php-stored-xss
    // ruleid: aegis-php-xss
    echo "<p>" . $_GET["q"] . "</p>";
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

function path_write_bad() {
    $name = $_GET["name"];
    // ruleid: aegis-php-path-traversal
    file_put_contents("/var/uploads/" . $name, "data");
}

function upload_bad() {
    $dest = "/var/uploads/" . $_POST["name"];
    // ruleid: aegis-php-path-traversal
    move_uploaded_file($_FILES["f"]["tmp_name"], $dest);
}

function upload_ok() {
    $dest = "/var/uploads/" . basename($_POST["name"]);
    // ok: aegis-php-path-traversal
    move_uploaded_file($_FILES["f"]["tmp_name"], $dest);
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
