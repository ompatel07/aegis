<?php
// ── Stored XSS (P3): a DB read is stored data, not reflected request data ─────
function stored_xss_bad($link) {
    $res = mysqli_query($link, "SELECT bio FROM users WHERE id = 1");
    $row = mysqli_fetch_assoc($res);
    // ruleid: aegis-php-stored-xss
    echo "<p>" . $row["bio"] . "</p>";
}

function stored_xss_keyed_by_request_bad($pdo) {
    // the request only CHOSE the row; what is printed is the stored value
    $st = $pdo->prepare("SELECT name FROM users WHERE id = ?");
    $st->execute([$_GET["id"]]);
    $user = $st->fetch();
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
    echo "<p>" . $_GET["q"] . "</p>";
}

