<?php
// Fixtures for rules/taint/php_weakness.yaml (Pass N3).

// ── weak random ─────────────────────────────────────────────────────────────
function weak_random_bad($user)
{
    // ruleid: aegis-php-weak-random-secret
    $csrf_token = md5(uniqid(rand(), true));
    // ruleid: aegis-php-weak-random-secret
    $_SESSION['csrf_token'] = sha1(microtime() . mt_rand());
    // ruleid: aegis-php-weak-random-secret
    $user->reset_token = substr(str_shuffle('abcdefghijklmnopqrstuvwxyz0123456789'), 0, 32);
    // ruleid: aegis-php-weak-random-secret
    $payload = ['api_key' => dechex(mt_rand())];
    // ruleid: aegis-php-weak-random-secret
    setcookie('remember_me', md5(uniqid()), ['secure' => true, 'httponly' => true]);
    return [$csrf_token, $payload];
}

// Real-code shapes that are NOT weak secrets (Dolibarr, TeamPass, FreshRSS triage)
function not_weak()
{
    // the pre-PHP-7 capability fallback: the else branch is dead
    if (function_exists('random_int')) {
        $c = random_int(0, 61);
    } else {
        $c = mt_rand(0, 61);
    }
    // ok: aegis-php-weak-random-secret
    $reset_token = $c;
    try {
        $t = bin2hex(random_bytes(10));
    } catch (Throwable $e) {
        // ok: aegis-php-weak-random-secret
        $api_token = uniqid('', true);
    }
    // CSPRNG output mixed in (FreshRSS generateSalt)
    // ok: aegis-php-weak-random-secret
    $salt = hash('sha256', uniqid('', true) . random_bytes(32));
    // a protocol nonce only needs uniqueness (Yubico, OAuth1)
    // ok: aegis-php-weak-random-secret
    $params = ['nonce' => md5(uniqid(rand()))];
    return [$reset_token, $salt, $params];
}

// a function that VERIFIES an OTP returns a verdict, not a secret (librenms TwoFactor)
function verifyHOTP($key, $otp)
{
    $counter = floor(microtime(true) / 30);
    // ok: aegis-php-weak-random-secret
    return $counter;
}

function generateSalt()
{
    // ruleid: aegis-php-weak-random-secret
    return substr(md5(mt_rand()), 0, 16);
}

function weak_random_ok($items, $tokens)
{
    // ok: aegis-php-weak-random-secret
    $index = array_rand($items);
    // ok: aegis-php-weak-random-secret
    $start = microtime(true);
    // the secret word is not the head noun
    // ok: aegis-php-weak-random-secret
    $token_expires = time() + mt_rand(0, 60);
    // a random value handed to a service does not make its answer weak
    // ok: aegis-php-weak-random-secret
    $session_token = $tokens->issue(mt_rand());
    // the fix
    // ok: aegis-php-weak-random-secret
    $csrf_token = bin2hex(random_bytes(32));
    return [$index, $start, $token_expires, $session_token, $csrf_token];
}

// ── weak hash ───────────────────────────────────────────────────────────────
function login_bad($db)
{
    $pass = $_POST['password'];
    // ruleid: aegis-php-weak-hash-credential
    $pass = md5($pass);
    // ruleid: aegis-php-weak-hash-credential
    $check = hash('sha1', $_POST['new_password']);
    // a non-password secret is not password storage (CRAM-MD5 key reduction)
    // ok: aegis-php-weak-hash-credential
    $key = pack('H32', md5($secret));
    return [$pass, $check];
}

function hash_password($raw)
{
    // ruleid: aegis-php-weak-hash-credential
    return sha1($raw);
}

function weak_hash_ok($body, $password)
{
    // ok: aegis-php-weak-hash-credential
    $etag = md5($body);
    // ok: aegis-php-weak-hash-credential
    $cache_key = sha1(serialize($body));
    // the fix
    // ok: aegis-php-weak-hash-credential
    $password_hash = password_hash($password, PASSWORD_DEFAULT);
    // a strong digest
    // ok: aegis-php-weak-hash-credential
    $digest = hash('sha256', $password);
    // "passport" is not "pass"
    // ok: aegis-php-weak-hash-credential
    $id = md5($passport_number);
    // an already-hashed input is not password storage (FreshRSS greader API token)
    // ok: aegis-php-weak-hash-credential
    $auth = sha1($salt . $user . $apiPasswordHash);
    // a digest that BECOMES a password (tcpdf random owner password)
    // ok: aegis-php-weak-hash-credential
    $owner_pass = md5(uniqid());
    return [$etag, $cache_key, $password_hash, $digest, $id, $auth, $owner_pass];
}

// Pwned Passwords k-anonymity range query (TeamPass): SHA-1 is the API's format
function pwned($password)
{
    // ok: aegis-php-weak-hash-credential
    $sha1 = strtoupper(sha1($password));
    $prefix = substr($sha1, 0, 5);
    return $prefix;
}

// HTTP Digest (RFC 7616) computes MD5(user:realm:password) by protocol (sabre)
function digest_response($username, $realm, $password)
{
    // ok: aegis-php-weak-hash-credential
    return md5($username . ':' . $realm . ':' . $password);
}

// ── weak cipher / key size: no context needed ───────────────────────────────
function ciphers($data, $key, $iv)
{
    // ruleid: aegis-php-weak-cipher
    $a = openssl_encrypt($data, 'des-ede3-cbc', $key, 0, $iv);
    // ruleid: aegis-php-weak-cipher
    $b = openssl_encrypt($data, 'aes-256-ecb', $key);
    // ruleid: aegis-php-weak-cipher
    $c = openssl_decrypt($data, 'bf-cbc', $key, 0, $iv);
    // ruleid: aegis-php-weak-cipher
    $d = mcrypt_encrypt(MCRYPT_RIJNDAEL_128, $key, $data, MCRYPT_MODE_ECB);
    // ruleid: aegis-php-weak-cipher
    $e = mcrypt_encrypt(MCRYPT_DES, $key, $data, MCRYPT_MODE_CBC, $iv);
    // ok: aegis-php-weak-cipher
    $f = openssl_encrypt($data, 'aes-256-gcm', $key, 0, $iv, $tag);
    // ECB opened as a primitive to build another mode (phpseclib CFB)
    // ok: aegis-php-weak-cipher
    $g = mcrypt_module_open(MCRYPT_RIJNDAEL_128, '', MCRYPT_MODE_ECB, '');
    return [$a, $b, $c, $d, $e, $f];
}

function keys()
{
    $weak = openssl_pkey_new(['private_key_bits' => 1024, 'private_key_type' => OPENSSL_KEYTYPE_RSA]);
    $ok = openssl_pkey_new(['private_key_bits' => 4096, 'private_key_type' => OPENSSL_KEYTYPE_RSA]);
    return [$weak, $ok];
}

// ── session cookie ──────────────────────────────────────────────────────────
function cookies($token)
{
    // ruleid: aegis-php-insecure-session-cookie
    setcookie('session_id', $token);
    // ruleid: aegis-php-insecure-session-cookie
    setcookie('auth_token', $token, time() + 3600, '/', '', true);
    // ruleid: aegis-php-insecure-session-cookie
    setcookie('remember_token', $token, ['expires' => time() + 86400, 'httponly' => true]);
    // ok: aegis-php-insecure-session-cookie
    setcookie('auth_token', $token, time() + 3600, '/', '', true, true);
    // ok: aegis-php-insecure-session-cookie
    setcookie('auth_token', $token, ['secure' => true, 'httponly' => true, 'samesite' => 'Lax']);
    // ok: aegis-php-insecure-session-cookie
    setcookie('csrf_token', $token);
    // ok: aegis-php-insecure-session-cookie
    setcookie('language', 'en');
    // deleting a cookie carries no secret
    // ok: aegis-php-insecure-session-cookie
    setcookie('session_id', '', time() - 3600);
}

// ruleid: aegis-php-insecure-session-cookie
ini_set('session.cookie_httponly', 0);
// ok: aegis-php-insecure-session-cookie
ini_set('session.cookie_secure', 1);
// ruleid: aegis-php-insecure-session-cookie
session_set_cookie_params(['lifetime' => 0, 'secure' => false, 'httponly' => true]);

// ── trust boundary ──────────────────────────────────────────────────────────
function trust()
{
    $_SESSION[$_GET['key']] = $_GET['value'];
    $_SESSION['is_admin'] = $_POST['admin'];
    $_SESSION['lang'] = $_GET['lang'];
    $_SESSION['role'] = lookup_role($_SESSION['user_id']);
}
