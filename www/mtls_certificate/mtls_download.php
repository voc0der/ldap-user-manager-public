<?php
declare(strict_types=1);
set_include_path('.:' . __DIR__ . '/../includes/');
include_once 'web_functions.inc.php';
include_once 'apprise_helpers.inc.php';
@session_start();
set_page_access('auth');

/**
 * mtls_download.php
 * - Validates single-use token
 * - Checks staged file is ready
 * - Marks token used
 * - Hands file delivery to the front proxy via X-Accel-Redirect
 * - Sends a styled Apprise notification
 */

// ---------- Helpers ----------
function client_ip(): string
{
  return apprise_client_ip();
}
function hard_fail(int $code, string $msg)
{
  http_response_code($code);
  header('Content-Type: text/plain; charset=UTF-8');
  header('X-Content-Type-Options: nosniff');
  echo $msg;
  exit;
}

// ---------- AuthZ ----------
$uid = trim((string)($USER_ID ?? ($_SESSION['user_id'] ?? '')));
$groups = function_exists('lum_current_user_groups_lower') ? lum_current_user_groups_lower() : [];
if (!$uid || !in_array('mtls', $groups, true)) {
  hard_fail(403, 'Forbidden');
}

// ---------- Input ----------
$token = isset($_GET['token']) ? (string)$_GET['token'] : '';
if (!preg_match('/^[a-f0-9]{48}$/', $token)) {
  hard_fail(400, 'Bad token');
}

// ---------- Paths ----------
$APP_ROOT = dirname(__DIR__);        // /opt/ldap_user_manager
$DATA     = $APP_ROOT . '/data/mtls';
$TOKENS   = $DATA . '/tokens';
$LOGS     = $DATA . '/logs';

// staging root, if it is mounted inside this container (read-only)
$STAGE_BASE = getenv('MTLS_STAGE_BASE') ?: '/mtls_stage';

// ---------- Validate token ----------
$token_hash = hash('sha256', $token);
$tfile      = $TOKENS . '/' . $token_hash . '.json';
$ufile      = $tfile . '.used';

if (!file_exists($tfile)) {
  // if there's a used record, report gone; otherwise not found
  if (file_exists($ufile)) {
    hard_fail(410, 'Token already used');
  }
  hard_fail(404, 'Token not found');
}

$rec = json_decode((string)file_get_contents($tfile), true) ?: null;
if (!$rec) {
  hard_fail(400, 'Token parse error');
}
if (($rec['exp'] ?? 0) < time()) {
  @unlink($tfile);
  hard_fail(410, 'Token expired');
}
if (!hash_equals((string)($rec['session'] ?? ''), session_id())) {
  hard_fail(403, 'Session mismatch');
}
if (!empty($rec['used'])) {
  hard_fail(410, 'Token already used');
}

// Get location from token (default to external for backwards compatibility)
$location = $rec['location'] ?? 'external';
$export_type = (string)($rec['export_type'] ?? 'pfx');
if (!in_array($export_type, ['pfx', 'crt_key_zip', 'all_bundle_zip'], true)) {
  $export_type = 'pfx';
}
$stage_file_name = $export_type === 'crt_key_zip'
  ? 'cert-key.zip'
  : ($export_type === 'all_bundle_zip' ? 'all-certs.zip' : 'client.p12');
$download_name = $export_type === 'crt_key_zip'
  ? 'mtls-cert-key.zip'
  : ($export_type === 'all_bundle_zip' ? 'mtls-all-certs.zip' : 'mtls-client.p12');
$content_type = $export_type === 'pfx' ? 'application/octet-stream' : 'application/zip';

// --- Ensure artifact is ready BEFORE marking used ---
// STAGE_BASE is typically mounted on the front proxy, not in this container --
// that mismatch is exactly why this check defaults to skipped.
// file_exists() against $real can never succeed from here regardless of
// whether the artifact was actually built. Use the same signal token_info
// already relies on instead: the artifact_ready flag the external stager sets
// on the token record itself once it's actually built the file, which lives
// in $TOKENS -- a path this container does have access to. Fall back to
// the filesystem check only for deployments where STAGE_BASE genuinely is
// mounted into this container.
$real = rtrim($STAGE_BASE, '/') . '/' . $token_hash . '/' . $stage_file_name;

$doCheck = (strtolower(getenv('MTLS_SKIP_STAGE_CHECK') ?: 'true') === 'false');
if ($doCheck) {
  $artifact_ready = !empty($rec['artifact_ready']);
  if (!$artifact_ready) {
    clearstatcache(true, $real);
    $artifact_ready = file_exists($real);
  }
  if (!$artifact_ready) {
    hard_fail(503, 'Artifact not ready');
  }
}

// ---------- Mark token used (atomic-ish) ----------
$rec['used'] = true;
@file_put_contents($tfile, json_encode($rec), LOCK_EX);
@rename($tfile, $ufile);

// ---------- Hand off to the front proxy (per-token staging) ----------
$opaque = '/_protected_mtls/' . $token_hash . '/' . $stage_file_name;

header('Content-Type: ' . $content_type);
header('X-Content-Type-Options: nosniff');
header('Content-Disposition: attachment; filename="' . $download_name . '"');
header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
header('Pragma: no-cache');
header('X-Accel-Redirect: ' . $opaque);

// ---------- Log ----------
$evt = [
  'evt'    => 'download',
  'uid'    => $uid,
  'ip'     => ($_SERVER['REMOTE_ADDR'] ?? ''),
  'ua'     => ($_SERVER['HTTP_USER_AGENT'] ?? ''),
  't'      => time(),
  'opaque' => $opaque,
];
@file_put_contents($LOGS . '/events.log', json_encode($evt) . "\n", FILE_APPEND);

// ---------- Apprise (styled + tagged) ----------
$host = $_SERVER['HTTP_HOST'] ?? php_uname('n') ?? 'host';
$ip   = client_ip();
$ua   = $_SERVER['HTTP_USER_AGENT'] ?? '';
$body = '🔐 `' . $host . '` **mTLS Download**:' . "\n"
      . 'User: `' . htmlspecialchars($uid, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8') . '`' . "\n"
      . 'IP: `' . htmlspecialchars($ip, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8') . '`' . "\n"
      . 'Token: `' . substr($token_hash, 0, 8) . '…`' . "\n"
      . 'UA: `' . htmlspecialchars($ua, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8') . '`';
apprise_notify($body);

exit; // The front proxy serves the file via X-Accel-Redirect
