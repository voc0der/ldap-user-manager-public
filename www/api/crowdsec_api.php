<?php
declare(strict_types=1);

set_include_path('.:' . __DIR__ . '/../includes/');
require_once 'web_functions.inc.php';

header('Content-Type: application/json');
header('Cache-Control: no-store, max-age=0');
header('Pragma: no-cache');
header('X-Content-Type-Options: nosniff');

$CROWDSEC_DIR = getenv('CROWDSEC_DIR')
    ?: (realpath(__DIR__ . '/../data/crowdsec') ?: (__DIR__ . '/../data/crowdsec'));

$Q = $CROWDSEC_DIR . '/actions/queued';
$R = $CROWDSEC_DIR . '/actions/results';

// Where to persist the edge-bans (the posted edge firewall group members)
$EDGE_BANS_FILE = '/opt/ldap_user_manager/data/crowdsec/edgebans.json';

function normalize_ipish(string $v): ?string
{
  $v = trim($v);
  if ($v === '') {
    return null;
  }

  // allow CIDR; validate bare IP
  $parts = explode('/', $v, 2);
  $bare  = $parts[0];

  if (!filter_var($bare, FILTER_VALIDATE_IP)) {
    return null;
  }

  if (count($parts) === 2) {
    if ($parts[1] === '' || !ctype_digit($parts[1])) {
      return null;
    }
    $mask = (int)$parts[1];
    $max  = str_contains($bare, ':') ? 128 : 32;
    if ($mask < 0 || $mask > $max) {
      return null;
    }
  }

  return $v;
}

function write_json_atomic(string $path, array $data, int $mode = 0640): bool
{
  $dir = dirname($path);

  // Don't follow links; also ensure directory exists + writable
  if (!is_dir($dir) || is_link($dir) || !is_writable($dir)) {
    return false;
  }

  $tmp = $path . '.tmp';

  $json = json_encode($data, JSON_UNESCAPED_SLASHES | JSON_PRETTY_PRINT);
  if (!is_string($json)) {
    return false;
  }

  if (@file_put_contents($tmp, $json . "\n", LOCK_EX) === false) {
    @unlink($tmp);
    return false;
  }

  @chmod($tmp, $mode);

  if (!@rename($tmp, $path)) {
    @unlink($tmp);
    return false;
  }

  return true;
}

const POLL_TIMEOUT_SEC  = 25;
const POLL_INTERVAL_MS  = 300;

function out(array $arr, int $code = 200): never
{
  http_response_code($code);
  echo json_encode($arr, JSON_UNESCAPED_SLASHES);
  exit;
}

function is_secure_action_dir(string $path): bool
{
  if (!is_dir($path) || is_link($path)) {
    return false;
  }
  $perm = @fileperms($path);
  // Reject world-writable dirs to reduce local tampering risk.
  if ($perm !== false && (($perm & 0x0002) !== 0)) {
    return false;
  }
  return true;
}

function is_secure_action_file(string $path, string $baseDir): bool
{
  if (!is_file($path) || is_link($path)) {
    return false;
  }

  $realBase = realpath($baseDir);
  $realPath = realpath($path);
  if ($realBase === false || $realPath === false) {
    return false;
  }

  return str_starts_with($realPath, $realBase . DIRECTORY_SEPARATOR);
}

function is_trusted_proxy_source(): bool
{
  if (!function_exists('lum_is_header_auth_request_trusted')) {
    return true;
  }
  return lum_is_header_auth_request_trusted();
}

function parse_duration_hours(string $duration): ?int
{
  $duration = strtolower(trim($duration));
  if ($duration === '') {
    return null;
  }
  $duration = preg_replace('/\s+/', '', $duration);
  if (!is_string($duration) || $duration === '') {
    return null;
  }

  if (!preg_match_all('/(\d+)([wdhms])/', $duration, $matches, PREG_SET_ORDER)) {
    return null;
  }

  $rebuilt = '';
  $seconds = 0;
  foreach ($matches as $m) {
    $value = (int)$m[1];
    $unit = $m[2];
    $rebuilt .= $m[0];

    switch ($unit) {
      case 'w':
        $seconds += $value * 7 * 24 * 3600;
        break;
      case 'd':
        $seconds += $value * 24 * 3600;
        break;
      case 'h':
        $seconds += $value * 3600;
        break;
      case 'm':
        $seconds += $value * 60;
        break;
      case 's':
        $seconds += $value;
        break;
      default:
        return null;
    }
  }

  if ($rebuilt !== $duration) {
    return null;
  }

  return (int)floor($seconds / 3600);
}

function authenticate_request(): void
{
  $expected_key = trim((string)(getenv('CROWDSEC_API_SHARED_KEY') ?: ''));

  $provided_key = trim((string)($_SERVER['HTTP_X_LUM_API_KEY'] ?? ''));

  // Fail closed: endpoint is unavailable until a shared key is configured.
  if ($expected_key === '') {
    out(['ok' => false, 'error' => 'shared key not configured'], 503);
  }
  if ($provided_key === '') {
    out(['ok' => false, 'error' => 'missing api key'], 401);
  }
  if (!hash_equals($expected_key, $provided_key)) {
    out(['ok' => false, 'error' => 'unauthorized'], 401);
  }
  if (!is_trusted_proxy_source()) {
    out(['ok' => false, 'error' => 'untrusted proxy source'], 403);
  }
}

if (($_SERVER['REQUEST_METHOD'] ?? '') !== 'POST') {
  header('Allow: POST');
  out(['ok' => false, 'error' => 'method not allowed'], 405);
}

authenticate_request();

$action = $_POST['action'] ?? '';
if ($action === '') {
  $raw_body = @file_get_contents('php://input');
  if (is_string($raw_body) && $raw_body !== '') {
    $decoded = json_decode($raw_body, true);
    if (is_array($decoded)) {
      $action = (string)($decoded['action'] ?? '');
    }
  }
}
$action = trim((string)$action);

if ($action !== 'banlist') {
  out(['ok' => false, 'error' => 'unknown action'], 400);
}

$min_age_hours = isset($_POST['min_age_hours']) ? max(1, (int)$_POST['min_age_hours']) : 500;

// ── Parse + sanitize exclude_ips, then write edgebans.json ────────────────────
$exclude_ips = [];

// Accept exclude_ips from form field (JSON string OR array)
if (isset($_POST['exclude_ips'])) {
  if (is_string($_POST['exclude_ips']) && $_POST['exclude_ips'] !== '') {
    $tmp = json_decode($_POST['exclude_ips'], true);
    if (is_array($tmp)) {
      $exclude_ips = $tmp;
    }
  } elseif (is_array($_POST['exclude_ips'])) {
    $exclude_ips = $_POST['exclude_ips'];
  }
}

// Also allow JSON body (if you ever call it that way)
if (empty($exclude_ips)) {
  $raw_body = @file_get_contents('php://input');
  if (is_string($raw_body) && $raw_body !== '') {
    $decoded = json_decode($raw_body, true);
    if (is_array($decoded) && isset($decoded['exclude_ips']) && is_array($decoded['exclude_ips'])) {
      $exclude_ips = $decoded['exclude_ips'];
    }
  }
}

// Clean + dedupe
$clean_exclude = [];
foreach ($exclude_ips as $v) {
  if (!is_string($v)) {
    continue;
  }
  $n = normalize_ipish($v);
  if ($n !== null) {
    $clean_exclude[] = $n;
  }
}
$clean_exclude = array_values(array_unique($clean_exclude));

// Write it to storage (non-fatal if it fails)
$edge_write_ok = write_json_atomic($EDGE_BANS_FILE, [
  'updated_utc'   => gmdate('c'),
  'count'         => count($clean_exclude),
  'min_age_hours' => $min_age_hours,
  'exclude_ips'   => $clean_exclude,
]);

// Build exclude set for filtering decisions
$exclude_set = [];
foreach ($clean_exclude as $v) {
  $bare = explode('/', $v, 2)[0];
  $exclude_set[$bare] = true;
}

// ── Write action to queue ─────────────────────────────────────────────────────
if (!is_secure_action_dir($Q)) {
  out(['ok' => false, 'error' => 'queue dir not ready'], 503);
}
if (!is_secure_action_dir($R)) {
  out(['ok' => false, 'error' => 'results dir not ready'], 503);
}

$ts        = gmdate('Ymd\THis\Z');
$rand      = bin2hex(random_bytes(16));
$action_id = 'banlist-' . $ts . '-' . $rand;

$payload = json_encode([
    'op'        => 'decisions.list',
    'action_id' => $action_id,
], JSON_UNESCAPED_SLASHES);

$tmp   = $Q . '/' . $action_id . '.json.tmp';
$final = $Q . '/' . $action_id . '.json';
$rfile = $R . '/' . $action_id . '.json';

if (@file_put_contents($tmp, $payload, LOCK_EX) === false) {
  out(['ok' => false, 'error' => 'failed to write action'], 500);
}
@chmod($tmp, 0640);
if (!@rename($tmp, $final)) {
  @unlink($tmp);
  out(['ok' => false, 'error' => 'failed to queue action'], 500);
}

// ── Poll for result ───────────────────────────────────────────────────────────
$deadline = microtime(true) + POLL_TIMEOUT_SEC;
$result   = null;

while (microtime(true) < $deadline) {
  usleep(POLL_INTERVAL_MS * 1000);
  if (!is_secure_action_file($rfile, $R)) {
    continue;
  }
  $raw = @file_get_contents($rfile);
  if ($raw === false) {
    continue;
  }
  $result = json_decode($raw, true);
  if (is_array($result)) {
    break;
  }
}

// Clean up regardless
@unlink($rfile);
@unlink($final); // in case stager never picked it up

if (!is_array($result)) {
  out(['ok' => false, 'error' => 'timed out waiting for cscli'], 504);
}
if (empty($result['ok'])) {
  out(['ok' => false, 'error' => 'cscli failed: ' . ($result['details'] ?? 'unknown')], 502);
}

$decisions = $result['data'] ?? [];
if (!is_array($decisions)) {
  out(['ok' => false, 'error' => 'unexpected data shape'], 502);
}

// ── Filter by remaining duration ──────────────────────────────────────────────
$ips = [];

foreach ($decisions as $dec) {
  if (!is_array($dec)) {
    continue;
  }

  $ip = trim((string)($dec['value'] ?? $dec['ip'] ?? ''));
  if ($ip === '') {
    continue;
  }

  // Strip known CrowdSec scope prefixes while preserving plain IPv6 values.
  if (preg_match('/^(?:ip|range|cidr|asn|country):(.+)$/i', $ip, $m)) {
    $ip = trim((string)$m[1]);
  }

  $bare = explode('/', $ip)[0];
  if (!filter_var($bare, FILTER_VALIDATE_IP)) {
    continue;
  }

  if (isset($exclude_set[$bare])) {
    continue;
  }

  $duration_raw = trim((string)($dec['duration'] ?? ''));
  $duration_hours = parse_duration_hours($duration_raw);
  if ($duration_hours === null) {
    continue;
  }
  if ($duration_hours < $min_age_hours) {
    continue;
  }

  $ips[] = $ip;
}

$ips = array_values(array_unique($ips));

// ── Read and consume remove_ips from edgebans.json ────────────────────────────
$remove_ips = [];
$edgeData = null;
if (is_file($EDGE_BANS_FILE)) {
  $edgeRaw = @file_get_contents($EDGE_BANS_FILE);
  if (is_string($edgeRaw) && $edgeRaw !== '') {
    $edgeData = json_decode($edgeRaw, true);
    if (is_array($edgeData) && !empty($edgeData['remove_ips']) && is_array($edgeData['remove_ips'])) {
      $remove_ips = array_values($edgeData['remove_ips']);
      // Clear remove_ips (consume-once)
      $edgeData['remove_ips'] = [];
      $edgeData['updated_utc'] = gmdate('c');
      write_json_atomic($EDGE_BANS_FILE, $edgeData);
    }
  }
}

out([
    'ok'              => true,
    'ips'             => $ips,
    'count'           => count($ips),
    'total_decisions' => count($decisions),
    'min_age_hours'   => $min_age_hours,
    'remove_ips'      => $remove_ips,
]);
