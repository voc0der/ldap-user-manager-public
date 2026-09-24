<?php
declare(strict_types=1);
@session_start();
set_include_path(__DIR__ . '/../includes/');
include_once 'web_functions.inc.php';

header('Content-Type: application/json');
header('X-Content-Type-Options: nosniff');
header('Cache-Control: no-store');

// Ensure logged-in to use
set_page_access('user');

// Determine admin / user
global $IS_ADMIN, $USER_ID;
$isAdmin = isset($IS_ADMIN) ? (bool)$IS_ADMIN : (isset($_SESSION['is_admin']) && $_SESSION['is_admin'] === true);
$userId  = $USER_ID ?? ($_SESSION['user_id'] ?? 'unknown');

// Optional ?user= override (beats session/vhost) — typically for admin tools
$userOverride = trim((string)($_GET['user'] ?? ''));
if ($userOverride !== '' && $isAdmin) {
  $userId = $userOverride;
}

// ---- Config / URL normalization ----
$rawBase = getenv('LEASE_API_BASE') ?: '/endpoints/ip_lease.php';   // can be full URL or path
$explicitOrigin = getenv('LEASE_API_ORIGIN') ?: '';                 // optional, e.g. https://your-fqdn

function normalize_api_base(string $base, string $explicitOrigin): string
{
  if (preg_match('#^https?://#i', $base)) {
    return rtrim($base, '&?');
  }
  $scheme = $_SERVER['HTTP_X_FORWARDED_PROTO'] ?? ($_SERVER['REQUEST_SCHEME'] ?? ((isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') ? 'https' : 'http'));
  $host   = get_trusted_host();
  $origin = $explicitOrigin !== '' ? rtrim($explicitOrigin, '/') : ($scheme . '://' . $host);
  return $origin . (str_starts_with($base, '/') ? $base : '/' . $base);
}
$apiBase = normalize_api_base($rawBase, $explicitOrigin);

// ---- Helpers ----
function canon_ip(?string $ip): ?string
{
  if (!$ip) {
    return null;
  }
  $ip = trim($ip);
  if (!filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4 | FILTER_FLAG_IPV6)) {
    return null;
  }
  $bin = @inet_pton($ip);
  return $bin === false ? null : inet_ntop($bin);
}
function get_client_ip(): ?string
{
  $c = [];
  $trust_forwarded = false;
  if (function_exists('lum_is_header_auth_request_trusted')) {
    $trust_forwarded = lum_is_header_auth_request_trusted();
  }

  // Only trust forwarded client IP headers when request source is trusted.
  if ($trust_forwarded && !empty($_SERVER['HTTP_X_FORWARDED_FOR'])) {
    foreach (explode(',', $_SERVER['HTTP_X_FORWARDED_FOR']) as $p) {
      $c[] = trim($p);
    }
  }
  if ($trust_forwarded && !empty($_SERVER['HTTP_X_REAL_IP'])) {
    $c[] = trim((string)$_SERVER['HTTP_X_REAL_IP']);
  }
  if (!empty($_SERVER['REMOTE_ADDR'])) {
    $c[] = trim($_SERVER['REMOTE_ADDR']);
  }
  foreach ($c as $v) {
    $canon = canon_ip($v);
    if ($canon) {
      return $canon;
    }
  }
  return null;
}
$clientIp = get_client_ip();

// tiny fetcher for list->entries; returns normalized entries with 'user' key set
function fetch_entries(string $apiBase, array $headers): array
{
  $url = $apiBase . (str_contains($apiBase, '?') ? '&' : '?') . http_build_query(['list' => '1'], '', '&', PHP_QUERY_RFC3986);
  $ch = curl_init();
  curl_setopt_array($ch, [
      CURLOPT_URL => $url,
      CURLOPT_RETURNTRANSFER => true,
      CURLOPT_FOLLOWLOCATION => true,
      CURLOPT_CONNECTTIMEOUT => 3,
      CURLOPT_TIMEOUT => 8,
      CURLOPT_USERAGENT => 'LUM-Lease-UI/1.0',
      CURLOPT_HTTPHEADER => $headers,
  ]);
  $resp = curl_exec($ch);
  $err  = curl_error($ch);
  $code = curl_getinfo($ch, CURLINFO_HTTP_CODE);

  if ($resp === false || $code < 200 || $code >= 300) {
    return [];
  }
  $data = json_decode($resp, true);
  if (!is_array($data)) {
    return [];
  }

  $entries = $data['entries'] ?? [];

  // Normalize: ensure 'user' exists; keep original 'label' for back-compat
  $out = [];
  foreach ((array)$entries as $e) {
    $user = $e['user'] ?? ($e['label'] ?? ($e['host'] ?? 'unknown'));
    $e['user'] = (string)$user;
    $out[] = $e;
  }
  return $out;
}

// ---- Operation selection ----
$allowed = ['list','clear','add','delete','prune','geo'];
$stateChanging = ['clear','add','delete','prune']; // Operations that modify state

$requestMethod = $_SERVER['REQUEST_METHOD'] ?? 'GET';

// Determine operation from either GET or POST
if ($requestMethod === 'POST') {
  // POST requests use JSON body
  $input = json_decode(file_get_contents('php://input'), true);
  if (!is_array($input)) {
    http_response_code(400);
    echo json_encode(['ok' => false, 'error' => 'Invalid JSON in POST body']);
    exit;
  }

  // Validate CSRF token for all POST requests
  csrf_verify_or_exit();

  // Extract operation from POST body
  $opKeys = array_keys($input);
  $opKeys = array_values(array_diff($opKeys, ['user'])); // allow user param
  if (count($opKeys) !== 1) {
    http_response_code(400);
    echo json_encode(['ok' => false, 'error' => 'Exactly one operation parameter required']);
    exit;
  }
  $key = $opKeys[0];
  $val = (string)($input[$key] ?? '');

  // Override userId if specified in POST
  $userOverride = trim((string)($input['user'] ?? ''));
  if ($userOverride !== '' && $isAdmin) {
    $userId = $userOverride;
  }
} else {
  // GET requests
  $getKeys = array_keys($_GET ?? []);
  $opKeys  = array_values(array_diff($getKeys, ['user']));  // allow ?user=
  if (count($opKeys) !== 1) {
    http_response_code(400);
    echo json_encode(['ok' => false, 'error' => 'Exactly one parameter required']);
    exit;
  }
  $key = $opKeys[0];
  $val = (string)($_GET[$key] ?? '');

  // Reject state-changing operations via GET
  if (in_array($key, $stateChanging, true)) {
    http_response_code(405);
    echo json_encode(['ok' => false, 'error' => 'State-changing operations require POST method']);
    exit;
  }
}

if (!in_array($key, $allowed, true)) {
  http_response_code(400);
  echo json_encode(['ok' => false, 'error' => 'Unknown operation', 'allowed' => $allowed]);
  exit;
}

// Enforce the same group gate index.php applies. set_page_access() only
// checks that the caller is authenticated, so without this any logged-in user
// could list, add and delete leases by calling this endpoint directly.
//
// `geo` is deliberately exempt: it is a shared IP-geolocation helper consumed
// by the admin-only account_manager pages (bans.php, show_user.php), whose
// admins are not necessarily in the lease_ip gate group. It carries its own
// admin-only check below.
if ($key !== 'geo') {
  lum_require_module_gate_json('lease_ip');
}

// Optional static toggle header from browser -> forwarded to the lease endpoint
$lumStaticHdr = strtolower(trim($_SERVER['HTTP_X_LUM_STATIC'] ?? '')); // '1'|'0'|''

// Common headers to upstream
$headers = [
    'Accept: application/json',
    'X-IP-Lease-Label: ' . $userId,   // upstream still expects "Label" header; UI shows it as "User"
    'X-IP-Lease-Source: LUM',
];

// ---- GEO lookup (server-side proxy for ip-api.com) --------------------------
if ($key === 'geo') {
  if (!$isAdmin) {
    http_response_code(403);
    echo json_encode(['ok' => false,'error' => 'Admin required']);
    exit;
  }
  $ip = canon_ip($val);
  if (!$ip) {
    http_response_code(400);
    echo json_encode(['ok' => false,'error' => 'Invalid IP']);
    exit;
  }

  $CACHE_DIR = sys_get_temp_dir() . '/lum_geo_cache';
  $TTL_SEC   = 600; // 10 minutes
  if (!is_dir($CACHE_DIR)) {
    @mkdir($CACHE_DIR, 0700, true);
  }
  $ckey = $CACHE_DIR . '/' . basename(sha1($ip)) . '.json';

  if (is_file($ckey) && (time() - filemtime($ckey) < $TTL_SEC)) {
    $cached = @file_get_contents($ckey);
    $j = json_decode((string)$cached, true);
    if (is_array($j)) {
      // nosemgrep: php.lang.security.injection.echoed-request.echoed-request
      echo json_encode(['ok' => true,'geo' => $j,'cached' => true]);
      exit;
    }
  }

  // Free plan is HTTP only; we proxy server-side to avoid mixed-content in browser.
  $fields = implode(',', [
      'status','message','query',
      'continent','continentCode','country','countryCode',
      'region','regionName','city','zip',
      'lat','lon','timezone',
      'isp','org','as','asname','reverse',
      'mobile','proxy','hosting','currency','offset',
  ]);
  $url = 'http://ip-api.com/json/' . rawurlencode($ip) . '?fields=' . rawurlencode($fields);

  $ch = curl_init();
  curl_setopt_array($ch, [
      CURLOPT_URL => $url,
      CURLOPT_RETURNTRANSFER => true,
      CURLOPT_FOLLOWLOCATION => true,
      CURLOPT_CONNECTTIMEOUT => 3,
      CURLOPT_TIMEOUT => 6,
      CURLOPT_USERAGENT => 'LUM-Geo/1.0',
  ]);
  $resp = curl_exec($ch);
  $err  = curl_error($ch);
  $code = curl_getinfo($ch, CURLINFO_HTTP_CODE);

  if ($resp === false || $code < 200 || $code >= 300) {
    http_response_code(502);
    echo json_encode(['ok' => false,'error' => 'Geo upstream failed: ' . $err,'status' => $code]);
    exit;
  }
  $data = json_decode($resp, true);
  if (!is_array($data)) {
    echo json_encode(['ok' => false,'error' => 'Bad JSON from ip-api']);
    exit;
  }

  // Cache & return
  @file_put_contents($ckey, json_encode($data, JSON_UNESCAPED_SLASHES));
  echo json_encode(['ok' => true, 'geo' => $data, 'cached' => false]);
  exit;
}

// ---- Permissions & effective IP/hours ----
$effectiveIp = null;
$hours = null;

if ($key === 'list') {
  // handled later (we’ll fetch, normalize, and filter server-side)
} elseif ($key === 'clear' || $key === 'prune') {
  if (!$isAdmin) {
    http_response_code(403);
    echo json_encode(['ok' => false,'error' => 'Admin required']);
    exit;
  }
  if ($key === 'prune') {
    $hours = is_numeric($val) ? (int)$val : 0;
    if ($hours <= 0) {
      http_response_code(400);
      echo json_encode(['ok' => false,'error' => 'Invalid hours']);
      exit;
    }
  }
} elseif ($key === 'add' || $key === 'delete') {
  if ($isAdmin) {
    $effectiveIp = canon_ip($val) ?: $clientIp;
    if (!$effectiveIp) {
      http_response_code(400);
      echo json_encode(['ok' => false,'error' => 'Invalid IP']);
      exit;
    }
  } else {
    // Non-admin:
    $wantIp = canon_ip($val);

    // If toggling static (X-LUM-Static present) OR deleting an arbitrary IP,
    // require that the target IP belongs to this user.
    $isStaticToggle = ($key === 'add' && $lumStaticHdr !== '');
    $isArbDelete    = ($key === 'delete' && $wantIp !== null);

    if ($isStaticToggle || $isArbDelete) {
      if (!$wantIp) {
        http_response_code(400);
        echo json_encode(['ok' => false,'error' => 'Invalid IP']);
        exit;
      }
      $entries = fetch_entries($apiBase, $headers);
      $owned = false;
      foreach ($entries as $e) {
        if (($e['ip'] ?? '') === $wantIp && ($e['user'] ?? '') === $userId) {
          $owned = true;
          break;
        }
      }
      if (!$owned) {
        http_response_code(403);
        echo json_encode(['ok' => false,'error' => 'Not permitted for this IP']);
        exit;
      }
      $effectiveIp = $wantIp;
    } else {
      // Plain add (no static header) or delete without IP => operate on detected client IP
      if (!$clientIp) {
        http_response_code(400);
        echo json_encode(['ok' => false,'error' => 'Cannot detect client IP']);
        exit;
      }
      $effectiveIp = $clientIp;
    }
  }
}

// ---- Build upstream URL with exactly one parameter ----
$one = [];
if ($key === 'list') {
  $one = ['list' => '1'];
} elseif ($key === 'clear') {
  $one = ['clear' => '1'];
} elseif ($key === 'prune') {
  $one = ['prune' => (string)$hours];
} elseif ($key === 'add') {
  $one = ['add' => $effectiveIp];
} elseif ($key === 'delete') {
  $one = ['delete' => $effectiveIp];
}

$qs  = http_build_query($one, '', '&', PHP_QUERY_RFC3986);
$url = $apiBase . (str_contains($apiBase, '?') ? '&' : '?') . $qs;

// ---- Upstream call (except special handling for list) ----
if ($key !== 'list') {
  $fwdHeaders = $headers;
  // forward static intent ONLY on add (still one GET var)
  if ($key === 'add' && $lumStaticHdr !== '') {
    $fwdHeaders[] = 'X-IP-Lease-Static: ' . (($lumStaticHdr === '1' || $lumStaticHdr === 'yes' || $lumStaticHdr === 'true') ? 'yes' : 'no');
  }

  $ch = curl_init();
  curl_setopt_array($ch, [
      CURLOPT_URL => $url,
      CURLOPT_RETURNTRANSFER => true,
      CURLOPT_FOLLOWLOCATION => true,
      CURLOPT_CONNECTTIMEOUT => 3,
      CURLOPT_TIMEOUT => 8,
      CURLOPT_USERAGENT => 'LUM-Lease-UI/1.0',
      CURLOPT_HTTPHEADER => $fwdHeaders,
  ]);
  $resp = curl_exec($ch);
  $err  = curl_error($ch);
  $code = curl_getinfo($ch, CURLINFO_HTTP_CODE);

  if ($resp === false) {
    http_response_code(502);
    echo json_encode(['ok' => false, 'error' => 'Upstream call failed: ' . $err]);
    exit;
  }

  $data = json_decode($resp, true);
  if ($data === null) {
    echo json_encode(['ok' => false, 'error' => 'Invalid JSON from lease endpoint', 'status' => $code, 'body' => $resp]);
    exit;
  }

  http_response_code(($code >= 200 && $code < 300) ? 200 : $code);
  echo json_encode($data);
  exit;
}

// ---- LIST handling: normalize + filter + ETag --------------------------------
$entries = fetch_entries($apiBase, $headers);

// For non-admins: only show entries where user === current user
if (!$isAdmin) {
  $entries = array_values(array_filter($entries, function ($e) use ($userId) {
    $u = $e['user'] ?? ($e['label'] ?? ($e['host'] ?? ''));
    return ($u === $userId);
  }));
}

// Compute weak ETag based on entries content
$etag = 'W/"' . substr(sha1(json_encode($entries)), 0, 20) . '"';
$ifNone = $_SERVER['HTTP_IF_NONE_MATCH'] ?? '';
if ($ifNone !== '' && trim($ifNone) === $etag) {
  header('ETag: ' . $etag);
  http_response_code(304);
  exit;
}

header('ETag: ' . $etag);
// JSON API response (application/json + nosniff).
// nosemgrep: php.lang.security.injection.echoed-request.echoed-request
echo json_encode(['ok' => true, 'entries' => $entries]);
