<?php
declare(strict_types=1);

set_include_path('.:' . __DIR__ . '/../includes/');
require_once 'web_functions.inc.php';
require_once 'ldap_functions.inc.php';
require_once 'apprise_helpers.inc.php';
@session_start();
set_page_access('admin');

header('Content-Type: application/json');

$CROWDSEC_DIR = getenv('CROWDSEC_DIR')
  ?: (realpath(__DIR__ . '/../data/crowdsec') ?: (__DIR__ . '/../data/crowdsec'));

$Q = $CROWDSEC_DIR . '/actions/queued';
$R = $CROWDSEC_DIR . '/actions/results';
const USER_IP_ROLLUP_MAX_BYTES = 8 * 1024 * 1024;

function out($arr, int $code = 200)
{
  http_response_code($code);
  echo json_encode($arr, JSON_UNESCAPED_SLASHES);
  exit;
}

function crowdsec_user_ip_rollup_path(): string
{
  $autheliaDir = getenv('AUTHELIA_DIR')
    ?: (realpath(__DIR__ . '/../data/authelia') ?: (__DIR__ . '/../data/authelia'));
  return $autheliaDir . '/user_ip_rollup.json';
}

function crowdsec_normalize_rollup_ip(string $ip): string
{
  $ip = trim($ip);
  if ($ip === '') {
    return '';
  }
  return filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4 | FILTER_FLAG_IPV6) ? $ip : '';
}

function crowdsec_load_rollup_ip_user_index(): array
{
  $path = crowdsec_user_ip_rollup_path();
  if (!is_file($path)) {
    return [];
  }

  $realPath = realpath($path);
  $realBase = realpath(dirname($path));
  if ($realPath === false || $realBase === false || strpos($realPath, $realBase . DIRECTORY_SEPARATOR) !== 0) {
    return [];
  }

  $size = @filesize($realPath);
  if ($size !== false && $size > USER_IP_ROLLUP_MAX_BYTES) {
    return [];
  }

  $raw = @file_get_contents($realPath);
  if ($raw === false || $raw === '') {
    return [];
  }

  $decoded = json_decode($raw, true);
  if (!is_array($decoded)) {
    return [];
  }

  $index = [];
  foreach ($decoded as $username => $rows) {
    $user = trim((string)$username);
    if ($user === '' || !is_array($rows)) {
      continue;
    }

    foreach ($rows as $row) {
      if (!is_array($row)) {
        continue;
      }
      $ip = crowdsec_normalize_rollup_ip((string)($row['ip'] ?? ''));
      if ($ip === '') {
        continue;
      }
      if (!isset($index[$ip])) {
        $index[$ip] = [];
      }
      $index[$ip][$user] = true;
    }
  }

  foreach ($index as $ip => $users) {
    $usernames = array_keys($users);
    sort($usernames, SORT_NATURAL | SORT_FLAG_CASE);
    $index[$ip] = $usernames;
  }

  return $index;
}

function crowdsec_extract_matchable_ips_from_value($value): array
{
  $raw = trim((string)$value);
  if ($raw === '') {
    return [];
  }

  if (preg_match('/^(?:ip|range|cidr|asn|country):(.+)$/i', $raw, $m)) {
    $raw = trim((string)$m[1]);
  }

  $candidates = [$raw];
  if (strpos($raw, '/') !== false) {
    $candidates[] = trim((string)explode('/', $raw, 2)[0]);
  }

  $out = [];
  foreach ($candidates as $candidate) {
    $ip = crowdsec_normalize_rollup_ip((string)$candidate);
    if ($ip === '') {
      continue;
    }
    $out[$ip] = true;
  }

  return array_keys($out);
}

function crowdsec_build_potential_false_positive_map(array $decisions): array
{
  $rollupIndex = crowdsec_load_rollup_ip_user_index();
  if (empty($rollupIndex)) {
    return [];
  }

  $matches = [];
  foreach ($decisions as $decision) {
    if (!is_array($decision)) {
      continue;
    }

    $source = (isset($decision['source']) && is_array($decision['source'])) ? $decision['source'] : [];
    $candidateValues = [
      $decision['value'] ?? null,
      $decision['ip'] ?? null,
      $source['value'] ?? null,
      $source['ip'] ?? null,
    ];

    foreach ($candidateValues as $candidateValue) {
      foreach (crowdsec_extract_matchable_ips_from_value($candidateValue) as $ip) {
        if (!isset($rollupIndex[$ip])) {
          continue;
        }
        $matches[$ip] = $rollupIndex[$ip];
      }
    }
  }

  if (!empty($matches)) {
    ksort($matches, SORT_NATURAL | SORT_FLAG_CASE);
  }

  return $matches;
}

/* ----------------------------- GET ---------------------------------------- */

$action = $_GET['action'] ?? '';

if ($action === 'edgebans') {
  $edgePath = $CROWDSEC_DIR . '/edgebans.json';
  if (!is_file($edgePath)) {
    out(['ok' => true, 'exclude_ips' => [], 'count' => 0]);
  }
  $realEdge = realpath($edgePath);
  $realBase = realpath($CROWDSEC_DIR);
  if (!$realEdge || !$realBase || strpos($realEdge, $realBase . DIRECTORY_SEPARATOR) !== 0) {
    out(['ok' => false, 'error' => 'invalid path'], 403);
  }
  $raw = @file_get_contents($realEdge);
  if ($raw === false) {
    out(['ok' => false, 'error' => 'read failed'], 500);
  }
  $data = json_decode($raw, true);
  if (!is_array($data)) {
    out(['ok' => false, 'error' => 'bad data'], 500);
  }
  $data['ok'] = true;
  out($data);
}

if ($action === 'result') {
  $id = preg_replace('/[^A-Za-z0-9_:-]/', '', $_GET['id'] ?? '');
  if (!$id) {
    out(['ok' => false, 'error' => 'missing id'], 400);
  }
  $p = $R . '/' . $id . '.json';
  if (!is_file($p)) {
    out(['ok' => false, 'error' => 'not ready'], 404);
  }
  $realP = realpath($p);
  $realR = realpath($R);
  if (!$realP || !$realR || strpos($realP, $realR . DIRECTORY_SEPARATOR) !== 0) {
    out(['ok' => false, 'error' => 'invalid path'], 403);
  }
  $raw = @file_get_contents($p);
  if ($raw === false) {
    out(['ok' => false, 'error' => 'read failed'], 500);
  }

  // Send apprise notification on successful unban (once)
  $j = json_decode($raw, true) ?: [];
  $metaPath = $R . '/' . $id . '.meta.json';
  $notifiedPath = $R . '/' . $id . '.notified';
  $ok = isset($j['ok']) ? (bool)$j['ok'] : false;
  $meta = is_file($metaPath) ? (json_decode((string)@file_get_contents($metaPath), true) ?: []) : [];
  $op = (string)($j['op'] ?? ($meta['op'] ?? ''));

  if ($ok && !is_file($notifiedPath)) {
    if ($op === 'decision.delete') {
      $host = $_SERVER['HTTP_HOST'] ?? (php_uname('n') ?: 'host');
      $ip = apprise_client_ip();
      $admin = (string)($j['requester']['admin_uid'] ?? ($meta['requester']['admin_uid'] ?? ($GLOBALS['USER_ID'] ?? 'unknown')));
      $decisionId = (string)($j['decision_id'] ?? ($meta['decision_id'] ?? ''));
      $details = (string)($j['details'] ?? 'CrowdSec decision removed');

      $appriseBody = '🛡️ `' . htmlspecialchars($host, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8') . '` **CrowdSec Unban**:' . "\n"
                   . htmlspecialchars($details, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8') . "\n"
                   . ($decisionId !== '' ? ('Decision ID: `' . htmlspecialchars($decisionId, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8') . '`' . "\n") : '')
                   . 'By: `' . htmlspecialchars($admin, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8') . '`' . "\n"
                   . 'IP: `' . htmlspecialchars($ip, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8') . '`';
      apprise_notify($appriseBody);
    }

    @file_put_contents($notifiedPath, '1');
    @chmod($notifiedPath, 0640);
  }

  if ($ok && $op === 'decisions.list' && isset($j['data']) && is_array($j['data'])) {
    $j['potential_false_positives'] = crowdsec_build_potential_false_positive_map($j['data']);
    echo json_encode($j, JSON_UNESCAPED_SLASHES | JSON_INVALID_UTF8_SUBSTITUTE);
    exit;
  }

  echo $raw;
  exit;
}

/* ----------------------------- POST (queue) ------------------------------- */

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
  out(['ok' => false, 'error' => 'method'], 405);
}

csrf_verify_or_exit();

$op = $_POST['op'] ?? '';
if (!in_array($op, ['decisions.list', 'decision.delete', 'alert.inspect', 'edgeban.remove'], true)) {
  out(['ok' => false, 'error' => 'bad op'], 400);
}

// ── edgeban.remove: synchronous, no queue needed ────────────────────────────
if ($op === 'edgeban.remove') {
  $rawIp = trim((string)($_POST['ip'] ?? ''));
  if ($rawIp === '') {
    out(['ok' => false, 'error' => 'missing ip'], 400);
  }

  // Validate IP/CIDR
  $parts = explode('/', $rawIp, 2);
  $bare  = $parts[0];
  if (!filter_var($bare, FILTER_VALIDATE_IP)) {
    out(['ok' => false, 'error' => 'invalid ip'], 400);
  }
  if (count($parts) === 2) {
    if ($parts[1] === '' || !ctype_digit($parts[1])) {
      out(['ok' => false, 'error' => 'invalid cidr'], 400);
    }
    $mask = (int)$parts[1];
    $max  = str_contains($bare, ':') ? 128 : 32;
    if ($mask < 0 || $mask > $max) {
      out(['ok' => false, 'error' => 'invalid cidr mask'], 400);
    }
  }

  $edgePath = $CROWDSEC_DIR . '/edgebans.json';
  $data = [];
  if (is_file($edgePath)) {
    $raw = @file_get_contents($edgePath);
    if (is_string($raw) && $raw !== '') {
      $decoded = json_decode($raw, true);
      if (is_array($decoded)) {
        $data = $decoded;
      }
    }
  }

  // Remove from exclude_ips
  $excludeIps = is_array($data['exclude_ips'] ?? null) ? $data['exclude_ips'] : [];
  $excludeIps = array_values(array_filter($excludeIps, function ($v) use ($rawIp) {
    return is_string($v) && $v !== $rawIp;
  }));

  // Add to remove_ips (dedupe)
  $removeIps = is_array($data['remove_ips'] ?? null) ? $data['remove_ips'] : [];
  if (!in_array($rawIp, $removeIps, true)) {
    $removeIps[] = $rawIp;
  }

  $data['exclude_ips']  = $excludeIps;
  $data['count']        = count($excludeIps);
  $data['remove_ips']   = array_values($removeIps);
  $data['updated_utc']  = gmdate('c');

  // Atomic write
  $tmp = $edgePath . '.tmp';
  $json = json_encode($data, JSON_UNESCAPED_SLASHES | JSON_PRETTY_PRINT);
  if (@file_put_contents($tmp, $json . "\n", LOCK_EX) === false) {
    out(['ok' => false, 'error' => 'write failed'], 500);
  }
  @chmod($tmp, 0640);
  if (!@rename($tmp, $edgePath)) {
    @unlink($tmp);
    out(['ok' => false, 'error' => 'rename failed'], 500);
  }

  out(['ok' => true, 'ip' => $rawIp]);
}

$admin_uid = $GLOBALS['USER_ID'] ?? ($_SESSION['user_id'] ?? 'unknown');
$ts        = gmdate('Ymd\THis\Z');
$rand      = bin2hex(random_bytes(4));
$action_id = $ts . '-' . $rand;

$payload = [
  'schema'     => 'crowdsec-action@v1',
  'action_id'  => $action_id,
  'request_ts' => time(),
  'requester'  => [
    'admin_uid' => $admin_uid,
    'ip'        => $_SERVER['REMOTE_ADDR'] ?? '',
    'ua'        => $_SERVER['HTTP_USER_AGENT'] ?? '',
  ],
  'op' => $op,
];

if ($op === 'decision.delete') {
  $decision_id = preg_replace('/[^0-9]/', '', $_POST['decision_id'] ?? '');
  if (!$decision_id) {
    out(['ok' => false, 'error' => 'missing decision_id'], 400);
  }
  $payload['decision_id'] = $decision_id;
}

if ($op === 'alert.inspect') {
  $alert_id = preg_replace('/[^0-9]/', '', $_POST['alert_id'] ?? '');
  if ($alert_id) {
    $payload['alert_id'] = $alert_id;
  } else {
    $decision_id = preg_replace('/[^0-9]/', '', $_POST['decision_id'] ?? '');
    if (!$decision_id) {
      out(['ok' => false, 'error' => 'missing alert_id or decision_id'], 400);
    }
    $payload['decision_id'] = $decision_id;
  }
}

if (!is_dir($Q) && !@mkdir($Q, 0770, true)) {
  out(['ok' => false, 'error' => 'queue dir missing'], 500);
}

$tmp   = $Q . '/' . $action_id . '.json.tmp';
$final = $Q . '/' . $action_id . '.json';

if (@file_put_contents($tmp, json_encode($payload, JSON_UNESCAPED_SLASHES), LOCK_EX) === false) {
  out(['ok' => false, 'error' => 'write failed'], 500);
}
@chmod($tmp, 0640);
if (!@rename($tmp, $final)) {
  @unlink($tmp);
  out(['ok' => false, 'error' => 'rename failed'], 500);
}

if (!is_dir($R)) {
  @mkdir($R, 0770, true);
}

// Persist lightweight metadata so result polling can notify with actor/context
$meta = [
  'action_id' => $action_id,
  'op'        => $op,
  'requester' => $payload['requester'],
];
if (isset($payload['decision_id'])) {
  $meta['decision_id'] = $payload['decision_id'];
}
if (isset($payload['alert_id'])) {
  $meta['alert_id'] = $payload['alert_id'];
}
@file_put_contents($R . '/' . $action_id . '.meta.json', json_encode($meta, JSON_UNESCAPED_SLASHES), LOCK_EX);
@chmod($R . '/' . $action_id . '.meta.json', 0640);

out(['ok' => true, 'action_id' => $action_id]);
