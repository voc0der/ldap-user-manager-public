<?php
declare(strict_types=1);

// Forwarded client IP headers are meaningful only when the direct peer is a
// configured trusted proxy. If web_functions.inc.php was not loaded, fail
// closed and use REMOTE_ADDR.
function apprise_client_ip(): string
{
  $candidates = [];
  $trust_forwarded = false;
  if (function_exists('lum_is_header_auth_request_trusted')) {
    $trust_forwarded = lum_is_header_auth_request_trusted();
  }

  if ($trust_forwarded && !empty($_SERVER['HTTP_CF_CONNECTING_IP'])) {
    $candidates[] = trim((string)$_SERVER['HTTP_CF_CONNECTING_IP']);
  }
  if ($trust_forwarded && !empty($_SERVER['HTTP_X_FORWARDED_FOR'])) {
    foreach (explode(',', (string)$_SERVER['HTTP_X_FORWARDED_FOR']) as $part) {
      $candidates[] = trim($part);
    }
  }
  if ($trust_forwarded && !empty($_SERVER['HTTP_X_REAL_IP'])) {
    $candidates[] = trim((string)$_SERVER['HTTP_X_REAL_IP']);
  }
  if (!empty($_SERVER['REMOTE_ADDR'])) {
    $candidates[] = trim((string)$_SERVER['REMOTE_ADDR']);
  }

  foreach ($candidates as $candidate) {
    if (filter_var($candidate, FILTER_VALIDATE_IP)) {
      $packed = @inet_pton($candidate);
      return $packed === false ? $candidate : (string)inet_ntop($packed);
    }
  }

  return '';
}

// Fire-and-forget multipart POST (using proc_open for security)
function apprise_notify(string $body, ?string $tag = null): void
{
  $url = getenv('APPRISE_URL');
  if (!$url) {
    return;
  }
  $tag = $tag ?: (getenv('APPRISE_TAG') ?: 'all');

  // Use proc_open with explicit argument array to prevent command injection
  $descriptors = [
    0 => ['pipe', 'r'],  // stdin
    1 => ['file', '/dev/null', 'w'],  // stdout
    2 => ['file', '/dev/null', 'w'],   // stderr
  ];

  $args = [
    'curl',
    '-s',
    '-X', 'POST',
    '-F', 'body=' . $body,
    '-F', 'tag=' . $tag,
    $url,
  ];

  $process = @proc_open($args, $descriptors, $pipes);
  if (is_resource($process)) {
    // Don't wait for process to complete (fire-and-forget)
    @proc_close($process);
  }
}

// Convenience wrapper for “User Deleted” events
function apprise_notify_user_deleted(string $uid, string $admin_uid, array $pre_groups = []): void
{
  $host = $_SERVER['HTTP_HOST'] ?? php_uname('n') ?? 'host';
  $ip   = apprise_client_ip();
  $grp  = trim(implode(', ', $pre_groups));
  $grp  = $grp === '' ? 'none' : $grp;

  $body = '🔐 `' . htmlspecialchars($host, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8') . '` **User Deleted**:' . "\n\n"
        . 'User: `' . htmlspecialchars($uid, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8') . '`' . "\n"
        . 'By: `' . htmlspecialchars($admin_uid, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8') . '`' . "\n"
        . 'IP: `' . htmlspecialchars($ip, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8') . '`' . "\n"
        . 'Groups: `' . htmlspecialchars($grp, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8') . '`';

  apprise_notify($body);
}
