<?php
declare(strict_types=1);
/*
  LUM Connection Tester (drop-in)
  - Base AllowedIPs from env WG_ALLOWEDIPS
  - External/WAN IPv4 autodetect (env override WG_EXTERNAL_IPV4), cached 15m in /tmp/lum_public_ipv4.json
*/
require_once __DIR__ . '/../includes/web_functions.inc.php';
set_page_access('auth');

lum_start_session();
global $IS_ADMIN, $USER_ID;
$isAdmin  = !empty($IS_ADMIN);
$username = $USER_ID ?? ($_SESSION['user_id'] ?? 'unknown');

/* Gate by group, same as lease_ip/index.php. The inline ?do=lease handler below
   adds the caller's IP to the lease allowlist, so authentication alone is not
   enough here. Answer in the caller's format: JSON for the inline API, HTML for
   the page itself. */
if (!lum_module_gate_satisfied('lease_ip')) {
  if (isset($_GET['do'])) {
    http_response_code(403);
    header('Content-Type: application/json; charset=utf-8');
    echo json_encode([
      'ok'    => false,
      'error' => 'Access denied: membership of the ' . lum_module_gate_group_label('lease_ip') . ' group is required.',
    ], JSON_UNESCAPED_SLASHES);
    exit;
  }

  render_header('Test Connection');
  echo '<div class="container" style="max-width:860px;margin-top:20px">
          <div class="alert alert-danger">
            Access denied: this page is only available to members of the <code>'
          . htmlspecialchars(lum_module_gate_group_label('lease_ip'), ENT_QUOTES, 'UTF-8')
          . '</code> group.
          </div>
        </div>';
  render_footer();
  exit;
}

/* -------------------- helpers -------------------- */
function h(?string $s): string
{
  return htmlspecialchars((string)$s, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
}
function canon_ip(?string $ip): ?string
{
  if (!$ip) {
    return null;
  }
  if (!filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4 | FILTER_FLAG_IPV6)) {
    return null;
  }
  $bin = @inet_pton($ip);
  return $bin === false ? null : @inet_ntop($bin);
}
function get_client_ip(): ?string
{
  $candidates = [];
  $trust_forwarded = false;
  if (function_exists('lum_is_header_auth_request_trusted')) {
    $trust_forwarded = lum_is_header_auth_request_trusted();
  }
  if ($trust_forwarded && !empty($_SERVER['HTTP_X_FORWARDED_FOR'])) {
    foreach (explode(',', $_SERVER['HTTP_X_FORWARDED_FOR']) as $p) {
      $candidates[] = trim($p);
    }
  }
  if ($trust_forwarded && !empty($_SERVER['HTTP_X_REAL_IP'])) {
    $candidates[] = trim($_SERVER['HTTP_X_REAL_IP']);
  }
  if (!empty($_SERVER['REMOTE_ADDR'])) {
    $candidates[] = trim($_SERVER['REMOTE_ADDR']);
  }
  foreach ($candidates as $v) {
    if ($v = canon_ip($v)) {
      return $v;
    }
  }
  return null;
}
function ip_in_cidr(string $ip, string $cidr): bool
{
  if (strpos($cidr, '/') === false) {
    return $ip === $cidr;
  }
  [$sub, $bits] = explode('/', $cidr, 2);
  $bits = (int)$bits;
  $ipBin  = @inet_pton($ip);
  $subBin = @inet_pton($sub);
  if ($ipBin === false || $subBin === false) {
    return false;
  }
  if (strlen($ipBin) !== strlen($subBin)) {
    return false;
  }
  $bytes = intdiv($bits, 8);
  $rem   = $bits % 8;
  if ($bytes && substr($ipBin, 0, $bytes) !== substr($subBin, 0, $bytes)) {
    return false;
  }
  if ($rem) {
    $mask = chr((0xFF00 >> $rem) & 0xFF);
    if ((ord($ipBin[$bytes]) & ord($mask)) !== (ord($subBin[$bytes]) & ord($mask))) {
      return false;
    }
  }
  return true;
}
function ip_in_any_cidr(string $ip, array $cidrs): bool
{
  foreach ($cidrs as $c) {
    $c = trim($c);
    if ($c !== '' && ip_in_cidr($ip, $c)) {
      return true;
    }
  }
  return false;
}
function parse_cidr_list(string $spec): array
{
  $spec = trim($spec);
  if ($spec === '') {
    return [];
  }
  $parts = preg_split('/[,\s;]+/', $spec, -1, PREG_SPLIT_NO_EMPTY);
  return array_values(array_unique(array_map('trim', $parts)));
}
function is_public_ipv4(string $ip): bool
{
  return (bool)filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4 | FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE);
}
function curl_quick_text(string $url, int $connectTO = 2, int $totalTO = 3): ?string
{
  $ch = curl_init($url);
  curl_setopt_array($ch, [
      CURLOPT_RETURNTRANSFER => true,
      CURLOPT_FOLLOWLOCATION => true,
      CURLOPT_CONNECTTIMEOUT => $connectTO,
      CURLOPT_TIMEOUT        => $totalTO,
      CURLOPT_USERAGENT      => 'LUM-ConnTest/1.2',
      CURLOPT_HEADER         => false,
  ]);
  $resp = curl_exec($ch);
  $code = curl_getinfo($ch, CURLINFO_HTTP_CODE) ?: 0;
  if ($resp === false || $code < 200 || $code >= 300) {
    return null;
  }
  return (string)$resp;
}
function detect_public_ipv4(?string $hostForDns = null): ?string
{
  foreach (['WG_EXTERNAL_IPV4','PUBLIC_IPV4','SERVER_PUBLIC_IP'] as $k) {
    $v = getenv($k);
    if ($v && is_public_ipv4($v)) {
      return $v;
    }
  }
  $cacheFile = '/tmp/lum_public_ipv4.json';
  $now = time();
  if (is_readable($cacheFile)) {
    $raw = @file_get_contents($cacheFile);
    if ($raw) {
      $j = @json_decode($raw, true);
      if (is_array($j) && !empty($j['ip']) && !empty($j['ts']) && ($now - (int)$j['ts'] < 900)) {
        if (is_public_ipv4($j['ip'])) {
          return $j['ip'];
        }
      }
    }
  }
  $candidates = [];
  $t = curl_quick_text('https://1.1.1.1/cdn-cgi/trace');
  if ($t && preg_match('/^ip=([0-9.]+)$/m', $t, $m) && is_public_ipv4($m[1])) {
    $candidates[] = $m[1];
  }
  $r = curl_quick_text('https://api.ipify.org');
  if ($r && is_public_ipv4(trim($r))) {
    $candidates[] = trim($r);
  }
  $r = curl_quick_text('https://ipv4.icanhazip.com');
  if ($r && is_public_ipv4(trim($r))) {
    $candidates[] = trim($r);
  }
  $r = curl_quick_text('https://ifconfig.me/ip');
  if ($r && is_public_ipv4(trim($r))) {
    $candidates[] = trim($r);
  }
  if ($hostForDns) {
    $a = @gethostbyname($hostForDns);
    if ($a && $a !== $hostForDns && is_public_ipv4($a)) {
      $candidates[] = $a;
    }
  }
  $ip = $candidates[0] ?? null;
  if ($ip) {
    @file_put_contents($cacheFile, json_encode(['ip' => $ip, 'ts' => $now]));
  }
  return $ip ?: null;
}
function http_request(string $url, string $method = 'GET', ?string $body = null, array $headers = []): array
{
  $ch = curl_init($url);
  $opts = [
      CURLOPT_RETURNTRANSFER => true,
      CURLOPT_FOLLOWLOCATION => true,
      CURLOPT_CONNECTTIMEOUT => 3,
      CURLOPT_TIMEOUT        => 4,
      CURLOPT_USERAGENT      => 'LUM-ConnTest/1.2',
      CURLOPT_HEADER         => false,
  ];
  if ($method !== 'GET') {
    $opts[CURLOPT_CUSTOMREQUEST] = $method;
    if ($body !== null) {
      $opts[CURLOPT_POSTFIELDS] = $body;
    }
  }
  if ($headers) {
    $opts[CURLOPT_HTTPHEADER] = $headers;
  }
  curl_setopt_array($ch, $opts);
  $resp = curl_exec($ch);
  $code = curl_getinfo($ch, CURLINFO_HTTP_CODE) ?: 0;
  $err  = curl_error($ch);
  return [$code >= 200 && $code < 300, $code, $err, (string)$resp];
}
function parse_filter_keys(string $spec): array
{
  $spec = strtolower(trim($spec));
  if ($spec === '') {
    return [];
  }
  $out = [];
  foreach (preg_split('/[,\s;]+/', $spec, -1, PREG_SPLIT_NO_EMPTY) as $p) {
    $p = trim($p);
    if (in_array($p, ['lan','vpn','mtls','leased'], true)) {
      $out[$p] = true;
    }
  }
  return $out;
}
function validate_safe_url(string $url): bool
{
  // Parse URL components
  $parts = parse_url($url);
  if ($parts === false || !isset($parts['scheme']) || !isset($parts['host'])) {
    return false;
  }

  // Only allow HTTP and HTTPS
  if (!in_array(strtolower($parts['scheme']), ['http', 'https'], true)) {
    return false;
  }

  // Resolve hostname to IP
  $host = $parts['host'];
  $ip = @gethostbyname($host);

  // If resolution failed, block it
  if ($ip === $host && !filter_var($host, FILTER_VALIDATE_IP)) {
    return false;
  }

  // Block private/reserved IP ranges (SSRF protection)
  if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
    // Block private ranges: 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16
    // Block localhost: 127.0.0.0/8
    // Block link-local: 169.254.0.0/16 (AWS metadata)
    // Block multicast: 224.0.0.0/4
    $private_patterns = [
        '/^0\./',                    // 0.0.0.0/8
        '/^127\./',                  // 127.0.0.0/8 (localhost)
        '/^10\./',                   // 10.0.0.0/8
        '/^172\.(1[6-9]|2\d|3[01])\./', // 172.16.0.0/12
        '/^192\.168\./',             // 192.168.0.0/16
        '/^169\.254\./',             // 169.254.0.0/16 (link-local, AWS metadata)
        '/^22[4-9]\./',              // 224.0.0.0/4 (multicast)
        '/^23\d\./',                 // 230-239 (multicast continued)
        '/^24\d\./',                 // 240.0.0.0/4 (reserved)
        '/^25[0-5]\./',              // 250-255 (reserved)
    ];

    foreach ($private_patterns as $pattern) {
      if (preg_match($pattern, $ip)) {
        return false;
      }
    }
  }

  return true;
}

/* -------------------- inputs + detection -------------------- */
$format = strtolower((string)($_GET['format'] ?? 'html'));
if (!in_array($format, ['html','json','iframe'], true)) {
  $format = 'html';
}
$allowEmbeddedHtml = in_array(strtolower((string)($_GET['embed'] ?? '0')), ['1','true','yes'], true);
$showMenu = !in_array(strtolower((string)($_GET['render_menu'] ?? '1')), ['0','no','false'], true);

$clientIp = get_client_ip() ?: '0.0.0.0';
$isV4     = (bool)filter_var($clientIp, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4);

/* VPN wins over LAN */
$lanCidrs       = ['10.0.0.0/8','172.16.0.0/12','192.168.0.0/16','127.0.0.1/32'];
$inLanRfc1918   = $isV4 && ip_in_any_cidr($clientIp, $lanCidrs);

$vpnSpec  = getenv('VPN_CIDR') ?: '';
$vpnCidrs = parse_cidr_list($vpnSpec);
$onVpn    = $isV4 && !empty($vpnCidrs) && ip_in_any_cidr($clientIp, $vpnCidrs);

$inLan    = $inLanRfc1918 && !$onVpn;

$mtlsHeader       = strtolower((string)($_SERVER['HTTP_X_MTLS'] ?? ''));
$usingMtls        = in_array($mtlsHeader, ['on','1','true'], true);
$mtlsExpiryHeader = trim((string)($_SERVER['HTTP_X_MTLS_EXPIRY'] ?? ''));
if ($mtlsExpiryHeader === '') {
  $mtlsExpiryHeader = null;
}

$hostNow = get_trusted_host();
$labels  = explode('.', $hostNow);
$apex    = (count($labels) >= 3) ? implode('.', array_slice($labels, -3)) : $hostNow;
$defaultApexBase = $SITE_PROTOCOL . $apex . '/endpoints/lease_ip.php';

$base = (string)($_GET['lease_url'] ?? (getenv('LEASE_API_BASE') ?: $defaultApexBase));

// Validate URL to prevent SSRF attacks
if (isset($_GET['lease_url']) && !validate_safe_url($base)) {
  http_response_code(400);
  header('Content-Type: application/json; charset=utf-8');
  echo json_encode(['ok' => false, 'error' => 'Invalid or unsafe URL provided'], JSON_UNESCAPED_SLASHES);
  exit;
}

$leaseUrl = (function ($u) {
  $q = parse_url($u, PHP_URL_QUERY);
  return ($q && preg_match('/(?:^|&)list=1(?:&|$)/', (string)$q))
      ? $u
      : $u . (strpos($u, '?') !== false ? '&' : '?') . 'list=1';
})($base);

/* -------- Resolve whitelist (list) -------- */
$isWhitelisted = false;
$wlMatch = null;
list($wlOk, $wlPayload, $wlHttp, $wlErr) = (function ($url) {
  $ch = curl_init($url);
  curl_setopt_array($ch, [
      CURLOPT_RETURNTRANSFER => true,
      CURLOPT_FOLLOWLOCATION => true,
      CURLOPT_CONNECTTIMEOUT => 2,
      CURLOPT_TIMEOUT        => 3,
      CURLOPT_USERAGENT      => 'LUM-ConnTest/1.2',
      CURLOPT_HTTPHEADER     => ['Accept: application/json'],
  ]);
  $body = curl_exec($ch);
  $code = curl_getinfo($ch, CURLINFO_HTTP_CODE) ?: 0;
  $err  = curl_error($ch);
  if ($body === false || $code < 200 || $code >= 300) {
    return [false, null, $code, $err ?: 'http_error'];
  }
  $data = json_decode($body, true);
  if (!is_array($data)) {
    return [false, null, $code, 'invalid_json'];
  }
  return [true, $data, $code, ''];
})($leaseUrl);

if ($wlOk && isset($wlPayload['entries']) && is_array($wlPayload['entries'])) {
  foreach ($wlPayload['entries'] as $e) {
    if (!isset($e['ip'])) {
      continue;
    }
    if ((string)$e['ip'] === $clientIp) {
      $isWhitelisted = true;
      $wlMatch = [
          'label'     => $e['label'] ?? null,
          'timestamp' => $e['timestamp'] ?? null,
          'source'    => $e['source'] ?? null,
          'static'    => (bool)($e['static'] ?? false),
      ];
      break;
    }
  }
}

$allNo     = (!$inLan && !$onVpn && !$usingMtls && !$isWhitelisted);
$sourceTag = 'LUM Iframe';

/* -------- AllowedIPs base + external -------- */
$wgBaseSpec = getenv('WG_ALLOWEDIPS') ?: '';
$wgBaseList = parse_cidr_list($wgBaseSpec);

$extIPv4   = detect_public_ipv4($hostNow);
$extCIDR   = $extIPv4 ? ($extIPv4 . '/32') : null;

/* Inline lease API */
if (isset($_GET['do']) && $_GET['do'] === 'lease') {
  if (($_SERVER['REQUEST_METHOD'] ?? 'GET') !== 'POST') {
    http_response_code(405);
    header('Content-Type: application/json; charset=utf-8');
    echo json_encode(['ok' => false, 'error' => 'Lease action requires POST'], JSON_UNESCAPED_SLASHES);
    exit;
  }

  $csrfToken = trim((string)($_SERVER['HTTP_X_CSRF_TOKEN'] ?? ($_POST['csrf_token'] ?? '')));
  if (!csrf_validate_token($csrfToken)) {
    http_response_code(403);
    header('Content-Type: application/json; charset=utf-8');
    echo json_encode(['ok' => false, 'error' => 'CSRF validation failed'], JSON_UNESCAPED_SLASHES);
    exit;
  }

  $target = $base . (strpos($base, '?') !== false ? '&' : '?') . 'add=' . rawurlencode($clientIp);
  $headers = [
      'Accept: application/json',
      'X-IP-Lease-Label: ' . $username,
      'X-IP-Lease-Source: ' . $sourceTag,
      'X-Forwarded-For: ' . $clientIp,
  ];
  [$ok, $code, $err, $body] = http_request($target, 'GET', null, $headers);
  error_log(sprintf('LUM-ConnTest: lease POST %s http=%d ok=%d', $target, (int)$code, $ok ? 1 : 0));
  header('Content-Type: application/json; charset=utf-8');
  echo json_encode([
      'ok'     => $ok,
      'http'   => $code,
      'err'    => $ok ? null : $err,
      'target' => $target,
      'body'   => substr($body ?? '', 0, 256),
  ], JSON_UNESCAPED_SLASHES);
  exit;
}

/* -------------------- render -------------------- */
if ($format === 'json') {
  header('Content-Type: application/json; charset=utf-8');
  echo json_encode([
      'ok'        => true,
      'user'      => $username,
      'client_ip' => $clientIp,
      'flags'     => [
          'in_lan'               => $inLan,
          'on_vpn'               => $onVpn,
          'using_whitelisted_ip' => $isWhitelisted,
          'using_mtls'           => $usingMtls,
      ],
      'mtls' => [
          'header'  => $mtlsHeader ?: null,
          'detected' => $usingMtls,
          'expiry'  => $mtlsExpiryHeader,
      ],
      'lease_api' => ['url' => $leaseUrl, 'ok' => $wlOk, 'http' => $wlHttp, 'err' => $wlOk ? null : $wlErr, 'match' => $wlMatch],
      'vpn_cidrs'       => $vpnCidrs,
      'allowedips_base' => $wgBaseList,
      'external_ipv4'   => $extIPv4,
      'ts' => date('Y-m-d H:i:s T'),
  ], JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
  exit;
} elseif ($format === 'iframe') {
  $iframeCsrfToken = csrf_get_token();
  $filterKeys     = parse_filter_keys((string)($_GET['filter'] ?? ''));
  $showLanRow     = empty($filterKeys) || isset($filterKeys['lan']);
  $showVpnRow     = empty($filterKeys) || isset($filterKeys['vpn']);
  $showMtlsRow    = empty($filterKeys) || isset($filterKeys['mtls']);
  $showLeasedRow  = empty($filterKeys) || isset($filterKeys['leased']);

  $flagsRendered = 0;
  $flagsNo = 0;
  if ($showLanRow) {
    $flagsRendered++;
    if (!$inLan) {
      $flagsNo++;
    }
  }
  if ($showVpnRow) {
    $flagsRendered++;
    if (!$onVpn) {
      $flagsNo++;
    }
  }
  if ($showMtlsRow) {
    $flagsRendered++;
    if (!$usingMtls) {
      $flagsNo++;
    }
  }
  if ($showLeasedRow) {
    $flagsRendered++;
    if (!$isWhitelisted) {
      $flagsNo++;
    }
  }
  $allRenderedNo = ($flagsRendered > 0 && $flagsRendered === $flagsNo);

  header('Content-Type: text/html; charset=utf-8');
  $selfLeaseUrl = $_SERVER['PHP_SELF'] . '?format=iframe&do=lease&lease_url=' . rawurlencode($base);

  /* Bubble content + copy text */
  $baseHtml   = implode(', ', array_map(fn ($c) => '<code>' . h($c) . '</code>', $wgBaseList));
  $appendSep  = $wgBaseList ? ', ' : '';
  $appendHtml = $appendSep . ($extCIDR ? '<code><u>' . h($extCIDR) . '</u></code>' : '<code><u>x.x.x.x/32</u></code>');
  $copyText   = ($extCIDR ? ', ' . $extCIDR : ', x.x.x.x/32');
  ?>
    <!doctype html>
    <html>
    <head>
      <meta charset="utf-8" />
      <meta name="viewport" content="width=device-width,initial-scale=1" />
      <style>
      :root {
        --fg:#e5e7eb;
        --card:#0b0f13;
        --border:rgba(255,255,255,.08);
        --glow:rgba(127,209,255,.35);
        --line:rgba(127,209,255,.45);
      }
      @media (prefers-color-scheme: light) {
        :root {
          --fg:#0a0a0a;
          --card:#ffffff;
          --border:rgba(0,0,0,.08);
          --glow:rgba(0,123,255,.25);
          --line:rgba(0,123,255,.45);
        }
      }
    
      * { box-sizing:border-box; }
    
      html,
      body {
        margin:0;
        padding:0;
        width:100%;
        height:100%;
      }
    
      body {
        background:#000;
        color:var(--fg);
        font:14px/1.4 system-ui,-apple-system,Segoe UI,Roboto,Ubuntu,Cantarell,Arial;
        display:flex;
        align-items:stretch;
        justify-content:stretch;
      }
    
      .micro {
        padding:10px 12px;
        border-radius:12px;
        background:var(--card);
        border:1px solid var(--border);
        overflow:visible;
        width:100%;
        height:100%;
      }
    
      .row {
        display:flex;
        justify-content:space-between;
        align-items:center;
        padding:8px 0;
      }
    
      .row + .row { border-top:1px solid var(--border); }
    
      .label {
        font-weight:600;
        letter-spacing:.2px;
        display:inline-flex;
        align-items:center;
        gap:6px;
        white-space:nowrap;
      }
    
      .yes,
      .no { font-weight:700; }
    
      .val {
        display:inline-flex;
        align-items:center;
        gap:6px;
      }
    
      .btn {
        display:inline-block;
        text-decoration:none;
        line-height:1;
        padding:8px 12px;
        border-radius:9px;
        font-weight:700;
        cursor:pointer;
        user-select:none;
        -webkit-tap-highlight-color:transparent;
        background:rgba(127,209,255,.18);
        color:#d6f1ff;
        border:1px solid var(--line);
      }
    
      .btn[aria-busy="true"] {
        opacity:.7;
        pointer-events:none;
      }
    
      .tip {
        position:relative;
        display:inline-flex;
        align-items:center;
        justify-content:center;
        min-width:16px;
        height:16px;
        border-radius:50%;
        font-size:11px;
        line-height:1;
        font-weight:800;
        background:
          radial-gradient(circle at 30% 30%, rgba(127,209,255,.22), rgba(127,209,255,.06) 60%),
          rgba(15,20,28,.72);
        color:#d6f1ff;
        border:1px solid var(--line);
        box-shadow:0 0 6px var(--glow), inset 0 0 6px rgba(127,209,255,.15);
        cursor:pointer;
        outline:none;
        user-select:none;
        touch-action:manipulation;
      }
    
      .helpchip {
        display:inline-flex;
        align-items:center;
        gap:4px;
        margin-left:4px;
        padding:2px 6px;
        border-radius:8px;
        font-size:11px;
        line-height:1.2;
        font-weight:700;
        background:rgba(127,209,255,.12);
        border:1px solid var(--line);
        color:#d6f1ff;
      }
    
      .helpchip .q {
        width:14px;
        height:14px;
        border-radius:50%;
        display:inline-flex;
        align-items:center;
        justify-content:center;
        font-size:10px;
        font-weight:800;
      }
    
      #tipBubble,
      #tipArrow {
        position:fixed;
        z-index:2147483646;
      }
    
      #tipBubble {
        max-width:min(90vw, 260px);
        padding:8px 9px;
        border-radius:10px;
        position:fixed;
        background:rgba(11,15,19,.98);
        color:#cfe9ff;
        border:1px solid var(--line);
        box-shadow:0 10px 22px var(--glow), 0 0 12px rgba(0,180,255,.16);
        font-size:12px;
        letter-spacing:.2px;
        white-space:normal;
        text-align:left;
      }
    
      #tipArrow {
        width:0;
        height:0;
        filter:drop-shadow(0 0 4px var(--glow));
      }
    
      .copybtn {
        margin-left:6px;
        padding:0 6px;
        height:18px;
        line-height:18px;
        border-radius:6px;
        border:1px solid var(--line);
        background:rgba(127,209,255,.12);
        color:#d6f1ff;
        font-size:11px;
        font-weight:800;
        cursor:pointer;
      }
    
      .copynote {
        position:absolute;
        right:8px;
        bottom:6px;
        font-size:11px;
        padding:2px 6px;
        border-radius:8px;
        background:rgba(16,185,129,.18);
        color:#10b981;
        border:1px solid rgba(16,185,129,.4);
      }
    
      .hidden { display:none !important; }
    
      /* minimal: plus icon spacing for Lease button */
      .btn .ico {
        display:inline-block;
        margin-right:6px;
        font-weight:900;
        line-height:1;
      }
    </style>
    </head>
    <body>
      <div class="micro">
        <?php if ($showLanRow): ?>
        <div class="row">
          <span class="label">
            Inside LAN
            <span class="tip" tabindex="0" role="button" aria-haspopup="true" aria-expanded="false"
              data-tip="<?php echo h('Private (RFC1918) or localhost — excludes VPN ranges.'); ?>">i</span>
          </span>
          <span class="<?php echo $inLan ? 'yes' : 'no'; ?>"><?php echo $inLan ? '✅' : '❌'; ?></span>
        </div>
        <?php endif; ?>

        <?php if ($showVpnRow): ?>
        <div class="row">
          <span class="label">
            On VPN
            <span class="tip" tabindex="0" role="button" aria-haspopup="true" aria-expanded="false"
              data-tip="<?php echo h('True if your client IP is within VPN_CIDR range(s).'); ?>">i</span>

            <?php if (!$onVpn && $allRenderedNo): ?>
              <!-- Inline micro Troubleshoot chip, next to info icon -->
              <button
                type="button"
                class="helpchip tip"
                aria-label="Troubleshoot VPN"
                data-tip-template="vpnHelpTpl"
              ><span class="q">?</span> Troubleshoot</button>
              <template id="vpnHelpTpl">
                <div>
                  <b>Add this to AllowedIPs on VPN profile</b><br/>
                  <?php echo $baseHtml . $appendHtml; ?>
                  <button type="button" class="copybtn" data-copy="<?php echo h($copyText); ?>" aria-label="Copy to clipboard">⧉</button>
                </div>
              </template>
            <?php endif; ?>
          </span>
          <span class="val">
            <span class="<?php echo $onVpn ? 'yes' : 'no'; ?>"><?php echo $onVpn ? '✅' : '❌'; ?></span>
          </span>
        </div>
        <?php endif; ?>

        <?php if ($showMtlsRow): ?>
        <div class="row">
          <span class="label">
            mTLS
            <span class="tip" tabindex="0" role="button" aria-haspopup="true" aria-expanded="false"
              data-tip="<?php echo h('True if the reverse proxy verified a client certificate (X-MTLS: on).'); ?>">i</span>
          </span>
          <span class="<?php echo $usingMtls ? 'yes' : 'no'; ?>"><?php echo $usingMtls ? '✅' : '❌'; ?></span>
        </div>
        <?php endif; ?>

        <?php if ($showLeasedRow): ?>
        <div class="row">
          <span class="label">
            Leased IP
            <span class="tip" tabindex="0" role="button" aria-haspopup="true" aria-expanded="false"
              data-tip="<?php echo h('True if your current IP is on the Lease IP allowlist.'); ?>">i</span>
          </span>
          <span class="val">
            <?php if ($allNo && $isV4): ?>
              <a id="leaseBtn" class="btn" href="<?php echo h($selfLeaseUrl); ?>" role="button" aria-label="Lease this IP"><span class="ico" aria-hidden="true">+</span>Lease this IP</a>
            <?php endif; ?>
            <span class="<?php echo $isWhitelisted ? 'yes' : 'no'; ?>"><?php echo $isWhitelisted ? '✅' : '❌'; ?></span>
          </span>
        </div>
        <?php endif; ?>
      </div>

      <?php if ($allNo && $isV4 && $showLeasedRow): ?>
      <script>
        (function(){
          var csrfToken = <?php echo json_encode($iframeCsrfToken); ?>;
          var btn = document.getElementById('leaseBtn'); if (!btn) return;
          var url = btn.getAttribute('href');
          btn.addEventListener('click', function(ev){
            ev.preventDefault(); btn.setAttribute('aria-busy','true'); btn.textContent='Leasing…';
            var finish = function(){ setTimeout(function(){ location.reload(); }, 800); };
            try {
              fetch(url, {
                method:'POST',
                credentials:'include',
                headers:{'X-CSRF-Token': csrfToken}
              }).finally(finish);
            } catch(_){ finish(); }
          });
        })();
      </script>
      <?php endif; ?>

      <div id="tipBubble" class="hidden" role="dialog" aria-live="polite"></div>
      <div id="tipArrow"  class="hidden" aria-hidden="true"></div>

      <script>
        (function(){
          var openEl=null, bubble=document.getElementById('tipBubble'), arrow=document.getElementById('tipArrow');
          var margin=8, gap=8, aSize=7, hoverTO=null;

          function clamp(v,min,max){ return Math.max(min,Math.min(max,v)); }

          function copyText(txt, inlineBtn){
            if (!txt) return;
            var done = function(){
              try{
                var note=document.createElement('div');
                note.className='copynote'; note.textContent='Copied';
                bubble.appendChild(note);
                if (inlineBtn){ var prev=inlineBtn.textContent; inlineBtn.textContent='Copied!'; setTimeout(function(){ inlineBtn.textContent=prev; }, 900); }
                setTimeout(function(){ if(note&&note.parentNode){ note.parentNode.removeChild(note);} }, 900);
              }catch(_){}
            };
            if (navigator.clipboard && navigator.clipboard.writeText) {
              navigator.clipboard.writeText(txt).then(done).catch(function(){
                try{
                  var ta=document.createElement('textarea');
                  ta.value=txt; ta.style.position='fixed'; ta.style.top='-1000px';
                  document.body.appendChild(ta); ta.focus(); ta.select();
                  document.execCommand('copy'); document.body.removeChild(ta); done();
                }catch(_){}
              });
            } else {
              try{
                var ta=document.createElement('textarea');
                ta.value=txt; ta.style.position='fixed'; ta.style.top='-1000px';
                document.body.appendChild(ta); ta.focus(); ta.select();
                document.execCommand('copy'); document.body.removeChild(ta); done();
              }catch(_){}
            }
          }

          function place(el){
            var r=el.getBoundingClientRect(), vw=Math.max(document.documentElement.clientWidth,window.innerWidth||0);
            var vh=Math.max(document.documentElement.clientHeight,window.innerHeight||0);

            var html='', tplId=el.getAttribute('data-tip-template');
            if (tplId){ var tpl=document.getElementById(tplId); html=tpl?tpl.innerHTML:''; }
            else if (el.hasAttribute('data-tip-html')){ html=el.getAttribute('data-tip-html')||''; }

            if (html) bubble.innerHTML=html; else bubble.textContent=el.getAttribute('data-tip')||'';
            bubble.classList.remove('hidden'); arrow.classList.remove('hidden');

            // Bind copy button (if present)
            var cbtn = bubble.querySelector('.copybtn');
            if (cbtn){
              var toCopy = cbtn.getAttribute('data-copy') || '';
              cbtn.addEventListener('click', function(ev){
                ev.preventDefault(); ev.stopPropagation();
                copyText(toCopy, cbtn);
              });
            }

            var bw=bubble.offsetWidth, bh=bubble.offsetHeight, cx=r.left+r.width/2;
            var top=r.top-gap-bh, placeTop=true; if (top<margin){ top=r.bottom+gap; placeTop=false; }
            var left=clamp(cx-bw/2, margin, vw-bw-margin);
            bubble.style.top=Math.round(top)+'px'; bubble.style.left=Math.round(left)+'px';
            var ax=clamp(cx, left+aSize+2, left+bw-aSize-2);
            if (placeTop){
              arrow.style.borderLeft=aSize+'px solid transparent'; arrow.style.borderRight=aSize+'px solid transparent';
              arrow.style.borderBottom='0'; arrow.style.borderTop=aSize+'px solid var(--line)';
              arrow.style.top=Math.round(top+bh)+'px'; arrow.style.left=Math.round(ax-aSize)+'px';
            } else {
              arrow.style.borderLeft=aSize+'px solid transparent'; arrow.style.borderRight=aSize+'px solid transparent';
              arrow.style.borderTop='0'; arrow.style.borderBottom=aSize+'px solid var(--line)';
              arrow.style.top=Math.round(top-aSize)+'px'; arrow.style.left=Math.round(ax-aSize)+'px';
            }

            el.setAttribute('aria-expanded','true');
          }

          function close(){ if(!openEl) return; openEl.setAttribute('aria-expanded','false'); openEl=null; bubble.classList.add('hidden'); arrow.classList.add('hidden'); }
          function open(el){ if (openEl===el){ close(); } else { openEl=el; place(el); } }

          function handleOpen(ev){
            // Don't close if clicking inside the bubble (enables copy button on mobile)
            if (ev.target && ev.target.closest && ev.target.closest('#tipBubble')) { return; }
            var tip=ev.target.closest('.tip');
            if (tip){ ev.preventDefault(); open(tip); } else { close(); }
          }

          document.addEventListener('pointerup', handleOpen, {passive:false});
          document.addEventListener('touchend',  handleOpen, {passive:false});
          document.addEventListener('click',     handleOpen, {passive:false});

          document.addEventListener('mouseover', function(ev){ var t=ev.target.closest('.tip'); if(!t) return; clearTimeout(hoverTO); open(t); });
          document.addEventListener('mouseout',  function(ev){ if (ev.target && ev.target.closest && ev.target.closest('.tip')) hoverTO=setTimeout(close,120); });

          document.addEventListener('keydown',   function(ev){
            if(ev.key==='Escape') close();
            if((ev.key==='Enter'||ev.key===' ')&&document.activeElement&&document.activeElement.classList&&document.activeElement.classList.contains('tip')){
              ev.preventDefault(); open(document.activeElement);
            }
          });

          window.addEventListener('resize', function(){ if(openEl) place(openEl); });
          window.addEventListener('scroll', function(){ if(openEl) place(openEl); }, {passive:true});
          window.addEventListener('blur', close);
        })();
      </script>
    </body>
    </html>
    <?php
  exit;
}

render_header('Test Connection', $showMenu, '', $allowEmbeddedHtml ? 'SAMEORIGIN' : 'DENY');

if (!$showMenu) {
  echo '<style>.navbar, .breadcrumb, .page-header{display:none!important;} body{padding-top:0!important;}</style>';
}
?>
<style>
.conn-wrap {
  max-width: 900px;
  margin: 18px auto 40px;
}
.conn-card {
  background: linear-gradient(
    135deg,
    var(--gradient-header, rgba(127, 209, 255, 0.08)) 0%,
    var(--gradient-end, rgba(18, 24, 32, 0.96)) 100%
  ), var(--bg-tertiary, #121820);
  border: 1px solid var(--border-primary, rgba(255, 255, 255, 0.12));
  border-radius: 14px;
  box-shadow: 0 0 20px var(--shadow-glow, rgba(42, 139, 220, 0.2));
  overflow: hidden;
}
.conn-head {
  padding: 12px 16px;
  border-bottom: 1px solid var(--border-primary, rgba(255, 255, 255, 0.12));
  color: var(--accent, #9fd1ff);
  font-weight: 700;
  letter-spacing: 0.4px;
  text-transform: uppercase;
}
.conn-body {
  padding: 14px;
}
.meta-grid {
  display: grid;
  gap: 8px;
}
.meta-row {
  display: grid;
  grid-template-columns: 180px 1fr;
  gap: 10px;
  align-items: center;
  padding: 8px 10px;
  border-radius: 10px;
  border: 1px solid var(--border-primary, rgba(255, 255, 255, 0.1));
  background: rgba(255, 255, 255, 0.02);
}
.meta-key {
  color: var(--text-muted, #9fb6c9);
  font-size: 12px;
  text-transform: uppercase;
  letter-spacing: 0.35px;
}
.chip {
  display: inline-block;
  padding: 3px 9px;
  border-radius: 999px;
  border: 1px solid var(--border-primary, rgba(127, 209, 255, 0.35));
  background: rgba(127, 209, 255, 0.1);
  color: var(--text-primary, #d9eeff);
  font-family: monospace;
  font-size: 13px;
}
.status-list {
  margin-top: 12px;
  display: grid;
  gap: 8px;
}
.status-row {
  display: flex;
  justify-content: space-between;
  align-items: center;
  gap: 12px;
  padding: 10px 12px;
  border-radius: 10px;
  border: 1px solid var(--border-primary, rgba(255, 255, 255, 0.1));
  background: rgba(255, 255, 255, 0.015);
}
.status-row span:first-child {
  color: var(--text-primary, #e2f1ff);
}
.status-flag {
  font-weight: 700;
  letter-spacing: 0.2px;
}
.status-flag.yes {
  color: #10b981;
}
.status-flag.no {
  color: #ef4444;
}
.conn-note {
  margin-top: 12px;
  color: var(--text-muted, #8aa0b2);
  font-size: 12px;
  line-height: 1.45;
}
.conn-block {
  margin-top: 12px;
  padding-top: 12px;
  border-top: 1px solid var(--border-primary, rgba(255, 255, 255, 0.12));
}
.conn-block-title {
  color: var(--accent, #9fd1ff);
  font-size: 12px;
  font-weight: 700;
  letter-spacing: 0.3px;
  text-transform: uppercase;
  margin-bottom: 8px;
}
.warning-note {
  margin-top: 10px;
  color: #ffb4b4;
  font-size: 12px;
}
.conn-card--embed {
  background: transparent;
  border: none;
  box-shadow: none;
  border-radius: 0;
}
.conn-card--embed .conn-body {
  padding: 16px 18px;
}
@media (max-width: 768px) {
  .conn-body {
    padding: 12px;
  }
  .meta-row {
    grid-template-columns: 1fr;
    gap: 6px;
  }
  .status-row {
    align-items: flex-start;
  }
}
</style>

<div class="container conn-wrap">
  <div class="conn-card<?php echo $allowEmbeddedHtml ? ' conn-card--embed' : ''; ?>">
    <?php if (!$allowEmbeddedHtml): ?>
      <div class="conn-head">Connection Check</div>
    <?php endif; ?>
    <div class="conn-body">
      <div class="meta-grid">
        <div class="meta-row">
          <div class="meta-key">Signed in as</div>
          <div><span class="chip"><?php echo h($username); ?></span></div>
        </div>
        <div class="meta-row">
          <div class="meta-key">Detected client IP</div>
          <div><span class="chip"><?php echo h($clientIp); ?></span></div>
        </div>
      </div>

      <div class="status-list">
        <div class="status-row">
          <span>Your device is inside the LAN (RFC1918).</span>
          <span class="status-flag <?php echo $inLan ? 'yes' : 'no'; ?>"><?php echo $inLan ? 'YES' : 'NO'; ?></span>
        </div>
        <div class="status-row">
          <span>Your device is on the VPN.</span>
          <span class="status-flag <?php echo $onVpn ? 'yes' : 'no'; ?>"><?php echo $onVpn ? 'YES' : 'NO'; ?></span>
        </div>
        <div class="status-row">
          <span>Your device is using a leased IP.</span>
          <span class="status-flag <?php echo $isWhitelisted ? 'yes' : 'no'; ?>"><?php echo $isWhitelisted ? 'YES' : 'NO'; ?></span>
        </div>
        <div class="status-row">
          <span>Your device is pinning an mTLS certificate.</span>
          <span class="status-flag <?php echo $usingMtls ? 'yes' : 'no'; ?>"><?php echo $usingMtls ? 'YES' : 'NO'; ?></span>
        </div>
      </div>

      <div class="conn-note">
        <?php if ($usingMtls): ?>
          mTLS detected via header <code>X-MTLS</code>=<code>on</code><?php if ($mtlsExpiryHeader !== null): ?>, <code>X-MTLS-Expiry</code>=<code><?php echo h($mtlsExpiryHeader); ?></code><?php endif; ?>.
        <?php else: ?>
          mTLS not detected on this path.
        <?php endif; ?>
      </div>

      <?php if ($isAdmin): ?>
        <div class="conn-block">
          <div class="conn-block-title">Admin Diagnostics</div>
          <div class="meta-grid">
            <div class="meta-row">
              <div class="meta-key">VPN CIDR(s)</div>
              <div><code class="chip"><?php echo h(implode(', ', $vpnCidrs) ?: '—'); ?></code></div>
            </div>
            <div class="meta-row">
              <div class="meta-key">Lease API</div>
              <div><code class="chip" style="word-break:break-all;"><?php echo h($leaseUrl); ?></code></div>
            </div>
            <div class="meta-row">
              <div class="meta-key">Ext IPv4</div>
              <div><code class="chip"><?php echo h($extIPv4 ?: 'n/a'); ?></code></div>
            </div>
          </div>
        </div>
      <?php endif; ?>

      <?php if ($isAdmin && $isWhitelisted && $wlMatch): ?>
        <div class="conn-block">
          <div class="conn-block-title">Lease Match</div>
          <div class="meta-grid">
            <?php if (!empty($wlMatch['label'])): ?>
              <div class="meta-row"><div class="meta-key">Label</div><div><span class="chip"><?php echo h((string)$wlMatch['label']); ?></span></div></div>
            <?php endif; ?>
            <?php if (!empty($wlMatch['source'])): ?>
              <div class="meta-row"><div class="meta-key">Source</div><div><span class="chip"><?php echo h((string)$wlMatch['source']); ?></span></div></div>
            <?php endif; ?>
            <?php if (!empty($wlMatch['timestamp'])): ?>
              <div class="meta-row"><div class="meta-key">Since</div><div><span class="chip"><?php echo h((string)$wlMatch['timestamp']); ?></span></div></div>
            <?php endif; ?>
            <?php if (array_key_exists('static', $wlMatch) && $wlMatch['static']): ?>
              <div class="meta-row"><div class="meta-key">Static</div><div><span class="chip">true</span></div></div>
            <?php endif; ?>
          </div>
        </div>
      <?php endif; ?>

      <?php if ($isAdmin && !$wlOk): ?>
        <div class="warning-note">
          Lease API lookup unavailable (HTTP <?php echo (int)$wlHttp; ?><?php echo $wlErr ? ', ' . h($wlErr) : ''; ?>).
          Status is shown without whitelist match details.
        </div>
      <?php endif; ?>
    </div>
  </div>
</div>

<?php render_footer();
