<?php
#Security level vars

$VALIDATED = false;
$IS_ADMIN = false;
$IS_SETUP_ADMIN = false;
$ACCESS_LEVEL_NAME = ['account','admin'];
unset($USER_ID);
$CURRENT_PAGE = htmlentities($_SERVER['PHP_SELF']);
$SENT_HEADERS = false;
$SESSION_TIMED_OUT = false;

$paths = explode('/', getcwd());
$THIS_MODULE = end($paths);

$GOOD_ICON = '&#9745;';
$WARN_ICON = '&#9888;';
$FAIL_ICON = '&#9940;';

// Customizable external links
$MFA_SETTINGS_URL = getenv('MFA_SETTINGS_URL') ?: '';

$JS_EMAIL_REGEX = '/^(([^<>()[\]\\.,;:\s@\"]+(\.[^<>()[\]\\.,;:\s@\"]+)*)|(\".+\"))@((\[[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\])|(([a-zA-Z\-0-9]+\.)+[a-zA-Z]{2,}))$/;';

if (isset($_SERVER['HTTPS']) and
   ($_SERVER['HTTPS'] == 'on' || $_SERVER['HTTPS'] == 1) or
   isset($_SERVER['HTTP_X_FORWARDED_PROTO']) and
   $_SERVER['HTTP_X_FORWARDED_PROTO'] == 'https') {
  $SITE_PROTOCOL = 'https://';
} else {
  $SITE_PROTOCOL = 'http://';
}

include('config.inc.php');    # get local settings
include('modules.inc.php');   # module definitions
include_once('session_helpers.inc.php'); # session helpers
include_once('oidc_functions.inc.php'); # OIDC helpers

if (substr($SERVER_PATH, -1) != '/') {
  $SERVER_PATH .= '/';
}
$THIS_MODULE_PATH = "{$SERVER_PATH}{$THIS_MODULE}";

$DEFAULT_COOKIE_OPTIONS = [ 'expires' => time() + (60 * $SESSION_TIMEOUT),
                                 'path' => $SERVER_PATH,
                                 'domain' => '',
                                 'secure' => $NO_HTTPS ? false : true,
                                 'httponly' => true,
                                 'samesite' => 'strict',
                               ];

/* ============================================================================
 * Group helpers for access checks / menu gating.
 * - Supports both header-based auth and local session auth.
 * - Configure per-module requirements in $MODULE_GROUP_GATES (modules.inc.php)
 * ========================================================================== */
if (!function_exists('lum_remote_groups_lower')) {
  function lum_remote_groups_lower(): array
  {
    $raw = $_SERVER['HTTP_REMOTE_GROUPS'] ?? '';
    if ($raw === '' || $raw === null) {
      return [];
    }
    $parts = preg_split('/[;,\s]+/', (string)$raw, -1, PREG_SPLIT_NO_EMPTY);
    if (!$parts) {
      return [];
    }
    $parts = array_map('trim', $parts);
    $parts = array_map('strtolower', $parts);
    return array_values(array_unique($parts));
  }
}

if (!function_exists('lum_user_in_group')) {
  function lum_user_in_group(string $group): bool
  {
    return in_array(strtolower($group), lum_current_user_groups_lower(), true);
  }
}

if (!function_exists('lum_module_gate_satisfied')) {
  /**
   * Server-side enforcement of the per-module group gates declared in
   * $MODULE_GROUP_GATES (modules.inc.php). True when the current user may use
   * the module. A module with no declared gate is open to any validated user.
   *
   * Deliberately does NOT honour GROUP_GATE_ADMIN_BYPASS: that constant only
   * controls whether a gated entry is *shown* in the nav. Access enforcement
   * requires real membership, which matches what the module index pages do.
   *
   * Every entry point for a gated module must call this -- gating only the
   * index page leaves the module's API endpoints wide open to any logged-in
   * user.
   */
  function lum_module_gate_satisfied(string $module): bool
  {
    global $VALIDATED, $USER_ID;

    if (empty($VALIDATED) || trim((string)($USER_ID ?? '')) === '') {
      return false;
    }

    $gates = $GLOBALS['MODULE_GROUP_GATES'] ?? [];
    $needs = array_map('strtolower', (array)($gates[$module] ?? []));
    if (empty($needs)) {
      return true;
    }

    $have = lum_current_user_groups_lower();
    foreach ($needs as $group) {
      if (in_array($group, $have, true)) {
        return true;
      }
    }

    return false;
  }
}

if (!function_exists('lum_module_gate_group_label')) {
  /**
   * Human-readable list of the groups a module gate accepts, for error copy.
   */
  function lum_module_gate_group_label(string $module): string
  {
    $gates = $GLOBALS['MODULE_GROUP_GATES'] ?? [];
    $needs = (array)($gates[$module] ?? []);
    return $needs ? implode(' or ', $needs) : '';
  }
}

if (!function_exists('lum_require_module_gate_json')) {
  /**
   * Enforce a module group gate on a JSON endpoint: 403 and exit on failure.
   */
  function lum_require_module_gate_json(string $module): void
  {
    if (lum_module_gate_satisfied($module)) {
      return;
    }

    http_response_code(403);
    if (!headers_sent()) {
      header('Content-Type: application/json; charset=utf-8');
    }

    $label = lum_module_gate_group_label($module);
    echo json_encode([
      'ok'    => false,
      'error' => $label === ''
        ? 'Access denied.'
        : "Access denied: membership of the {$label} group is required.",
    ], JSON_UNESCAPED_SLASHES);
    exit;
  }
}

if (!function_exists('lum_parse_cidr_list')) {
  function lum_parse_cidr_list(string $spec): array
  {
    $spec = trim($spec);
    if ($spec === '') {
      return [];
    }
    $parts = preg_split('/[,\s;]+/', $spec, -1, PREG_SPLIT_NO_EMPTY);
    if (!is_array($parts)) {
      return [];
    }
    $out = [];
    foreach ($parts as $part) {
      $part = trim((string)$part);
      if ($part !== '') {
        $out[$part] = true;
      }
    }
    return array_keys($out);
  }
}

if (!function_exists('lum_normalize_ip')) {
  function lum_normalize_ip(?string $ip): ?string
  {
    $ip = trim((string)$ip);
    if ($ip === '') {
      return null;
    }
    if (!filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4 | FILTER_FLAG_IPV6)) {
      return null;
    }
    $packed = @inet_pton($ip);
    if ($packed === false) {
      return null;
    }
    $normalized = @inet_ntop($packed);
    return ($normalized === false || $normalized === null) ? null : $normalized;
  }
}

if (!function_exists('lum_ip_in_cidr')) {
  function lum_ip_in_cidr(string $ip, string $cidr): bool
  {
    $ip = (string)(lum_normalize_ip($ip) ?? '');
    if ($ip === '') {
      return false;
    }

    $cidr = trim($cidr);
    if ($cidr === '') {
      return false;
    }

    if (strpos($cidr, '/') === false) {
      $cidr_ip = lum_normalize_ip($cidr);
      return $cidr_ip !== null && $cidr_ip === $ip;
    }

    [$subnet_raw, $prefix_raw] = explode('/', $cidr, 2);
    $subnet = lum_normalize_ip($subnet_raw);
    if ($subnet === null || !ctype_digit(trim($prefix_raw))) {
      return false;
    }

    $prefix = (int)trim($prefix_raw);
    $ip_bin = @inet_pton($ip);
    $subnet_bin = @inet_pton($subnet);
    if ($ip_bin === false || $subnet_bin === false) {
      return false;
    }
    if (strlen($ip_bin) !== strlen($subnet_bin)) {
      return false;
    }

    $max_prefix = strlen($ip_bin) * 8;
    if ($prefix < 0 || $prefix > $max_prefix) {
      return false;
    }

    $full_bytes = intdiv($prefix, 8);
    $remaining_bits = $prefix % 8;

    if ($full_bytes > 0 && substr($ip_bin, 0, $full_bytes) !== substr($subnet_bin, 0, $full_bytes)) {
      return false;
    }

    if ($remaining_bits > 0) {
      $mask = chr((0xFF00 >> $remaining_bits) & 0xFF);
      if ((ord($ip_bin[$full_bytes]) & ord($mask)) !== (ord($subnet_bin[$full_bytes]) & ord($mask))) {
        return false;
      }
    }

    return true;
  }
}

if (!function_exists('lum_header_auth_trusted_source_required')) {
  function lum_header_auth_trusted_source_required(): bool
  {
    $env = getenv('HEADER_AUTH_REQUIRE_TRUSTED_PROXY');
    if ($env === false || $env === null || trim((string)$env) === '') {
      return true;
    }
    return strcasecmp((string)$env, 'false') !== 0;
  }
}

if (!function_exists('lum_is_header_auth_request_trusted')) {
  function lum_is_header_auth_request_trusted(): bool
  {
    $remote_ip = lum_normalize_ip($_SERVER['REMOTE_ADDR'] ?? '');
    if ($remote_ip === null) {
      return false;
    }

    $cidrs = lum_parse_cidr_list((string)(getenv('REVERSE_PROXY_WHITELIST') ?: ''));
    if (empty($cidrs)) {
      return !lum_header_auth_trusted_source_required();
    }

    foreach ($cidrs as $cidr) {
      if (lum_ip_in_cidr($remote_ip, $cidr)) {
        return true;
      }
    }
    return false;
  }
}

if (!function_exists('lum_client_ip')) {
  /**
   * Resolve the client IP without allowing callers to spoof proxy headers.
   * Forwarded headers are considered only when REMOTE_ADDR is a configured
   * trusted proxy; otherwise the direct peer address is authoritative.
   */
  function lum_client_ip(): string
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
      $normalized = lum_normalize_ip($candidate);
      if ($normalized !== null) {
        return $normalized;
      }
    }

    return '';
  }
}

if (!function_exists('lum_current_user_groups_lower')) {
  function lum_current_user_groups_lower(): array
  {
    global $OIDC_ENABLED, $REMOTE_HTTP_HEADERS_LOGIN, $VALIDATED, $USER_ID;

    static $cache = null;
    if ($cache !== null) {
      return $cache;
    }

    if ($VALIDATED !== true || !isset($USER_ID) || trim((string)$USER_ID) === '') {
      $cache = [];
      return $cache;
    }

    if (!empty($OIDC_ENABLED) && function_exists('oidc_session_groups_lower')) {
      $oidc_groups = oidc_session_groups_lower();
      if (!empty($oidc_groups)) {
        $cache = $oidc_groups;
        return $cache;
      }
    } elseif ($REMOTE_HTTP_HEADERS_LOGIN) {
      $cache = lum_remote_groups_lower();
      return $cache;
    }

    if (!function_exists('open_ldap_connection') || !function_exists('ldap_user_group_membership')) {
      @include_once 'ldap_functions.inc.php';
    }
    if (!function_exists('open_ldap_connection') || !function_exists('ldap_user_group_membership')) {
      $cache = [];
      return $cache;
    }

    $groups = [];
    $ldap_connection = null;
    try {
      $ldap_connection = open_ldap_connection();
      $groups = ldap_user_group_membership($ldap_connection, (string)$USER_ID);
    } catch (\Throwable $e) {
      $groups = [];
    } finally {
      if (is_resource($ldap_connection) || is_object($ldap_connection)) {
        @ldap_close($ldap_connection);
      }
    }

    $normalized = [];
    foreach ((array)$groups as $group_name) {
      $group_name = strtolower(trim((string)$group_name));
      if ($group_name !== '') {
        $normalized[$group_name] = true;
      }
    }
    $cache = array_keys($normalized);
    return $cache;
  }
}

if (!empty($OIDC_ENABLED)) {
  validate_passkey_cookie();
} elseif ($REMOTE_HTTP_HEADERS_LOGIN) {
  login_via_headers();
} else {
  validate_passkey_cookie();
}

if (!defined('GROUP_GATE_ADMIN_BYPASS')) {
  // If true, admins can see gated menu items even if they aren't in the group.
  define('GROUP_GATE_ADMIN_BYPASS', true);
}

if (!function_exists('get_trusted_host')) {
  /**
   * Returns a validated, trusted host value for use in redirects and URL construction.
   * Prevents Host header injection attacks by:
   * 1. Preferring TRUSTED_HOST env var (explicit configuration)
   * 2. Falling back to SERVER_NAME (set by server config, not user-controllable)
   * 3. Only using HTTP_HOST as last resort, with validation
   *
   * @return string Validated host value
   */
  function get_trusted_host(): string
  {
    // 1. Check for explicit trusted host configuration
    $trustedHost = getenv('TRUSTED_HOST');
    if ($trustedHost && is_string($trustedHost) && $trustedHost !== '') {
      return $trustedHost;
    }

    // 2. Prefer SERVER_NAME (set by server configuration)
    if (!empty($_SERVER['SERVER_NAME'])) {
      return $_SERVER['SERVER_NAME'];
    }

    // 3. Fall back to HTTP_HOST with validation
    $host = $_SERVER['HTTP_HOST'] ?? 'localhost';

    // Strip port if present for validation
    $hostOnly = preg_replace('/:\d+$/', '', $host);

    // Validate hostname format (basic check)
    // Allow: alphanumeric, dots, hyphens, underscores (for localhost variants)
    if (!preg_match('/^[a-zA-Z0-9._-]+$/', $hostOnly)) {
      // Invalid host format, fall back to localhost
      error_log('LUM Security: Invalid host header detected: ' . $host);
      return 'localhost';
    }

    return $host;
  }
}


######################################################

function generate_passkey()
{

  // Use cryptographically secure random bytes instead of predictable mt_rand()
  return bin2hex(random_bytes(32));

}


######################################################

if (!function_exists('csrf_generate_token')) {
  /**
   * Generate a CSRF token and store it in the session.
   * Should be called on login or when a token doesn't exist.
   *
   * @return string The generated CSRF token
   */
  function csrf_generate_token(): string
  {
    if (session_status() !== PHP_SESSION_ACTIVE) {
      lum_start_session();
    }

    $token = bin2hex(random_bytes(32));
    $_SESSION['csrf_token'] = $token;

    return $token;
  }
}

if (!function_exists('csrf_get_token')) {
  /**
   * Get the current CSRF token, generating one if it doesn't exist.
   *
   * @return string The CSRF token
   */
  function csrf_get_token(): string
  {
    if (session_status() !== PHP_SESSION_ACTIVE) {
      lum_start_session();
    }

    if (empty($_SESSION['csrf_token'])) {
      return csrf_generate_token();
    }

    return $_SESSION['csrf_token'];
  }
}

if (!function_exists('csrf_validate_token')) {
  /**
   * Validate a CSRF token from request.
   * Checks both POST data and custom header.
   *
   * @param string|null $token Token to validate (optional, auto-detected if not provided)
   * @return bool True if valid, false otherwise
   */
  function csrf_validate_token(?string $token = null): bool
  {
    if (session_status() !== PHP_SESSION_ACTIVE) {
      lum_start_session();
    }

    // Get expected token from session
    $expected = $_SESSION['csrf_token'] ?? null;
    if (!$expected) {
      return false;
    }

    // Get token from request if not provided
    if ($token === null) {
      // Check POST parameter
      $token = $_POST['csrf_token'] ?? null;

      // Check custom header (for AJAX requests)
      if (!$token) {
        $token = $_SERVER['HTTP_X_CSRF_TOKEN'] ?? null;
      }
    }

    if (!$token) {
      return false;
    }

    // Use timing-safe comparison
    return hash_equals($expected, $token);
  }
}

if (!function_exists('csrf_verify_or_exit')) {
  /**
   * Verify CSRF token or terminate with error response.
   * Use this at the start of state-changing endpoints.
   *
   * @param int $status_code HTTP status code to return on failure (default: 403)
   */
  function csrf_verify_or_exit(int $status_code = 403): void
  {
    if (!csrf_validate_token()) {
      http_response_code($status_code);

      // Return JSON for AJAX requests
      if (!empty($_SERVER['HTTP_X_REQUESTED_WITH']) &&
          strtolower($_SERVER['HTTP_X_REQUESTED_WITH']) === 'xmlhttprequest' ||
          (isset($_SERVER['HTTP_ACCEPT']) && strpos($_SERVER['HTTP_ACCEPT'], 'application/json') !== false)) {
        header('Content-Type: application/json');
        echo json_encode(['ok' => false, 'error' => 'CSRF validation failed']);
      } else {
        echo 'CSRF validation failed';
      }

      error_log('LUM Security: CSRF validation failed from ' . ($_SERVER['REMOTE_ADDR'] ?? 'unknown'));
      exit;
    }
  }
}


######################################################

function set_passkey_cookie($user_id, $is_admin)
{

  # Create a random value, store it locally and set it in a cookie.

  global $SESSION_TIMEOUT, $VALIDATED, $USER_ID, $IS_ADMIN, $log_prefix, $SESSION_DEBUG, $DEFAULT_COOKIE_OPTIONS;

  // Prevent session fixation by regenerating session ID on login
  if (session_status() === PHP_SESSION_ACTIVE) {
    session_regenerate_id(true);
  }

  $passkey = generate_passkey();
  $this_time = time();
  $admin_val = 0;

  if ($is_admin == true) {
    $admin_val = 1;
    $IS_ADMIN = true;
  }

  // Use dedicated session directory instead of /tmp for security
  $session_dir = getenv('SESSION_DIR') ?: (dirname(__DIR__) . '/data/sessions');
  if (!is_dir($session_dir)) {
    $old_umask = umask(0077);
    @ mkdir($session_dir, 0700, true);
    umask($old_umask);
  }

  // Use hashed filename to prevent enumeration attacks
  $filename = hash('sha256', $user_id);
  $session_file = $session_dir . '/' . $filename;

  $old_umask = umask(0077); // Set restrictive umask before file creation
  $bytes_written = @file_put_contents($session_file, "$passkey:$admin_val:$this_time");
  if ($bytes_written !== false) {
    @chmod($session_file, 0600); // Ensure only owner can read/write
  }
  umask($old_umask); // Restore original umask

  if ($bytes_written === false) {
    error_log("$log_prefix Session: failed to persist session file at {$session_file}", 0);
    $VALIDATED = false;
    return false;
  }

  $encoded_user = rawurlencode((string)$user_id);
  $orf_cookie_set = setcookie('orf_cookie', "{$encoded_user}:{$passkey}", $DEFAULT_COOKIE_OPTIONS);
  $sessto_cookie_opts = $DEFAULT_COOKIE_OPTIONS;
  $sessto_cookie_opts['expires'] = $this_time + 7200;
  $sessto_cookie_set = setcookie('sessto_cookie', $this_time + (60 * $SESSION_TIMEOUT), $sessto_cookie_opts);
  if (!$orf_cookie_set || !$sessto_cookie_set) {
    error_log("$log_prefix Session: failed to send auth cookies for user {$user_id} (headers_sent=" . (headers_sent() ? 'true' : 'false') . ')', 0);
    $VALIDATED = false;
    $IS_ADMIN = false;
    unset($USER_ID);
    return false;
  }
  if ($SESSION_DEBUG == true) {
    error_log("$log_prefix Session: user $user_id validated (IS_ADMIN={$IS_ADMIN}), sent orf_cookie to the browser.", 0);
  }

  // Generate a fresh CSRF token on login/refresh.
  // During early include-time auth checks this function can run before the
  // conditional csrf_* declarations below are executed.
  if (function_exists('csrf_generate_token')) {
    csrf_generate_token();
  } else {
    if (session_status() === PHP_SESSION_NONE) {
      lum_start_session();
    }
    if (session_status() === PHP_SESSION_ACTIVE) {
      $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
    }
  }

  $VALIDATED = true;
  $USER_ID = (string)$user_id;

  return true;
}


######################################################

function login_via_headers()
{

  global $IS_ADMIN, $USER_ID, $VALIDATED, $LDAP, $log_prefix;

  if (!lum_is_header_auth_request_trusted()) {
    http_response_code(403);
    $remote = $_SERVER['REMOTE_ADDR'] ?? 'unknown';
    $wl = (string)(getenv('REVERSE_PROXY_WHITELIST') ?: '');
    error_log("$log_prefix Security: blocked header auth from untrusted source $remote (whitelist='$wl')", 0);
    echo 'Access denied: untrusted reverse-proxy source for header authentication.';
    exit(0);
  }

  $remote_user = trim((string)($_SERVER['HTTP_REMOTE_USER'] ?? ''));
  if ($remote_user === '') {
    $VALIDATED = false;
    $IS_ADMIN = false;
    unset($USER_ID);
    return;
  }
  $USER_ID = $remote_user;
  // Accept semicolons/commas/whitespace as separators for robustness
  $groups_raw = $_SERVER['HTTP_REMOTE_GROUPS'] ?? '';
  $remote_groups = preg_split('/[;,\s]+/', (string)$groups_raw, -1, PREG_SPLIT_NO_EMPTY);
  $IS_ADMIN = in_array($LDAP['admins_group'], $remote_groups ?: []);
  // users are always validated as we assume, that the auth server does this
  $VALIDATED = true;

  if (session_status() === PHP_SESSION_NONE) {
    lum_start_session();
  }
  if (empty($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
  }

}


######################################################

function validate_passkey_cookie()
{

  global $SESSION_TIMEOUT, $IS_ADMIN, $USER_ID, $VALIDATED, $log_prefix, $SESSION_TIMED_OUT, $SESSION_DEBUG, $DEFAULT_COOKIE_OPTIONS;

  $this_time = time();
  $VALIDATED = false;
  $IS_ADMIN = false;

  if (isset($_COOKIE['orf_cookie'])) {

    $cookie_value = (string)$_COOKIE['orf_cookie'];
    $sep = strrpos($cookie_value, ':');
    if ($sep === false) {
      if ($SESSION_DEBUG == true) {
        error_log("$log_prefix Session: malformed orf_cookie value: {$cookie_value}", 0);
      }
      return;
    }
    $user_id = rawurldecode(substr($cookie_value, 0, $sep));
    $c_passkey = substr($cookie_value, $sep + 1);

    // Use dedicated session directory instead of /tmp for security
    $session_dir = getenv('SESSION_DIR') ?: (dirname(__DIR__) . '/data/sessions');
    $filename = basename(hash('sha256', $user_id));
    $session_path = $session_dir . '/' . $filename;

    $session_file = @ file_get_contents($session_path);
    if (!$session_file) {
      if ($SESSION_DEBUG == true) {
        error_log("$log_prefix Session: orf_cookie was sent by the client but the session file wasn't found at $session_path", 0);
      }
    } else {
      list($f_passkey, $f_is_admin, $f_time) = explode(':', $session_file);
      if (!empty($c_passkey) and hash_equals((string)$f_passkey, (string)$c_passkey) and $this_time < $f_time + (60 * $SESSION_TIMEOUT)) {
        if ($f_is_admin === '1') {
          $IS_ADMIN = true;
        }
        $VALIDATED = true;
        $USER_ID = $user_id;
        if ($SESSION_DEBUG == true) {
          error_log("$log_prefix Setup session: Cookie and session file values match for user {$user_id} - VALIDATED (ADMIN = {$IS_ADMIN})", 0);
        }

        // Refresh activity without rotating the passkey cookie.
        // Rotating passkey on every request causes race conditions with parallel
        // browser requests (avatars/theme API), resulting in random de-auth.
        $admin_val = ($IS_ADMIN ? 1 : 0);
        $old_umask = umask(0077);
        $bytes_written = @file_put_contents($session_path, "{$f_passkey}:{$admin_val}:{$this_time}");
        if ($bytes_written !== false) {
          @chmod($session_path, 0600);
        }
        umask($old_umask);

        if ($bytes_written === false) {
          error_log("$log_prefix Session: failed to refresh session activity at {$session_path}", 0);
          $VALIDATED = false;
          $IS_ADMIN = false;
          unset($USER_ID);
          return;
        }

        $encoded_user = rawurlencode((string)$USER_ID);
        @setcookie('orf_cookie', "{$encoded_user}:{$f_passkey}", $DEFAULT_COOKIE_OPTIONS);
        $sessto_cookie_opts = $DEFAULT_COOKIE_OPTIONS;
        $sessto_cookie_opts['expires'] = $this_time + 7200;
        @setcookie('sessto_cookie', $this_time + (60 * $SESSION_TIMEOUT), $sessto_cookie_opts);

        if (session_status() === PHP_SESSION_NONE) {
          lum_start_session();
        }
        if (session_status() === PHP_SESSION_ACTIVE && empty($_SESSION['csrf_token'])) {
          $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
        }
      } else {
        if ($SESSION_DEBUG == true) {
          $this_error = "$log_prefix Session: orf_cookie was sent by the client and the session file was found at $session_path, but";
          if (empty($c_passkey)) {
            $this_error .= " the cookie passkey wasn't set;";
          }
          if ($c_passkey !== $f_passkey) {
            $this_error .= " the session file passkey didn't match the cookie passkey;";
          }
          $this_error .= " Cookie: {$_COOKIE['orf_cookie']} - Session file contents: $session_file";
          error_log($this_error, 0);
        }
      }
    }

  } else {
    if ($SESSION_DEBUG == true) {
      error_log("$log_prefix Session: orf_cookie wasn't sent by the client.", 0);
    }
    if (isset($_COOKIE['sessto_cookie'])) {
      $this_session_timeout = $_COOKIE['sessto_cookie'];
      if ($this_time >= $this_session_timeout) {
        $SESSION_TIMED_OUT = true;
        if ($SESSION_DEBUG == true) {
          error_log("$log_prefix Session: The session had timed-out (over $SESSION_TIMEOUT mins idle).", 0);
        }
      }
    }
  }

}


######################################################
# CSRF Protection Functions
######################################################

function generate_csrf_token()
{
  // Generate a cryptographically secure CSRF token
  if (session_status() === PHP_SESSION_NONE) {
    lum_start_session();
  }
  if (!isset($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
  }
  return $_SESSION['csrf_token'];
}

function validate_csrf_token($token)
{
  // Validate CSRF token using timing-safe comparison
  if (session_status() === PHP_SESSION_NONE) {
    lum_start_session();
  }
  if (!isset($_SESSION['csrf_token'])) {
    return false;
  }
  return hash_equals($_SESSION['csrf_token'], $token ?? '');
}

function csrf_token_field()
{
  // Generate HTML hidden input field for CSRF token
  $token = generate_csrf_token();
  return '<input type="hidden" name="csrf_token" value="' . htmlspecialchars($token, ENT_QUOTES, 'UTF-8') . '">';
}


######################################################

// Shared file-backed sliding-window rate limiter.
function rate_key($uid, $kind)
{
  return hash('sha256', $uid . '|' . $kind);
}

function rate_allow($dir, $key, $limit, $per_seconds)
{
  $dir = rtrim((string)$dir, '/');
  $limit = (int)$limit;
  $per_seconds = (int)$per_seconds;
  if ($dir === '' || $limit < 1 || $per_seconds < 1) {
    return false;
  }

  if (!is_dir($dir)) {
    $old_umask = umask(0077);
    $created = @mkdir($dir, 0700, true);
    umask($old_umask);
    if (!$created && !is_dir($dir)) {
      return false;
    }
  }

  $path = $dir . '/rate_' . $key . '.json';
  $old_umask = umask(0077);
  $handle = @fopen($path, 'c+');
  umask($old_umask);
  if ($handle === false) {
    return false;
  }

  try {
    if (!flock($handle, LOCK_EX)) {
      return false;
    }

    rewind($handle);
    $stored = stream_get_contents($handle);
    $timestamps = json_decode((string)$stored, true);
    if (!is_array($timestamps)) {
      $timestamps = [];
    }

    $now = time();
    $window_start = $now - $per_seconds;
    $timestamps = array_values(array_filter($timestamps, function ($timestamp) use ($window_start) {
      return is_numeric($timestamp) && (int)$timestamp >= $window_start;
    }));

    if (count($timestamps) >= $limit) {
      return false;
    }

    $timestamps[] = $now;
    $encoded = json_encode($timestamps);
    if ($encoded === false) {
      return false;
    }

    rewind($handle);
    if (!ftruncate($handle, 0) || fwrite($handle, $encoded) === false) {
      return false;
    }
    fflush($handle);
    @chmod($path, 0600);
    return true;
  } finally {
    @flock($handle, LOCK_UN);
    fclose($handle);
  }
}


######################################################

function lum_setup_override_enabled(): bool
{
  return strcasecmp(trim((string)(getenv('LUM_ALLOW_SETUP') ?: '')), 'true') === 0;
}

/**
 * Disable setup after the administrators group has at least one real member.
 * LUM_ALLOW_SETUP=true is the explicit recovery/reconfiguration escape hatch.
 */
function lum_require_setup_incomplete($ldap_connection): void
{
  global $SERVER_PATH;

  if (lum_setup_override_enabled()) {
    return;
  }

  if (!function_exists('lum_setup_is_complete')) {
    error_log('Setup availability check is unavailable.');
    http_response_code(500);
    exit(1);
  }

  if (!lum_setup_is_complete($ldap_connection)) {
    return;
  }

  $trusted_host = get_trusted_host();
  header("Location: //{$trusted_host}{$SERVER_PATH}index.php\n\n");
  exit(0);
}


######################################################

function set_setup_cookie()
{

  # Create a random value, store it locally and set it in a cookie.

  global $SESSION_TIMEOUT, $IS_SETUP_ADMIN, $log_prefix, $SESSION_DEBUG, $DEFAULT_COOKIE_OPTIONS;

  $passkey = generate_passkey();
  $this_time = time();

  $IS_SETUP_ADMIN = true;

  // Use dedicated session directory instead of /tmp for security
  $session_dir = getenv('SESSION_DIR') ?: (dirname(__DIR__) . '/data/sessions');
  if (!is_dir($session_dir)) {
    $old_umask = umask(0077);
    @ mkdir($session_dir, 0700, true);
    umask($old_umask);
  }

  $session_file = $session_dir . '/ldap_setup';
  $old_umask = umask(0077);
  @ file_put_contents($session_file, "$passkey:$this_time");
  @ chmod($session_file, 0600);
  umask($old_umask);

  setcookie('setup_cookie', $passkey, $DEFAULT_COOKIE_OPTIONS);

  if ($SESSION_DEBUG == true) {
    error_log("$log_prefix Setup session: sent setup_cookie to the client.", 0);
  }

}


######################################################

function validate_setup_cookie()
{

  global $SESSION_TIMEOUT, $IS_SETUP_ADMIN, $log_prefix, $SESSION_DEBUG;

  if (isset($_COOKIE['setup_cookie'])) {

    $c_passkey = $_COOKIE['setup_cookie'];

    // Use dedicated session directory instead of /tmp for security
    $session_dir = getenv('SESSION_DIR') ?: (dirname(__DIR__) . '/data/sessions');
    $session_path = $session_dir . '/ldap_setup';

    $session_file = @ file_get_contents($session_path);
    if (!$session_file) {
      $IS_SETUP_ADMIN = false;
      if ($SESSION_DEBUG == true) {
        error_log("$log_prefix Setup session: setup_cookie was sent by the client but the session file wasn't found at $session_path", 0);
      }
    }
    list($f_passkey, $f_time) = explode(':', $session_file);
    $this_time = time();
    if (!empty($c_passkey) and hash_equals((string)$f_passkey, (string)$c_passkey) and $this_time < $f_time + (60 * $SESSION_TIMEOUT)) {
      $IS_SETUP_ADMIN = true;
      if ($SESSION_DEBUG == true) {
        error_log("$log_prefix Setup session: Cookie and session file values match - VALIDATED ", 0);
      }
      set_setup_cookie();
    } elseif ($SESSION_DEBUG == true) {
      $this_error = "$log_prefix Setup session: setup_cookie was sent by the client and the session file was found at /tmp/ldap_setup, but";
      if (empty($c_passkey)) {
        $this_error .= " the cookie passkey wasn't set;";
      }
      if ($c_passkey != $f_passkey) {
        $this_error .= " the session file passkey didn't match the cookie passkey;";
      }
      $this_error .= " Cookie: {$_COOKIE['setup_cookie']} - Session file contents: $session_file";
      error_log($this_error, 0);
    }
  } elseif ($SESSION_DEBUG == true) {
    error_log("$log_prefix Session: setup_cookie wasn't sent by the client.", 0);
  }

}


######################################################

function lum_clear_oidc_session_state(): void
{
  if (session_status() === PHP_SESSION_NONE) {
    if (function_exists('lum_start_session')) {
      lum_start_session();
    } else {
      @session_start();
    }
  }
  if (session_status() === PHP_SESSION_ACTIVE) {
    unset($_SESSION['oidc_auth'], $_SESSION['oidc_user'], $_SESSION['user_id'], $_SESSION['email']);
  }
}

######################################################

function log_out($method = 'normal')
{

  # Delete the passkey from the database and the passkey cookie

  global $USER_ID, $SERVER_PATH, $DEFAULT_COOKIE_OPTIONS;

  $this_time = time();

  $orf_cookie_opts = $DEFAULT_COOKIE_OPTIONS;
  $orf_cookie_opts['expires'] = $this_time - 20000;
  $sessto_cookie_opts = $DEFAULT_COOKIE_OPTIONS;
  $sessto_cookie_opts['expires'] = $this_time - 20000;

  setcookie('orf_cookie', '', $orf_cookie_opts);
  setcookie('sessto_cookie', '', $sessto_cookie_opts);

  // Use dedicated session directory and consistent hashing
  $session_dir = getenv('SESSION_DIR') ?: (dirname(__DIR__) . '/data/sessions');
  $filename = basename(hash('sha256', $USER_ID));
  // Session file name is a SHA-256 hex digest.
  // nosemgrep: php.lang.security.unlink-use.unlink-use
  @ unlink($session_dir . '/' . $filename);

  $method = strtolower(trim((string)$method));
  if ($method === 'auto') {
    $options = '?logged_out';
  } else {
    $options = '';
  }

  $trusted_host = get_trusted_host();
  $local_redirect_relative = "//{$trusted_host}{$SERVER_PATH}index.php$options";
  $site_protocol = (string)($GLOBALS['SITE_PROTOCOL'] ?? 'https://');
  $local_redirect_absolute = "{$site_protocol}{$trusted_host}{$SERVER_PATH}index.php$options";

  $redirect_target = $local_redirect_relative;
  $used_direct_global_logout = false;
  if ($method === 'global') {
    $global_logout = lum_global_logout_url();
    if ($global_logout !== '') {
      $redirect_target = $global_logout;
      $used_direct_global_logout = true;
    } elseif (!empty($GLOBALS['OIDC_ENABLED']) && function_exists('oidc_logout_redirect_url')) {
      $oidc_redirect = oidc_logout_redirect_url($local_redirect_absolute);
      if (is_string($oidc_redirect) && trim($oidc_redirect) !== '') {
        $redirect_target = $oidc_redirect;
      }
    }
  } elseif ($method !== 'local' && !empty($GLOBALS['OIDC_ENABLED']) && function_exists('oidc_logout_redirect_url')) {
    $oidc_redirect = oidc_logout_redirect_url($local_redirect_absolute);
    if (is_string($oidc_redirect) && trim($oidc_redirect) !== '') {
      $redirect_target = $oidc_redirect;
    }
  }

  if ($method === 'local' || $used_direct_global_logout) {
    lum_clear_oidc_session_state();
  }

  header("Location: {$redirect_target}\n\n");

}


######################################################

function lum_remote_header_logout_url(): string
{
  global $EMAIL_DOMAIN;

  $logout_domain = trim((string)($EMAIL_DOMAIN ?? getenv('EMAIL_DOMAIN') ?? ''));
  $logout_domain = preg_replace('#^https?://#i', '', $logout_domain);
  $logout_domain = preg_replace('#/.*$#', '', $logout_domain);
  $logout_domain = preg_replace('/:\d+$/', '', $logout_domain);
  $logout_domain = preg_replace('/^auth\./i', '', $logout_domain);
  $logout_domain = strtolower($logout_domain);
  if ($logout_domain !== '' && preg_match('/^[a-z0-9.-]+$/', $logout_domain)) {
    return 'https://auth.' . $logout_domain . '/logout';
  }

  return '';
}

######################################################

function lum_global_logout_url(): string
{
  global $OIDC_ENABLED, $OIDC_ISSUER_URL, $REMOTE_HTTP_HEADERS_LOGIN;

  if (!empty($OIDC_ENABLED)) {
    $issuer = rtrim(trim((string)$OIDC_ISSUER_URL), '/');
    if ($issuer !== '' && preg_match('#^https?://#i', $issuer)) {
      return $issuer . '/logout';
    }
  }

  if (!empty($REMOTE_HTTP_HEADERS_LOGIN)) {
    return lum_remote_header_logout_url();
  }

  return '';
}

######################################################

function render_header($title = '', $menu = true, $body_class = '', $frame_options = 'DENY')
{

  global $SITE_NAME, $IS_ADMIN, $SENT_HEADERS, $SERVER_PATH, $CUSTOM_STYLES, $USER_ID;

  if (empty($title)) {
    $title = $SITE_NAME;
  }

  $email_domain = getenv('EMAIL_DOMAIN') ?: 'default-domain.com';

  // Send security headers
  if (!headers_sent()) {
    $frame_options = strtoupper((string)$frame_options);
    if (!in_array($frame_options, ['DENY', 'SAMEORIGIN'], true)) {
      $frame_options = 'DENY';
    }
    header('X-Frame-Options: ' . $frame_options);
    header('X-Content-Type-Options: nosniff');
    header('X-XSS-Protection: 1; mode=block');
    header('Referrer-Policy: strict-origin-when-cross-origin');
    header('Permissions-Policy: geolocation=(), microphone=(), camera=()');
  }

  #Initialise the HTML output for the page.

  $initial_theme = 'green-cyberpunk';
  if (!empty($USER_ID)) {
    $valid_themes = ['green-cyberpunk', 'oled-black', 'standard', 'cyberpunk-red'];
    $prefs_dir = dirname(__DIR__) . '/data/user_preferences';
    $prefs_file = $prefs_dir . '/' . hash('sha256', $USER_ID) . '.json';

    if (is_readable($prefs_file)) {
      $prefs_raw = @file_get_contents($prefs_file);
      if ($prefs_raw !== false) {
        $prefs = json_decode($prefs_raw, true);
        $saved_theme = is_array($prefs) ? ($prefs['theme'] ?? '') : '';
        if (in_array($saved_theme, $valid_themes, true)) {
          $initial_theme = $saved_theme;
        }
      }
    }
  }

  ?>
<HTML data-theme="<?php echo htmlspecialchars($initial_theme, ENT_QUOTES, 'UTF-8'); ?>">
<HEAD>
 <TITLE><?php print "$title"; ?></TITLE>
 <meta charset="utf-8">
 <meta name="viewport" content="width=device-width, initial-scale=1">
 <meta name="csrf-token" content="<?php echo htmlspecialchars(csrf_get_token(), ENT_QUOTES, 'UTF-8'); ?>">
 <meta http-equiv="Content-Security-Policy" content="default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline' https://<?php echo htmlspecialchars($email_domain, ENT_QUOTES, 'UTF-8'); ?>; font-src 'self' https://<?php echo htmlspecialchars($email_domain, ENT_QUOTES, 'UTF-8'); ?>;">
 <link rel="stylesheet" href="<?php print $SERVER_PATH; ?>bootstrap/css/bootstrap.min.css">
 <link rel="stylesheet" href="<?php print $SERVER_PATH; ?>css/custom-theme.css">
 <?php if ($CUSTOM_STYLES) {
   echo '<link rel="stylesheet" href="' . $CUSTOM_STYLES . '">';
 } ?>
 <script>
 // CSRF token for AJAX requests
 window.CSRF_TOKEN = <?php echo json_encode(csrf_get_token()); ?>;
 </script>
 <script src="<?php print $SERVER_PATH; ?>js/lum_ui.min.js"></script>
 <script src="<?php print $SERVER_PATH; ?>bootstrap/js/bootstrap.bundle.min.js"></script>
 <?php if (!empty($USER_ID)) { ?>
 <script src="<?php print $SERVER_PATH; ?>js/theme-switcher.min.js"></script>
 <?php } ?>
</HEAD>
<BODY<?php if ($body_class) {
  echo ' class="' . htmlspecialchars($body_class, ENT_QUOTES, 'UTF-8') . '"';
} ?>>
<div class="grid-trails"></div>
<?php

 if ($menu == true) {
   render_menu();
 }

  if (isset($_GET['logged_in'])) {

    ?>
  <script>
    lumUI.ready(function() {
      var toast = document.querySelector('.lum-login-toast');
      if (!toast) {
        return;
      }

      var close = toast.querySelector('.close');
      if (close) {
        close.addEventListener('click', function(e) {
          e.preventDefault();
          lumUI.dismiss(toast, 200);
        });
      }

      window.setTimeout(function() {
        lumUI.dismiss(toast, 350);
      }, 4000);
    });
  </script>
  <div class="alert alert-success lum-login-toast" role="status">
    <button type="button" class="close" aria-label="Close"><span aria-hidden="true">&times;</span></button>
    <p class="text-center">You've logged in successfully.</p>
  </div>
  <?php

  }

  $header_auth_enabled = (isset($GLOBALS['REMOTE_HTTP_HEADERS_LOGIN']) && $GLOBALS['REMOTE_HTTP_HEADERS_LOGIN'] === true);
  $oidc_enabled = (isset($GLOBALS['OIDC_ENABLED']) && $GLOBALS['OIDC_ENABLED'] === true);
  $reverse_proxy_whitelist = trim((string)(getenv('REVERSE_PROXY_WHITELIST') ?: ''));
  if ($header_auth_enabled && !$oidc_enabled && $reverse_proxy_whitelist === '') {
    ?>
  <div class="alert alert-warning" role="alert" style="margin:10px;">
    <button type="button" class="close" data-dismiss="alert" aria-label="Close"><span aria-hidden="TRUE">&times;</span></button>
    <p class="text-center" style="margin:0;">
      Security warning: <code>REMOTE_HTTP_HEADERS_LOGIN=true</code> but <code>REVERSE_PROXY_WHITELIST</code> is not set.
      Configure a trusted proxy CIDR/IP allowlist to prevent header spoofing.
    </p>
  </div>
    <?php
  }
  $SENT_HEADERS = true;

}

######################################################

function format_module_label($module)
{
  $module_key = (string)$module;
  $overrides = [
    'change_password' => 'Password',
    'mtls_certificate' => 'Certificate',
  ];
  if (isset($overrides[$module_key])) {
    return $overrides[$module_key];
  }

  // Start with your current behavior
  $label = ucwords(str_replace('_', ' ', $module));

  // Fix common initialisms/acronyms
  // (Surround with spaces so we fix beginning/middle/end uniformly, then trim)
  $pad = ' ' . $label . ' ';
  $pad = strtr($pad, [
    ' Ip '   => ' IP ',
    ' Id '   => ' ID ',
    ' Ui '   => ' UI ',
    ' Url '  => ' URL ',
    ' Api '  => ' API ',
    ' Ldap ' => ' LDAP ',
    ' Sso '  => ' SSO ',
    ' Ssh '  => ' SSH ',
    ' Vpn '  => ' VPN ',
    ' Tls '  => ' TLS ',
  ]);

  // Special cases that aren’t plain uppercase
  $pad = preg_replace('/\bOauth\b/u', 'OAuth', $pad);
  $pad = preg_replace('/\bMtls\b/u', 'mTLS', $pad);

  return trim($pad);
}

######################################################

function lum_module_visible_in_nav(string $module, string $access, bool $validated, bool $is_admin, array $user_groups_lower, array $module_group_gates): bool
{
  $show = true;

  if ($validated) {
    if ($access == 'hidden_on_login' && $access != 'always') {
      $show = false;
    }
    if (!$is_admin && $access == 'admin' && $access != 'always') {
      $show = false;
    }
  } else {
    if ($access != 'hidden_on_login' && $access != 'always') {
      $show = false;
    }
  }

  if ($show && $validated && !empty($module_group_gates[$module])) {
    $needs = array_map('strtolower', (array)$module_group_gates[$module]);
    $has_any = false;
    foreach ($needs as $g) {
      if (in_array($g, $user_groups_lower, true)) {
        $has_any = true;
        break;
      }
    }
    if (!$has_any && !(GROUP_GATE_ADMIN_BYPASS && $is_admin)) {
      $show = false;
    }
  }

  return $show;
}

######################################################

function lum_account_manager_nav_items(): array
{
  global $SERVER_PATH, $THIS_MODULE;

  static $cache = null;
  if ($cache !== null) {
    return $cache;
  }

  $script = basename($_SERVER['SCRIPT_FILENAME'] ?? '');
  $is_account_module = ($THIS_MODULE === 'account_manager');
  $orphans_count = 0;

  if (function_exists('get_mfa_orphan_counts')) {
    try {
      $oc = get_mfa_orphan_counts();
      $orphans_count = (int)($oc['subjects'] ?? 0);
    } catch (\Throwable $e) {
      $orphans_count = 0;
    }
  }

  $items = [
    [
      'key' => 'users',
      'label' => 'Users',
      'href' => $SERVER_PATH . 'account_manager/index.php',
      'active' => $is_account_module && in_array($script, ['index.php', 'show_user.php', 'new_user.php'], true),
      'external' => false,
      'badge' => null,
    ],
    [
      'key' => 'groups',
      'label' => 'Groups',
      'href' => $SERVER_PATH . 'account_manager/groups.php',
      'active' => $is_account_module && in_array($script, ['groups.php', 'show_group.php', 'show_role.php'], true),
      'external' => false,
      'badge' => null,
    ],
  ];

  $items[] = [
    'key' => 'bans',
    'label' => 'Bans',
    'href' => $SERVER_PATH . 'account_manager/bans.php',
    'active' => $is_account_module && $script === 'bans.php',
    'external' => false,
    'badge' => null,
  ];

  if ($orphans_count > 0 || ($is_account_module && $script === 'orphans.php')) {
    $items[] = [
      'key' => 'mfa_orphans',
      'label' => 'MFA Orphans',
      'href' => $SERVER_PATH . 'account_manager/orphans.php',
      'active' => $is_account_module && $script === 'orphans.php',
      'external' => false,
      'badge' => ($orphans_count > 0 ? $orphans_count : null),
    ];
  }

  $cache = $items;
  return $items;
}

######################################################

function lum_build_navigation_items(): array
{
  global $MODULES, $THIS_MODULE, $VALIDATED, $IS_ADMIN, $SERVER_PATH, $MFA_SETTINGS_URL;
  global $MODULE_GROUP_GATES;

  static $cache = null;
  if ($cache !== null) {
    return $cache;
  }

  $items = [];
  $MODULE_GROUP_GATES = (isset($MODULE_GROUP_GATES) && is_array($MODULE_GROUP_GATES)) ? $MODULE_GROUP_GATES : [];
  $user_groups_lower = lum_current_user_groups_lower();

  $visible_modules = [];
  foreach ($MODULES as $module => $access) {
    if (lum_module_visible_in_nav((string)$module, (string)$access, (bool)$VALIDATED, (bool)$IS_ADMIN, $user_groups_lower, $MODULE_GROUP_GATES)) {
      $visible_modules[$module] = true;
    }
  }

  $show_account_tabs = $VALIDATED && $IS_ADMIN && !empty($visible_modules['account_manager']);
  if ($show_account_tabs) {
    foreach (lum_account_manager_nav_items() as $nav_item) {
      $items[] = $nav_item;
    }
  }

  foreach ($MODULES as $module => $access) {
    if (empty($visible_modules[$module])) {
      continue;
    }
    if ($module === 'log_out' || $module === 'messages') {
      continue;
    }
    if ($show_account_tabs && $module === 'account_manager') {
      continue;
    }

    $items[] = [
      'key' => $module,
      'label' => format_module_label(stripslashes((string)$module)),
      'href' => $SERVER_PATH . $module . '/',
      'active' => ($module === $THIS_MODULE),
      'external' => false,
      'badge' => null,
    ];
  }

  if (!empty($MFA_SETTINGS_URL) && $VALIDATED) {
    $items[] = [
      'key' => 'mfa_settings',
      'label' => 'MFA',
      'href' => $MFA_SETTINGS_URL,
      'active' => false,
      'external' => true,
      'badge' => null,
    ];
  }

  $cache = $items;
  return $items;
}

######################################################

function lum_current_navigation_label(): string
{
  global $SITE_NAME, $THIS_MODULE;

  if ((string)$THIS_MODULE === 'messages') {
    return 'Messages';
  }

  $items = lum_build_navigation_items();
  foreach ($items as $item) {
    if (!empty($item['active']) && !empty($item['label'])) {
      return (string)$item['label'];
    }
  }
  if (!empty($items[0]['label'])) {
    return (string)$items[0]['label'];
  }
  return (string)$SITE_NAME;
}

######################################################

function lum_first_navigation_href(): ?string
{
  $items = lum_build_navigation_items();
  foreach ($items as $item) {
    if (!empty($item['external'])) {
      continue;
    }
    if (!empty($item['href'])) {
      return (string)$item['href'];
    }
  }
  return null;
}

######################################################

if (!function_exists('lum_messages_unread_count')) {
  function lum_messages_unread_count(string $uid): int
  {
    $uid = trim($uid);
    if ($uid === '') {
      return 0;
    }

    $messages_helpers = __DIR__ . '/messages_functions.inc.php';
    if (!is_file($messages_helpers)) {
      return 0;
    }
    include_once 'messages_functions.inc.php';

    if (!function_exists('messages_is_enabled') || !messages_is_enabled()) {
      return 0;
    }

    $state = null;
    if (function_exists('messages_state_path')) {
      $state_path = messages_state_path();
      if (is_readable($state_path)) {
        $state_raw = @file_get_contents($state_path);
        if ($state_raw !== false) {
          $decoded = json_decode($state_raw, true);
          if (is_array($decoded)) {
            $state = $decoded;
          }
        }
      }
    }

    if (!is_array($state) && function_exists('messages_load_store')) {
      $loaded = messages_load_store();
      if (!empty($loaded['ok']) && isset($loaded['state']) && is_array($loaded['state'])) {
        $state = $loaded['state'];
      }
    }

    if (!is_array($state) || !function_exists('messages_counts_for_uid')) {
      return 0;
    }

    $counts = messages_counts_for_uid($state, $uid);
    return max(0, (int)($counts['unread'] ?? 0));
  }
}

######################################################

function render_menu()
{
  global $SITE_NAME, $USER_ID, $SERVER_PATH, $CUSTOM_LOGO;

  $nav_items = lum_build_navigation_items();
  $current_label = lum_current_navigation_label();
  $has_global_logout = (lum_global_logout_url() !== '');
  $messages_url = $SERVER_PATH . 'messages/';
  $messages_unread = (!empty($USER_ID)) ? lum_messages_unread_count((string)$USER_ID) : 0;
  $messages_unread_label = ($messages_unread > 99) ? '99+' : (string)$messages_unread;

  ?>
  <nav class="navbar navbar-default navbar-expand-md app-navbar">
    <div class="container-fluid">

      <!-- Brand + hamburger -->
      <div class="navbar-header">
        <button type="button"
                class="navbar-toggler"
                data-toggle="collapse"
                data-target="#main-navbar"
                data-bs-toggle="collapse"
                data-bs-target="#main-navbar"
                aria-expanded="false"
                aria-controls="main-navbar">
          <span class="sr-only">Toggle navigation</span>
          <span class="icon-bar"></span>
          <span class="icon-bar"></span>
          <span class="icon-bar"></span>
        </button>
        <span class="navbar-current-page visible-xs-inline"><?php echo htmlspecialchars($current_label, ENT_QUOTES, 'UTF-8'); ?></span>

        <a class="navbar-brand hidden-xs" href="./" data-text="<?php echo htmlspecialchars($SITE_NAME, ENT_QUOTES, 'UTF-8'); ?>">
          <?php if ($CUSTOM_LOGO) { ?>
            <img src="<?php echo $CUSTOM_LOGO; ?>" alt="logo" class="navbar-logo">
          <?php } ?>
          <?php echo $SITE_NAME; ?>
        </a>
      </div>

      <!-- Collapsible nav -->
      <div id="main-navbar" class="collapse navbar-collapse">
        <div class="app-navbar-main">
          <ul class="nav navbar-nav app-nav-tabs">
            <?php foreach ($nav_items as $item):
              $is_active = !empty($item['active']);
              $item_href = htmlspecialchars((string)$item['href'], ENT_QUOTES, 'UTF-8');
              $item_label = htmlspecialchars((string)$item['label'], ENT_QUOTES, 'UTF-8');
              $item_badge = isset($item['badge']) ? (int)$item['badge'] : 0;
              ?>
              <li class="<?php echo $is_active ? 'active' : ''; ?>">
                <a class="account-subnav__item <?php echo $is_active ? 'is-active' : ''; ?>"
                   href="<?php echo $item_href; ?>"
                   <?php echo $is_active ? 'aria-current="page"' : ''; ?>>
                  <span><?php echo $item_label; ?></span>
                  <?php if ($item_badge > 0): ?>
                    <span class="account-subnav__badge"><?php echo $item_badge; ?></span>
                  <?php endif; ?>
                </a>
              </li>
            <?php endforeach; ?>
          </ul>

          <!-- Right side: username with theme dropdown -->
          <?php if (!empty($USER_ID)) { ?>
          <div class="app-navbar-user">
            <ul class="nav navbar-nav navbar-right">
              <li class="navbar-text user-tag">
                <div class="theme-dropdown"
                     id="theme-dropdown"
                     data-has-global-logout="<?php echo $has_global_logout ? '1' : '0'; ?>">
                  <span class="username username--glitch"
                        data-u="<?php echo htmlspecialchars($USER_ID, ENT_QUOTES, 'UTF-8'); ?>">
                    <img class="username-avatar"
                         src="<?php echo htmlspecialchars($SERVER_PATH . 'api/avatar.php', ENT_QUOTES, 'UTF-8'); ?>"
                         alt=""
                         loading="lazy"
                         decoding="async"
                         onerror="this.style.display='none';">
                    <span class="username-text"><?php echo htmlspecialchars($USER_ID, ENT_QUOTES, 'UTF-8'); ?></span>
                  </span>
                  <div class="theme-dropdown-menu">
                    <div class="theme-dropdown-header">Select Theme</div>
                    <div class="theme-option" data-theme="green-cyberpunk">
                      <div class="theme-color-preview green-cyberpunk"></div>
                      <span>Green Cyberpunk</span>
                    </div>
                    <div class="theme-option" data-theme="oled-black">
                      <div class="theme-color-preview oled-black"></div>
                      <span>OLED Black</span>
                    </div>
                    <div class="theme-option" data-theme="standard">
                      <div class="theme-color-preview standard"></div>
                      <span>Standard</span>
                    </div>
                    <div class="theme-option" data-theme="cyberpunk-red">
                      <div class="theme-color-preview cyberpunk-red"></div>
                      <span>Cyberpunk Red</span>
                    </div>
                    <div class="theme-dropdown-divider" role="separator"></div>
                    <a class="theme-option theme-action theme-option-messages"
                       href="<?php echo htmlspecialchars($messages_url, ENT_QUOTES, 'UTF-8'); ?>">
                      <span class="theme-option-glyph theme-option-glyph-envelope" aria-hidden="true">&#9993;</span>
                      <span>Messages</span>
                      <?php if ($messages_unread > 0): ?>
                        <span class="theme-option-badge"
                              title="<?php echo htmlspecialchars((string)$messages_unread, ENT_QUOTES, 'UTF-8'); ?> unread message<?php echo $messages_unread === 1 ? '' : 's'; ?>">
                          <?php echo htmlspecialchars($messages_unread_label, ENT_QUOTES, 'UTF-8'); ?>
                        </span>
                      <?php endif; ?>
                    </a>
                    <div class="theme-option theme-action theme-option-logout"
                         data-action="logout"
                         role="button"
                         tabindex="0"
                         aria-label="Log out">
                      <span class="theme-option-glyph theme-option-glyph-logout" aria-hidden="true">&#x21AA;</span>
                      <span>Log out</span>
                    </div>
                  </div>
                </div>
              </li>
            </ul>
          </div>
          <?php } ?>
        </div>
      </div>
    </div>
  </nav>
  <?php
}


######################################################

function render_footer()
{

  #Finish rendering an HTML page.

  ?>
 </BODY>
</HTML>
<?php

}


######################################################

function set_page_access($level)
{

  global $IS_ADMIN, $IS_SETUP_ADMIN, $VALIDATED, $log_prefix, $SESSION_DEBUG, $SESSION_TIMED_OUT, $SERVER_PATH;

  #Set the security level needed to view a page.
  #This should be one of the first pieces of code
  #you call on a page.
  #Either 'setup', 'admin', 'user', or 'auth'.

  if ($level == 'setup') {
    if ($IS_SETUP_ADMIN == true) {
      return;
    } else {
      $trusted_host = get_trusted_host();
      header("Location: //{$trusted_host}{$SERVER_PATH}setup/index.php?unauthorised\n\n");
      if ($SESSION_DEBUG == true) {
        error_log("$log_prefix Session: UNAUTHORISED: page security level is 'setup' but IS_SETUP_ADMIN isn't TRUE", 0);
      }
      exit(0);
    }
  }

  if ($SESSION_TIMED_OUT == true) {
    $reason = 'session_timeout';
  } else {
    $reason = 'unauthorised';
  }

  if ($level == 'admin') {
    if ($IS_ADMIN == true and $VALIDATED == true) {
      return;
    } else {
      $trusted_host = get_trusted_host();
      header("Location: //{$trusted_host}{$SERVER_PATH}log_in/index.php?$reason&redirect_to=" . base64_encode($_SERVER['REQUEST_URI']) . "\n\n");
      if ($SESSION_DEBUG == true) {
        error_log("$log_prefix Session: no access to page ($reason): page security level is 'admin' but IS_ADMIN = '{$IS_ADMIN}' and VALIDATED = '{$VALIDATED}' (user) ", 0);
      }
      exit(0);
    }
  }

  if ($level == 'user' || $level == 'auth') {
    if ($VALIDATED == true) {
      return;
    } else {
      $trusted_host = get_trusted_host();
      header("Location: //{$trusted_host}{$SERVER_PATH}log_in/index.php?$reason&redirect_to=" . base64_encode($_SERVER['REQUEST_URI']) . "\n\n");
      if ($SESSION_DEBUG == true) {
        error_log("$log_prefix Session: no access to page ($reason): page security level is '$level' but VALIDATED = '{$VALIDATED}'", 0);
      }
      exit(0);
    }
  }

}


######################################################

function is_valid_email($email)
{

  return (!filter_var($email, FILTER_VALIDATE_EMAIL)) ? false : true;

}


######################################################

function render_js_username_check()
{

  global $USERNAME_REGEX, $ENFORCE_SAFE_SYSTEM_NAMES;

  if ($ENFORCE_SAFE_SYSTEM_NAMES == true) {

    print <<<EoCheckJS
<script>

 function check_entity_name_validity(name,div_id) {

  var check_regex = /$USERNAME_REGEX/;

  if (! check_regex.test(name) ) {
   document.getElementById(div_id).classList.add("has-error");
  }
  else {
   document.getElementById(div_id).classList.remove("has-error");
  }

 }

</script>

EoCheckJS;
  } else {
    print '<script> function check_entity_name_validity(name,div_id) {} </script>';
  }

}


######################################################

function generate_username($fn, $ln)
{

  global $USERNAME_FORMAT;

  $username = $USERNAME_FORMAT;
  $username = str_replace('{first_name}', strtolower($fn), $username);
  $username = str_replace('{first_name_initial}', strtolower($fn[0]), $username);
  $username = str_replace('{last_name}', strtolower($ln), $username);
  $username = str_replace('{last_name_initial}', strtolower($ln[0]), $username);

  return $username;

}


######################################################

function render_js_username_generator($firstname_field_id, $lastname_field_id, $username_field_id, $username_div_id)
{

  #Parameters are the IDs of the input fields and username name div in the account creation form.
  #The div will be set to warning if the username is invalid.

  global $USERNAME_FORMAT, $ENFORCE_SAFE_SYSTEM_NAMES;

  $remove_accents = '';
  if ($ENFORCE_SAFE_SYSTEM_NAMES == true) {
    $remove_accents = ".normalize('NFD').replace(/[\u0300-\u036f]/g, '')";
  }

  print <<<EoRenderJS

<script>
 function update_username() {

  var first_name = document.getElementById('$firstname_field_id').value;
  var last_name  = document.getElementById('$lastname_field_id').value;
  var template = '$USERNAME_FORMAT';

  var actual_username = template;

  actual_username = actual_username.replace('{first_name}', first_name.toLowerCase()$remove_accents );
  actual_username = actual_username.replace('{first_name_initial}', first_name.charAt(0).toLowerCase()$remove_accents );
  actual_username = actual_username.replace('{last_name}', last_name.toLowerCase()$remove_accents );
  actual_username = actual_username.replace('{last_name_initial}', last_name.charAt(0).toLowerCase()$remove_accents );

  check_entity_name_validity(actual_username,'$username_div_id');

  document.getElementById('$username_field_id').value = actual_username;

 }

</script>

EoRenderJS;

}


######################################################

function render_js_cn_generator($firstname_field_id, $lastname_field_id, $cn_field_id, $cn_div_id)
{

  global $ENFORCE_SAFE_SYSTEM_NAMES;

  if ($ENFORCE_SAFE_SYSTEM_NAMES == true) {
    $gen_js = "first_name.toLowerCase().normalize('NFD').replace(/[\u0300-\u036f]/g, '') + last_name.toLowerCase().normalize('NFD').replace(/[\u0300-\u036f]/g, '')";
  } else {
    $gen_js = "first_name + ' ' + last_name";
  }

  print <<<EoRenderCNJS
<script>

 var auto_cn_update = true;

 function update_cn() {

  if ( auto_cn_update == true ) {
    var first_name = document.getElementById('$firstname_field_id').value;
    var last_name  = document.getElementById('$lastname_field_id').value;
    this_cn = $gen_js;

    check_entity_name_validity(this_cn,'$cn_div_id');

    document.getElementById('$cn_field_id').value = this_cn;
  }

 }
</script>

EoRenderCNJS;

}


######################################################

function render_js_email_generator($username_field_id, $email_field_id)
{

  global $EMAIL_DOMAIN;

  print <<<EoRenderEmailJS
<script>

 var auto_email_update = true;

 function update_email() {

  if ( auto_email_update == true && "$EMAIL_DOMAIN" != ""  ) {
    var username = document.getElementById('$username_field_id').value;
    document.getElementById('$email_field_id').value = username + '@' + "$EMAIL_DOMAIN";
  }

 }
</script>

EoRenderEmailJS;

}


######################################################

function render_js_homedir_generator($username_field_id, $homedir_field_id)
{

  print <<<EoRenderHomedirJS
<script>

 var auto_homedir_update = true;

 function update_homedir() {

  if ( auto_homedir_update == true ) {
    var username = document.getElementById('$username_field_id').value;
    document.getElementById('$homedir_field_id').value = "/home/" + username;
  }

 }
</script>

EoRenderHomedirJS;

}

######################################################

function render_dynamic_field_js()
{

  ?>
<script>

  function add_field_to(attribute_name,value=null) {

    var parent      = document.getElementById(attribute_name + '_input_div');
    var input_div   = document.createElement('div');

    window[attribute_name + '_count'] = (window[attribute_name + '_count'] === undefined) ? 1 : window[attribute_name + '_count'] + 1;
    var input_field_id = attribute_name + window[attribute_name + '_count'];
    var input_div_id = 'div' + '_' + input_field_id;

    input_div.className = 'input-group';
    input_div.id = input_div_id;

    parent.appendChild(input_div);

    var input_field = document.createElement('input');
        input_field.type = 'text';
        input_field.className = 'form-control';
        input_field.id = input_field_id;
        input_field.name = attribute_name + '[]';
        input_field.value = value;

    var button_span = document.createElement('span');
        button_span.className = 'input-group-btn';

    var remove_button = document.createElement('button');
        remove_button.type = 'button';
        remove_button.className = 'btn btn-default';
        remove_button.onclick = function() { var div_to_remove = document.getElementById(input_div_id); div_to_remove.innerHTML = ""; }
        remove_button.innerHTML = '-';

    input_div.appendChild(input_field);
    input_div.appendChild(button_span);
    button_span.appendChild(remove_button);

  }

</script>
<?php

}


######################################################

function render_attribute_fields($attribute, $label, $values_r, $resource_identifier, $onkeyup = '', $inputtype = '', $tabindex = null, $help_text = '')
{

  global $THIS_MODULE_PATH;

  ?>

     <div class="form-group" id="<?php print $attribute; ?>_div">

       <label for="<?php print $attribute; ?>" class="col-sm-3 control-label"><?php print $label; ?></label>
       <div class="col-sm-6" id="<?php print $attribute; ?>_input_div">
	      <?php if ($inputtype == 'multipleinput') {
	        ?><div class="input-group">
                  <input type="text" class="form-control" id="<?php print $attribute; ?>" name="<?php print $attribute; ?>[]" value="<?php if (isset($values_r[0])) {
                    print $values_r[0];
                  } ?>">
                  <div class="input-group-btn"><button type="button" class="btn btn-default" onclick="add_field_to('<?php print $attribute; ?>')">+</i></button></div>
              </div>
            <?php
               if (isset($values_r['count']) and $values_r['count'] > 0) {
                 unset($values_r['count']);
                 $remaining_values = array_slice($values_r, 1);
                 print '<script>';
                 foreach ($remaining_values as $this_value) {
                   print "add_field_to('$attribute','$this_value');";
                 }
                 print '</script>';
               }
	      } elseif ($inputtype == 'binary') {
	        $button_text = 'Browse';
	        $file_button_action = 'disabled';
	        $description = 'Select a file to upload';
	        $mimetype = '';

	        if (isset($values_r[0])) {
	          $this_file_info = new finfo(FILEINFO_MIME_TYPE);
	          $mimetype = $this_file_info->buffer($values_r[0]);
	          if (strlen($mimetype) > 23) {
	            $mimetype = substr($mimetype, 0, 19) . '...';
	          }
	          $description = "Download $mimetype file (" . human_readable_filesize(strlen($values_r[0])) . ')';
	          $button_text = 'Replace file';
	          if ($resource_identifier != '') {
	            $this_url = "//{$_SERVER['HTTP_HOST']}{$THIS_MODULE_PATH}/download.php?resource_identifier={$resource_identifier}&attribute={$attribute}";
	            $file_button_action = "onclick=\"window.open('$this_url','_blank');\"";
	          }
	        }
	        if ($mimetype == 'image/jpeg') {
	          $this_image = base64_encode($values_r[0]);
	          print "<img class='img-thumbnail' src='data:image/jpeg;base64,$this_image'>";
	          $description = '';
	        } else {
	          ?>
                 <button type="button" <?php print $file_button_action; ?> class="btn btn-default" id="<?php print $attribute; ?>-file-info"><?php print $description; ?></button>
               <?php } ?>
               <label class="btn btn-default">
                 <?php print $button_text; ?><input <?php if (isset($tabindex)) { ?>tabindex="<?php print $tabindex; ?>" <?php } ?>type="file" style="display:none" onchange="var info = document.getElementById('<?php print $attribute; ?>-file-info'); if (info) { info.textContent = this.files[0].name; }" id="<?php print $attribute; ?>" name="<?php print $attribute; ?>">
               </label>
            <?php
	      } else { ?>
              <input <?php if (isset($tabindex)) { ?>tabindex="<?php print $tabindex; ?>" <?php } ?>type="text" class="form-control" id="<?php print $attribute; ?>" name="<?php print $attribute; ?>" value="<?php if (isset($values_r[0])) {
                print $values_r[0];
              } ?>" <?php if ($onkeyup != '') {
                print "onkeyup=\"$onkeyup\"";
              } ?>>
	      <?php
	      }
  ?>
	      <?php if (trim((string)$help_text) !== '') { ?>
	      <div class="help-min" style="margin-top:6px;"><?php echo htmlspecialchars((string)$help_text, ENT_QUOTES, 'UTF-8'); ?></div>
	      <?php } ?>
	      </div>

	    </div>

  <?php
}


######################################################

function human_readable_filesize($bytes)
{
  for ($i = 0; ($bytes / 1024) > 0.9; $i++, $bytes /= 1024) {
  }
  return round($bytes, [0,0,1,2,2,3,3,4,4][$i]) . ['B','kB','MB','GB','TB','PB','EB','ZB','YB'][$i];
}


######################################################

function render_alert_banner($message, $alert_class = 'success', $timeout = 4000)
{

  ?>
    <script>
      lumUI.ready(function() {
        document.querySelectorAll('.alert .close').forEach(function(button) {
          button.addEventListener('click', function() {
            var alert = button.parentElement;
            if (alert && alert.classList.contains('alert')) {
              lumUI.dismiss(alert, 300);
            }
          });
        });
        window.setTimeout(function() {
          document.querySelectorAll('.alert').forEach(function(alert) {
            lumUI.dismiss(alert, 500);
          });
        }, <?php print $timeout; ?>);
      });
    </script>
    <div class="alert alert-<?php print $alert_class; ?>" role="alert">
     <button type="button" class="close" aria-label="Close"><span aria-hidden="true">&times;</span></button>
     <p class="text-center"><?php print $message; ?></p>
    </div>
<?php
}


##EoFile
?>
