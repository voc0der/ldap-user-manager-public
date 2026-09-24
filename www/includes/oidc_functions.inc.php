<?php

if (!function_exists('oidc_is_enabled')) {
  function oidc_is_enabled(): bool
  {
    return !empty($GLOBALS['OIDC_ENABLED']);
  }
}

if (!function_exists('oidc_start_session')) {
  function oidc_start_session(): void
  {
    if (session_status() === PHP_SESSION_ACTIVE) {
      return;
    }

    $opts = $GLOBALS['DEFAULT_COOKIE_OPTIONS'] ?? [];
    $params = [
      'lifetime' => 0,
      'path' => $opts['path'] ?? '/',
      'secure' => isset($opts['secure']) ? (bool)$opts['secure'] : true,
      'httponly' => isset($opts['httponly']) ? (bool)$opts['httponly'] : true,
      // OIDC callback is a top-level cross-site redirect from IdP -> app.
      // Strict would drop this cookie and break state/PKCE verification.
      'samesite' => 'Lax',
    ];

    if (function_exists('lum_start_session')) {
      lum_start_session($params);
      return;
    }

    if (!headers_sent()) {
      @session_set_cookie_params($params);
      @session_start();
    }
  }
}

if (!function_exists('oidc_base64url_encode')) {
  function oidc_base64url_encode(string $value): string
  {
    return rtrim(strtr(base64_encode($value), '+/', '-_'), '=');
  }
}

if (!function_exists('oidc_base64url_decode')) {
  function oidc_base64url_decode(string $value): ?string
  {
    $value = strtr($value, '-_', '+/');
    $pad = strlen($value) % 4;
    if ($pad !== 0) {
      $value .= str_repeat('=', 4 - $pad);
    }
    $decoded = base64_decode($value, true);
    if ($decoded === false) {
      return null;
    }
    return $decoded;
  }
}

if (!function_exists('oidc_random_b64url')) {
  function oidc_random_b64url(int $bytes = 32): string
  {
    return oidc_base64url_encode(random_bytes(max(16, $bytes)));
  }
}

if (!function_exists('oidc_sanitize_groups')) {
  function oidc_sanitize_groups($raw): array
  {
    $out = [];

    if (is_array($raw)) {
      foreach ($raw as $group_name) {
        $group_name = strtolower(trim((string)$group_name));
        if ($group_name !== '') {
          $out[$group_name] = true;
        }
      }
      return array_keys($out);
    }

    if (!is_string($raw)) {
      return [];
    }

    $parts = preg_split('/[;,\s]+/', $raw, -1, PREG_SPLIT_NO_EMPTY);
    if (!is_array($parts)) {
      return [];
    }

    foreach ($parts as $group_name) {
      $group_name = strtolower(trim((string)$group_name));
      if ($group_name !== '') {
        $out[$group_name] = true;
      }
    }

    return array_keys($out);
  }
}

if (!function_exists('oidc_default_redirect_target')) {
  function oidc_default_redirect_target(): string
  {
    $server_path = (string)($GLOBALS['SERVER_PATH'] ?? '/');
    if ($server_path === '' || $server_path[0] !== '/') {
      $server_path = '/' . ltrim($server_path, '/');
    }
    if (substr($server_path, -1) !== '/') {
      $server_path .= '/';
    }
    return $server_path . 'index.php';
  }
}

if (!function_exists('oidc_safe_relative_target')) {
  function oidc_safe_relative_target(?string $candidate): string
  {
    $candidate = trim((string)$candidate);
    if ($candidate === '') {
      return oidc_default_redirect_target();
    }

    $candidate = str_replace(["\r", "\n"], '', $candidate);

    if (strpos($candidate, '://') !== false || strpos($candidate, '//') === 0) {
      return oidc_default_redirect_target();
    }

    if ($candidate[0] !== '/') {
      $candidate = '/' . ltrim($candidate, '/');
    }

    return $candidate;
  }
}

if (!function_exists('oidc_decode_redirect_to_param')) {
  function oidc_decode_redirect_to_param(?string $encoded): string
  {
    $encoded = trim((string)$encoded);
    if ($encoded === '') {
      return oidc_default_redirect_target();
    }

    $decoded = base64_decode($encoded, true);
    if ($decoded === false) {
      return oidc_default_redirect_target();
    }

    return oidc_safe_relative_target($decoded);
  }
}

if (!function_exists('oidc_http_request')) {
  function oidc_http_request(string $method, string $url, array $headers = [], ?string $body = null): array
  {
    $method = strtoupper(trim($method));
    $timeout = (int)($GLOBALS['OIDC_HTTP_TIMEOUT'] ?? 10);
    if ($timeout < 2 || $timeout > 120) {
      $timeout = 10;
    }
    $skip_tls_verify = !empty($GLOBALS['OIDC_TLS_SKIP_VERIFY']);

    if (function_exists('curl_init')) {
      $ch = curl_init($url);
      if ($ch === false) {
        return ['ok' => false, 'status' => 0, 'body' => '', 'error' => 'Unable to initialize curl'];
      }

      $curl_headers = [];
      foreach ($headers as $k => $v) {
        if (is_int($k)) {
          $curl_headers[] = (string)$v;
        } else {
          $curl_headers[] = (string)$k . ': ' . (string)$v;
        }
      }

      $opts = [
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_HEADER => false,
        CURLOPT_CUSTOMREQUEST => $method,
        CURLOPT_TIMEOUT => $timeout,
        CURLOPT_CONNECTTIMEOUT => min(10, $timeout),
        CURLOPT_HTTPHEADER => $curl_headers,
      ];
      if ($body !== null) {
        $opts[CURLOPT_POSTFIELDS] = $body;
      }

      if ($skip_tls_verify) {
        $opts[CURLOPT_SSL_VERIFYPEER] = false;
        $opts[CURLOPT_SSL_VERIFYHOST] = 0;
      }

      curl_setopt_array($ch, $opts);
      $resp_body = curl_exec($ch);
      if ($resp_body === false) {
        $error = (string)curl_error($ch);
        return ['ok' => false, 'status' => 0, 'body' => '', 'error' => $error];
      }

      $status = (int)curl_getinfo($ch, CURLINFO_HTTP_CODE);

      return [
        'ok' => ($status >= 200 && $status < 300),
        'status' => $status,
        'body' => (string)$resp_body,
        'error' => '',
      ];
    }

    $hdr_lines = [];
    foreach ($headers as $k => $v) {
      if (is_int($k)) {
        $hdr_lines[] = (string)$v;
      } else {
        $hdr_lines[] = (string)$k . ': ' . (string)$v;
      }
    }

    $ctx_opts = [
      'http' => [
        'method' => $method,
        'header' => implode("\r\n", $hdr_lines),
        'content' => ($body ?? ''),
        'timeout' => $timeout,
        'ignore_errors' => true,
      ],
    ];

    if ($skip_tls_verify) {
      $ctx_opts['ssl'] = [
        'verify_peer' => false,
        'verify_peer_name' => false,
      ];
    }

    $context = stream_context_create($ctx_opts);
    $resp_body = @file_get_contents($url, false, $context);
    if ($resp_body === false) {
      return ['ok' => false, 'status' => 0, 'body' => '', 'error' => 'HTTP request failed'];
    }

    $status = 0;
    $resp_headers = [];
    if (function_exists('http_get_last_response_headers')) {
      $resp_headers = (array)(@http_get_last_response_headers() ?: []);
    }

    $status_line = '';
    if (isset($resp_headers[0]) && is_string($resp_headers[0])) {
      $status_line = $resp_headers[0];
    } else {
      foreach ($resp_headers as $key => $value) {
        if (is_int($key) && is_string($value) && stripos($value, 'HTTP/') === 0) {
          $status_line = $value;
          break;
        }
      }
    }
    if ($status_line !== '' && preg_match('#\s(\d{3})\s#', $status_line, $m)) {
      $status = (int)$m[1];
    }

    return [
      'ok' => ($status >= 200 && $status < 300),
      'status' => $status,
      'body' => (string)$resp_body,
      'error' => '',
    ];
  }
}

if (!function_exists('oidc_get_discovery_document')) {
  function oidc_get_discovery_document(): array
  {
    static $cache = null;

    if ($cache !== null) {
      return ['ok' => true, 'data' => $cache, 'error' => ''];
    }

    if (!oidc_is_enabled()) {
      return ['ok' => false, 'data' => [], 'error' => 'OIDC is not enabled'];
    }

    $issuer = rtrim((string)($GLOBALS['OIDC_ISSUER_URL'] ?? ''), '/');
    $url = trim((string)($GLOBALS['OIDC_DISCOVERY_URL'] ?? ''));
    if ($url === '') {
      if ($issuer === '') {
        return ['ok' => false, 'data' => [], 'error' => 'OIDC issuer URL is not configured'];
      }
      $url = $issuer . '/.well-known/openid-configuration';
    }

    $resp = oidc_http_request('GET', $url, ['Accept' => 'application/json']);
    if (!$resp['ok']) {
      return ['ok' => false, 'data' => [], 'error' => 'OIDC discovery failed (' . $resp['status'] . ')'];
    }

    $doc = json_decode((string)$resp['body'], true);
    if (!is_array($doc)) {
      return ['ok' => false, 'data' => [], 'error' => 'OIDC discovery returned invalid JSON'];
    }

    foreach (['authorization_endpoint', 'token_endpoint', 'jwks_uri'] as $key) {
      if (empty($doc[$key]) || !is_string($doc[$key])) {
        return ['ok' => false, 'data' => [], 'error' => 'OIDC discovery is missing ' . $key];
      }
    }

    $cache = $doc;
    return ['ok' => true, 'data' => $cache, 'error' => ''];
  }
}

if (!function_exists('oidc_get_redirect_uri')) {
  function oidc_get_redirect_uri(): string
  {
    $configured = trim((string)($GLOBALS['OIDC_REDIRECT_URI'] ?? ''));
    if ($configured !== '') {
      return $configured;
    }

    $site_protocol = (string)($GLOBALS['SITE_PROTOCOL'] ?? 'https://');
    $server_path = (string)($GLOBALS['SERVER_PATH'] ?? '/');
    if ($server_path === '' || $server_path[0] !== '/') {
      $server_path = '/' . ltrim($server_path, '/');
    }
    if (substr($server_path, -1) !== '/') {
      $server_path .= '/';
    }

    $host = '';
    if (function_exists('get_trusted_host')) {
      $host = (string)get_trusted_host();
    }
    if ($host === '') {
      $host = (string)($_SERVER['HTTP_HOST'] ?? 'localhost');
    }

    return $site_protocol . $host . $server_path . 'log_in/callback.php';
  }
}

if (!function_exists('oidc_normalize_scopes')) {
  function oidc_normalize_scopes(): string
  {
    $scopes_raw = trim((string)($GLOBALS['OIDC_SCOPES'] ?? 'openid profile email groups'));
    if ($scopes_raw === '') {
      $scopes_raw = 'openid profile email groups';
    }

    $parts = preg_split('/[\s,]+/', $scopes_raw, -1, PREG_SPLIT_NO_EMPTY);
    if (!is_array($parts)) {
      $parts = ['openid', 'profile', 'email', 'groups'];
    }

    $uniq = [];
    foreach ($parts as $scope) {
      $scope = trim((string)$scope);
      if ($scope !== '') {
        $uniq[$scope] = true;
      }
    }

    if (!isset($uniq['openid'])) {
      $uniq = ['openid' => true] + $uniq;
    }

    return implode(' ', array_keys($uniq));
  }
}

if (!function_exists('oidc_prepare_login_redirect')) {
  function oidc_prepare_login_redirect(?string $redirect_to_param = null): array
  {
    if (!oidc_is_enabled()) {
      return ['ok' => false, 'url' => '', 'error' => 'OIDC is not enabled'];
    }

    $discovery = oidc_get_discovery_document();
    if (!$discovery['ok']) {
      return ['ok' => false, 'url' => '', 'error' => $discovery['error']];
    }

    $doc = $discovery['data'];
    $client_id = trim((string)($GLOBALS['OIDC_CLIENT_ID'] ?? ''));
    if ($client_id === '') {
      return ['ok' => false, 'url' => '', 'error' => 'OIDC client ID is not configured'];
    }

    oidc_start_session();

    $state = oidc_random_b64url(32);
    $nonce = oidc_random_b64url(32);
    $code_verifier = oidc_random_b64url(64);
    $code_challenge = oidc_base64url_encode(hash('sha256', $code_verifier, true));

    $_SESSION['oidc_auth'] = [
      'state' => $state,
      'nonce' => $nonce,
      'code_verifier' => $code_verifier,
      'created_at' => time(),
      'expires_at' => time() + 600,
      'redirect_to' => oidc_decode_redirect_to_param($redirect_to_param),
    ];

    $query = [
      'response_type' => 'code',
      'client_id' => $client_id,
      'redirect_uri' => oidc_get_redirect_uri(),
      'scope' => oidc_normalize_scopes(),
      'state' => $state,
      'nonce' => $nonce,
      'code_challenge' => $code_challenge,
      'code_challenge_method' => 'S256',
    ];

    $auth_url = (string)$doc['authorization_endpoint'];
    $sep = (strpos($auth_url, '?') === false) ? '?' : '&';
    $auth_url .= $sep . http_build_query($query, '', '&', PHP_QUERY_RFC3986);

    return ['ok' => true, 'url' => $auth_url, 'error' => ''];
  }
}

if (!function_exists('oidc_decode_jwt')) {
  function oidc_decode_jwt(string $jwt): ?array
  {
    $parts = explode('.', $jwt);
    if (count($parts) !== 3) {
      return null;
    }

    [$h64, $p64, $s64] = $parts;
    $header_json = oidc_base64url_decode($h64);
    $payload_json = oidc_base64url_decode($p64);
    $signature = oidc_base64url_decode($s64);

    if ($header_json === null || $payload_json === null || $signature === null) {
      return null;
    }

    $header = json_decode($header_json, true);
    $payload = json_decode($payload_json, true);
    if (!is_array($header) || !is_array($payload)) {
      return null;
    }

    return [
      'header' => $header,
      'payload' => $payload,
      'signature' => $signature,
      'signed_data' => $h64 . '.' . $p64,
    ];
  }
}

if (!function_exists('oidc_asn1_len')) {
  function oidc_asn1_len(int $len): string
  {
    if ($len < 128) {
      return chr($len);
    }

    $tmp = '';
    while ($len > 0) {
      $tmp = chr($len & 0xFF) . $tmp;
      $len >>= 8;
    }

    return chr(0x80 | strlen($tmp)) . $tmp;
  }
}

if (!function_exists('oidc_asn1_int')) {
  function oidc_asn1_int(string $bytes): string
  {
    if ($bytes === '') {
      $bytes = "\x00";
    }
    if ((ord($bytes[0]) & 0x80) !== 0) {
      $bytes = "\x00" . $bytes;
    }
    return "\x02" . oidc_asn1_len(strlen($bytes)) . $bytes;
  }
}

if (!function_exists('oidc_jwk_to_pem')) {
  function oidc_jwk_to_pem(array $jwk): ?string
  {
    if (($jwk['kty'] ?? '') !== 'RSA') {
      return null;
    }

    $n = isset($jwk['n']) ? oidc_base64url_decode((string)$jwk['n']) : null;
    $e = isset($jwk['e']) ? oidc_base64url_decode((string)$jwk['e']) : null;
    if ($n === null || $e === null) {
      return null;
    }

    $modulus = oidc_asn1_int($n);
    $exponent = oidc_asn1_int($e);
    $rsa_pub = "\x30" . oidc_asn1_len(strlen($modulus . $exponent)) . $modulus . $exponent;

    $alg_id = hex2bin('300d06092a864886f70d0101010500');
    if ($alg_id === false) {
      return null;
    }

    $bit_string = "\x03" . oidc_asn1_len(strlen($rsa_pub) + 1) . "\x00" . $rsa_pub;
    $spki = "\x30" . oidc_asn1_len(strlen($alg_id . $bit_string)) . $alg_id . $bit_string;

    return "-----BEGIN PUBLIC KEY-----\n"
      . chunk_split(base64_encode($spki), 64, "\n")
      . "-----END PUBLIC KEY-----\n";
  }
}

if (!function_exists('oidc_get_jwks_keys')) {
  function oidc_get_jwks_keys(string $jwks_uri): array
  {
    static $cache = [];

    $now = time();
    if (isset($cache[$jwks_uri]) && ($cache[$jwks_uri]['exp'] ?? 0) > $now) {
      return (array)$cache[$jwks_uri]['keys'];
    }

    $resp = oidc_http_request('GET', $jwks_uri, ['Accept' => 'application/json']);
    if (!$resp['ok']) {
      return [];
    }

    $json = json_decode((string)$resp['body'], true);
    $keys = (is_array($json) && isset($json['keys']) && is_array($json['keys'])) ? $json['keys'] : [];
    $cache[$jwks_uri] = [
      'exp' => $now + 300,
      'keys' => $keys,
    ];

    return $keys;
  }
}

if (!function_exists('oidc_pick_jwk')) {
  function oidc_pick_jwk(array $jwt_header, array $keys): ?array
  {
    $kid = trim((string)($jwt_header['kid'] ?? ''));

    if ($kid !== '') {
      foreach ($keys as $key) {
        if (!is_array($key)) {
          continue;
        }
        if (($key['kid'] ?? '') === $kid) {
          return $key;
        }
      }
    }

    foreach ($keys as $key) {
      if (!is_array($key)) {
        continue;
      }
      if (($key['kty'] ?? '') !== 'RSA') {
        continue;
      }
      $use = strtolower((string)($key['use'] ?? 'sig'));
      if ($use !== 'sig') {
        continue;
      }
      return $key;
    }

    return null;
  }
}

if (!function_exists('oidc_validate_id_token_claims')) {
  function oidc_validate_id_token_claims(array $payload, string $expected_nonce, string &$error): bool
  {
    $error = '';

    $discovery = oidc_get_discovery_document();
    if (!$discovery['ok']) {
      $error = $discovery['error'];
      return false;
    }

    $expected_issuer = trim((string)($discovery['data']['issuer'] ?? ($GLOBALS['OIDC_ISSUER_URL'] ?? '')));
    $issuer = trim((string)($payload['iss'] ?? ''));
    if ($expected_issuer === '' || $issuer === '' || !hash_equals($expected_issuer, $issuer)) {
      $error = 'OIDC ID token issuer mismatch';
      return false;
    }

    $client_id = trim((string)($GLOBALS['OIDC_CLIENT_ID'] ?? ''));
    if ($client_id === '') {
      $error = 'OIDC client ID is missing';
      return false;
    }

    $aud = $payload['aud'] ?? null;
    $aud_ok = false;
    if (is_string($aud)) {
      $aud_ok = hash_equals($client_id, $aud);
    } elseif (is_array($aud)) {
      foreach ($aud as $aud_val) {
        if (is_string($aud_val) && hash_equals($client_id, $aud_val)) {
          $aud_ok = true;
          break;
        }
      }
    }
    if (!$aud_ok) {
      $error = 'OIDC ID token audience mismatch';
      return false;
    }

    $now = time();
    $leeway = 60;

    $exp = isset($payload['exp']) ? (int)$payload['exp'] : 0;
    if ($exp <= ($now - $leeway)) {
      $error = 'OIDC ID token has expired';
      return false;
    }

    if (isset($payload['iat']) && (int)$payload['iat'] > ($now + $leeway)) {
      $error = 'OIDC ID token has invalid iat';
      return false;
    }

    if (isset($payload['nbf']) && (int)$payload['nbf'] > ($now + $leeway)) {
      $error = 'OIDC ID token is not valid yet';
      return false;
    }

    if ($expected_nonce !== '') {
      $nonce = trim((string)($payload['nonce'] ?? ''));
      if ($nonce === '' || !hash_equals($expected_nonce, $nonce)) {
        $error = 'OIDC nonce validation failed';
        return false;
      }
    }

    return true;
  }
}

if (!function_exists('oidc_verify_id_token_signature')) {
  function oidc_verify_id_token_signature(array $jwt, string &$error): bool
  {
    $error = '';

    $alg = strtoupper((string)($jwt['header']['alg'] ?? ''));
    $algo_map = [
      'RS256' => OPENSSL_ALGO_SHA256,
      'RS384' => OPENSSL_ALGO_SHA384,
      'RS512' => OPENSSL_ALGO_SHA512,
    ];

    if (!isset($algo_map[$alg])) {
      $error = 'Unsupported ID token signing algorithm: ' . $alg;
      return false;
    }

    $discovery = oidc_get_discovery_document();
    if (!$discovery['ok']) {
      $error = $discovery['error'];
      return false;
    }

    $jwks_uri = trim((string)($discovery['data']['jwks_uri'] ?? ''));
    if ($jwks_uri === '') {
      $error = 'OIDC discovery missing jwks_uri';
      return false;
    }

    $keys = oidc_get_jwks_keys($jwks_uri);
    if (empty($keys)) {
      $error = 'No JWKS keys available';
      return false;
    }

    $jwk = oidc_pick_jwk($jwt['header'], $keys);
    if ($jwk === null) {
      $error = 'Unable to locate signing key for ID token';
      return false;
    }

    $pem = oidc_jwk_to_pem($jwk);
    if ($pem === null) {
      $error = 'Unable to convert JWK to PEM';
      return false;
    }

    $verified = openssl_verify((string)$jwt['signed_data'], (string)$jwt['signature'], $pem, $algo_map[$alg]);
    if ($verified !== 1) {
      $error = 'OIDC ID token signature verification failed';
      return false;
    }

    return true;
  }
}

if (!function_exists('oidc_exchange_code')) {
  function oidc_exchange_code(string $code, string $code_verifier): array
  {
    $discovery = oidc_get_discovery_document();
    if (!$discovery['ok']) {
      return ['ok' => false, 'data' => [], 'error' => $discovery['error']];
    }

    $token_endpoint = (string)$discovery['data']['token_endpoint'];
    $client_id = trim((string)($GLOBALS['OIDC_CLIENT_ID'] ?? ''));
    $client_secret = (string)($GLOBALS['OIDC_CLIENT_SECRET'] ?? '');

    $post = [
      'grant_type' => 'authorization_code',
      'code' => $code,
      'redirect_uri' => oidc_get_redirect_uri(),
      'client_id' => $client_id,
      'code_verifier' => $code_verifier,
    ];
    if ($client_secret !== '') {
      $post['client_secret'] = $client_secret;
    }

    $resp = oidc_http_request(
      'POST',
      $token_endpoint,
      ['Content-Type' => 'application/x-www-form-urlencoded', 'Accept' => 'application/json'],
      http_build_query($post, '', '&', PHP_QUERY_RFC3986),
    );

    if (!$resp['ok']) {
      return ['ok' => false, 'data' => [], 'error' => 'Token exchange failed (' . $resp['status'] . ')'];
    }

    $json = json_decode((string)$resp['body'], true);
    if (!is_array($json)) {
      return ['ok' => false, 'data' => [], 'error' => 'Token endpoint returned invalid JSON'];
    }

    return ['ok' => true, 'data' => $json, 'error' => ''];
  }
}

if (!function_exists('oidc_fetch_userinfo_claims')) {
  function oidc_fetch_userinfo_claims(string $access_token): array
  {
    if ($access_token === '') {
      return [];
    }

    $discovery = oidc_get_discovery_document();
    if (!$discovery['ok']) {
      return [];
    }

    $userinfo_endpoint = trim((string)($discovery['data']['userinfo_endpoint'] ?? ''));
    if ($userinfo_endpoint === '') {
      return [];
    }

    $resp = oidc_http_request(
      'GET',
      $userinfo_endpoint,
      [
        'Accept' => 'application/json',
        'Authorization' => 'Bearer ' . $access_token,
      ],
    );

    if (!$resp['ok']) {
      return [];
    }

    $json = json_decode((string)$resp['body'], true);
    return is_array($json) ? $json : [];
  }
}

if (!function_exists('oidc_claim_username')) {
  function oidc_claim_username(array $claims): string
  {
    $preferred = trim((string)($GLOBALS['OIDC_USERNAME_CLAIM'] ?? 'preferred_username'));
    $candidates = [];
    if ($preferred !== '') {
      $candidates[] = $preferred;
    }
    $candidates = array_merge($candidates, ['preferred_username', 'username', 'upn', 'email', 'sub']);

    foreach ($candidates as $claim_name) {
      if (!isset($claims[$claim_name])) {
        continue;
      }
      $value = trim((string)$claims[$claim_name]);
      if ($value !== '') {
        return $value;
      }
    }

    return '';
  }
}

if (!function_exists('oidc_claim_groups')) {
  function oidc_claim_groups(array $claims): array
  {
    $preferred = trim((string)($GLOBALS['OIDC_GROUPS_CLAIM'] ?? 'groups'));
    $candidates = [];
    if ($preferred !== '') {
      $candidates[] = $preferred;
    }
    $candidates = array_merge($candidates, ['groups', 'group', 'roles']);

    foreach ($candidates as $claim_name) {
      if (!array_key_exists($claim_name, $claims)) {
        continue;
      }
      $groups = oidc_sanitize_groups($claims[$claim_name]);
      if (!empty($groups)) {
        return $groups;
      }
    }

    return [];
  }
}

if (!function_exists('oidc_claim_email')) {
  function oidc_claim_email(array $claims): string
  {
    $preferred = trim((string)($GLOBALS['OIDC_EMAIL_CLAIM'] ?? 'email'));
    $candidates = [];
    if ($preferred !== '') {
      $candidates[] = $preferred;
    }
    $candidates = array_merge($candidates, ['email', 'mail']);

    foreach ($candidates as $claim_name) {
      if (!isset($claims[$claim_name])) {
        continue;
      }
      $value = trim((string)$claims[$claim_name]);
      if ($value !== '') {
        return $value;
      }
    }

    return '';
  }
}

if (!function_exists('oidc_ldap_find_account_identifier')) {
  function oidc_ldap_find_account_identifier(string $lookup_attribute, string $lookup_value): ?string
  {
    if (!function_exists('open_ldap_connection')) {
      @include_once 'ldap_functions.inc.php';
    }
    if (!function_exists('open_ldap_connection')) {
      return null;
    }

    $lookup_attribute = strtolower(trim($lookup_attribute));
    $lookup_value = trim($lookup_value);
    if ($lookup_attribute === '' || $lookup_value === '') {
      return null;
    }
    if (!preg_match('/^[a-z0-9][a-z0-9-]*$/', $lookup_attribute)) {
      return null;
    }

    $account_attr = strtolower(trim((string)($GLOBALS['LDAP']['account_attribute'] ?? 'uid')));
    $user_dn = (string)($GLOBALS['LDAP']['user_dn'] ?? '');
    if ($user_dn === '') {
      return null;
    }

    $ldap_connection = null;
    try {
      $ldap_connection = open_ldap_connection();
      $filter = '(' . $lookup_attribute . '=' . ldap_escape($lookup_value, '', LDAP_ESCAPE_FILTER) . ')';
      $search = @ldap_search($ldap_connection, $user_dn, $filter, [$account_attr, 'dn']);
      if (!$search) {
        return null;
      }

      $entries = @ldap_get_entries($ldap_connection, $search);
      if (!is_array($entries) || !isset($entries['count']) || (int)$entries['count'] !== 1) {
        return null;
      }

      $entry = $entries[0] ?? [];
      $value = trim((string)($entry[$account_attr][0] ?? ''));
      if ($value !== '') {
        return $value;
      }

      $dn = trim((string)($entry['dn'] ?? ''));
      if ($dn !== '' && preg_match('/(^|,)' . preg_quote($account_attr, '/') . '=([^,]+)/i', $dn, $m)) {
        return trim((string)$m[2]);
      }
    } catch (\Throwable $e) {
      return null;
    } finally {
      if (is_resource($ldap_connection) || is_object($ldap_connection)) {
        @ldap_close($ldap_connection);
      }
    }

    return null;
  }
}

if (!function_exists('oidc_ldap_groups_for_user')) {
  function oidc_ldap_groups_for_user(string $username): array
  {
    if (!function_exists('open_ldap_connection') || !function_exists('ldap_user_group_membership')) {
      @include_once 'ldap_functions.inc.php';
    }
    if (!function_exists('open_ldap_connection') || !function_exists('ldap_user_group_membership')) {
      return [];
    }

    $ldap_connection = null;
    try {
      $ldap_connection = open_ldap_connection();
      return oidc_sanitize_groups((array)ldap_user_group_membership($ldap_connection, $username));
    } catch (\Throwable $e) {
      return [];
    } finally {
      if (is_resource($ldap_connection) || is_object($ldap_connection)) {
        @ldap_close($ldap_connection);
      }
    }
  }
}

if (!function_exists('oidc_resolve_lum_username')) {
  function oidc_resolve_lum_username(string $raw_username, array $claims, string &$error): ?string
  {
    $error = '';
    $raw_username = trim($raw_username);
    if ($raw_username === '') {
      $error = 'No usable username claim found in OIDC response';
      return null;
    }

    $lookup_attr = trim((string)($GLOBALS['OIDC_LDAP_LOOKUP_ATTRIBUTE'] ?? ($GLOBALS['SITE_LOGIN_LDAP_ATTRIBUTE'] ?? 'uid')));
    $email_attr = trim((string)($GLOBALS['OIDC_LDAP_EMAIL_ATTRIBUTE'] ?? 'mail'));
    $require_ldap_user = !empty($GLOBALS['OIDC_REQUIRE_LDAP_USER']);

    $candidates = [];
    if ($lookup_attr !== '') {
      $candidates[] = [$lookup_attr, $raw_username];
    }

    $username_claim = trim((string)($GLOBALS['OIDC_USERNAME_CLAIM'] ?? 'preferred_username'));
    if ($lookup_attr !== '' && $username_claim !== '') {
      $claim_value = trim((string)($claims[$username_claim] ?? ''));
      if ($claim_value !== '' && strcasecmp($claim_value, $raw_username) !== 0) {
        $candidates[] = [$lookup_attr, $claim_value];
      }
    }

    $email = oidc_claim_email($claims);
    if ($email_attr !== '' && $email !== '') {
      $candidates[] = [$email_attr, $email];
    }

    $seen = [];
    foreach ($candidates as $candidate) {
      [$attr, $value] = $candidate;
      $key = strtolower(trim((string)$attr)) . "\x00" . trim((string)$value);
      if (isset($seen[$key])) {
        continue;
      }
      $seen[$key] = true;

      $resolved = oidc_ldap_find_account_identifier((string)$attr, (string)$value);
      if ($resolved !== null && trim($resolved) !== '') {
        return trim($resolved);
      }
    }

    if ($require_ldap_user) {
      $error = 'OIDC user could not be mapped to an LDAP account';
      return null;
    }

    return $raw_username;
  }
}

if (!function_exists('oidc_complete_callback')) {
  function oidc_complete_callback(array $query): array
  {
    if (!oidc_is_enabled()) {
      return ['ok' => false, 'error' => 'OIDC is not enabled', 'redirect_to' => oidc_default_redirect_target()];
    }

    oidc_start_session();

    $auth = $_SESSION['oidc_auth'] ?? null;
    if (!is_array($auth)) {
      return ['ok' => false, 'error' => 'Missing OIDC authorization session', 'redirect_to' => oidc_default_redirect_target()];
    }

    if (($auth['expires_at'] ?? 0) < time()) {
      unset($_SESSION['oidc_auth']);
      return ['ok' => false, 'error' => 'OIDC authorization session expired', 'redirect_to' => oidc_default_redirect_target()];
    }

    if (!empty($query['error'])) {
      $msg = trim((string)($query['error_description'] ?? $query['error']));
      unset($_SESSION['oidc_auth']);
      return ['ok' => false, 'error' => ($msg !== '' ? $msg : 'OIDC authorization failed'), 'redirect_to' => oidc_default_redirect_target()];
    }

    $state = trim((string)($query['state'] ?? ''));
    if ($state === '' || !hash_equals((string)($auth['state'] ?? ''), $state)) {
      unset($_SESSION['oidc_auth']);
      return ['ok' => false, 'error' => 'OIDC state validation failed', 'redirect_to' => oidc_default_redirect_target()];
    }

    $code = trim((string)($query['code'] ?? ''));
    if ($code === '') {
      unset($_SESSION['oidc_auth']);
      return ['ok' => false, 'error' => 'OIDC callback did not include an authorization code', 'redirect_to' => oidc_default_redirect_target()];
    }

    $exchange = oidc_exchange_code($code, (string)($auth['code_verifier'] ?? ''));
    if (!$exchange['ok']) {
      unset($_SESSION['oidc_auth']);
      return ['ok' => false, 'error' => $exchange['error'], 'redirect_to' => oidc_default_redirect_target()];
    }

    $tokens = $exchange['data'];
    $id_token = trim((string)($tokens['id_token'] ?? ''));
    if ($id_token === '') {
      unset($_SESSION['oidc_auth']);
      return ['ok' => false, 'error' => 'Token response did not include id_token', 'redirect_to' => oidc_default_redirect_target()];
    }

    $jwt = oidc_decode_jwt($id_token);
    if ($jwt === null) {
      unset($_SESSION['oidc_auth']);
      return ['ok' => false, 'error' => 'Unable to decode ID token', 'redirect_to' => oidc_default_redirect_target()];
    }

    $verify_error = '';
    if (!oidc_verify_id_token_signature($jwt, $verify_error)) {
      unset($_SESSION['oidc_auth']);
      return ['ok' => false, 'error' => $verify_error, 'redirect_to' => oidc_default_redirect_target()];
    }

    if (!oidc_validate_id_token_claims($jwt['payload'], (string)($auth['nonce'] ?? ''), $verify_error)) {
      unset($_SESSION['oidc_auth']);
      return ['ok' => false, 'error' => $verify_error, 'redirect_to' => oidc_default_redirect_target()];
    }

    $claims = $jwt['payload'];
    $access_token = trim((string)($tokens['access_token'] ?? ''));
    $userinfo = oidc_fetch_userinfo_claims($access_token);
    if (!empty($userinfo)) {
      $claims = array_merge($claims, $userinfo);
    }

    $raw_username = oidc_claim_username($claims);
    if ($raw_username === '') {
      unset($_SESSION['oidc_auth']);
      return ['ok' => false, 'error' => 'No usable username claim found in OIDC response', 'redirect_to' => oidc_default_redirect_target()];
    }

    $resolve_error = '';
    $username = oidc_resolve_lum_username($raw_username, $claims, $resolve_error);
    if ($username === null || trim($username) === '') {
      unset($_SESSION['oidc_auth']);
      return ['ok' => false, 'error' => ($resolve_error !== '' ? $resolve_error : 'OIDC user mapping failed'), 'redirect_to' => oidc_default_redirect_target()];
    }

    $groups = oidc_claim_groups($claims);
    $ldap_groups = oidc_ldap_groups_for_user($username);
    if (!empty($ldap_groups)) {
      $groups = $ldap_groups;
    }
    $email = oidc_claim_email($claims);

    $admin_group = strtolower(trim((string)($GLOBALS['LDAP']['admins_group'] ?? '')));
    $is_admin = ($admin_group !== '' && in_array($admin_group, $groups, true));

    $_SESSION['oidc_user'] = [
      'username' => $username,
      'source_username' => $raw_username,
      'groups' => $groups,
      'email' => $email,
      'claims' => $claims,
      'id_token' => $id_token,
      'access_token' => $access_token,
      'refresh_token' => trim((string)($tokens['refresh_token'] ?? '')),
      'logged_in_at' => time(),
    ];
    $_SESSION['user_id'] = $username;
    if ($email !== '') {
      $_SESSION['email'] = $email;
    }

    unset($_SESSION['oidc_auth']);

    if (!function_exists('set_passkey_cookie')) {
      return ['ok' => false, 'error' => 'Session bootstrap error: set_passkey_cookie unavailable', 'redirect_to' => oidc_default_redirect_target()];
    }

    if (!set_passkey_cookie($username, $is_admin)) {
      return ['ok' => false, 'error' => 'Failed to persist local session state', 'redirect_to' => oidc_default_redirect_target()];
    }

    $redirect_to = oidc_safe_relative_target((string)($auth['redirect_to'] ?? oidc_default_redirect_target()));

    return ['ok' => true, 'error' => '', 'redirect_to' => $redirect_to];
  }
}

if (!function_exists('oidc_session_claims')) {
  function oidc_session_claims(): array
  {
    if (!oidc_is_enabled()) {
      return [];
    }

    oidc_start_session();
    $claims = $_SESSION['oidc_user']['claims'] ?? [];
    return is_array($claims) ? $claims : [];
  }
}

if (!function_exists('oidc_session_groups_lower')) {
  function oidc_session_groups_lower(): array
  {
    if (!oidc_is_enabled()) {
      return [];
    }

    oidc_start_session();

    $groups = $_SESSION['oidc_user']['groups'] ?? null;
    if ($groups !== null) {
      return oidc_sanitize_groups($groups);
    }

    return oidc_claim_groups(oidc_session_claims());
  }
}

if (!function_exists('oidc_session_user_email')) {
  function oidc_session_user_email(): string
  {
    if (!oidc_is_enabled()) {
      return '';
    }

    oidc_start_session();

    $email = trim((string)($_SESSION['oidc_user']['email'] ?? ''));
    if ($email !== '') {
      return $email;
    }

    return oidc_claim_email(oidc_session_claims());
  }
}

if (!function_exists('oidc_logout_redirect_url')) {
  function oidc_logout_redirect_url(string $fallback_redirect_url): ?string
  {
    if (!oidc_is_enabled()) {
      return null;
    }

    oidc_start_session();

    $id_token_hint = trim((string)($_SESSION['oidc_user']['id_token'] ?? ''));
    unset($_SESSION['oidc_auth'], $_SESSION['oidc_user'], $_SESSION['user_id'], $_SESSION['email']);

    $endpoint = trim((string)($GLOBALS['OIDC_END_SESSION_ENDPOINT'] ?? ''));
    if ($endpoint === '') {
      $discovery = oidc_get_discovery_document();
      if ($discovery['ok']) {
        $endpoint = trim((string)($discovery['data']['end_session_endpoint'] ?? ''));
      }
    }

    if ($endpoint === '') {
      return null;
    }

    $post_logout = trim((string)($GLOBALS['OIDC_POST_LOGOUT_REDIRECT_URI'] ?? ''));
    if ($post_logout === '') {
      $post_logout = $fallback_redirect_url;
    }

    $params = [];
    if ($post_logout !== '') {
      $params['post_logout_redirect_uri'] = $post_logout;
    }
    if ($id_token_hint !== '') {
      $params['id_token_hint'] = $id_token_hint;
    }

    if (!empty($params)) {
      $sep = (strpos($endpoint, '?') === false) ? '?' : '&';
      $endpoint .= $sep . http_build_query($params, '', '&', PHP_QUERY_RFC3986);
    }

    return $endpoint;
  }
}
