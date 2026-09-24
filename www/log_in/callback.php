<?php

set_include_path('.:' . __DIR__ . '/../includes/');

include_once 'web_functions.inc.php';

if (empty($OIDC_ENABLED) || !function_exists('oidc_complete_callback')) {
  $trusted_host = get_trusted_host();
  header("Location: //{$trusted_host}{$SERVER_PATH}log_in/index.php?oidc_error=" . rawurlencode('OIDC is not configured') . "\n\n");
  exit(0);
}

$result = oidc_complete_callback($_GET);
if (empty($result['ok'])) {
  $error = trim((string)($result['error'] ?? 'OIDC login failed'));
  $target = (string)($result['redirect_to'] ?? oidc_default_redirect_target());
  $trusted_host = get_trusted_host();
  $query = [
    'oidc_error' => $error,
    'redirect_to' => base64_encode($target),
  ];
  $uri = $SERVER_PATH . 'log_in/index.php?' . http_build_query($query, '', '&', PHP_QUERY_RFC3986);
  header("Location: //{$trusted_host}{$uri}\n\n");
  exit(0);
}

$target = oidc_safe_relative_target((string)($result['redirect_to'] ?? oidc_default_redirect_target()));
$target .= (strpos($target, '?') === false ? '?' : '&') . 'logged_in';

$trusted_host = get_trusted_host();
header("Location: //{$trusted_host}{$target}\n\n");
exit(0);
