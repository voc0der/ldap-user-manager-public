<?php

set_include_path(__DIR__ . '/includes/');
include_once 'web_functions.inc.php';

if (empty($VALIDATED) && !empty($OIDC_ENABLED)) {
  $trusted_host = get_trusted_host();
  $request_uri = (string)($_SERVER['REQUEST_URI'] ?? ($SERVER_PATH . 'index.php'));
  if (function_exists('oidc_safe_relative_target')) {
    $request_uri = oidc_safe_relative_target($request_uri);
  } else {
    $request_uri = '/index.php';
  }
  $redirect_to = base64_encode($request_uri);
  $login_uri = $SERVER_PATH . 'log_in/index.php?redirect_to=' . rawurlencode($redirect_to);
  header("Location: //{$trusted_host}{$login_uri}\n\n");
  exit(0);
}

if (!empty($VALIDATED)) {
  $target = lum_first_navigation_href();
  if (!empty($target)) {
    if (isset($_GET['logged_in'])) {
      $target .= (strpos($target, '?') === false ? '?' : '&') . 'logged_in';
    }
    header("Location: {$target}");
    exit(0);
  }
}

render_header('', true, 'page-landing');

if (isset($_GET['logged_in'])) {
  ?>
 <div class="alert alert-success">
 <p class="text-center">You're logged in. Select from the menu above.</p>
 </div>
 <?php
}

render_footer();
?>
