<?php

set_include_path('.:' . __DIR__ . '/../includes/');

include_once 'web_functions.inc.php';
include_once 'ldap_functions.inc.php';

function lum_login_redirect_target_from_param(?string $encoded): string
{
  if (function_exists('oidc_decode_redirect_to_param')) {
    return oidc_decode_redirect_to_param($encoded);
  }

  $default = '/index.php';
  $decoded = base64_decode((string)$encoded, true);
  if ($decoded === false) {
    return $default;
  }

  $decoded = trim(str_replace(["\r", "\n"], '', (string)$decoded));
  if ($decoded === '' || strpos($decoded, '://') !== false || strpos($decoded, '//') === 0) {
    return $default;
  }

  if ($decoded[0] !== '/') {
    $decoded = '/' . ltrim($decoded, '/');
  }

  return $decoded;
}

function lum_login_redirect_with_host(string $target, bool $logged_in = false): void
{
  $target = trim($target);
  if ($target === '' || $target[0] !== '/') {
    $target = '/index.php';
  }

  if ($logged_in) {
    $target .= (strpos($target, '?') === false ? '?' : '&') . 'logged_in';
  }

  $trusted_host = get_trusted_host();
  header("Location: //{$trusted_host}{$target}\n\n");
  exit(0);
}

$redirect_to_param = $_POST['redirect_to'] ?? $_GET['redirect_to'] ?? '';
$redirect_target = lum_login_redirect_target_from_param($redirect_to_param);
$redirect_to_encoded = base64_encode($redirect_target);

if (!empty($VALIDATED)) {
  lum_login_redirect_with_host($redirect_target, false);
}

$oidc_error = trim((string)($_GET['oidc_error'] ?? ''));
if (!empty($OIDC_ENABLED) && $oidc_error === '') {
  $prepared = oidc_prepare_login_redirect($redirect_to_encoded);
  if (!empty($prepared['ok'])) {
    header('Location: ' . $prepared['url']);
    exit(0);
  }
  $oidc_error = trim((string)($prepared['error'] ?? 'OIDC login failed to start'));
}

$invalid_login = false;
$missing_fields = false;
$login_error = '';

if (empty($OIDC_ENABLED) && !$REMOTE_HTTP_HEADERS_LOGIN && $_SERVER['REQUEST_METHOD'] === 'POST') {
  $username = trim((string)($_POST['username'] ?? ''));
  $password = (string)($_POST['password'] ?? '');

  if ($username === '' || $password === '') {
    $missing_fields = true;
  } else {
    $ldap_connection = open_ldap_connection();
    $auth_user = @ldap_auth_username($ldap_connection, $username, $password);

    if ($auth_user !== false && trim((string)$auth_user) !== '') {
      $groups = @ldap_user_group_membership($ldap_connection, (string)$auth_user);
      $is_admin = in_array((string)$LDAP['admins_group'], (array)$groups, true);
      @ldap_close($ldap_connection);

      if (set_passkey_cookie((string)$auth_user, $is_admin)) {
        lum_login_redirect_with_host($redirect_target, true);
      }

      $login_error = 'Failed to persist local session state.';
    } else {
      $invalid_login = true;
    }

    @ldap_close($ldap_connection);
  }
}

render_header($SITE_NAME . ' login', false, 'page-landing');
?>

<div class="container" style="max-width:760px;margin-top:28px;">
  <div class="card panel-modern">
    <div class="panel-heading text-center">Sign in</div>
    <div class="card-body" style="padding:18px;">
      <?php if (!empty($oidc_error)) { ?>
        <div class="alert alert-danger">
          <p class="text-center" style="margin:0;">OIDC login failed: <?php echo htmlspecialchars($oidc_error, ENT_QUOTES, 'UTF-8'); ?></p>
        </div>
        <div class="text-center" style="margin-top:14px;">
          <a class="btn btn-primary btn-pill" href="<?php echo htmlspecialchars($SERVER_PATH . 'log_in/index.php?redirect_to=' . rawurlencode($redirect_to_encoded), ENT_QUOTES, 'UTF-8'); ?>">Retry OIDC login</a>
        </div>
      <?php } elseif (!empty($OIDC_ENABLED)) { ?>
        <div class="alert alert-info">
          <p class="text-center" style="margin:0;">Redirecting to Authelia for OIDC sign-in...</p>
        </div>
      <?php } elseif ($REMOTE_HTTP_HEADERS_LOGIN) { ?>
        <div class="alert alert-warning">
          <p class="text-center" style="margin:0;">Header-based login is enabled. Access this app through your reverse proxy / Authelia portal.</p>
        </div>
      <?php } else { ?>

        <?php if ($missing_fields) { ?>
          <div class="alert alert-warning"><p class="text-center" style="margin:0;">Please provide both username and password.</p></div>
        <?php } ?>
        <?php if ($invalid_login) { ?>
          <div class="alert alert-danger"><p class="text-center" style="margin:0;">Invalid credentials.</p></div>
        <?php } ?>
        <?php if ($login_error !== '') { ?>
          <div class="alert alert-danger"><p class="text-center" style="margin:0;"><?php echo htmlspecialchars($login_error, ENT_QUOTES, 'UTF-8'); ?></p></div>
        <?php } ?>

        <form class="form-horizontal" method="post" action="">
          <input type="hidden" name="redirect_to" value="<?php echo htmlspecialchars($redirect_to_encoded, ENT_QUOTES, 'UTF-8'); ?>">

          <div class="form-group">
            <label for="username" class="col-sm-3 control-label"><?php echo htmlspecialchars((string)$SITE_LOGIN_FIELD_LABEL, ENT_QUOTES, 'UTF-8'); ?></label>
            <div class="col-sm-9">
              <input
                type="text"
                class="form-control"
                id="username"
                name="username"
                autocomplete="username"
                required>
            </div>
          </div>

          <div class="form-group">
            <label for="password" class="col-sm-3 control-label">Password</label>
            <div class="col-sm-9">
              <input
                type="password"
                class="form-control"
                id="password"
                name="password"
                autocomplete="current-password"
                required>
            </div>
          </div>

          <div class="form-group" style="margin-top:16px;">
            <div class="col-sm-offset-3 col-sm-9">
              <button type="submit" class="btn btn-primary btn-pill">Log in</button>
            </div>
          </div>
        </form>
      <?php } ?>
    </div>
  </div>
</div>

<?php
render_footer();
