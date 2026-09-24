<?php

set_include_path('.:' . __DIR__ . '/../includes/');

include_once 'web_functions.inc.php';
include_once 'ldap_functions.inc.php';

$setup_connection = open_ldap_connection();
lum_require_setup_incomplete($setup_connection);
ldap_close($setup_connection);

// CSRF tokens live in the session, which can't start once output has begun.
lum_start_session();

$rate_limited = false;

if (isset($_POST['admin_password'])) {
  if (!validate_csrf_token($_POST['csrf_token'] ?? '')) {
    $trusted_host = get_trusted_host();
    header("Location: //{$trusted_host}{$THIS_MODULE_PATH}/index.php?invalid_csrf\n\n");
    exit(0);
  }

  $rate_dir = getenv('SESSION_DIR') ?: (dirname(__DIR__) . '/data/sessions');
  $rate_identity = lum_client_ip();
  if ($rate_identity === '') {
    $rate_identity = 'unknown';
  }

  if (!rate_allow($rate_dir, rate_key($rate_identity, 'setup_admin_bind'), 5, 300)) {
    http_response_code(429);
    header('Retry-After: 300');
    $rate_limited = true;
  } else {
    $ldap_connection = open_ldap_connection();
    $user_auth = ldap_setup_auth($ldap_connection, $_POST['admin_password']);
    ldap_close($ldap_connection);

    if ($user_auth != false) {
      set_setup_cookie($user_auth);
      $trusted_host = get_trusted_host();
      header("Location: //{$trusted_host}{$THIS_MODULE_PATH}/run_checks.php\n\n");
      exit(0);
    }

    $trusted_host = get_trusted_host();
    header("Location: //{$trusted_host}{$THIS_MODULE_PATH}/index.php?invalid\n\n");
    exit(0);
  }
}

if (!isset($_POST['admin_password']) || $rate_limited) {
  render_header("$ORGANISATION_NAME account manager setup - log in");

  if (isset($_GET['invalid'])) {
    ?>
 <div class="alert alert-warning">
  <p class="text-center">The password was incorrect.</p>
 </div>
 <?php
  }

  if (isset($_GET['invalid_csrf'])) {
    ?>
 <div class="alert alert-warning">
  <p class="text-center">Security check failed. Please refresh and try again.</p>
 </div>
 <?php
  }

  if ($rate_limited) {
    ?>
 <div class="alert alert-warning">
  <p class="text-center">Too many setup login attempts. Please wait five minutes and try again.</p>
 </div>
 <?php
  }
  ?>
 <div class="container">
  <div class="card panel-modern">
   <div class="panel-heading text-center">Directory administrator password</div>
   <div class="panel-body text-center">
    <form class="form-inline" action='' method='post'>
     <?php echo csrf_token_field(); ?>
     <div class="form-group">
      <input type='password' class="form-control" name='admin_password' autocomplete='current-password' required>
     </div>
     <div class="form-group">
      <input type='submit' class="btn btn-default" value='Log in'>
     </div>
    </form>
   </div>
  </div>
 </div>
<?php
}
render_footer();
?>
