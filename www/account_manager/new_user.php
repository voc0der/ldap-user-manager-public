<?php
// www/account_manager/new_user.php  (modernized styling + hard validation + Apprise on create)

set_include_path('.:' . __DIR__ . '/../includes/');

include_once 'web_functions.inc.php';
include_once 'ldap_functions.inc.php';
include_once 'module_functions.inc.php';
include_once 'apprise_helpers.inc.php'; // for apprise_notify + helpers
include_once 'role_functions.inc.php';
include_once 'invite_functions.inc.php';

// ---- Password Policy (adjust as needed) ----
const DEFAULT_MIN_LEN = 12;
const ADMIN_MIN_LEN   = 15;   // for admin/privileged roles
const NO_MFA_MIN_LEN  = 15;   // for accounts without MFA
const MAX_LEN         = 256;  // allow long passphrases

// make sure mail sending flag is defined to avoid notices
if (!isset($EMAIL_SENDING_ENABLED)) {
  // infer from SMTP config if present
  $EMAIL_SENDING_ENABLED = !empty($SMTP['host'] ?? '');
}

// Unicode-aware length
function pw_len(string $s): int
{
  if (function_exists('mb_strlen')) {
    return mb_strlen($s, 'UTF-8');
  }
  return strlen($s);
}

// Safely predeclare common attribute arrays to avoid undefined-index notices
$uid = $cn = $givenname = $sn = $mail = [];

// -------- Attribute map wiring --------
$attribute_map = $LDAP['default_attribute_map'];
if (isset($LDAP['account_additional_attributes'])) {
  $attribute_map = ldap_complete_attribute_array($attribute_map, $LDAP['account_additional_attributes']);
}
if (!array_key_exists($LDAP['account_attribute'], $attribute_map)) {
  $attribute_map = array_merge($attribute_map, [$LDAP['account_attribute'] => ['label' => 'Username']]);
}
if (!array_key_exists('displayname', $attribute_map)) {
  $attribute_map['displayname'] = ['label' => 'Display name'];
} else {
  if (!isset($attribute_map['displayname']['label']) || $attribute_map['displayname']['label'] === '') {
    $attribute_map['displayname']['label'] = 'Display name';
  }
  unset($attribute_map['displayname']['default']);
  $attribute_map['displayname']['onkeyup'] = '';
}

if (isset($_POST['setup_admin_account'])) {
  $admin_setup = true;
  validate_setup_cookie();
  set_page_access('setup');
  $setup_connection = open_ldap_connection();
  lum_require_setup_incomplete($setup_connection);
  ldap_close($setup_connection);
  $completed_action = "{$SERVER_PATH}log_in";
  $page_title = 'New administrator account';
  // CSRF tokens live in the session, which can't start once output has begun.
  lum_start_session();
  render_header("$ORGANISATION_NAME account manager - setup administrator account", false);
} else {
  set_page_access('admin');
  $completed_action = "{$THIS_MODULE_PATH}/";
  $page_title = 'New account';
  $admin_setup = false;
  render_header("$ORGANISATION_NAME account manager");
  render_submenu();
}

$invalid_email = false;
$invalid_cn = false;
$invalid_givenname = false;
$invalid_sn = false;
$invalid_account_identifier = false;
$mismatched_passwords = false;
$too_short = false;
$too_long = false;

$disabled_email_tickbox = true;
$account_attribute = $LDAP['account_attribute'];

$new_account_r = [];

// -------- Build attribute values from POST/FILE/defaults (robust) --------
foreach ($attribute_map as $attribute => $attr_r) {

  // Files
  if (!empty($_FILES[$attribute]['size'])) {
    // Limit avatar uploads to 5MB to prevent memory exhaustion
    $max_size = 5 * 1024 * 1024; // 5MB
    if ($_FILES[$attribute]['size'] > $max_size) {
      $error_message = 'File too large. Maximum size is 5MB.';
      continue;
    }

    $this_attribute = [];
    $this_attribute['count'] = 1;
    $this_attribute[0] = @file_get_contents($_FILES[$attribute]['tmp_name']) ?: '';
    $$attribute = $this_attribute;
    $new_account_r[$attribute] = $this_attribute;
    unset($new_account_r[$attribute]['count']);
  }

  // POST (strings or arrays)
  if (isset($_POST[$attribute])) {
    $this_attribute = [];

    if (is_array($_POST[$attribute]) && count($_POST[$attribute]) > 0) {
      foreach ($_POST[$attribute] as $key => $value) {
        $value = (string)$value;
        if ($value !== '') {
          $this_attribute[$key] = filter_var($value, FILTER_SANITIZE_FULL_SPECIAL_CHARS);
        }
      }
      if (count($this_attribute) > 0) {
        $this_attribute['count'] = count($this_attribute);
        $$attribute = $this_attribute;
      }
    } else {
      $val = (string)$_POST[$attribute];
      if ($val !== '') {
        $this_attribute['count'] = 1;
        $this_attribute[0] = filter_var($val, FILTER_SANITIZE_FULL_SPECIAL_CHARS);
        $$attribute = $this_attribute;
      }
    }
  }

  // Defaults
  if (!isset($$attribute) && isset($attr_r['default'])) {
    $$attribute['count'] = 1;
    $$attribute[0] = $attr_r['default'];
  }

  if (isset($$attribute)) {
    $new_account_r[$attribute] = $$attribute;
    unset($new_account_r[$attribute]['count']);
  }
}

// -------- Pre-fill from account_request (optional; safe) --------
if (isset($_GET['account_request'])) {
  $givenname0 = isset($_GET['first_name']) ? (string)$_GET['first_name'] : '';
  $sn0        = isset($_GET['last_name']) ? (string)$_GET['last_name'] : '';
  $mail0      = isset($_GET['email']) ? (string)$_GET['email'] : '';

  if ($givenname0 !== '') {
    $givenname = ['count' => 1, 0 => filter_var($givenname0, FILTER_SANITIZE_FULL_SPECIAL_CHARS)];
    $new_account_r['givenname'] = $givenname;
    unset($new_account_r['givenname']['count']);
  }
  if ($sn0 !== '') {
    $sn = ['count' => 1, 0 => filter_var($sn0, FILTER_SANITIZE_FULL_SPECIAL_CHARS)];
    $new_account_r['sn'] = $sn;
    unset($new_account_r['sn']['count']);
  }

  if ($mail0 !== '') {
    $mail = ['count' => 1, 0 => filter_var($mail0, FILTER_SANITIZE_EMAIL)];
    $disabled_email_tickbox = false;
  } else {
    // synthesize from UID if available
    $uid0 = $uid[0] ?? '';
    if ($uid0 !== '' && isset($EMAIL_DOMAIN)) {
      $mail = ['count' => 1, 0 => ($uid0 . '@' . $EMAIL_DOMAIN)];
      $disabled_email_tickbox = false;
    }
  }
  if (!empty($mail)) {
    $new_account_r['mail'] = $mail;
    unset($new_account_r['mail']['count']);
  }
}

// -------- Generate missing uid/cn on request or form post --------
if (isset($_GET['account_request']) || isset($_POST['create_account'])) {
  $given0 = $givenname[0] ?? '';
  $sn0    = $sn[0] ?? '';
  if (!isset($uid[0]) || $uid[0] === '') {
    $uid0 = generate_username($given0, $sn0);
    $uid  = ['count' => 1, 0 => $uid0];
    $new_account_r['uid'] = $uid;
    unset($new_account_r['uid']['count']);
  }
  if (!isset($cn[0]) || $cn[0] === '') {
    if (!empty($ENFORCE_SAFE_SYSTEM_NAMES)) {
      $cn0 = $given0 . $sn0;
    } else {
      $cn0 = trim($given0 . ' ' . $sn0);
    }
    $cn = ['count' => 1, 0 => $cn0];
    $new_account_r['cn'] = $cn;
    unset($new_account_r['cn']['count']);
  }
}

// -------- Process create --------
if (isset($_POST['create_account'])) {
  // Setup authentication is still session-based, so every creation path also
  // requires the request-bound CSRF token.
  if (!validate_csrf_token($_POST['csrf_token'] ?? '')) {
    die('CSRF token validation failed. Please refresh the page and try again.');
  }

  $password = (string)($_POST['password'] ?? '');
  if ($password !== '') {
    $new_account_r['password'][0] = $password;
  }

  // Safe getters
  $account_identifier = (string)($new_account_r[$account_attribute][0] ?? ($uid[0] ?? ''));
  $this_cn        = (string)($cn[0]        ?? '');
  $this_mail      = (string)($mail[0]      ?? '');
  $this_givenname = (string)($givenname[0] ?? '');
  $this_sn        = (string)($sn[0]        ?? '');
  $this_password  = $password;
  $this_displayname = trim((string)($new_account_r['displayname'][0] ?? ''));
  $lineage_creator_uid = trim((string)($GLOBALS['USER_ID'] ?? ($_SERVER['HTTP_REMOTE_USER'] ?? ($_SESSION['user_id'] ?? ''))));
  if ($lineage_creator_uid === '') {
    $lineage_creator_uid = 'unknown';
  }

  if ($this_displayname === '' && $account_identifier !== '') {
    $new_account_r['displayname'][0] = $account_identifier;
  }

  // ---- Server-side hard validation (requireds)
  if ($this_cn === '') {
    $invalid_cn = true;
  }
  if ($account_identifier === '') {
    $invalid_account_identifier = true;
  }
  if ($this_givenname === '') {
    $invalid_givenname = true;
  }
  if ($this_sn === '') {
    $invalid_sn = true;
  }
  if ($this_mail !== '' && !is_valid_email($this_mail)) {
    $invalid_email = true;
  }
  if ($password !== ($_POST['password_match'] ?? '')) {
    $mismatched_passwords = true;
  }
  if (!empty($ENFORCE_SAFE_SYSTEM_NAMES) && !preg_match("/$USERNAME_REGEX/", $account_identifier)) {
    $invalid_account_identifier = true;
  }

  // ---- Length-only password policy (new accounts)
  $min_len = ($admin_setup ? max(ADMIN_MIN_LEN, NO_MFA_MIN_LEN) : NO_MFA_MIN_LEN);
  $len = pw_len($password);
  if ($len < $min_len) {
    $too_short = true;
  }
  if ($len > MAX_LEN) {
    $too_long  = true;
  }

  // ---- Decide whether to send email
  $send_user_email = false;
  if (isset($_POST['send_email']) && $EMAIL_SENDING_ENABLED == true && $this_mail !== '' && is_valid_email($this_mail)) {
    $send_user_email = true;
  }

  $has_errors =
        $mismatched_passwords
     || $too_short
     || $too_long
     || $invalid_account_identifier
     || $invalid_cn
     || $invalid_email
     || $invalid_givenname
     || $invalid_sn
     || $this_password === '';

  if (!$has_errors) {
    $ldap_connection = open_ldap_connection();
    $new_account = ldap_new_account($ldap_connection, $new_account_r);

    if ($new_account) {
      $creation_message = 'The account was created.';

      // Admin-setup: add to admins group and clean temporary entries
      if ($admin_setup === true) {
        $member_add = ldap_add_member_to_group($ldap_connection, $LDAP['admins_group'], $account_identifier);
        if (!$member_add) { ?>
          <div class="alert alert-warning">
            <p class="text-center"><?php print $creation_message; ?> Unfortunately adding it to the admin group failed.</p>
          </div>
        <?php
        }
        // Tidy up empty uniquemember entries left over from the setup wizard
        $USER_ID = 'tmp_admin';
        ldap_delete_member_from_group($ldap_connection, $LDAP['admins_group'], '');
        if (isset($DEFAULT_USER_GROUP)) {
          ldap_delete_member_from_group($ldap_connection, $DEFAULT_USER_GROUP, '');
        }
      } else {
        // Regular user creation: process group selections
        if (!empty($_POST['user_groups']) && is_array($_POST['user_groups'])) {
          foreach ($_POST['user_groups'] as $group) {
            $group = filter_var($group, FILTER_SANITIZE_FULL_SPECIAL_CHARS);
            if (!empty($group)) {
              ldap_add_member_to_group($ldap_connection, $group, $account_identifier);
            }
          }
        }
      }

      // Lineage/audit record (fail closed)
      $post_groups = ldap_user_group_membership($ldap_connection, $account_identifier);
      $audit_event_id = invite_record_event(
        $lineage_creator_uid,
        $account_identifier,
        $this_mail,
        'account_manager:new_user',
        'Account Manager (New User)',
        $post_groups,
        'new_user',
      );

      if ($audit_event_id === false) {
        foreach ((array)$post_groups as $group_name) {
          ldap_delete_member_from_group($ldap_connection, (string)$group_name, $account_identifier);
        }
        ldap_delete_account($ldap_connection, $account_identifier);
        ?>
      <div class="alert alert-danger">
        <p class="text-center"><strong>Account creation was rolled back.</strong></p>
        <p class="text-center">Lineage audit write failed, so the new account was not kept.</p>
      </div>
        <?php
        render_footer();
        exit(0);
      }

      // Send email to user (optional)
      if ($send_user_email) {
        include_once 'mail_functions.inc.php';
        $mail_body    = parse_mail_text($new_account_mail_body, $password, $account_identifier, $this_givenname, $this_sn);
        $mail_subject = parse_mail_text($new_account_mail_subject, $password, $account_identifier, $this_givenname, $this_sn);

        $sent_email = send_email($this_mail, "$this_givenname $this_sn", $mail_subject, $mail_body);
        $creation_message = 'The account was created';
        if ($sent_email) {
          $creation_message .= ' and an email sent to ' . htmlspecialchars($this_mail, ENT_QUOTES, 'UTF-8') . '.';
        } else {
          $creation_message .= " but unfortunately the email wasn't sent.<br>More information will be available in the logs.";
        }
      }

      // ---- Apprise: User Created (after any group adjustments)
      $admin_uid   = $lineage_creator_uid;
      // helper might not exist in older include—fallback gracefully
      if (!function_exists('apprise_notify_user_created')) {
        // local inline variant using the same style
        if (function_exists('apprise_notify')) {
          $host = $_SERVER['HTTP_HOST'] ?? php_uname('n') ?? 'host';
          $ip   = function_exists('apprise_client_ip') ? apprise_client_ip() : ($_SERVER['REMOTE_ADDR'] ?? '');
          $grp  = trim(implode(', ', $post_groups));
          $grp  = $grp === '' ? 'none' : $grp;
          $body = '🔐 `' . htmlspecialchars($host, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8') . '` **User Created**:' . "\n"
                . 'User: `' . htmlspecialchars($account_identifier, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8') . '`' . "\n"
                . 'Email: `' . htmlspecialchars(($this_mail ?: 'none'), ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8') . '`' . "\n"
                . 'By: `' . htmlspecialchars($admin_uid, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8') . '`' . "\n"
                . 'IP: `' . htmlspecialchars($ip, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8') . '`' . "\n"
                . 'Groups: `' . htmlspecialchars($grp, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8') . '`';
          apprise_notify($body);
        }
      } else {
        // use helper if you've added it to apprise_helpers.inc.php
        apprise_notify_user_created($account_identifier, $admin_uid, $this_mail, $post_groups);
      }
      // -------------------------------------------------------

      ?>
      <div class="alert alert-success">
        <p class="text-center"><?php print $creation_message; ?></p>
      </div>
      <form action='<?php print $completed_action; ?>'>
        <p align="center"><input type='submit' class="btn btn-success" value='Finished'></p>
      </form>
      <?php
      render_footer();
      exit(0);
    } else {
      // Log detailed error information server-side only
      ldap_get_option($ldap_connection, LDAP_OPT_DIAGNOSTIC_MESSAGE, $detailed_err);
      // Log line, not SQL.
      // nosemgrep: php.lang.security.injection.tainted-sql-string.tainted-sql-string
      error_log("$log_prefix Failed to create account for {$account_identifier}: " . ldap_error($ldap_connection) . ' -- ' . $detailed_err, 0);
      ?>
      <div class="alert alert-danger">
        <p class="text-center"><strong>Failed to create the account.</strong></p>
        <p class="text-center">Please check the account details and try again. If the problem persists, contact your system administrator.</p>
      </div>
<?php
            render_footer();
      exit(0);
    }
  }
}

// ---------- Enable "Email these credentials" if a valid recipient email is present ----------
if ($EMAIL_SENDING_ENABLED == true && $admin_setup != true) {
  // Try to discover the current email value
  $recipient_email = '';

  // Prefer what you've already collected in $new_account_r
  if (isset($new_account_r['mail'][0]) && is_string($new_account_r['mail'][0])) {
    $recipient_email = trim($new_account_r['mail'][0]);
  } elseif (isset($mail[0]) && is_string($mail[0])) {
    $recipient_email = trim($mail[0]);
  }

  // Optional: synthesize from UID + EMAIL_DOMAIN if we have both and no email yet
  if ($recipient_email === '' && isset($EMAIL_DOMAIN) && !empty($uid[0] ?? '')) {
    $recipient_email = $uid[0] . '@' . $EMAIL_DOMAIN;
    // reflect it back into the structures so the form shows it
    $mail[0] = $recipient_email;
    $new_account_r['mail'] = ['0' => $recipient_email];
  }

  // Finally decide if checkbox should be enabled
  $disabled_email_tickbox = !($recipient_email !== '' && is_valid_email($recipient_email));
}


// -------- Render errors (if any) --------
$errors = '';
if ($invalid_cn) {
  $errors .= "<li>The Common Name is required</li>\n";
}
if ($invalid_givenname) {
  $errors .= "<li>First Name is required</li>\n";
}
if ($invalid_sn) {
  $errors .= "<li>Last Name is required</li>\n";
}
if ($invalid_account_identifier) {
  $errors .= '<li>The account identifier (' . $attribute_map[$account_attribute]['label'] . ") is invalid.</li>\n";
}
if ($invalid_email) {
  $errors .= "<li>The email address is invalid</li>\n";
}
if ($mismatched_passwords) {
  $errors .= "<li>The passwords are mismatched</li>\n";
}
if ($too_short) {
  $errors .= '<li>Password is too short (minimum ' . (int)max(ADMIN_MIN_LEN, NO_MFA_MIN_LEN) . " characters for new accounts)</li>\n";
}
if ($too_long) {
  $errors .= '<li>Password is too long (maximum ' . (int)MAX_LEN . " characters)</li>\n";
}

if ($errors !== '') { ?>
  <div class="alert alert-warning">
    <p class="text-align: center">
      There were issues creating the account:
      <ul><?php print $errors; ?></ul>
    </p>
  </div>
<?php
}

render_js_username_check();
render_js_username_generator('givenname', 'sn', 'uid', 'uid_div');
render_js_cn_generator('givenname', 'sn', 'cn', 'cn_div');
render_js_email_generator('uid', 'mail');
render_js_homedir_generator('uid', 'homedirectory');

$tabindex = 1;
?>

<!-- keep your generator scripts -->
<script type="text/javascript" src="<?php print $SERVER_PATH; ?>js/generate_password.min.js"></script>

<script type="text/javascript">
function codePointLen(str){return Array.from(str||"").length;}
function clamp(v,min,max){return Math.max(min,Math.min(max,v));}

function updateMeter(minLen){
  var pw   = document.getElementById('password').value || "";
  var len  = codePointLen(pw);
  var pct  = clamp(Math.round((len / minLen) * 100), 0, 100);

  var bar   = document.getElementById('LengthProgress');
  var label = document.getElementById('LengthLabel');

  bar.style.width = pct + "%";
  bar.className = "progress-bar";
  if (pct >= 100) bar.className += " progress-bar-success";
  else if (pct >= 50) bar.className += " progress-bar-info";

  label.textContent = len + " / " + minLen;
}

function check_passwords_match(){
  var pw = document.getElementById('password').value;
  var cf = document.getElementById('confirm').value;
  var pwDiv = document.getElementById('password_div');
  var cfDiv = document.getElementById('confirm_div');
  if (cf.length === 0){ pwDiv.classList.remove("has-error"); cfDiv.classList.remove("has-error"); return; }
  if (pw !== cf){ pwDiv.classList.add("has-error"); cfDiv.classList.add("has-error"); }
  else { pwDiv.classList.remove("has-error"); cfDiv.classList.remove("has-error"); }
}

function random_password(){
  generatePassword(32,'password','confirm');
  updateMeter(<?php echo (int)max(ADMIN_MIN_LEN, NO_MFA_MIN_LEN); ?>);
  check_passwords_match();
}

function parseRoleGroups(raw){
  try {
    var parsed = JSON.parse(raw || "[]");
    return Array.isArray(parsed) ? parsed : [];
  } catch (_e) {
    return [];
  }
}

function applyRoleGroups(button){
  var select = document.getElementById('user_groups');
  if (!select) return;

  var roleGroups = parseRoleGroups(button.getAttribute('data-role-groups'));
  if (!roleGroups.length) return;

  var options = Array.prototype.slice.call(select.options || []);
  roleGroups.forEach(function(groupName){
    var wanted = String(groupName || '').toLowerCase();
    if (!wanted) return;
    options.forEach(function(opt){
      if ((opt.value || '').toLowerCase() === wanted) {
        opt.selected = true;
      }
    });
  });

  button.classList.add('role-quick-active');
  button.setAttribute('aria-pressed', 'true');
  select.dispatchEvent(new Event('change', { bubbles: true }));
}

document.addEventListener('DOMContentLoaded', function(){
  updateMeter(<?php echo (int)max(ADMIN_MIN_LEN, NO_MFA_MIN_LEN); ?>);

  var roleButtons = document.querySelectorAll('.role-quick-btn');
  roleButtons.forEach(function(button){
    button.setAttribute('aria-pressed', 'false');
    button.addEventListener('click', function(){
      applyRoleGroups(button);
    });
  });
});
</script>

<script type="text/javascript">
// Robustly enable/disable "Email these credentials" based on the visible email value.
// Handles programmatic updates from generators (UID->mail, name->mail, etc.).
(function () {
  function looksLikeEmail(v) {
    v = (v || '').trim();
    return v.length > 3 && /^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(v);
  }

  function refreshCheckbox() {
    var emailInput = document.getElementById('mail');
    var sendBox    = document.getElementById('send_email_checkbox');
    if (!emailInput || !sendBox) return;
    sendBox.disabled = !looksLikeEmail(emailInput.value);
  }

  // If scripts set mail.value directly, dispatch events so our listeners run.
  function hookMailValueSetter() {
    var emailInput = document.getElementById('mail');
    if (!emailInput) return;

    // Use the HTMLInputElement prototype descriptor
    var desc = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value');
    if (!desc || !desc.set) return; // safety

    var origSet = desc.set;
    var origGet = desc.get;

    try {
      Object.defineProperty(emailInput, 'value', {
        configurable: true,
        enumerable: desc.enumerable,
        get: function () {
          return origGet ? origGet.call(emailInput) : emailInput.getAttribute('value') || '';
        },
        set: function (val) {
          origSet.call(emailInput, val);
          // notify anyone watching (including us)
          emailInput.dispatchEvent(new Event('input',  { bubbles: true }));
          emailInput.dispatchEvent(new Event('change', { bubbles: true }));
        }
      });
    } catch (e) {
      // If redefining the property fails in this environment, that's fine; we still have other fallbacks.
    }
  }

  function wire() {
    var emailInput = document.getElementById('mail');
    var uid        = document.getElementById('uid');
    var given      = document.getElementById('givenname');
    var sn         = document.getElementById('sn');

    // Any time these fields change, re-check the email value
    [emailInput, uid, given, sn].forEach(function (el) {
      if (!el) return;
      el.addEventListener('input',  function () { setTimeout(refreshCheckbox, 0); });
      el.addEventListener('change', refreshCheckbox);
      el.addEventListener('blur',   refreshCheckbox);
    });

    hookMailValueSetter();

    // Initial + delayed passes (catch async generators)
    refreshCheckbox();
    setTimeout(refreshCheckbox, 200);
    setTimeout(refreshCheckbox, 700);
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', wire);
  } else {
    wire();
  }
})();
</script>


<div class="container wrap-narrow">
  <div class="card panel-modern">
    <div class="panel-heading text-center"><?php print $page_title; ?></div>
    <div class="card-body">

      <form class="form-horizontal" action="" enctype="multipart/form-data" method="post">
        <?php if ($admin_setup == true) { ?><input type="hidden" name="setup_admin_account" value="true"><?php } ?>
        <input type="hidden" name="create_account">
        <?php print csrf_token_field(); ?>

        <?php
          $tabindex = 1;
foreach ($attribute_map as $attribute => $attr_r) {
  $label = $attr_r['label'];
  $onkeyup = isset($attr_r['onkeyup']) ? $attr_r['onkeyup'] : '';
  $help_text = '';
  if ($attribute == $LDAP['account_attribute']) {
    $label = "<strong>$label</strong><sup>&ast;</sup>";
    $help_text = 'Used as login and as display name fallback when Display Name is left blank.';
  }
  if (!empty($attr_r['required'])) {
    $label = "<strong>$label</strong><sup>&ast;</sup>";
  }
  if ($attribute === 'mail') {
    $help_text = 'Invite credentials are sent only to this address.';
  }
  if ($attribute === 'displayname') {
    $help_text = 'Starts blank. If left blank, username is used verbatim.';
  }
  $these_values = isset($$attribute) ? $$attribute : [];
  $inputtype = isset($attr_r['inputtype']) ? $attr_r['inputtype'] : '';
  render_attribute_fields($attribute, $label, $these_values, '', $onkeyup, $inputtype, $tabindex, $help_text);
  $tabindex++;
}
?>

        <div class="form-group" id="password_div">
          <label for="password" class="col-sm-3 control-label">Password</label>
          <div class="col-sm-6">
            <input tabindex="<?php print $tabindex + 1; ?>" type="password" class="form-control" id="password" name="password"
                   maxlength="<?php echo (int)MAX_LEN; ?>"
                   oninput="updateMeter(<?php echo (int)max(ADMIN_MIN_LEN, NO_MFA_MIN_LEN); ?>); check_passwords_match();">
            <div class="help-min text-left" style="margin-top:6px;">
              Policy: minimum <strong><?php echo (int)max(ADMIN_MIN_LEN, NO_MFA_MIN_LEN); ?></strong> characters for new accounts; maximum <strong><?php echo (int)MAX_LEN; ?></strong>. No composition rules.
            </div>
          </div>
          <div class="col-sm-3">
            <input tabindex="<?php print $tabindex + 2; ?>" type="button" class="btn btn-soft btn-pill btn-sm" id="password_generator" onclick="random_password();" value="Generate password">
          </div>
        </div>

        <div class="form-group" id="confirm_div">
          <label for="confirm" class="col-sm-3 control-label">Confirm</label>
          <div class="col-sm-6">
            <input tabindex="<?php print $tabindex + 3; ?>" type="password" class="form-control" id="confirm" name="password_match"
                   maxlength="<?php echo (int)MAX_LEN; ?>"
                   oninput="check_passwords_match();">
          </div>
        </div>

        <div class="form-group">
          <label class="col-sm-3 control-label">Strength</label>
          <div class="col-sm-6">
            <div class="progress progress-modern">
              <div id="LengthProgress" class="progress-bar" role="progressbar" style="width:0%;">
                <span id="LengthLabel">0 / <?php echo (int)max(ADMIN_MIN_LEN, NO_MFA_MIN_LEN); ?></span>
              </div>
            </div>
          </div>
        </div>

<?php if ($admin_setup != true) { ?>
        <!-- Group Selection -->
        <div class="form-group">
          <label class="col-sm-3 control-label">Groups</label>
          <div class="col-sm-9">
            <div class="help-min" style="margin-bottom:12px;">Assign this user to groups. You can use roles for quick assignment.</div>
          </div>
        </div>

        <!-- Role Quick Select -->
        <?php
  $data = roles_load_presets();
  $available_roles = $data['roles'] ?? [];

  if (!empty($available_roles)) {
    echo "<div class='form-group'>\n";
    echo "  <label class='col-sm-3 control-label'>Quick Roles</label>\n";
    echo "  <div class='col-sm-9'>\n";
    echo "    <div class='quick-role-shell'>\n";
    echo "      <div class='quick-role-grid' role='group' aria-label='Quick roles'>\n";

    foreach ($available_roles as $role) {
      $role_name = htmlspecialchars($role['name'], ENT_QUOTES, 'UTF-8');
      $role_groups = $role['groups'] ?? [];
      $group_list = htmlspecialchars(implode(', ', $role_groups), ENT_QUOTES, 'UTF-8');

      echo "      <button type='button' class='btn btn-soft role-quick-btn quick-role-btn' \n";
      echo "              data-role-groups='" . htmlspecialchars(json_encode($role_groups), ENT_QUOTES, 'UTF-8') . "'\n";
      echo "              title='Apply: $group_list'>$role_name</button>\n";
    }

    echo "      </div>\n";
    echo "      <div class='help-min quick-role-hint'>Click a role to add its groups below</div>\n";
    echo "    </div>\n";
    echo "  </div>\n";
    echo "</div>\n";
  }
  ?>

        <!-- Group Multi-Select -->
        <div class="form-group">
          <label class="col-sm-3 control-label"></label>
          <div class="col-sm-9">
            <select multiple class="form-control" id="user_groups" name="user_groups[]" size="8">
              <?php
          $ldap_connection = open_ldap_connection();
  $all_groups = ldap_get_group_list($ldap_connection);
  ldap_close($ldap_connection);

  foreach ($all_groups as $group) {
    echo "<option value='" . htmlspecialchars($group, ENT_QUOTES, 'UTF-8') . "'>" . htmlspecialchars($group, ENT_QUOTES, 'UTF-8') . "</option>\n";
  }
  ?>
            </select>
            <div class="help-min">Hold Ctrl/Cmd to select multiple groups</div>
          </div>
        </div>
<?php } ?>

<?php if ($EMAIL_SENDING_ENABLED == true && $admin_setup != true) { ?>
        <div class="form-group" id="send_email_div">
          <label for="send_email" class="col-sm-3 control-label"> </label>
          <div class="col-sm-6">
            <label class="help-min" style="margin:0">
              <input tabindex="<?php print $tabindex + 4; ?>" type="checkbox" class="form-check-input" id="send_email_checkbox" name="send_email" <?php if ($disabled_email_tickbox == true) {
                print 'disabled';
              } ?>>
              Email these credentials to the user?
            </label>
          </div>
        </div>
<?php } ?>

        <div class="form-group text-center">
          <button tabindex="<?php print $tabindex + 5; ?>" type="submit" class="btn btn-primary btn-pill">Create account</button>
        </div>
      </form>

      <div class="help-min text-center" style="margin-top:6px;">
        <sup>&ast;</sup>The account identifier
      </div>
    </div>
  </div>
</div>

<?php render_footer(); ?>
