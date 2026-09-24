<?php
// change_password/index.php (modernized, single global min length + Apprise notify)

set_include_path('.:' . __DIR__ . '/../includes/');
include_once 'web_functions.inc.php';
include_once 'ldap_functions.inc.php';
@include_once 'apprise_helpers.inc.php'; // apprise_notify(), apprise_client_ip()

set_page_access('user');

// ---- Policy (global) ----
const DEFAULT_MIN_LEN = 12;
const MAX_LEN         = 256;

// Multibyte length helper (count Unicode code points)
function pw_len(string $s): int
{
  if (function_exists('mb_strlen')) {
    return mb_strlen($s, 'UTF-8');
  }
  return strlen($s);
}

@session_start();
global $USER_ID;

$min_len = DEFAULT_MIN_LEN;
$alerts = [];

// ---- POST handling ----
if (isset($_POST['change_password'])) {
  if (!validate_csrf_token($_POST['csrf_token'] ?? '')) {
    $alerts[] = 'Security check failed. Please refresh and try again.';
  } else {
    $password = is_string($_POST['password'] ?? null) ? $_POST['password'] : '';
    $confirm = is_string($_POST['password_match'] ?? null) ? $_POST['password_match'] : '';

    if ($password === '') {
      $alerts[] = 'Please enter a password.';
    }
    if ($confirm  === '') {
      $alerts[] = 'Please confirm your password.';
    }
    if ($password !== '' && $confirm !== '' && $password !== $confirm) {
      $alerts[] = "The passwords didn't match.";
    }

    if ($password !== '') {
      $len = pw_len($password);
      if ($len < $min_len) {
        $alerts[] = 'Password is too short. Minimum length is ' . (int)$min_len . ' characters.';
      }
      if ($len > MAX_LEN) {
        $alerts[] = 'Password is too long. Maximum length is ' . (int)MAX_LEN . ' characters.';
      }
    }

    // Only attempt LDAP change if all checks passed
    if (empty($alerts)) {
      $ldap_connection = open_ldap_connection();
      $changed = @ldap_change_password($ldap_connection, $USER_ID, $password);

      if ($changed) {
        // ---- Apprise: Password Changed (self-service)
        if (function_exists('apprise_notify')) {
          $host = $_SERVER['HTTP_HOST'] ?? php_uname('n') ?? 'host';
          $ip   = function_exists('apprise_client_ip')
                ? apprise_client_ip()
                : ($_SERVER['REMOTE_ADDR'] ?? '');
          $body = '🔐 `' . htmlspecialchars($host, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8') . '` **Password Changed**:' . "\n"
                . 'User: `' . htmlspecialchars($USER_ID, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8') . '`' . "\n"
                . 'IP: `' . htmlspecialchars($ip, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8') . '`';
          apprise_notify($body);
        }

        render_header("$ORGANISATION_NAME account manager - password changed"); ?>
              <div class="container" style="max-width:720px;margin:24px auto">
                <div class="card panel-modern">
                  <div class="panel-heading text-center">Success</div>
                  <div class="card-body">
                    <p>Your password has been updated.</p>
                  </div>
                </div>
              </div>
              <?php render_footer();
        exit;
      } else {
        // Graceful failure: bubble a generic error, not die()
        $alerts[] = 'We couldn’t update your password right now. Please try again or contact support.';
      }
    }
  }
}

// ---- Render form ----
render_header("Change your $ORGANISATION_NAME password");

?>

<div class="container wrap-narrow">
  <div class="card panel-modern">
    <div class="panel-heading text-center">Change your password</div>
    <div class="card-body">

      <?php if (!empty($alerts)): ?>
        <?php foreach ($alerts as $msg): ?>
          <div class="alert alert-warning" role="alert">
            <p class="text-center"><?php echo htmlspecialchars($msg); ?></p>
          </div>
        <?php endforeach; ?>
      <?php endif; ?>

      <div class="policy-box help-min">
        <strong>Policy.</strong>
        Minimum <strong><?php echo (int)$min_len; ?></strong> characters; maximum <strong><?php echo (int)MAX_LEN; ?></strong>.
        No composition rules—any characters allowed (spaces &amp; full Unicode). Paste from your password manager is encouraged.
      </div>

      <form class="form-horizontal" action="" method="post" autocomplete="off" novalidate>
        <input type="hidden" id="change_password" name="change_password" value="1">
        <?php echo csrf_token_field(); ?>

        <div class="form-group" id="password_div">
          <label for="password" class="col-sm-4 control-label">Password</label>
          <div class="col-sm-8">
            <div class="inline-controls">
              <input
                type="password"
                class="form-control"
                id="password"
                name="password"
                autocomplete="new-password"
                maxlength="<?php echo (int)MAX_LEN; ?>"
                oninput="updateMeter(); checkPasswordsMatch(); gateSubmit();"
              >
            </div>
            <div class="toggle-line">
              <label class="help-min" style="margin:0"><input type="checkbox" onclick="togglePw()"> Show password</label>
              <span id="caps-hint" class="help-min" aria-live="polite"></span>
            </div>
            <div class="help-min text-left" id="pw_help" style="margin-top:6px;"></div>
          </div>
        </div>

        <div class="form-group" id="confirm_div">
          <label for="confirm" class="col-sm-4 control-label">Confirm</label>
          <div class="col-sm-8">
            <input
              type="password"
              class="form-control"
              id="confirm"
              name="password_match"
              autocomplete="new-password"
              maxlength="<?php echo (int)MAX_LEN; ?>"
              oninput="checkPasswordsMatch(); gateSubmit();"
            >
            <div class="help-min text-left" id="match_help" style="margin-top:6px;color:var(--danger);"></div>
          </div>
        </div>

        <div class="form-group">
          <div class="col-sm-12">
            <div class="progress progress-modern">
              <div id="LengthProgress" class="progress-bar" role="progressbar" style="width:0%;">
                <span id="LengthLabel">0 / <?php echo (int)$min_len; ?></span>
              </div>
            </div>
          </div>
        </div>

        <div class="form-group text-center">
          <button id="submit-btn" type="submit" class="btn btn-primary btn-pill" disabled>Change password</button>
          <span class="help-min" style="margin-left:8px;">Button enables when requirements are met.</span>
        </div>
      </form>

    </div>
  </div>
</div>

<script type="text/javascript">
// Count Unicode code points
function codePointLen(str){ return Array.from(str).length; }
function clamp(v,min,max){ return Math.max(min, Math.min(max,v)); }

function updateMeter(){
  var minLen = <?php echo (int)$min_len; ?>;
  var maxLen = <?php echo (int)MAX_LEN; ?>;
  var pw = document.getElementById('password').value || "";
  var len = codePointLen(pw);

  var pct   = clamp(Math.round((len / minLen) * 100), 0, 100);
  var bar   = document.getElementById('LengthProgress');
  var label = document.getElementById('LengthLabel');
  var help  = document.getElementById('pw_help');

  bar.style.width = pct + "%";
  label.textContent = len + " / " + minLen;

  bar.className = "progress-bar";
  if (pct >= 100) bar.className += " progress-bar-success";
  else if (pct >= 50) bar.className += " progress-bar-info";

  if (len === 0)        help.textContent = "";
  else if (len < minLen)help.textContent = "Keep going—minimum " + minLen + " characters.";
  else if (len > maxLen)help.textContent = "Too long—maximum " + maxLen + " characters.";
  else                  help.textContent = "Looks good. No special character requirements.";
}

function checkPasswordsMatch(){
  var pw = document.getElementById('password').value;
  var cf = document.getElementById('confirm').value;
  var pwDiv = document.getElementById('password_div');
  var cfDiv = document.getElementById('confirm_div');
  var matchHelp = document.getElementById('match_help');

  if (cf.length === 0){
    pwDiv.classList.remove("has-error");
    cfDiv.classList.remove("has-error");
    matchHelp.textContent = "";
    return;
  }
  if (pw !== cf){
    pwDiv.classList.add("has-error");
    cfDiv.classList.add("has-error");
    matchHelp.textContent = "⚠ Passwords don't match!";
    matchHelp.style.color = "#ff5d5d";
  }
  else {
    pwDiv.classList.remove("has-error");
    cfDiv.classList.remove("has-error");
    matchHelp.textContent = "✓ Passwords match";
    matchHelp.style.color = "#7cf1b4";
  }
}

function togglePw(){
  var f = document.getElementById('password');
  f.type = (f.type === 'password') ? 'text' : 'password';
}

// Enable submit when both: min length & match & <= MAX
function gateSubmit(){
  var btn = document.getElementById('submit-btn');
  var pw = document.getElementById('password').value || "";
  var cf = document.getElementById('confirm').value || "";
  var minLen = <?php echo (int)$min_len; ?>;
  var maxLen = <?php echo (int)MAX_LEN; ?>;
  var ok = (codePointLen(pw) >= minLen) && (codePointLen(pw) <= maxLen) && (pw === cf) && pw.length > 0;
  btn.disabled = !ok;
}

// Simple CapsLock hint
(function capsLockHint(){
  var hint = document.getElementById('caps-hint');
  function onKey(e){
    try{
      var caps = e.getModifierState && e.getModifierState('CapsLock');
      hint.textContent = caps ? "Caps Lock is ON" : "";
    }catch(_){}
  }
  document.getElementById('password').addEventListener('keydown', onKey);
  document.getElementById('password').addEventListener('keyup', onKey);
})();

document.addEventListener('DOMContentLoaded', function(){
  updateMeter(); gateSubmit();
});
</script>

<?php render_footer(); ?>
