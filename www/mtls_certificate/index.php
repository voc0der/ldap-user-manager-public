<?php
declare(strict_types=1);
set_include_path('.:' . __DIR__ . '/../includes/');
include_once 'web_functions.inc.php';

// Require authenticated session.
set_page_access('auth');
@session_start();

$uid         = trim((string)($USER_ID ?? ($_SESSION['user_id'] ?? '')));
$groups_list = function_exists('lum_current_user_groups_lower') ? lum_current_user_groups_lower() : [];
$has_mtls    = in_array('mtls', $groups_list, true);
$has_admin   = in_array('admin', $groups_list, true);
$can_choose_location = $has_mtls && $has_admin;

// Gate by group (no identity leak)
if (!$uid || !$has_mtls) {
  render_header('mTLS Certificate');
  echo '<div class="container" style="max-width:860px;margin-top:20px"><div class="alert alert-danger">Access denied: this page is only available to members of the <code>mtls</code> group.</div></div>';
  render_footer();
  exit;
}

// Store location choice (default to external)
if (!isset($_SESSION['mtls_location'])) {
  $_SESSION['mtls_location'] = 'external';
}
if (!isset($_SESSION['mtls_export_type'])) {
  $_SESSION['mtls_export_type'] = 'pfx';
}

// Optional deep-link preset, e.g. ?type=export&target=allzip. A valid preset
// preselects step 1 and auto-continues; anything else is ignored and the page
// behaves normally.
$preset_export_type = null;
$q_type   = is_string($_GET['type'] ?? null) ? strtolower(trim($_GET['type'])) : '';
$q_target = is_string($_GET['target'] ?? null) ? strtolower(trim($_GET['target'])) : '';
if ($q_type === 'export') {
  $preset_export_type = ['pfx' => 'pfx', 'zip' => 'crt_key_zip', 'allzip' => 'all_bundle_zip'][$q_target] ?? null;
}
$sel_export_type = $preset_export_type ?? (string)$_SESSION['mtls_export_type'];

// With a preset, step 1's options are collapsed and replaced by a "you are here"
// toast plus brief instructions, for people arriving from a link. Static markup only.
$preset = $preset_export_type === null ? null : [
  'pfx' => [
    'title'  => 'Certificate (.pfx)',
    'notice' => 'your certificate (.pfx)',
    'steps'  => ['Import it into your browser or system certificate store using the password shown with the download.'],
  ],
  'zip' => [
    'title'  => 'Certificate and private key (.zip)',
    'notice' => 'your certificate and private key (.zip)',
    'steps'  => ['Unzip it and point your app at <code>cert.crt</code> and <code>privkey.pem</code>.'],
  ],
  'allzip' => [
    'title'  => 'Full certificate bundle (.zip)',
    'notice' => 'the full certificate bundle (.zip)',
    'steps'  => ['Unzip it and use whichever format your app needs; the password files are included.'],
  ],
][$q_target];

// CSRF token for API posts
if (empty($_SESSION['csrf'])) {
  $_SESSION['csrf'] = bin2hex(random_bytes(16));
}

render_header('mTLS Certificate');
?>

<div class="container" style="max-width:720px; margin-top:20px">
  <div class="mtls-card">
    <ol class="mtls-steps" aria-label="Steps">
      <li class="active" data-step="1"><span class="dot">1</span>Customize</li>
      <span class="sep" aria-hidden="true"></span>
      <li data-step="2"><span class="dot">2</span>Send code</li>
      <span class="sep" aria-hidden="true"></span>
      <li data-step="3"><span class="dot">3</span>Verify</li>
      <span class="sep" aria-hidden="true"></span>
      <li data-step="4"><span class="dot">4</span>Download</li>
    </ol>

    <div class="mtls-body">

      <div class="mtls-row" id="step-1">
        <?php if ($preset !== null): ?>
        <div id="preset-notice" class="alert alert-info" role="status" style="margin-top:0">
          <button type="button" class="close" aria-label="Close"><span aria-hidden="true">&times;</span></button>
          <strong>You're here to download <?= htmlspecialchars($preset['notice'], ENT_QUOTES, 'UTF-8') ?>.</strong>
        </div>
        <h5><?= htmlspecialchars($preset['title'], ENT_QUOTES, 'UTF-8') ?></h5>
        <ol style="padding-left:1.25rem; margin-bottom:10px">
          <li>Send yourself a code below, enter it, and download the file.</li>
          <?php foreach ($preset['steps'] as $step): ?>
          <li><?= $step ?></li>
          <?php endforeach; ?>
        </ol>
        <a href="./" class="help-min">Choose a different download</a>
        <?php endif; ?>
        <div id="customize-options"<?= $preset !== null ? ' style="display:none; margin-top:1.5rem"' : '' ?>>
          <h5>Customize</h5>
          <p class="help-min">Choose your certificate source and export format before requesting a verification code.</p>
          <?php if ($can_choose_location): ?>
          <div id="location-group">
            <div style="margin-bottom:10px; font-weight:600">Location</div>
            <div style="margin-bottom:12px">
              <label class="radio-inline" style="margin-right:20px">
                <input type="radio" name="location" value="external" <?= $_SESSION['mtls_location'] === 'external' ? 'checked' : '' ?>>
                External (Default)
              </label>
              <label class="radio-inline">
                <input type="radio" name="location" value="internal" <?= $_SESSION['mtls_location'] === 'internal' ? 'checked' : '' ?>>
                Internal
              </label>
            </div>
          </div>
          <?php endif; ?>
          <div style="margin-bottom:10px; font-weight:600">Export type</div>
          <div style="margin-bottom:12px">
            <label class="radio-inline" style="margin-right:20px">
              <input type="radio" name="export_type" value="pfx" <?= $sel_export_type === 'pfx' ? 'checked' : '' ?>>
              .pfx (Default)
            </label>
            <label class="radio-inline">
              <input type="radio" name="export_type" value="crt_key_zip" <?= $sel_export_type === 'crt_key_zip' ? 'checked' : '' ?>>
              cert.crt + privkey.pem (.zip)
            </label>
            <label class="radio-inline" style="display:block; margin-top:8px">
              <input type="radio" name="export_type" value="all_bundle_zip" <?= $sel_export_type === 'all_bundle_zip' ? 'checked' : '' ?>>
              All certs bundle (.zip) Includes password files.
            </label>
          </div>
          <button id="btn-customize" class="btn btn-primary">Continue</button>
          <span id="customize-status" class="text-info btn-inline-gap" aria-live="polite"></span>
        </div>
      </div>

      <div class="mtls-row" id="step-2" aria-disabled="true">
        <h5>Send verification code</h5>
        <p class="help-min">We’ll email a one-time code to confirm it’s you. This keeps the certificate link private.</p>
        <button id="btn-send" class="btn btn-primary">Send code</button>
        <button id="btn-resend" class="btn btn-default btn-inline-gap" style="display:none">Resend</button>
        <span id="send-status" class="text-info btn-inline-gap" aria-live="polite"></span>
      </div>

      <div class="mtls-row" id="step-3" aria-disabled="true">
        <h5>Enter code</h5>
        <form id="verify-form" class="form-inline" onsubmit="return false">
          <label for="code" class="sr-only">Verification code</label>
          <input type="text" id="code" class="form-control" maxlength="8" pattern="\d{4,8}" placeholder="6-digit code" disabled required>
          <button id="btn-verify" class="btn btn-success btn-inline-gap" disabled>Verify</button>
          <span id="verify-status" class="text-info btn-inline-gap" aria-live="polite"></span>
        </form>
      </div>

      <div class="mtls-row" id="step-4" aria-disabled="true">
        <h5>Download</h5>
        <div id="dl-area" class="text-muted">Waiting for verification…</div>
        <div id="expiry-hint" class="help-block help-min" style="margin-top:8px;"></div>
        <div id="p12-pass-row" class="help-block help-min" style="margin-top:6px;"></div>
      </div>

    </div>
  </div>
  
</div>

<script>
(function(){
  const csrf = <?= json_encode($_SESSION['csrf']) ?>;
  const canChooseLocation = <?= json_encode($can_choose_location) ?>;
  let selectedLocation = <?= json_encode($_SESSION['mtls_location']) ?>;
  let selectedExportType = <?= json_encode($sel_export_type) ?>;
  const autoContinue = <?= json_encode($preset_export_type !== null) ?>;

  // UX constants
  // The external stager may need to fetch certificate material (notably for
  // the internal location) before it can build the requested export, so
  // worst-case time-to-ready can run well past a few seconds. Poll for up to
  // 2 minutes (still comfortably inside the token's 5-minute expiry) rather
  // than giving up early.
  const POLL_MAX = 120;          // how many times to poll token_info
  const POLL_DELAY_MS = 1000;    // delay between polls
  const RESEND_COOLDOWN_MS = 15000;

  function q(sel){ return document.querySelector(sel); }
  function msg(el, text, kind){ el.textContent = text; el.className = kind ? ('text-' + kind) : ''; }
  function enable(el, on){ if(!el) return; el.disabled = !on; if (on) el.removeAttribute('disabled'); else el.setAttribute('disabled',''); }
  function setAriaDisabled(block, on){ if(!block) return; block.setAttribute('aria-disabled', on ? 'true' : 'false'); }
  function setLocationVisibility(exportType) {
    if (!canChooseLocation) return;
    const locationGroup = q('#location-group');
    if (!locationGroup) return;

    const hideLocation = exportType === 'all_bundle_zip';
    locationGroup.style.display = hideLocation ? 'none' : '';
    locationGroup.setAttribute('aria-hidden', hideLocation ? 'true' : 'false');

    const radios = document.getElementsByName('location');
    for (let r of radios) {
      r.disabled = hideLocation;
    }
  }
  function markStep(n, state){
    Array.prototype.forEach.call(document.querySelectorAll('.mtls-steps li[data-step]'), li => {
      li.classList.remove('active','done');
      const step = parseInt(li.getAttribute('data-step'), 10);
      if (step === n && state === 'active') li.classList.add('active');
      if (step < n) li.classList.add('done');
      if (state === 'done' && step === n) li.classList.add('done');
    });
  }
  function setDisabledLink(a, disabled) {
    if (!a) return;
    if (disabled) {
      a.classList.add('disabled');
      a.setAttribute('aria-disabled','true');
      a.style.pointerEvents = 'none';
    } else {
      a.classList.remove('disabled');
      a.removeAttribute('aria-disabled');
      a.style.pointerEvents = '';
    }
  }
  function copyToClipboard(text){
    try {
      navigator.clipboard.writeText(text);
    } catch(e) {
      const ta = document.createElement('textarea');
      ta.value = text; document.body.appendChild(ta); ta.select();
      try { document.execCommand('copy'); } catch(_) {}
      document.body.removeChild(ta);
    }
  }

  let resendCooldownTimer = null;
  function stopResendCooldown() {
    if (resendCooldownTimer !== null) {
      clearInterval(resendCooldownTimer);
      resendCooldownTimer = null;
    }
  }
  function startResendCooldown(btn) {
    stopResendCooldown();
    const readyAt = Date.now() + RESEND_COOLDOWN_MS;
    enable(btn, false);
    btn.style.display = '';

    const tick = function() {
      const remainingMs = readyAt - Date.now();
      if (remainingMs <= 0) {
        stopResendCooldown();
        btn.textContent = 'Resend';
        enable(btn, true);
        return;
      }
      const seconds = Math.ceil(remainingMs / 1000);
      btn.textContent = 'Resend (' + seconds + 's)';
    };

    tick();
    resendCooldownTimer = setInterval(tick, 250);
  }

  async function pollTokenInfo(token, exportType){
    const hint = q('#expiry-hint');
    const passRow = q('#p12-pass-row');
    const needsPfxPassword = exportType === 'pfx';
    const isAllBundle = exportType === 'all_bundle_zip';
    let artifactReady = false;

    for (let i=0; i<POLL_MAX; i++){
      try {
        const r = await fetch('mtls_api.php?action=token_info', {
          method: 'POST',
          headers: {'Content-Type': 'application/json'},
          body: JSON.stringify({csrf, token})
        });
        const j = await r.json();
        if (r.ok && j.ok) {
          // expiry
          if (typeof j.expires_days === 'number') {
            const d = j.expires_days;
            if (d < 0) {
              hint.textContent = 'Certificate appears expired.';
              hint.className = 'text-danger help-min';
            } else {
              hint.textContent = 'Your current certificate expires in about ' + d + ' day' + (d===1?'':'s') + '.';
              hint.className = 'text-muted help-min';
            }
          } else {
            hint.textContent = 'Checking certificate status…';
            hint.className = 'text-info help-min';
          }

          // password (only relevant for PKCS#12 export)
          if (needsPfxPassword && typeof j.p12_password === 'string' && j.p12_password.length > 0) {
            passRow.innerHTML = '';
            const label = document.createElement('span');
            label.textContent = 'PKCS#12 password: ';
            const code = document.createElement('code');
            code.className = 'k';
            code.textContent = j.p12_password;
            const btn = document.createElement('button');
            btn.type = 'button';
            btn.className = 'btn btn-xs btn-default copy-btn';
            btn.textContent = 'Copy';
            btn.addEventListener('click', () => copyToClipboard(j.p12_password));
            passRow.appendChild(label);
            passRow.appendChild(code);
            passRow.appendChild(btn);
          }

          if (j.artifact_ready === true) {
            artifactReady = true;
            break;
          }
        } else {
          if (r.status === 403 || r.status === 404 || r.status === 410) {
            break;
          }
        }
      } catch(e) { /* keep polling */ }
      await new Promise(res => setTimeout(res, POLL_DELAY_MS));
    }

    // final fallback
    if (needsPfxPassword && !q('#p12-pass-row').textContent.trim()) {
      passRow.textContent = 'PKCS#12 password not available.';
      passRow.className = 'text-warning help-min';
    } else if (isAllBundle && !q('#p12-pass-row').textContent.trim()) {
      passRow.textContent = 'All bundle selected. Password files are included in the ZIP.';
      passRow.className = 'text-muted help-min';
    } else if (!needsPfxPassword && !q('#p12-pass-row').textContent.trim()) {
      passRow.textContent = 'ZIP export selected. No PKCS#12 password is required.';
      passRow.className = 'text-muted help-min';
    }
    if (!q('#expiry-hint').textContent.trim()) {
      hint.textContent = 'Expiry could not be determined.';
      hint.className = 'text-warning help-min';
    }

    return artifactReady;
  }

  // Initial state
  markStep(1, 'active');
  setAriaDisabled(q('#step-2'), true);
  setAriaDisabled(q('#step-3'), true);
  setAriaDisabled(q('#step-4'), true);
  setLocationVisibility(selectedExportType);

  const exportTypeRadios = document.getElementsByName('export_type');
  for (let r of exportTypeRadios) {
    r.addEventListener('change', () => {
      if (!r.checked) return;
      selectedExportType = r.value;
      setLocationVisibility(selectedExportType);
    });
  }

  // CUSTOMIZE (step 1)
  const btnCustomize = q('#btn-customize');
  btnCustomize.addEventListener('click', async () => {
    if (canChooseLocation) {
      const radios = document.getElementsByName('location');
      for (let r of radios) {
        if (r.checked) {
          selectedLocation = r.value;
          break;
        }
      }
    }
    for (let r of exportTypeRadios) {
      if (r.checked) {
        selectedExportType = r.value;
        break;
      }
    }
    const s = q('#customize-status'); msg(s, 'Saving options…', 'info');
    enable(btnCustomize, false);
    try {
      const r = await fetch('mtls_api.php?action=set_customize', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({
          csrf,
          location: selectedLocation,
          export_type: selectedExportType
        })
      });
      const j = await r.json();
      if(!r.ok || !j.ok) throw new Error(j.error || ('HTTP ' + r.status));
      selectedLocation = j.location || selectedLocation;
      selectedExportType = j.export_type || selectedExportType;
      setLocationVisibility(selectedExportType);
      msg(s, 'Options saved.', 'success');

      // Unlock step 2
      markStep(2, 'active');
      setAriaDisabled(q('#step-2'), false);
      enable(q('#btn-send'), true);
    } catch(e) {
      // A collapsed (deep-link) step 1 would otherwise leave no way to retry.
      q('#customize-options').style.display = '';
      msg(s, e.message, 'danger');
      enable(btnCustomize, true);
    }
  });

  // SEND
  const btnSend   = q('#btn-send');
  const btnResend = q('#btn-resend');
  btnSend.addEventListener('click', sendCode);
  btnResend.addEventListener('click', sendCode);

  async function sendCode() {
    const s = q('#send-status'); msg(s, 'Sending…', 'info');
    enable(btnSend, false); enable(btnResend, false);
    try {
      const r = await fetch('mtls_api.php?action=send_code', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({csrf, location: selectedLocation})
      });
      const j = await r.json();
      if(!r.ok || !j.ok) throw new Error(j.error || ('HTTP ' + r.status));
      msg(s, 'Code sent. Check your email.', 'success');

      // Unlock step 3
      markStep(3, 'active');
      setAriaDisabled(q('#step-3'), false);
      enable(q('#code'), true);
      enable(q('#btn-verify'), true);
      // Show resend after first attempt
      startResendCooldown(btnResend);
    } catch(e) {
      msg(s, e.message, 'danger');
      enable(btnSend, true); enable(btnResend, true);
    }
  }

  // VERIFY
  const input = q('#code');
  input.addEventListener('input', () => {
    const v = input.value.trim();
    enable(q('#btn-verify'), /^\d{4,8}$/.test(v));
  });

  q('#btn-verify').addEventListener('click', async () => {
    const s = q('#verify-status'); msg(s, 'Verifying…', 'info');
    enable(q('#btn-verify'), false);
    try {
      const v = input.value.trim();
      const r = await fetch('mtls_api.php?action=verify_code', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({csrf, code: v})
      });
      const j = await r.json();
      if(!r.ok || !j.ok) throw new Error(j.error || ('HTTP ' + r.status));
      const tokenExportType = (j.export_type === 'crt_key_zip' || j.export_type === 'all_bundle_zip')
        ? j.export_type
        : 'pfx';
      selectedExportType = tokenExportType;

      // Build download button; keep disabled until token info indicates readiness (or timeout fallback).
      const area = q('#dl-area');
      area.innerHTML = '';
      const a = document.createElement('a');
      a.href = 'mtls_download.php?token=' + encodeURIComponent(j.token);
      const icon = document.createElement('span');
      icon.className = 'glyphicon glyphicon-download-alt';
      icon.setAttribute('aria-hidden', 'true');
      icon.style.marginRight = '6px';
      const text = document.createTextNode(
        tokenExportType === 'crt_key_zip'
          ? 'Download cert.crt + privkey.pem (.zip) (single-use, valid 5 min)'
          : (tokenExportType === 'all_bundle_zip'
            ? 'Download all certs bundle (.zip, single-use, valid 5 min)'
            : 'Download certificate (.pfx, single-use, valid 5 min)')
      );
      a.appendChild(icon);
      a.appendChild(text);
      a.className = 'btn btn-warning';
      setDisabledLink(a, true);
      a.addEventListener('click', () => {
        a.classList.remove('btn-warning');
        a.classList.add('btn-success');
        icon.style.color = 'var(--success)';
        icon.style.textShadow = '0 0 8px var(--success)';
      });
      area.appendChild(a);

      // Unlock step 4
      markStep(4, 'active');
      setAriaDisabled(q('#step-4'), false);

      // Poll for expiry + P12 password (host stager injects into token JSON)
      const hint = q('#expiry-hint');
      hint.textContent = 'Preparing certificate…';
      hint.className = 'text-info help-min';
      if (tokenExportType === 'pfx') {
        q('#p12-pass-row').textContent = 'Waiting for password…';
        q('#p12-pass-row').className = 'text-info help-min';
      } else if (tokenExportType === 'all_bundle_zip') {
        q('#p12-pass-row').textContent = 'All bundle selected. Password files are included in the ZIP.';
        q('#p12-pass-row').className = 'text-muted help-min';
      } else {
        q('#p12-pass-row').textContent = 'ZIP export selected. Download includes cert.crt and privkey.pem.';
        q('#p12-pass-row').className = 'text-muted help-min';
      }
      msg(s, 'Verified. Token issued. Preparing download…', 'success');

      const artifactReady = await pollTokenInfo(j.token, tokenExportType);
      setDisabledLink(a, false);
      if (artifactReady) {
        msg(s, 'Verified. Token issued.', 'success');
      } else {
        msg(s, 'Verified. Token issued. Download is enabled. Status probe timed out, but the file may already be ready.', 'info');
      }
    } catch(e) {
      msg(s, e.message, 'danger');
      enable(q('#btn-verify'), true);
    }
  });

  // Deep-link preset (?type=...&target=...): skip straight past step 1.
  if (autoContinue) btnCustomize.click();

  // "You're here to download…" notice: fades out on its own (same feel as the login toast).
  const notice = q('#preset-notice');
  if (notice) {
    const dismiss = () => lumUI.dismiss(notice, 350);
    const timer = setTimeout(dismiss, 9000);
    const close = notice.querySelector('.close');
    if (close) close.addEventListener('click', () => { clearTimeout(timer); dismiss(); });
  }
})();
</script>
<?php
render_footer();
