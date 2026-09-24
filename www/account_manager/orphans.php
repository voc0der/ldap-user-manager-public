<?php
declare(strict_types=1);

/**
 * MFA Orphans (TOTP + WebAuthn) — no full-page refresh
 * - Reads status.json
 * - Compares subjects to LDAP UIDs (case-insensitive)
 * - Queues deletes via authelia_api.php (AJAX)
 * - Polls status.json every 3s after actions until changes are visible
 */

set_include_path('.:' . __DIR__ . '/../includes/');
require_once 'web_functions.inc.php';
require_once 'ldap_functions.inc.php';
require_once 'module_functions.inc.php';
require_once 'apprise_helpers.inc.php';

@session_start();
set_page_access('admin');

// ====== OPTIONS ==============================================================
$MATCH_BY_UID_ONLY = true; // consider orphan if subject does not match an LDAP uid

// Use the shared CSRF token that csrf_verify_or_exit() validates.
$CSRF = csrf_get_token();

// Resolve Authelia paths
$AUTHELIA_DIR = getenv('AUTHELIA_DIR')
  ?: (realpath(__DIR__ . '/../data/authelia') ?: (__DIR__ . '/../data/authelia'));
$STATUS = $AUTHELIA_DIR . '/status.json';

// Correct API endpoint
$API    = $THIS_MODULE_PATH . '/authelia_api.php';

function h(?string $s): string
{
  return htmlspecialchars((string)$s, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
}
function human_time_diff($now, $ts)
{
  $diff = abs($now - $ts);
  $units = [31536000 => 'year',2592000 => 'month',604800 => 'week',86400 => 'day',3600 => 'hour',60 => 'minute',1 => 'second'];
  foreach ($units as $secs => $name) {
    if ($diff >= $secs) {
      $v = (int)floor($diff / $secs);
      return $v . ' ' . $name . ($v > 1 ? 's' : '');
    }
  }
  return '0 seconds';
}

// ----------------------------------------------------------------------------
// Load snapshot on first render
$status = ['generated_ts' => 0,'totp' => [],'webauthn' => []];
$STATUS_EXISTS = is_file($STATUS);
$STATUS_BYTES  = $STATUS_EXISTS ? (int)@filesize($STATUS) : 0;

if ($STATUS_EXISTS) {
  $raw = @file_get_contents($STATUS);
  if ($raw !== false) {
    $j = json_decode($raw, true);
    if (is_array($j)) {
      $status = $j;
    }
  }
}
$gen  = (int)($status['generated_ts'] ?? 0);
$totp = is_array($status['totp'] ?? null) ? $status['totp'] : [];
$web  = is_array($status['webauthn'] ?? null) ? $status['webauthn'] : [];

// LDAP valid UIDs
$ldap   = open_ldap_connection();
$people = ldap_get_user_list($ldap);
$uidsLC = []; // lower(uid) => canonical uid
foreach ($people as $uid => $attribs) {
  $uidsLC[strtolower($uid)] = $uid;
}

// Build orphan lists
$orphTOTP = [];      // [subject]
$orphWeb  = [];      // [subject => count]
$subjects = [];      // unique set of orphan subjects

$resolveNotOrphan = function (string $subject) use ($uidsLC, $MATCH_BY_UID_ONLY): bool {
  $sl = strtolower(trim($subject));
  return isset($uidsLC[$sl]);
};

foreach ($totp as $subj => $present) {
  if (!$present) {
    continue;
  }
  if (!$resolveNotOrphan((string)$subj)) {
    $orphTOTP[] = (string)$subj;
    $subjects[(string)$subj] = true;
  }
}
foreach ($web as $subj => $count) {
  $has = is_array($count) ? (int)($count['count'] ?? 1) > 0 : ((int)$count > 0);
  if (!$has) {
    continue;
  }
  if (!$resolveNotOrphan((string)$subj)) {
    $orphWeb[(string)$subj] = is_array($count) ? (int)($count['count'] ?? 1) : (int)$count;
    if ($orphWeb[(string)$subj] <= 0) {
      $orphWeb[(string)$subj] = 1;
    }
    $subjects[(string)$subj] = true;
  }
}
$totalSubjects = count($subjects);

// Sets for rendering “Delete BOTH” only when truly in both lists
$hasTotp = [];
foreach ($orphTOTP as $s) {
  $hasTotp[$s] = true;
}
$hasWeb  = [];
foreach ($orphWeb as $s => $_) {
  $hasWeb[$s] = true;
}

// ----------------------------------------------------------------------------
// Render
render_header("$ORGANISATION_NAME account manager");
render_submenu();
?>

<div class="container wrap-narrow">
  <div class="card panel-modern">
    <div class="panel-heading">
      <div class="panel-headline panel-headline--stacked">
        <h3 class="card-title">MFA Orphans</h3>
        <div class="panel-badges">
          <span class="badge-soft" id="count_subjects" title="Unique subjects"><?php echo (int)$totalSubjects; ?> subjects</span>
          <span class="badge-soft" id="count_totp" title="TOTP entries"><?php echo count($orphTOTP); ?> TOTP</span>
          <span class="badge-soft" id="count_web" title="WebAuthn entries"><?php echo count($orphWeb); ?> WebAuthn</span>
        </div>
      </div>
      <div class="kv panel-kicker">
        Snapshot:
        <code id="snap_ts" title="UTC: <?php echo $gen ? h(gmdate('Y-m-d H:i:s \U\T\C', $gen)) : 'unknown'; ?>">
          <?php
            if ($gen) {
              $dt = new DateTime("@$gen");
              $dt->setTimezone(new DateTimeZone(date_default_timezone_get()));
              echo h($dt->format('Y-m-d H:i:s T'));
            } else {
              echo 'unknown';
            }
?>
        </code>
        <?php if ($gen): ?>
        <span class="help-min" id="snap_age">(≈ <?php echo h(human_time_diff(time(), $gen)); ?> ago)</span>
        <?php else: ?>
        <span class="help-min" id="snap_age"></span>
        <?php endif; ?>
        <div class="snap-hint">
          status.json: <span class="pill" id="snap_present"><?php echo $STATUS_EXISTS ? 'present' : 'missing'; ?></span>
          <?php if ($STATUS_EXISTS): ?> • size: <span class="pill" id="snap_size"><?php echo (int)$STATUS_BYTES; ?> bytes</span><?php else: ?>
            • size: <span class="pill" id="snap_size">0 bytes</span>
          <?php endif; ?>
        </div>
      </div>
    </div>

    <div class="card-body">
      <div class="panel-toolbar panel-toolbar--actions-only<?php echo $totalSubjects > 0 ? '' : ' hidden'; ?>" id="bulk_delete_all_wrap">
        <div class="panel-toolbar-actions">
          <button id="bulk_delete_all" class="btn btn-danger btn-pill">Delete ALL orphans</button>
        </div>
      </div>
      <?php if (!$STATUS_EXISTS): ?>
        <div class="alert alert-warning" role="alert" style="margin:0 0 10px;">
          Couldn’t find <code><?php echo h($STATUS); ?></code>. The worker generates this file.
        </div>
      <?php endif; ?>

      <div id="zero_state" class="<?php echo $totalSubjects === 0 ? '' : 'hidden'; ?>">
        <div class="alert alert-success" role="alert" style="margin:0;">
          No MFA orphans detected. 🎉
        </div>
      </div>

      <div id="tables_wrap" class="<?php echo $totalSubjects === 0 ? 'hidden' : ''; ?>">

      <?php if (!empty($orphTOTP)): ?>
      <h4 style="margin-top:0;">TOTP (orphaned)</h4>
      <div class="table-responsive">
        <table class="table table-dark table-striped table-modern" id="table_totp">
          <thead><tr><th style="width:40px"><input type="checkbox" id="chk_all_totp"></th><th>Authelia subject</th><th style="width:320px">Action</th></tr></thead>
          <tbody>
          <?php foreach ($orphTOTP as $subj): ?>
            <tr data-kind="totp" data-user="<?php echo h($subj); ?>">
              <td><input type="checkbox" class="chk_one"></td>
              <td class="col-user"><code><?php echo h($subj); ?></code></td>
              <td class="col-actions">
                <button type="button" class="btn btn-xs btn-danger btn-pill btn-del-totp" data-user="<?php echo h($subj); ?>">Delete TOTP</button>
                <?php if (isset($hasWeb[$subj])): ?>
                  <button type="button" class="btn btn-xs btn-soft btn-pill btn-delete-both" data-user="<?php echo h($subj); ?>">Delete TOTP + WebAuthn</button>
                <?php endif; ?>
              </td>
            </tr>
          <?php endforeach; ?>
          </tbody>
        </table>
      </div>
      <?php endif; ?>

      <?php if (!empty($orphWeb)): ?>
      <h4>WebAuthn (orphaned)</h4>
      <div class="table-responsive">
        <table class="table table-dark table-striped table-modern" id="table_web">
          <thead><tr><th style="width:40px"><input type="checkbox" id="chk_all_web"></th><th>Authelia subject</th><th>Device count</th><th style="width:360px">Action</th></tr></thead>
          <tbody>
          <?php foreach ($orphWeb as $subj => $cnt): ?>
            <tr data-kind="web" data-user="<?php echo h($subj); ?>">
              <td><input type="checkbox" class="chk_one"></td>
              <td class="col-user"><code><?php echo h($subj); ?></code></td>
              <td class="col-count"><?php echo (int)$cnt; ?></td>
              <td class="col-actions">
                <button type="button" class="btn btn-xs btn-danger btn-pill btn-del-web" data-user="<?php echo h($subj); ?>">Delete WebAuthn (all)</button>
                <?php if (isset($hasTotp[$subj])): ?>
                  <button type="button" class="btn btn-xs btn-soft btn-pill btn-delete-both" data-user="<?php echo h($subj); ?>">Delete TOTP + WebAuthn</button>
                <?php endif; ?>
              </td>
            </tr>
          <?php endforeach; ?>
          </tbody>
        </table>
      </div>
      <?php endif; ?>

      <div id="bulk_controls" class="<?php echo $totalSubjects > 0 ? '' : 'hidden'; ?>">
        <button id="bulk_delete_selected" class="btn btn-danger btn-pill">Delete selected</button>
        <span id="bulk_status" class="help-min" style="margin-left:10px;"></span>
      </div>

      </div><!-- /tables_wrap -->
    </div>
  </div>
</div>

<script>
(function(){
  var API  = <?php echo json_encode($API); ?>;
  var CSRF = <?php echo json_encode($CSRF); ?>;

  // Keep a local copy of the last-seen generated_ts so we can update snapshot header
  var lastGenTs = <?php echo (int)$gen; ?>;

  function one(sel){ return document.querySelector(sel); }
  function all(sel){ return Array.prototype.slice.call(document.querySelectorAll(sel)); }
  function rowsFor(kind, user){
    return all('tr[data-kind="' + kind + '"][data-user="' + CSS.escape(user) + '"]');
  }
  function setText(sel, text){
    var el = one(sel);
    if (el) el.textContent = text;
  }
  function setHidden(sel, hidden){
    var el = one(sel);
    if (el) el.classList.toggle('hidden', hidden);
  }

  function setStatus(msg){ setText('#bulk_status', msg); }

  function updateHeaderCounts(){
    // recompute from DOM
    var totpCount = all('tr[data-kind="totp"]').length;
    var webCount  = all('tr[data-kind="web"]').length;

    // unique subjects across both tables
    var seen = {};
    all('tr[data-kind]').forEach(function(tr){ seen[tr.dataset.user] = true; });
    var subjCount = Object.keys(seen).length;

    setText('#count_totp', totpCount + ' TOTP');
    setText('#count_web', webCount + ' WebAuthn');
    setText('#count_subjects', subjCount + ' subjects');

    // hide/show zero state and controls
    var empty = (totpCount + webCount === 0);
    setHidden('#tables_wrap', empty);
    setHidden('#bulk_controls', empty);
    setHidden('#bulk_delete_all_wrap', empty);
    setHidden('#zero_state', !empty);
  }

  function updateBothButtons(){
    // Only show "Delete TOTP + WebAuthn" when the subject exists in both tables currently
    all('tr[data-kind]').forEach(function(tr){
      var subj = tr.dataset.user;
      var inTotp = rowsFor('totp', subj).length > 0;
      var inWeb  = rowsFor('web', subj).length > 0;
      var bothBtns = tr.querySelectorAll('.btn-delete-both');
      if (inTotp && inWeb){
        var actions = tr.querySelector('.col-actions');
        if (!bothBtns.length && actions){
          // add the button after the first action button
          var btn = document.createElement('button');
          btn.type = 'button';
          btn.className = 'btn btn-xs btn-soft btn-pill btn-delete-both';
          btn.dataset.user = subj;
          btn.textContent = 'Delete TOTP + WebAuthn';
          actions.append(' ', btn);
        }
      } else {
        bothBtns.forEach(function(b){ b.remove(); });
      }
    });
  }

  function formatLocal(ts){
    var d = new Date(ts*1000);
    var pad = n => (n<10?'0':'')+n;
    var z  = Intl.DateTimeFormat().resolvedOptions().timeZone || '';
    return d.getFullYear()+'-'+pad(d.getMonth()+1)+'-'+pad(d.getDate())+' '+pad(d.getHours())+':'+pad(d.getMinutes())+':'+pad(d.getSeconds())+' '+z;
  }
  function humanAge(ts){
    var diff = Math.abs(Math.floor(Date.now()/1000) - ts);
    var units = [[31536000,'year'],[2592000,'month'],[604800,'week'],[86400,'day'],[3600,'hour'],[60,'minute'],[1,'second']];
    for (var i=0;i<units.length;i++){
      var s = units[i][0], n = units[i][1];
      if (diff>=s){ var v = Math.floor(diff/s); return v+' '+n+(v>1?'s':''); }
    }
    return '0 seconds';
  }

  // ---- API calls ----
  // Resolves with the parsed JSON body; rejects with {status, responseText}.
  function request(url, options){
    return fetch(url, Object.assign({ credentials: 'same-origin' }, options)).then(function(res){
      return res.text().then(function(body){
        if (!res.ok) throw { status: res.status, responseText: body };
        try {
          return JSON.parse(body);
        } catch (e) {
          throw { status: res.status, responseText: body };
        }
      });
    }, function(){
      throw { status: 0, responseText: '' };
    });
  }

  function fetchStatus(){
    return request(API + '?action=status&t=' + Date.now(), {
      method: 'GET',
      headers: { 'Accept': 'application/json' }
    });
  }

  function queue(data){
    data.csrf_token = CSRF;
    return request(API, {
      method: 'POST',
      headers: { 'Accept': 'application/json', 'X-CSRF-Token': CSRF },
      body: new URLSearchParams(data)
    });
  }
  function queueTotp(user){ return queue({op:'totp.delete', user:user}); }
  function queueWeb(user){ return queue({op:'webauthn.delete', user:user, scope:'all'}); }

  // Apply a newly fetched snapshot to DOM for a set of "targets"
  // wantMap: { user: { totp:false? (meaning we want totp absent), web:0? (want web count == 0) } }
  function applySnapshot(snapshot, wantMap){
    if (!snapshot || typeof snapshot !== 'object') return {done:false};

    var totp = snapshot.totp || {};
    var web  = snapshot.webauthn || {};
    var changedSomething = false;
    var satisfiedAll = true;

    // Update header snapshot info if generated_ts changed
    if (snapshot.generated_ts && snapshot.generated_ts !== lastGenTs){
      lastGenTs = snapshot.generated_ts;
      var snapTs = one('#snap_ts');
      if (snapTs){
        snapTs.textContent = formatLocal(lastGenTs);
        snapTs.title = 'UTC: ' + new Date(lastGenTs*1000).toUTCString();
      }
      setText('#snap_age', '(≈ ' + humanAge(lastGenTs) + ' ago)');
      // We also update size/present opportunistically (we don’t know size here)
      setText('#snap_present', 'present');
    }

    // For each target, check if desired state now visible
    Object.keys(wantMap).forEach(function(user){
      var want = wantMap[user] || {};
      // current presence:
      var curTotp = !!totp[user];
      var curWeb  = 0;
      if (web.hasOwnProperty(user)) {
        curWeb = (typeof web[user] === 'number') ? web[user] : (web[user] && typeof web[user].count === 'number' ? web[user].count : 0);
      }

      // Evaluate fulfillment
      var totpFulfilled = (want.hasOwnProperty('totp') ? (want.totp === false && curTotp === false) : true);
      var webFulfilled  = (want.hasOwnProperty('web')  ? (want.web  === 0     && curWeb  === 0)    : true);

      if (!totpFulfilled || !webFulfilled) satisfiedAll = false;

      // If fulfilled, mutate DOM for that section
      if (totpFulfilled){
        var rowsT = rowsFor('totp', user);
        if (rowsT.length){
          rowsT.forEach(function(r){ r.remove(); });
          changedSomething = true;
        }
      }
      if (webFulfilled){
        var rowsW = rowsFor('web', user);
        if (rowsW.length){
          rowsW.forEach(function(r){ r.remove(); });
          changedSomething = true;
        }
      }
    });

    if (changedSomething){
      updateHeaderCounts();
      updateBothButtons();
      // Also uncheck “select all” if lists changed
      all('#chk_all_totp, #chk_all_web').forEach(function(c){ c.checked = false; });
    }

    return {done: satisfiedAll};
  }

  // Poller that keeps asking until wantMap is satisfied or timeout reached
  function pollUntilReflected(wantMap, maxTries){
    var tries = 0, max = maxTries || 60; // ~3 minutes @ 3s
    setStatus('Waiting for status.json update…');

    function tick(){
      tries++;
      fetchStatus().then(function(snap){
        var res = applySnapshot(snap, wantMap);
        if (res.done){
          setStatus('Update reflected in status.json.');
          return; // stop (don’t schedule another tick)
        }
        if (tries < max){
          setTimeout(tick, 3000);
        } else {
          setStatus('Gave up waiting for status.json (will catch up later).');
        }
      }, function(){
        if (tries < max){
          setTimeout(tick, 3000);
        } else {
          setStatus('Failed to read status.json repeatedly.');
        }
      });
    }
    setTimeout(tick, 3000);
  }

  function onClick(selector, handler){
    document.addEventListener('click', function(e){
      var el = e.target.closest(selector);
      if (el) handler(el);
    });
  }

  // Single-row: Delete TOTP
  onClick('.btn-del-totp', function(btn){
    var user = btn.dataset.user;
    btn.disabled = true;
    btn.textContent = 'Queuing…';
    setStatus('Queuing TOTP delete for ' + user + '…');
    queueTotp(user).then(function(res){
      setStatus('Queued TOTP for ' + user + (res && res.action_id ? ' ('+res.action_id+')' : ''));
      var want = {}; want[user] = {totp:false}; // we want totp to be absent
      pollUntilReflected(want, 80);
    }, function(xhr){
      setStatus('Failed TOTP for ' + user + ': ' + (xhr.responseText || xhr.status));
      btn.disabled = false;
      btn.textContent = 'Delete TOTP';
    });
  });

  // Single-row: Delete WebAuthn (all)
  onClick('.btn-del-web', function(btn){
    var user = btn.dataset.user;
    btn.disabled = true;
    btn.textContent = 'Queuing…';
    setStatus('Queuing WebAuthn delete for ' + user + '…');
    queueWeb(user).then(function(res){
      setStatus('Queued WebAuthn for ' + user + (res && res.action_id ? ' ('+res.action_id+')' : ''));
      var want = {}; want[user] = {web:0}; // we want web count to be 0
      pollUntilReflected(want, 80);
    }, function(xhr){
      setStatus('Failed WebAuthn for ' + user + ': ' + (xhr.responseText || xhr.status));
      btn.disabled = false;
      btn.textContent = 'Delete WebAuthn (all)';
    });
  });

  // Single-row: Delete BOTH (TOTP then WebAuthn)
  onClick('.btn-delete-both', function(btn){
    var user = btn.dataset.user;
    btn.disabled = true;
    btn.textContent = 'Queuing…';
    setStatus('Queuing BOTH for ' + user + '…');

    // Queue both in sequence; WebAuthn is queued even if TOTP fails, and
    // success is only reported once both have been queued.
    var totpError = null;
    queueTotp(user)
      .catch(function(xhr){ totpError = xhr; })
      .then(function(){ return queueWeb(user); })
      .then(function(res){
        if (totpError) throw totpError;
        setStatus('Queued BOTH for ' + user + (res && res.action_id ? ' ('+res.action_id+')' : ''));
        var want = {}; want[user] = {totp:false, web:0};
        pollUntilReflected(want, 100);
      })
      .catch(function(xhr){
        setStatus('Failed BOTH for ' + user + ': ' + (xhr.responseText || xhr.status));
        btn.disabled = false;
        btn.textContent = 'Delete TOTP + WebAuthn';
      });
  });

  // master checkboxes
  var chkAllTotp = one('#chk_all_totp');
  if (chkAllTotp) chkAllTotp.addEventListener('change', function(){
    var checked = this.checked;
    all('tr[data-kind="totp"] .chk_one').forEach(function(c){ c.checked = checked; });
  });
  var chkAllWeb = one('#chk_all_web');
  if (chkAllWeb) chkAllWeb.addEventListener('change', function(){
    var checked = this.checked;
    all('tr[data-kind="web"] .chk_one').forEach(function(c){ c.checked = checked; });
  });

  // bulk delete selected (AJAX + poll until reflected)
  var bulkSelected = one('#bulk_delete_selected');
  if (bulkSelected) bulkSelected.addEventListener('click', function(){
    var picked = all('tr[data-kind]').filter(function(tr){ return tr.querySelector('input.chk_one:checked'); });
    if (!picked.length) { setStatus('Nothing selected.'); return; }

    // Build want map and queue list
    var want = {}; // user => desired states
    var ops = [];  // promises
    picked.forEach(function(tr){
      var user = tr.dataset.user;
      var kind = tr.dataset.kind;
      if (!want[user]) want[user] = {};
      if (kind === 'totp'){ want[user].totp = false; ops.push(queueTotp(user)); }
      if (kind === 'web') { want[user].web  = 0;     ops.push(queueWeb(user));  }
    });

    setStatus('Queuing ' + ops.length + ' action(s)…');

    // Run queues (not necessarily sequential)
    var done = 0, fail = 0;
    Promise.all(ops.map(p => p.then(()=>{done++;}, ()=>{fail++;}))).then(function(){
      setStatus('Queued: ' + done + ', failed: ' + fail + '. Waiting for status.json…');
      pollUntilReflected(want, 120);
    });
  });

  // bulk delete ALL
  var bulkAll = one('#bulk_delete_all');
  if (bulkAll) bulkAll.addEventListener('click', function(){
    // Check all, then use bulk selected
    all('tr[data-kind] .chk_one').forEach(function(c){ c.checked = true; });
    if (bulkSelected) bulkSelected.click();
  });

})();
</script>

<?php
ldap_close($ldap);
render_footer();
