<?php
declare(strict_types=1);
require_once __DIR__ . '/../includes/web_functions.inc.php';
set_page_access('auth');

@session_start();
global $IS_ADMIN, $USER_ID;
$isAdmin  = !empty($IS_ADMIN);
$username = $USER_ID ?? ($_SESSION['user_id'] ?? 'unknown');

function canon_ip(?string $ip): ?string
{
  if (!$ip) {
    return null;
  }
  if (!filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4 | FILTER_FLAG_IPV6)) {
    return null;
  }
  $bin = @inet_pton($ip);
  return $bin === false ? null : inet_ntop($bin);
}
function get_client_ip(): ?string
{
  $c = [];
  $trust_forwarded = false;
  if (function_exists('lum_is_header_auth_request_trusted')) {
    $trust_forwarded = lum_is_header_auth_request_trusted();
  }
  if ($trust_forwarded && !empty($_SERVER['HTTP_X_FORWARDED_FOR'])) {
    foreach (explode(',', $_SERVER['HTTP_X_FORWARDED_FOR']) as $p) {
      $c[] = trim($p);
    }
  }
  if ($trust_forwarded && !empty($_SERVER['HTTP_X_REAL_IP'])) {
    $c[] = trim($_SERVER['HTTP_X_REAL_IP']);
  }
  if (!empty($_SERVER['REMOTE_ADDR'])) {
    $c[] = trim($_SERVER['REMOTE_ADDR']);
  }
  foreach ($c as $v) {
    if ($v = canon_ip($v)) {
      return $v;
    }
  }
  return null;
}
$clientIp = get_client_ip();

// ---------- Gate by group (from $MODULE_GROUP_GATES['lease_ip']) ----------
if (!lum_module_gate_satisfied('lease_ip')) {
  render_header('Lease IP');
  echo '<div class="container" style="max-width:860px;margin-top:20px">
            <div class="alert alert-danger">
              Access denied: this page is only available to members of the <code>'
          . htmlspecialchars(lum_module_gate_group_label('lease_ip'), ENT_QUOTES, 'UTF-8')
          . '</code> group.
            </div>
          </div>';
  render_footer();
  exit;
}

render_header('Lease IP');
?>

<div class="container lease-wrap">

  <?php if (!$isAdmin): ?>
  <!-- MY LEASES (non-admins only) -->
  <div class="card panel-modern">
    <div class="card-header">
      <div class="header-inline">
        <div class="grow">
          <span class="header-title">MY LEASES</span>
          <span class="header-count">COUNT: <span id="my-count">–</span></span>
        </div>
        <button class="btn btn-soft btn-pill btn-test-connection" type="button">Test</button>
        <button id="btn-toggle-ip" class="btn btn-primary btn-pill">Add my IP</button>
        <button id="my-refresh" class="btn btn-muted btn-pill">Refresh</button>
      </div>
    </div>
    <div class="card-body">
      <div class="table-responsive">
        <table class="table table-dark table-striped table-modern">
          <thead>
          <tr>
            <th>Username</th>
            <th>Source</th>
            <th>Timestamp</th>
            <th>IP</th>
            <th>Expiry</th>
            <th class="text-right">Actions</th>
          </tr>
          </thead>
          <tbody id="my-tbody"></tbody>
          <tfoot>
          <tr>
            <td colspan="6"><span id="my-status" class="smallprint"></span></td>
          </tr>
          </tfoot>
        </table>
      </div>
    </div>
  </div>
  <?php endif; ?>

  <?php if ($isAdmin): ?>
  <!-- ADMIN: ACTIVE LEASES -->
  <div class="card panel-modern">
    <div class="card-header">
      <div class="header-inline">
        <div class="grow">
          <span class="header-title">ACTIVE LEASES</span>
          <span class="header-count">TOTAL: <span id="count">–</span></span>
        </div>
        <button class="btn btn-soft btn-pill btn-test-connection" type="button">Test</button>
        <button id="btn-toggle-ip" class="btn btn-primary btn-pill">Add my IP</button>
        <button id="btn-refresh" class="btn btn-muted btn-pill">Refresh list</button>
      </div>
    </div>
    <div class="card-body">
      <div class="table-responsive">
        <table class="table table-dark table-striped table-modern">
          <thead>
          <tr>
            <th>Username</th>
            <th>Source</th>
            <th>Timestamp</th>
            <th>IP</th>
            <th>Expiry</th>
            <th class="text-right">Actions</th>
          </tr>
          </thead>
          <tbody id="tbody"></tbody>
          <tfoot>
          <tr>
            <td colspan="6">
              <div class="control-line">
                <label class="smallprint">Add IP (admin):</label>
                <input id="manual-ip" type="text" class="form-control input-slim" placeholder="e.g. 203.0.113.7 or 2001:db8::1">
                <label class="smallprint" style="margin:0 6px 0 2px;">
                  <input id="manual-static" type="checkbox"> Static
                </label>
                <button id="btn-add-manual" class="btn btn-soft btn-pill">Add IP</button>
                <span class="help-note">Static entries are skipped by prune.</span>
              </div>
            </td>
          </tr>
          <tr>
            <td colspan="6">
              <div class="control-line">
                <button id="btn-clear" class="btn btn-soft btn-pill">Clear all</button>
                <label class="smallprint">Prune (hours):</label>
                <input id="prune-hours" type="number" min="1" value="96" class="form-control" style="width:6.5em;">
                <button id="btn-prune" class="btn btn-soft btn-pill">Run prune</button>
                <span id="admin-status" class="smallprint"></span>
              </div>
            </td>
          </tr>
          </tfoot>
        </table>
      </div>
    </div>
  </div>
  <?php endif; ?>

</div>

<script>
  window.LEASE_IP = {
    clientIp: <?php echo json_encode($clientIp); ?>,
    isAdmin: <?php echo $isAdmin ? 'true' : 'false'; ?>,
    userId: <?php echo json_encode($username); ?>
  };
</script>
<script src="<?php echo $SERVER_PATH; ?>js/lum_geo_ui.min.js"></script>
<script src="lease_ui.min.js"></script>

<?php render_footer(); ?>
