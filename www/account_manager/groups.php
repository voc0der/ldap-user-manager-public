<?php
// www/account_manager/groups.php  (TOTAL in header; right-aligned "New group" with input popping to its left)

set_include_path('.:' . __DIR__ . '/../includes/');

include_once 'web_functions.inc.php';
include_once 'ldap_functions.inc.php';
include_once 'module_functions.inc.php';
include_once 'role_functions.inc.php';

set_page_access('admin');

render_header("$ORGANISATION_NAME account manager");
render_submenu();

$ldap_connection = open_ldap_connection();

if (isset($_POST['delete_group'])) {
  // CSRF Protection
  if (!validate_csrf_token($_POST['csrf_token'] ?? '')) {
    die('CSRF token validation failed. Please refresh the page and try again.');
  }

  $this_group = urldecode($_POST['delete_group']);
  $del_group = ldap_delete_group($ldap_connection, $this_group);
  if ($del_group) {
    render_alert_banner("Group <strong>$this_group</strong> was deleted.");
  } else {
    render_alert_banner("Group <strong>$this_group</strong> wasn't deleted.  See the logs for more information.", 'danger', 15000);
  }
}

if (isset($_POST['delete_role'])) {
  // CSRF Protection
  if (!validate_csrf_token($_POST['csrf_token'] ?? '')) {
    die('CSRF token validation failed. Please refresh the page and try again.');
  }

  $role_id = trim((string)($_POST['delete_role'] ?? ''));
  $role_name = 'Unknown';
  $valid_role_id = (bool)preg_match('/^[A-Za-z0-9._:-]{1,128}$/', $role_id);
  $role = $valid_role_id ? roles_get_by_id($role_id) : null;
  if ($role) {
    $role_name = htmlspecialchars((string)($role['name'] ?? ''), ENT_QUOTES, 'UTF-8');
  }

  if ($valid_role_id && roles_delete($role_id)) {
    render_alert_banner("Role <strong>$role_name</strong> was deleted.");
  } else {
    render_alert_banner("Role <strong>$role_name</strong> wasn't deleted. See the logs for more information.", 'danger', 15000);
  }
}

$groups = ldap_get_group_list($ldap_connection);
$totalGroups = count($groups);
ldap_close($ldap_connection);

$roles_data = roles_load_presets();
$roles_raw = $roles_data['roles'] ?? [];
$roles = is_array($roles_raw)
  ? array_values(array_filter($roles_raw, static fn ($role) => is_array($role)))
  : [];
$totalRoles = count($roles);
usort($roles, static fn ($a, $b) => strcasecmp((string)($a['name'] ?? ''), (string)($b['name'] ?? '')));

render_js_username_check();
?>

<script type="text/javascript">
function show_new_group_form(){
  var group_form   = document.getElementById('group_name');
  var group_submit = document.getElementById('add_group');
  group_form.classList.remove('hidden');
  group_submit.classList.remove('hidden');
  try { group_form.focus(); } catch(e){}
}
</script>

<div class="container wrap-narrow">
  <div class="card panel-modern">
    <div class="panel-heading">
      <div class="panel-headline">
        <h3 class="card-title">Groups</h3>
        <span class="header-total">Total: <?php echo number_format($totalGroups); ?></span>
      </div>
    </div>

    <div class="card-body">
      <div class="panel-toolbar">
        <div class="panel-toolbar-search">
          <div class="input-group">
            <span class="input-group-addon glyphicon glyphicon-search"></span>
            <input class="form-control" id="group_search_input" type="text" placeholder="Search groups…">
          </div>
          <div class="help-min">Type to filter the list below.</div>
        </div>
        <div class="panel-toolbar-actions" id="new_group_div">
          <form action="<?php print "{$THIS_MODULE_PATH}"; ?>/show_group.php" method="post" class="toolbar-new-group-form">
            <input type="hidden" name="new_group">
            <input type="text" class="form-control hidden new-group-input" name="group_name" id="group_name"
                   placeholder="Group name"
                   onkeyup="check_entity_name_validity(document.getElementById('group_name').value,'new_group_div');">
            <button id="add_group" class="btn btn-success btn-pill btn-sm hidden" type="submit">Add</button>
            <button id="show_new_group" class="btn btn-primary btn-pill" type="button" onclick="show_new_group_form();">
              New group
            </button>
          </form>
        </div>
      </div>

      <div class="table-responsive">
        <table class="table table-dark table-striped table-modern">
          <thead>
            <tr><th>Group name</th></tr>
          </thead>
          <tbody id="grouplist">
<?php foreach ($groups as $group) {
  $safe_group = htmlspecialchars($group, ENT_QUOTES, 'UTF-8');
  print "  <tr>\n    <td><a href='{$THIS_MODULE_PATH}/show_group.php?group_name=" . urlencode($group) . "'>$safe_group</a></td>\n  </tr>\n";
} ?>
          </tbody>
        </table>
      </div>

      <div id="roles_section" style="margin-top:22px;padding-top:14px;border-top:1px solid var(--border-primary);">
        <div class="panel-headline" style="margin-bottom:10px;">
          <h4 class="card-title" style="margin:0;">Roles</h4>
          <span class="header-total">Total: <?php echo number_format($totalRoles); ?></span>
        </div>

        <div class="help-min" style="margin-bottom:12px;">
          Roles are still presets of group memberships. Manage them here under Groups.
        </div>

        <div class="panel-toolbar">
          <div class="panel-toolbar-search">
            <div class="input-group">
              <span class="input-group-addon glyphicon glyphicon-search"></span>
              <input class="form-control" id="role_search_input" type="text" placeholder="Search roles…">
            </div>
            <div class="help-min">Type to filter the list below.</div>
          </div>
          <div class="panel-toolbar-actions">
            <form action="<?php print $THIS_MODULE_PATH; ?>/show_role.php" method="post">
              <input type="hidden" name="new_role" value="1">
              <button class="btn btn-primary btn-pill" type="submit">New role</button>
            </form>
          </div>
        </div>

        <div class="table-responsive">
          <table class="table table-dark table-striped table-modern">
            <thead>
              <tr>
                <th>Priority</th>
                <th>Role Name</th>
                <th>Groups</th>
                <th>Description</th>
                <th style="width:170px">Actions</th>
              </tr>
            </thead>
            <tbody id="rolelist">
<?php
if (empty($roles)) {
  echo "<tr><td colspan='5' class='text-center help-min'>No roles defined yet. Create one to get started.</td></tr>\n";
} else {
  foreach ($roles as $role) {
    $role_id = (string)($role['id'] ?? '');
    $safe_name = htmlspecialchars((string)($role['name'] ?? ''), ENT_QUOTES, 'UTF-8');
    $safe_desc = htmlspecialchars((string)($role['description'] ?? ''), ENT_QUOTES, 'UTF-8');
    $role_groups = (isset($role['groups']) && is_array($role['groups'])) ? $role['groups'] : [];
    $group_count = count($role_groups);
    $priority = (int)($role['priority'] ?? 100);

    echo "  <tr>\n";
    echo "    <td><span class='badge'>" . $priority . "</span></td>\n";
    echo "    <td><a href='{$THIS_MODULE_PATH}/show_role.php?role_id=" . urlencode($role_id) . "'>$safe_name</a></td>\n";
    echo "    <td>\n";
    echo "      <span class='badge'>$group_count group" . ($group_count !== 1 ? 's' : '') . "</span>\n";

    if (!empty($role_groups)) {
      echo "      <div class='role-group-pills'>\n";
      foreach (array_slice($role_groups, 0, 5) as $g) {
        echo "        <span class='pill'>" . htmlspecialchars((string)$g, ENT_QUOTES, 'UTF-8') . "</span>\n";
      }
      if (count($role_groups) > 5) {
        echo "        <span class='pill'>+" . (count($role_groups) - 5) . " more</span>\n";
      }
      echo "      </div>\n";
    }

    echo "    </td>\n";
    echo "    <td class='help-min'>$safe_desc</td>\n";
    echo "    <td>\n";
    echo "      <a class='btn btn-xs btn-soft btn-pill' href='{$THIS_MODULE_PATH}/show_role.php?role_id=" . urlencode($role_id) . "'>Edit</a>\n";
    echo "      <form action='{$THIS_MODULE_PATH}/groups.php#roles_section' method='post' style='display:inline;'>\n";
    echo "        <input type='hidden' name='delete_role' value='" . htmlspecialchars($role_id, ENT_QUOTES, 'UTF-8') . "'>\n";
    echo          csrf_token_field() . "\n";
    echo "        <button class='btn btn-xs btn-danger btn-pill' type='submit' onclick='return confirm(\"Delete this role preset?\");'>Delete</button>\n";
    echo "      </form>\n";
    echo "    </td>\n";
    echo "  </tr>\n";
  }
}
?>
            </tbody>
          </table>
        </div>
      </div>
    </div>
  </div>
</div>

<script>
// Keep simple client-side filters for both sections.
lumUI.ready(function(){
  lumUI.bindRowFilter('#group_search_input', '#grouplist tr');
  lumUI.bindRowFilter('#role_search_input', '#rolelist tr');
});
</script>

<?php render_footer(); ?>
