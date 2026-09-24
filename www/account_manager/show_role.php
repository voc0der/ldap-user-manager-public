<?php
// www/account_manager/show_role.php - Create/edit role

set_include_path('.:' . __DIR__ . '/../includes/');

include_once 'web_functions.inc.php';
include_once 'ldap_functions.inc.php';
include_once 'module_functions.inc.php';
include_once 'role_functions.inc.php';

set_page_access('admin');

render_header("$ORGANISATION_NAME account manager");
render_submenu();

$ldap_connection = open_ldap_connection();

// Determine mode: new or edit
$is_new = isset($_POST['new_role']) || isset($_GET['new_role']);
$role_id = '';
$role_name = '';
$role_description = '';
$role_groups = [];
$role_priority = 100;

if (!$is_new) {
  $role_id = $_GET['role_id'] ?? $_POST['role_id'] ?? '';

  if ($role_id === '') {
    ?>
    <div class="alert alert-danger">
      <p class="text-center">The role identifier is missing.</p>
    </div>
    <?php
    render_footer();
    exit(0);
  }

  $role = roles_get_by_id($role_id);

  if (!$role) {
    ?>
    <div class="alert alert-danger">
      <p class="text-center">This role doesn't exist.</p>
    </div>
    <?php
    render_footer();
    exit(0);
  }

  $role_name = $role['name'];
  $role_description = $role['description'] ?? '';
  $role_groups = $role['groups'] ?? [];
  $role_priority = (int)($role['priority'] ?? 100);
}

// Handle form submission
if (isset($_POST['save_role'])) {
  // CSRF Protection
  if (!validate_csrf_token($_POST['csrf_token'] ?? '')) {
    die('CSRF token validation failed. Please refresh the page and try again.');
  }

  $new_name = trim($_POST['role_name'] ?? '');
  $new_description = trim($_POST['role_description'] ?? '');
  $new_priority = (int)($_POST['role_priority'] ?? 100);
  $new_groups = [];

  // Extract groups from POST (numeric indices)
  foreach ($_POST as $key => $value) {
    if (is_numeric($key) && !empty($value)) {
      $new_groups[] = $value;
    }
  }

  // Validation
  $errors = [];
  if ($new_name === '') {
    $errors[] = 'Role name is required';
  }
  if (empty($new_groups)) {
    $errors[] = 'At least one group must be selected';
  }

  if (empty($errors)) {
    if ($is_new) {
      $result = roles_create($new_name, $new_groups, $new_description, $new_priority);
      if ($result) {
        $role_id = $result;
        $is_new = false;
        render_alert_banner('Role <strong>' . htmlspecialchars($new_name, ENT_QUOTES, 'UTF-8') . '</strong> was created.');
      } else {
        render_alert_banner('Failed to create role. Check the logs for more information.', 'danger', 15000);
      }
    } else {
      $result = roles_update($role_id, $new_name, $new_groups, $new_description, $new_priority);
      if ($result) {
        render_alert_banner('Role <strong>' . htmlspecialchars($new_name, ENT_QUOTES, 'UTF-8') . '</strong> was updated.');
      } else {
        render_alert_banner('Failed to update role. Check the logs for more information.', 'danger', 15000);
      }
    }

    // Refresh data
    if (!$is_new) {
      $role = roles_get_by_id($role_id);
      $role_name = $role['name'];
      $role_description = $role['description'] ?? '';
      $role_groups = $role['groups'] ?? [];
      $role_priority = (int)($role['priority'] ?? 100);
    }
  } else {
    render_alert_banner('<strong>Validation errors:</strong><ul><li>' . implode('</li><li>', array_map('htmlspecialchars', $errors)) . '</li></ul>', 'warning', 15000);
  }
}

// Get all available groups from LDAP
$all_groups = ldap_get_group_list($ldap_connection);
$selected_groups = $role_groups;
$available_groups = array_diff($all_groups, $selected_groups);

ldap_close($ldap_connection);
?>

<style type='text/css'>
/* Modern chrome styling (consistent with show_group.php) */
.wrap-narrow { max-width: 1100px; margin: 18px auto 32px; }
.panel-modern {
  background: linear-gradient(135deg, var(--gradient-start) 0%, var(--gradient-end) 100%), var(--bg-secondary);
  border: 1px solid var(--border-primary);
  border-radius: 12px;
  overflow: hidden;
}
.panel-modern .panel-heading {
  background: var(--gradient-header);
  color: var(--accent);
  font-weight: 600;
  letter-spacing: .4px;
  text-transform: uppercase;
  padding: 10px 14px;
  border-bottom: 1px solid var(--border-primary);
}
.panel-modern .panel-title { margin:0; font-size:18px; letter-spacing:.2px; color: var(--accent); }
.panel-modern .panel-body,
.panel-modern .card-body { padding:16px 16px 18px; }
.help-min { color: var(--text-muted); font-size:12px; }
.btn-pill { border-radius:999px; }
.btn-soft { background: var(--gradient-start); border:1px solid var(--border-primary); color: var(--accent); }
.btn-soft:hover { background: var(--gradient-header); border-color: var(--border-hover); color: var(--accent-2); }
.invisible { visibility:hidden; } .visible { visibility:visible; }

/* Dual list styling */
.dual-list .well { background: var(--bg-tertiary); border:1px solid var(--border-primary); border-radius:10px; }
.dual-list .list-group { margin-top: 8px; }
.dual-list .list-group-item { background:transparent; border-color: var(--border-primary); color: var(--text-primary); cursor:pointer; }
.dual-list .list-group-item.active { background: var(--gradient-header); border-color: var(--accent); color: var(--accent); }
.list-arrows { padding-top: 60px; }
.list-arrows button { margin-bottom: 12px; }
</style>

<div class="container wrap-narrow">
  <div class="card panel-modern">
    <div class="panel-heading clearfix">
      <h3 class="panel-title float-start" style="padding-top:7.5px;">
        <?php echo $is_new ? 'New Role' : htmlspecialchars($role_name, ENT_QUOTES, 'UTF-8'); ?>
      </h3>
      <?php if (!$is_new) { ?>
      <div class="float-end">
        <button class="btn btn-warning btn-pill" onclick="show_delete_role_button();">Delete role</button>
        <form action="<?php print $THIS_MODULE_PATH; ?>/groups.php#roles_section" method="post" style="display:inline;">
          <input type="hidden" name="delete_role" value="<?php print htmlspecialchars($role_id, ENT_QUOTES, 'UTF-8'); ?>">
          <?php print csrf_token_field(); ?>
          <button class="btn btn-danger btn-pill invisible" id="delete_role">Confirm deletion</button>
        </form>
      </div>
      <?php } ?>
    </div>

    <div class="card-body">
      <form class="form-horizontal" action="" method="post">
        <?php if (!$is_new) { ?>
          <input type="hidden" name="role_id" value="<?php print htmlspecialchars($role_id, ENT_QUOTES, 'UTF-8'); ?>">
        <?php } else { ?>
          <input type="hidden" name="new_role" value="1">
        <?php } ?>
        <input type="hidden" name="save_role" value="1">
        <?php print csrf_token_field(); ?>

        <div class="form-group">
          <label for="role_name" class="col-sm-3 control-label"><strong>Role Name</strong><sup>&ast;</sup></label>
          <div class="col-sm-6">
            <input type="text" class="form-control" id="role_name" name="role_name"
                   value="<?php echo htmlspecialchars($role_name, ENT_QUOTES, 'UTF-8'); ?>"
                   required maxlength="100">
            <div class="help-min">Display name for this role</div>
          </div>
        </div>

        <div class="form-group">
          <label for="role_description" class="col-sm-3 control-label">Description</label>
          <div class="col-sm-6">
            <textarea class="form-control" id="role_description" name="role_description" rows="3" maxlength="500"><?php echo htmlspecialchars($role_description, ENT_QUOTES, 'UTF-8'); ?></textarea>
            <div class="help-min">Optional description of this role's purpose</div>
          </div>
        </div>

        <div class="form-group">
          <label for="role_priority" class="col-sm-3 control-label"><strong>Priority</strong><sup>&ast;</sup></label>
          <div class="col-sm-6">
            <input type="number" class="form-control" id="role_priority" name="role_priority"
                   value="<?php echo (int)$role_priority; /* nosemgrep: php.lang.security.injection.echoed-request.echoed-request */ ?>"
                   min="1" max="999" required>
            <div class="help-min">Lower number = higher priority. Users matching multiple roles will show the highest priority role.</div>
          </div>
        </div>

        <div class="form-group">
          <label class="col-sm-3 control-label"><strong>Groups</strong><sup>&ast;</sup></label>
          <div class="col-sm-9">
            <div class="help-min" style="margin-bottom:12px;">Select the groups that define this role. Users with all these groups will be shown as having this role.</div>
          </div>
        </div>

        <div class="row">
          <div class="dual-list list-left col-md-5">
            <strong>Selected groups</strong>
            <div class="well">
              <div class="row">
                <div class="col-md-10">
                  <div class="input-group">
                    <span class="input-group-addon glyphicon glyphicon-search"></span>
                    <input type="text" name="SearchDualList" class="form-control" placeholder="search" />
                  </div>
                </div>
                <div class="col-md-2">
                  <div class="btn-group">
                    <a class="btn btn-soft btn-pill selector" title="select all"><i class="glyphicon glyphicon-unchecked">☐</i></a>
                  </div>
                </div>
              </div>
              <ul class="list-group" id="selected_groups_list">
                <?php foreach ($selected_groups as $group) {
                  print "<li class='list-group-item'>" . htmlspecialchars($group, ENT_QUOTES, 'UTF-8') . "</li>\n";
                } ?>
              </ul>
            </div>
          </div>

          <div class="list-arrows col-md-1 text-center">
            <button class="btn btn-soft btn-sm btn-pill move-left" type="button">←</button>
            <button class="btn btn-soft btn-sm btn-pill move-right" type="button">→</button>
          </div>

          <div class="dual-list list-right col-md-5">
            <strong>Available groups</strong>
            <div class="well">
              <div class="row">
                <div class="col-md-2">
                  <div class="btn-group">
                    <a class="btn btn-soft btn-pill selector" title="select all"><i class="glyphicon glyphicon-unchecked">☐</i></a>
                  </div>
                </div>
                <div class="col-md-10">
                  <div class="input-group">
                    <input type="text" name="SearchDualList" class="form-control" placeholder="search" />
                    <span class="input-group-addon glyphicon glyphicon-search"></span>
                  </div>
                </div>
              </div>
              <ul class="list-group">
                <?php foreach ($available_groups as $group) {
                  print "<li class='list-group-item'>" . htmlspecialchars($group, ENT_QUOTES, 'UTF-8') . "</li>\n";
                } ?>
              </ul>
            </div>
          </div>
        </div>

        <div class="form-group text-center" style="margin-top:20px;">
          <button type="submit" class="btn btn-primary btn-pill" id="save_button">
            <?php echo $is_new ? 'Create role' : 'Save changes'; ?>
          </button>
          <a href="<?php print $THIS_MODULE_PATH; ?>/groups.php#roles_section" class="btn btn-default btn-pill">Cancel</a>
        </div>

        <!-- Hidden container for form submission -->
        <div id="hidden_groups_container"></div>
      </form>
    </div>
  </div>
</div>

<script type="text/javascript">
function show_delete_role_button() {
  var del_button = document.getElementById('delete_role');
  del_button.classList.replace('invisible','visible');
}

// Dual-list functionality (adapted from show_group.php)
lumUI.ready(function () {
  lumUI.initDualList(updateSaveButton);

  // Before the role form submits, inject selected groups as hidden inputs.
  // (Only the role form: the delete-role form must not be blocked by this.)
  var container = document.getElementById('hidden_groups_container');
  var roleForm = container ? container.closest('form') : null;
  if (roleForm) {
    roleForm.addEventListener('submit', function(e) {
      container.replaceChildren();

      var selected = document.querySelectorAll('#selected_groups_list li');
      selected.forEach(function(li, index) {
        var hidden = document.createElement('input');
        hidden.type = 'hidden';
        hidden.name = index;
        hidden.value = li.textContent.trim();
        container.appendChild(hidden);
      });

      // Validate at least one group
      if (selected.length === 0) {
        alert('Please select at least one group for this role.');
        e.preventDefault();
      }
    });
  }

  function updateSaveButton() {
    var hasGroups = document.querySelectorAll('#selected_groups_list li').length > 0;
    var saveButton = document.getElementById('save_button');
    if (saveButton) saveButton.disabled = !hasGroups;
  }

  updateSaveButton();
});
</script>

<?php render_footer(); ?>
