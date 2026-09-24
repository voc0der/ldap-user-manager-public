<?php
// www/account_manager/show_group.php (modernized styling only)

set_include_path('.:' . __DIR__ . '/../includes/');

include_once 'web_functions.inc.php';
include_once 'ldap_functions.inc.php';
include_once 'module_functions.inc.php';

set_page_access('admin');

render_header("$ORGANISATION_NAME account manager");
render_submenu();

$ldap_connection = open_ldap_connection();

if (!isset($_POST['group_name']) and !isset($_GET['group_name'])) {
  ?>
 <div class="alert alert-danger">
  <p class="text-center">The group name is missing.</p>
 </div>
<?php
   render_footer();
  exit(0);
} else {
  $group_cn = (isset($_POST['group_name']) ? $_POST['group_name'] : $_GET['group_name']);
  $group_cn = urldecode($group_cn);
}

if ($ENFORCE_SAFE_SYSTEM_NAMES == true and !preg_match("/$USERNAME_REGEX/", $group_cn)) {
  ?>
 <div class="alert alert-danger">
  <p class="text-center">The group name is invalid.</p>
 </div>
<?php
   render_footer();
  exit(0);
}

######################################################################################

$initialise_group = false;
$new_group = false;
$group_exists = false;

$create_group_message = 'Add members to create the new group';
$current_members = [];
$full_dn = $create_group_message;
$has_been = '';

$attribute_map = $LDAP['default_group_attribute_map'];
if (isset($LDAP['group_additional_attributes'])) {
  $attribute_map = ldap_complete_attribute_array($attribute_map, $LDAP['group_additional_attributes']);
}

$to_update = [];
$this_group = [];

if (isset($_POST['new_group'])) {
  $new_group = true;
} elseif (isset($_POST['initialise_group'])) {
  $initialise_group = true;
  $full_dn = "{$LDAP['group_attribute']}=$group_cn,{$LDAP['group_dn']}";
  $has_been = 'created';
} else {
  $this_group = ldap_get_group_entry($ldap_connection, $group_cn);
  if ($this_group) {
    $current_members = ldap_get_group_members($ldap_connection, $group_cn);
    $full_dn = $this_group[0]['dn'];
    $has_been = 'updated';
    $group_exists = true;
  } else {
    $new_group = true;
  }
}

foreach ($attribute_map as $attribute => $attr_r) {

  if (isset($this_group[0][$attribute]) and $this_group[0][$attribute]['count'] > 0) {
    $$attribute = $this_group[0][$attribute];
  } else {
    $$attribute = [];
  }

  if (isset($_FILES[$attribute]['size']) and $_FILES[$attribute]['size'] > 0) {
    // Limit avatar uploads to 5MB to prevent memory exhaustion
    $max_size = 5 * 1024 * 1024; // 5MB
    if ($_FILES[$attribute]['size'] > $max_size) {
      $error_message = 'File too large. Maximum size is 5MB.';
      continue;
    }

    $this_attribute = [];
    $this_attribute['count'] = 1;
    $this_attribute[0] = file_get_contents($_FILES[$attribute]['tmp_name']);
    $$attribute = $this_attribute;
    $to_update[$attribute] = $this_attribute;
    unset($to_update[$attribute]['count']);
  }

  if (isset($_POST[$attribute])) {
    $this_attribute = [];
    if (is_array($_POST[$attribute])) {
      foreach ($_POST[$attribute] as $key => $value) {
        if ($value != '') {
          $this_attribute[$key] = filter_var($value, FILTER_SANITIZE_FULL_SPECIAL_CHARS);
        }
      }
      $this_attribute['count'] = count($this_attribute);
    } elseif ($_POST[$attribute] != '') {
      $this_attribute['count'] = 1;
      $this_attribute[0] = filter_var($_POST[$attribute], FILTER_SANITIZE_FULL_SPECIAL_CHARS);
    }
    if ($this_attribute != $$attribute) {
      $$attribute = $this_attribute;
      $to_update[$attribute] = $this_attribute;
      unset($to_update[$attribute]['count']);
    }
  }

  if (!isset($$attribute) and isset($attr_r['default'])) {
    $$attribute['count'] = 1;
    $$attribute[0] = $attr_r['default'];
  }
}

if (!isset($gidnumber[0]) or !is_numeric($gidnumber[0])) {
  $gidnumber[0] = ldap_get_highest_id($ldap_connection, $type = 'gid');
  $gidnumber['count'] = 1;
}

######################################################################################

$all_accounts = ldap_get_user_list($ldap_connection);
$all_people = [];
foreach ($all_accounts as $this_person => $attrs) {
  array_push($all_people, $this_person);
}
$non_members = array_diff($all_people, $current_members);

if (isset($_POST['update_members'])) {

  // CSRF Protection
  if (!validate_csrf_token($_POST['csrf_token'] ?? '')) {
    die('CSRF token validation failed. Please refresh the page and try again.');
  }

  $updated_membership = [];
  foreach ($_POST['membership'] as $index => $member) {
    if (is_numeric($index)) {
      array_push($updated_membership, filter_var($member, FILTER_SANITIZE_FULL_SPECIAL_CHARS));
    }
  }

  if ($group_cn == $LDAP['admins_group'] and !array_search($USER_ID, $updated_membership)) {
    array_push($updated_membership, $USER_ID);
  }

  $members_to_del = array_diff($current_members, $updated_membership);
  $members_to_add = array_diff($updated_membership, $current_members);

  if ($initialise_group == true) {
    $initial_member = array_shift($members_to_add);
    $group_add = ldap_new_group($ldap_connection, $group_cn, $initial_member, $to_update);
    if (!$group_add) {
      render_alert_banner('There was a problem creating the group.  See the logs for more information.', 'danger', 10000);
      $group_exists = false;
      $new_group = true;
    } else {
      $group_exists = true;
      $new_group = false;
    }
  }

  if ($group_exists == true) {
    if ($initialise_group != true and count($to_update) > 0) {
      if (isset($this_group[0]['objectclass'])) {
        $existing_objectclasses = $this_group[0]['objectclass'];
        unset($existing_objectclasses['count']);
        if ($existing_objectclasses != $LDAP['group_objectclasses']) {
          $to_update['objectclass'] = $LDAP['group_objectclasses'];
        }
      }
      $updated_attr = ldap_update_group_attributes($ldap_connection, $group_cn, $to_update);
      if ($updated_attr) {
        render_alert_banner('The group attributes have been updated.');
      } else {
        render_alert_banner('There was a problem updating the group attributes.  See the logs for more information.', 'danger', 15000);
      }
    }

    foreach ($members_to_add as $this_member) {
      ldap_add_member_to_group($ldap_connection, $group_cn, $this_member);
    }
    foreach ($members_to_del as $this_member) {
      ldap_delete_member_from_group($ldap_connection, $group_cn, $this_member);
    }

    $non_members = array_diff($all_people, $updated_membership);
    $group_members = $updated_membership;

    $rfc2307bis_available = ldap_detect_rfc2307bis($ldap_connection);
    if ($rfc2307bis_available == true and count($group_members) == 0) {
      $group_members = ldap_get_group_members($ldap_connection, $group_cn);
      $non_members = array_diff($all_people, $group_members);
      render_alert_banner("Groups can't be empty, so the final member hasn't been removed.  You could try deleting the group", 'danger', 15000);
    } else {
      render_alert_banner("The group has been {$has_been}.");
    }
  } else {
    $group_members = [];
    $non_members = $all_people;
  }
} else {
  $group_members = $current_members;
}

ldap_close($ldap_connection);
?>

<script type="text/javascript">
 function show_delete_group_button() {
   var group_del_submit = document.getElementById('delete_group');
   group_del_submit.classList.replace('invisible','visible');
 }

 function update_form_with_users() {
  var members_form = document.getElementById('group_members');
  var member_list_ul = document.getElementById('membership_list');
  var member_list = member_list_ul.getElementsByTagName("li");
  for (var i = 0; i < member_list.length; ++i) {
    var hidden = document.createElement("input");
    hidden.type = "hidden";
    hidden.name = 'membership[]';
    hidden.value = member_list[i]['textContent'];
    members_form.appendChild(hidden);
  }
  members_form.submit();
 }

 lumUI.ready(function () {
    lumUI.initDualList(function () {
        if (document.getElementById('membership_list')) {
          ['submit_members', 'submit_attributes'].forEach(function (id) {
            var button = document.getElementById(id);
            if (button) button.disabled = false;
          });
        }
    });
 });
</script>

<style type='text/css'>
/* ---- modern chrome ---- */
.wrap-narrow { max-width: 1100px; margin: 18px auto 32px; }
.panel-group { margin-bottom: 0; }
.panel-group > .card.panel-modern { margin-bottom: 1rem; }
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

/* dual list visual refresh (keeps your selectors intact) */
.dual-list .well { background: var(--bg-tertiary); border:1px solid var(--border-primary); border-radius:10px; }
.dual-list .list-group { margin-top: 8px; }
.dual-list .list-group-item { background:transparent; border-color: var(--border-primary); color: var(--text-primary); cursor:pointer; }
.dual-list .list-group-item.active { background: var(--gradient-header); border-color: var(--accent); color: var(--accent); }
.list-left li, .list-right li { cursor: pointer; }
.list-arrows { padding-top: 60px; }
.list-arrows button { margin-bottom: 12px; }
.right_button { width: 200px; float: right; }
</style>

<div class="container wrap-narrow">
  <div class="col-md-12">
    <div class="panel-group">
      <div class="card panel-modern">

        <div class="panel-heading clearfix">
          <h3 class="panel-title float-start" style="padding-top: 7.5px;">
            <?php print htmlspecialchars($group_cn, ENT_QUOTES, 'UTF-8'); ?><?php if ($group_cn == $LDAP['admins_group']) {
              print ' <sup>(admin group)</sup>' ;
            } ?>
          </h3>
          <div class="float-end">
            <button class="btn btn-warning btn-pill" onclick="show_delete_group_button();" <?php if ($group_cn == $LDAP['admins_group']) {
              print 'disabled';
            } ?>>Delete group</button>
            <form action="<?php print "{$THIS_MODULE_PATH}"; ?>/groups.php" method="post" enctype="multipart/form-data" style="display:inline;">
              <input type="hidden" name="delete_group" value="<?php print htmlspecialchars($group_cn, ENT_QUOTES, 'UTF-8'); ?>">
              <?php print csrf_token_field(); ?>
              <button class="btn btn-danger btn-pill invisible" id="delete_group">Confirm deletion</button>
            </form>
          </div>
        </div>

        <ul class="list-group">
          <li class="list-group-item group-dn-item">
            <span class="group-dn-label">LDAP Identifier</span>
            <code class="group-dn-value"><?php print htmlspecialchars($full_dn, ENT_QUOTES, 'UTF-8'); ?></code>
          </li>
        </ul>

        <div class="card-body">
          <div class="row">
            <div class="dual-list list-left col-md-5">
              <strong>Members</strong>
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
                <ul class="list-group" id="membership_list">
                  <?php
                  foreach ($group_members as $member) {
                    $safe_member = htmlspecialchars((string)$member, ENT_QUOTES, 'UTF-8');
                    if ($group_cn == $LDAP['admins_group'] and $member == $USER_ID) {
                      print "<div class='list-group-item' style='opacity: 0.5; pointer-events:none;'>$safe_member</div>\n";
                    } else {
                      print "<li class='list-group-item'>$safe_member</li>\n";
                    }
                  }
?>
                </ul>
              </div>
            </div>

            <div class="list-arrows col-md-1 text-center">
              <button class="btn btn-soft btn-sm btn-pill move-left">←</button>
              <button class="btn btn-soft btn-sm btn-pill move-right">→</button>
              <form id="group_members" action="<?php print $CURRENT_PAGE; ?>" method="post">
                <input type="hidden" name="update_members">
                <input type="hidden" name="group_name" value="<?php print htmlspecialchars($group_cn, ENT_QUOTES, 'UTF-8'); ?>">
                <?php if ($new_group == true) { ?><input type="hidden" name="initialise_group"><?php } ?>
                <?php print csrf_token_field(); ?>
                <button id="submit_members" class="btn btn-primary btn-pill" <?php if (count($group_members) == 0) {
                  print 'disabled';
                } ?> type="submit" onclick="update_form_with_users()">Save</button>
            </div>

            <div class="dual-list list-right col-md-5">
              <strong>Available accounts</strong>
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
                  <?php foreach ($non_members as $nonmember) {
                    print "<li class='list-group-item'>" . htmlspecialchars((string)$nonmember, ENT_QUOTES, 'UTF-8') . "</li>\n";
                  } ?>
                </ul>
              </div>
            </div>
          </div>
        </div>
      </div>

<?php if (count($attribute_map) > 0) { ?>
      <div class="card panel-modern">
        <div class="panel-heading clearfix">
          <h3 class="panel-title float-start" style="padding-top: 7.5px;">Group attributes</h3>
        </div>
        <div class="card-body">
          <div class="col-md-8">
            <?php
              $tabindex = 1;
  foreach ($attribute_map as $attribute => $attr_r) {
    $label = $attr_r['label'];
    if (isset($$attribute)) {
      $these_values = $$attribute;
    } else {
      $these_values = [];
    }
    print "<div class='row'>";
    $dl_identifider = ($full_dn != $create_group_message) ? $full_dn : '';
    if (isset($attr_r['inputtype'])) {
      $inputtype = $attr_r['inputtype'];
    } else {
      $inputtype = '';
    }
    render_attribute_fields($attribute, $label, $these_values, $dl_identifider, '', $inputtype, $tabindex);
    print '</div>';
    $tabindex++;
  }
  ?>
            <div class="row">
              <div class="col-md-4 col-md-offset-3">
                <div class="form-group">
                  <button id="submit_attributes" class="btn btn-primary btn-pill" <?php if (count($group_members) == 0) {
                    print 'disabled';
                  } ?> type="submit" tabindex="<?php print $tabindex; ?>" onclick="update_form_with_users()">Save</button>
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>
<?php } ?>
              </form>
    </div>
  </div>
</div>
<?php render_footer(); ?>
