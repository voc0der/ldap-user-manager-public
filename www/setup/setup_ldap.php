<?php

set_include_path('.:' . __DIR__ . '/../includes/');

include_once 'web_functions.inc.php';
include_once 'ldap_functions.inc.php';
include_once 'module_functions.inc.php';

$ldap_connection = open_ldap_connection();
lum_require_setup_incomplete($ldap_connection);

validate_setup_cookie();
set_page_access('setup');

// CSRF tokens live in the session, which can't start once output has begun.
lum_start_session();

render_header("$ORGANISATION_NAME account manager setup");

$no_errors = true;
$show_create_admin_button = false;

# Set up missing stuff

if (isset($_POST['fix_problems'])) {
  if (!validate_csrf_token($_POST['csrf_token'] ?? '')) {
    render_alert_banner('Security check failed. Please go back and retry setup.', 'danger', 10000);
    render_footer();
    exit(0);
  }

  ?>
<script>
    lumUI.ready(function(){
     const popoverTriggerList = document.querySelectorAll('[data-bs-toggle="popover"]');
     const popoverList = [...popoverTriggerList].map(el => new bootstrap.Popover(el));
    });
</script>
<div class='container'>

 <div class="card panel-modern">
  <div class="card-header">Updating LDAP...</div>
   <div class="card-body">
    <ul class="list-group">

<?php

   if (isset($_POST['setup_group_ou'])) {
     $ou_add = @ ldap_add($ldap_connection, $LDAP['group_dn'], [ 'objectClass' => 'organizationalUnit', 'ou' => $LDAP['group_ou'] ]);
     if ($ou_add == true) {
       print "$li_good Created OU <strong>{$LDAP['group_dn']}</strong></li>\n";
     } else {
       $error = ldap_error($ldap_connection);
       print "$li_fail Couldn't create {$LDAP['group_dn']}: <pre>$error</pre></li>\n";
       $no_errors = false;
     }
   }


  if (isset($_POST['setup_user_ou'])) {
    $ou_add = @ ldap_add($ldap_connection, $LDAP['user_dn'], [ 'objectClass' => 'organizationalUnit', 'ou' => $LDAP['user_ou'] ]);
    if ($ou_add == true) {
      print "$li_good Created OU <strong>{$LDAP['user_dn']}</strong></li>\n";
    } else {
      $error = ldap_error($ldap_connection);
      print "$li_fail Couldn't create {$LDAP['user_dn']}: <pre>$error</pre></li>\n";
      $no_errors = false;
    }
  }


  if (isset($_POST['setup_last_gid'])) {

    $highest_gid = ldap_get_highest_id($ldap_connection, 'gid');
    $description = 'Records the last GID used to create a Posix group. This prevents the re-use of a GID from a deleted group.';

    $add_lastgid_r = [ 'objectClass' => ['device','top'],
                            'serialnumber' => $highest_gid,
                            'description' => $description ];

    $gid_add = @ ldap_add($ldap_connection, "cn=lastGID,{$LDAP['base_dn']}", $add_lastgid_r);

    if ($gid_add == true) {
      print "$li_good Created <strong>cn=lastGID,{$LDAP['base_dn']}</strong></li>\n";
    } else {
      $error = ldap_error($ldap_connection);
      print "$li_fail Couldn't create cn=lastGID,{$LDAP['base_dn']}: <pre>$error</pre></li>\n";
      $no_errors = false;
    }
  }


  if (isset($_POST['setup_last_uid'])) {

    $highest_uid = ldap_get_highest_id($ldap_connection, 'uid');
    $description = 'Records the last UID used to create a Posix account. This prevents the re-use of a UID from a deleted account.';

    $add_lastuid_r = [ 'objectClass' => ['device','top'],
                            'serialnumber' => $highest_uid,
                            'description' => $description ];

    $uid_add = @ ldap_add($ldap_connection, "cn=lastUID,{$LDAP['base_dn']}", $add_lastuid_r);

    if ($uid_add == true) {
      print "$li_good Created <strong>cn=lastUID,{$LDAP['base_dn']}</strong></li>\n";
    } else {
      $error = ldap_error($ldap_connection);
      print "$li_fail Couldn't create cn=lastUID,{$LDAP['base_dn']}: <pre>$error</pre></li>\n";
      $no_errors = false;
    }
  }


  if (isset($_POST['setup_default_group'])) {

    $group_add = ldap_new_group($ldap_connection, $DEFAULT_USER_GROUP);

    if ($group_add == true) {
      print "$li_good Created default group: <strong>$DEFAULT_USER_GROUP</strong></li>\n";
    } else {
      $error = ldap_error($ldap_connection);
      print "$li_fail Couldn't create default group: <pre>$error</pre></li>\n";
      $no_errors = false;
    }
  }

  if (isset($_POST['setup_admins_group'])) {

    $group_add = ldap_new_group($ldap_connection, $LDAP['admins_group']);

    if ($group_add == true) {
      print "$li_good Created LDAP administrators group: <strong>{$LDAP['admins_group']}</strong></li>\n";
    } else {
      $error = ldap_error($ldap_connection);
      print "$li_fail Couldn't create LDAP administrators group: <pre>$error</pre></li>\n";
      $no_errors = false;
    }
  }

  $admins = ldap_get_group_members($ldap_connection, $LDAP['admins_group']);

  if (count($admins) < 1) {

    ?>
  <div class="form-group">
  <form action="<?php print "{$SERVER_PATH}account_manager/new_user.php"; ?>" method="post">
  <input type="hidden" name="setup_admin_account">
  <?php
    print "$li_fail The LDAP administration group is empty. ";
    print "<a href='#' data-bs-toggle='popover' title='LDAP account administrators' data-bs-content='";
    print "Only members of this group ({$LDAP['admins_group']}) will be able to access the account managment section, so we need to add people to it.";
    print "'>What's this?</a>";
    print "<label class='float-end'><input type='checkbox' name='setup_admin_account' class='float-end' checked>Create a new account and add it to the admin group?&nbsp;</label>";
    print "</li>\n";
    $show_create_admin_button = true;
  } else {
    print "$li_good The LDAP account administrators group (<strong>{$LDAP['admins_group']}</strong>) isn't empty.</li>";
  }


  ?>
  </ul>
 </div>
</div>
<?php

  ##############

   if ($no_errors == true) {
     if ($show_create_admin_button == false) {
       ?>
 </form>
 <div class='well'>
  <form action="<?php print $THIS_MODULE_PATH; ?>">
   <input type='submit' class="btn btn-success center-block" value='Finished' class='center-block'>
  </form>
 </div>
 <?php
     } else {
       ?>
    <div class='well'>
    <input type='submit' class="btn btn-warning center-block" value='Create new account >' class='center-block'>
   </form>
  </div>
  <?php
     }
   } else {
     ?>
 </form>
 <div class='well'>
  <form action="<?php print $THIS_MODULE_PATH; ?>/run_checks.php">
   <input type='submit' class="btn btn-danger center-block" value='< Re-run setup' class='center-block'>
  </form>
 </div>
<?php

   }

}

render_footer();

?>
