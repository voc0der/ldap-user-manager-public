<?php
// www/invite/index.php

declare(strict_types=1);

set_include_path('.:' . __DIR__ . '/../includes/');

include_once 'web_functions.inc.php';
include_once 'ldap_functions.inc.php';
include_once 'invite_functions.inc.php';
include_once 'apprise_helpers.inc.php';

if (session_status() === PHP_SESSION_NONE) {
  session_start();
}

set_page_access('auth');

function invite_generate_password(int $length = 32): string
{
  $length = max(1, min(128, $length));
  $chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz123456789';
  $password_chars = [];

  for ($i = 0; $i < $length; $i++) {
    $password_chars[] = $chars[random_int(0, strlen($chars) - 1)];
  }

  return implode('', $password_chars);
}

function invite_format_event_time(int $timestamp): string
{
  if ($timestamp <= 0) {
    return '<span class="help-min">unknown</span>';
  }

  try {
    $dt = (new DateTimeImmutable('@' . $timestamp))
      ->setTimezone(new DateTimeZone(date_default_timezone_get()));
    $now = new DateTimeImmutable('now', $dt->getTimezone());
    $formatted = $dt->format('Y-m-d H:i');
    $day_delta = (int)$now->setTime(0, 0)->diff($dt->setTime(0, 0))->format('%r%a');
    $fmt_relative = static function (int $count, string $unit, bool $future): string {
      $label = $count . ' ' . $unit . ($count === 1 ? '' : 's');
      return $future ? ('in ' . $label) : ($label . ' ago');
    };

    if ($day_delta === 0) {
      $relative = 'Today';
    } elseif ($day_delta === -1) {
      $relative = 'Yesterday';
    } elseif ($day_delta === 1) {
      $relative = 'Tomorrow';
    } else {
      $future = ($day_delta > 0);
      $abs_days = abs($day_delta);

      if ($abs_days < 7) {
        $relative = $fmt_relative($abs_days, 'day', $future);
      } elseif ($abs_days < 30) {
        $weeks = max(1, (int)floor($abs_days / 7));
        $relative = $fmt_relative($weeks, 'week', $future);
      } elseif ($abs_days < 365) {
        $months = max(1, (int)floor($abs_days / 30));
        $relative = $fmt_relative($months, 'month', $future);
      } else {
        $years = max(1, (int)floor($abs_days / 365));
        $relative = $fmt_relative($years, 'year', $future);
      }
    }

    return '<span title="' . htmlspecialchars($dt->format('Y-m-d H:i:s T'), ENT_QUOTES, 'UTF-8') . '">' .
           htmlspecialchars($formatted, ENT_QUOTES, 'UTF-8') .
           '<br><small style="color:#888;">' . htmlspecialchars($relative, ENT_QUOTES, 'UTF-8') . '</small></span>';
  } catch (Exception $e) {
    return '<span class="help-min">unknown</span>';
  }
}

function invite_build_lineage_topology(array $all_users, array $root_candidates): array
{
  $users_by_key = [];
  foreach (array_keys($all_users) as $uid) {
    $uid_label = trim((string)$uid);
    $uid_key = strtolower($uid_label);
    if ($uid_key !== '') {
      $users_by_key[$uid_key] = $uid_label;
    }
  }

  $latest_by_invitee = [];
  $events_doc = invite_load_events();
  $events = (array)($events_doc['events'] ?? []);
  foreach ($events as $event) {
    if (!is_array($event)) {
      continue;
    }
    $invitee_uid = trim((string)($event['invitee_uid'] ?? ''));
    $invitee_key = strtolower($invitee_uid);
    if ($invitee_key === '' || !isset($users_by_key[$invitee_key])) {
      continue;
    }
    $created_ts = (int)($event['created_ts'] ?? 0);
    $existing_ts = (int)($latest_by_invitee[$invitee_key]['created_ts'] ?? -1);
    if ($created_ts >= $existing_ts) {
      $latest_by_invitee[$invitee_key] = [
        'created_ts' => $created_ts,
        'inviter_uid' => trim((string)($event['inviter_uid'] ?? '')),
      ];
    }
  }

  $parent_by_child = [];
  $children_by_parent = [];
  foreach ($latest_by_invitee as $child_key => $lineage_row) {
    $inviter_key = strtolower(trim((string)($lineage_row['inviter_uid'] ?? '')));
    if ($inviter_key === '' || $inviter_key === $child_key || !isset($users_by_key[$inviter_key])) {
      continue;
    }
    $parent_by_child[$child_key] = $inviter_key;
    if (!isset($children_by_parent[$inviter_key])) {
      $children_by_parent[$inviter_key] = [];
    }
    $children_by_parent[$inviter_key][$child_key] = true;
  }

  $root_lookup = [];
  foreach ($root_candidates as $root_candidate) {
    $root_label = trim((string)$root_candidate);
    $root_key = strtolower($root_label);
    if ($root_key !== '') {
      $root_lookup[$root_key] = $root_label;
    }
  }

  $root_key = '';
  if (count($root_lookup) === 1) {
    $possible_root = array_key_first($root_lookup);
    if ($possible_root !== null && isset($users_by_key[$possible_root])) {
      $root_key = $possible_root;
    }
  }

  $visible_lookup = [];
  if ($root_key !== '') {
    $queue = [$root_key];
    while (!empty($queue)) {
      $current = array_shift($queue);
      if (isset($visible_lookup[$current])) {
        continue;
      }
      $visible_lookup[$current] = true;
      $children = array_keys((array)($children_by_parent[$current] ?? []));
      foreach ($children as $child_key) {
        if (!isset($visible_lookup[$child_key])) {
          $queue[] = $child_key;
        }
      }
    }
  } else {
    $visible_lookup = array_fill_keys(array_keys($users_by_key), true);
  }

  $visible_keys = array_keys($visible_lookup);
  usort($visible_keys, static function (string $a, string $b) use ($users_by_key): int {
    return strnatcasecmp((string)$users_by_key[$a], (string)$users_by_key[$b]);
  });

  $nodes = [];
  foreach ($visible_keys as $uid_key) {
    $parent_key = (string)($parent_by_child[$uid_key] ?? '');
    if (!isset($visible_lookup[$parent_key])) {
      $parent_key = '';
    }
    if ($uid_key === $root_key) {
      $parent_key = '';
    }
    $nodes[] = [
      'id' => $uid_key,
      'label' => (string)$users_by_key[$uid_key],
      'parent' => ($parent_key !== '') ? $parent_key : null,
      'is_root' => ($uid_key === $root_key),
    ];
  }

  $unlinked_labels = [];
  if ($root_key !== '') {
    foreach ($users_by_key as $uid_key => $uid_label) {
      if (!isset($visible_lookup[$uid_key])) {
        $unlinked_labels[] = (string)$uid_label;
      }
    }
    sort($unlinked_labels, SORT_NATURAL | SORT_FLAG_CASE);
  }

  return [
    'root_uid' => ($root_key !== '') ? (string)$users_by_key[$root_key] : '',
    'nodes' => $nodes,
    'total_active' => count($users_by_key),
    'visible_count' => count($nodes),
    'unlinked_labels' => $unlinked_labels,
  ];
}

$invite_access_group = getenv('INVITE_ACCESS_GROUP') ?: 'invite';
$can_invite = lum_user_in_group($invite_access_group);
$invite_target_group = getenv('INVITE_TARGET_GROUP') ?: $invite_access_group;
$invite_profile_id = 'group:' . strtolower($invite_target_group);

render_header("$ORGANISATION_NAME invite");

if (!$can_invite) {
  http_response_code(403);
  ?>
  <div class="container wrap-narrow">
    <div class="card panel-modern">
      <div class="panel-heading text-center">Invite</div>
      <div class="card-body">
        <div class="alert alert-danger">
          <p class="text-center">Access denied. You must be in the <strong><?php echo htmlspecialchars($invite_access_group, ENT_QUOTES, 'UTF-8'); ?></strong> LDAP group to invite users.</p>
        </div>
      </div>
    </div>
  </div>
  <?php
  render_footer();
  exit(0);
}

if (!isset($EMAIL_SENDING_ENABLED)) {
  $EMAIL_SENDING_ENABLED = !empty($SMTP['host'] ?? '');
}

$ldap_connection = open_ldap_connection();
$all_groups = ldap_get_group_list($ldap_connection);
$group_lookup = [];
foreach ($all_groups as $group_name) {
  $group_lookup[strtolower((string)$group_name)] = (string)$group_name;
}
$invite_target_group_key = strtolower($invite_target_group);
$invite_target_group_resolved = (string)($group_lookup[$invite_target_group_key] ?? '');
$active_invitee_uids = [];
$all_users = ldap_get_user_list($ldap_connection);
if (is_array($all_users)) {
  foreach (array_keys($all_users) as $existing_uid) {
    $existing_uid_key = strtolower(trim((string)$existing_uid));
    if ($existing_uid_key !== '') {
      $active_invitee_uids[$existing_uid_key] = true;
    }
  }
}

$form_uid = '';
$form_mail = '';
$form_givenname = '';
$form_sn = '';
$errors = [];
$warnings = [];
$success_message = '';
$lineage_topology = ['root_uid' => '', 'nodes' => [], 'total_active' => 0, 'visible_count' => 0, 'unlinked_labels' => []];
$assigned_group_label = ($invite_target_group_resolved !== '') ? $invite_target_group_resolved : $invite_target_group;
$invite_profile_name = $assigned_group_label . ' only';
$current_inviter_uid = trim((string)($GLOBALS['USER_ID'] ?? ($_SERVER['HTTP_REMOTE_USER'] ?? ($_SESSION['user_id'] ?? ''))));

if (isset($_POST['create_invite'])) {
  if (!validate_csrf_token($_POST['csrf_token'] ?? '')) {
    $errors[] = 'CSRF token validation failed. Please refresh the page and try again.';
  }

  $form_uid = trim((string)filter_var($_POST['uid'] ?? '', FILTER_SANITIZE_FULL_SPECIAL_CHARS));
  $form_mail = trim((string)filter_var($_POST['mail'] ?? '', FILTER_SANITIZE_EMAIL));

  if ($form_uid === '') {
    $errors[] = 'Username is required.';
  } else {
    $form_givenname = $form_uid;
    $form_sn = substr($form_uid, 0, 1);
  }
  if ($form_mail === '') {
    $errors[] = 'Email is required.';
  }
  if ($form_mail !== '' && !is_valid_email($form_mail)) {
    $errors[] = 'Email must be a valid address.';
  }
  if (!empty($ENFORCE_SAFE_SYSTEM_NAMES) && $form_uid !== '' && !preg_match("/$USERNAME_REGEX/", $form_uid)) {
    $errors[] = 'Username is invalid.';
  }

  if (!$EMAIL_SENDING_ENABLED) {
    $errors[] = 'Invite is disabled because SMTP is not configured. Set SMTP_HOSTNAME and related mail settings first.';
  }

  if ($invite_target_group_resolved === '') {
    $errors[] = 'Invite target group "' . $invite_target_group . '" does not exist in LDAP.';
  }

  if ($invite_target_group_resolved !== '' && !empty($LDAP['admins_group']) && strcasecmp($invite_target_group_resolved, (string)$LDAP['admins_group']) === 0) {
    $errors[] = 'Invite target group is misconfigured to the LDAP admin group. Refusing to continue.';
  }

  $final_groups = ($invite_target_group_resolved !== '') ? [$invite_target_group_resolved] : [];

  if (empty($errors)) {
    $account_identifier = $form_uid;
    $displayname_value = $form_uid;
    $cn_value = !empty($ENFORCE_SAFE_SYSTEM_NAMES)
      ? ($form_givenname . $form_sn)
      : trim($form_givenname . ' ' . $form_sn);

    $generated_password = invite_generate_password(32);

    $new_account_r = [
      'givenname' => [0 => $form_givenname],
      'sn' => [0 => $form_sn],
      'uid' => [0 => $form_uid],
      'cn' => [0 => $cn_value],
      'mail' => [0 => $form_mail],
      'displayname' => [0 => $displayname_value],
      $LDAP['account_attribute'] => [0 => $account_identifier],
      'password' => [0 => $generated_password],
    ];

    $new_account = ldap_new_account($ldap_connection, $new_account_r);

    if (!$new_account) {
      $errors[] = 'Failed to create the account. Check server logs for details.';
    } else {
      $group_assign_failed = false;
      foreach ($final_groups as $group_name) {
        if (!ldap_add_member_to_group($ldap_connection, $group_name, $account_identifier)) {
          $group_assign_failed = true;
        }
      }

      if ($group_assign_failed) {
        foreach ($final_groups as $group_name) {
          ldap_delete_member_from_group($ldap_connection, $group_name, $account_identifier);
        }
        ldap_delete_account($ldap_connection, $account_identifier);
        $errors[] = 'Account creation was rolled back because one or more group assignments failed.';
      } else {
        $inviter_uid = ($current_inviter_uid !== '') ? $current_inviter_uid : 'unknown';
        $audit_event_id = invite_record_event($inviter_uid, $account_identifier, $form_mail, $invite_profile_id, $invite_profile_name, $final_groups);
        if ($audit_event_id === false) {
          foreach ($final_groups as $group_name) {
            ldap_delete_member_from_group($ldap_connection, $group_name, $account_identifier);
          }
          ldap_delete_account($ldap_connection, $account_identifier);
          $errors[] = 'Invite audit write failed. The account was rolled back to preserve audit integrity.';
          $audit_event_id = null;
        }

        if (!empty($errors)) {
          // No-op: keep errors for rendering and skip email notification.
        } else {
          include_once 'mail_functions.inc.php';

          $mail_body = parse_mail_text($new_account_mail_body, $generated_password, $account_identifier, $form_givenname, $form_sn);
          $mail_subject = parse_mail_text($new_account_mail_subject, $generated_password, $account_identifier, $form_givenname, $form_sn);
          $sent_email = send_email($form_mail, trim($form_givenname . ' ' . $form_sn), $mail_subject, $mail_body);

          if (!$sent_email) {
            foreach ($final_groups as $group_name) {
              ldap_delete_member_from_group($ldap_connection, $group_name, $account_identifier);
            }
            ldap_delete_account($ldap_connection, $account_identifier);
            if (is_string($audit_event_id) && $audit_event_id !== '' && !invite_delete_event($audit_event_id)) {
              $warnings[] = 'Invite rollback succeeded, but removing the temporary audit event failed.';
            }
            $errors[] = 'Invite email could not be sent. The account was rolled back so no undisclosed credentials remain.';
          } else {
            if (function_exists('apprise_notify_user_created')) {
              $post_groups = ldap_user_group_membership($ldap_connection, $account_identifier);
              apprise_notify_user_created($account_identifier, $inviter_uid, $form_mail, $post_groups);
            }

            $success_message = 'Invite sent and account created successfully.';
            $form_uid = '';
            $form_mail = '';
            $form_givenname = '';
            $form_sn = '';
          }
        }
      }
    }
  }
}

$normalized_roots = [];
$root_candidates = ldap_get_group_members($ldap_connection, 'root');
foreach ((array)$root_candidates as $root_candidate) {
  $root_candidate = trim((string)$root_candidate);
  if ($root_candidate !== '') {
    $normalized_roots[strtolower($root_candidate)] = $root_candidate;
  }
}

$single_root_uid = '';
if (count($normalized_roots) === 1) {
  $single_root_uid = (string)array_values($normalized_roots)[0];
}
if ($current_inviter_uid !== '' && $single_root_uid !== '' && strcasecmp($single_root_uid, $current_inviter_uid) === 0) {
  $root_self_events = invite_list_for_inviter($current_inviter_uid, 500, ['auto_root']);
  foreach ($root_self_events as $root_self_event) {
    $event_id = trim((string)($root_self_event['event_id'] ?? ''));
    $event_inviter_uid = trim((string)($root_self_event['inviter_uid'] ?? ''));
    $event_invitee_uid = trim((string)($root_self_event['invitee_uid'] ?? ''));
    if (
      $event_id !== ''
      && strcasecmp($event_inviter_uid, $current_inviter_uid) === 0
      && strcasecmp($event_invitee_uid, $current_inviter_uid) === 0
    ) {
      if (!invite_delete_event($event_id)) {
        $warnings[] = 'Failed to remove stale root self-lineage audit entry.';
      }
    }
  }
}

if (!empty($IS_ADMIN)) {
  $lineage_topology = invite_build_lineage_topology((array)$all_users, array_values($normalized_roots));
}

$invite_history = invite_list_for_inviter($current_inviter_uid, 200, ['invite', 'auto_root']);
$invite_history = array_values(array_filter(
  $invite_history,
  static function (array $invite_event) use ($active_invitee_uids): bool {
    $invitee_uid = strtolower(trim((string)($invite_event['invitee_uid'] ?? '')));
    return $invitee_uid !== '' && isset($active_invitee_uids[$invitee_uid]);
  },
));

if (is_resource($ldap_connection) || is_object($ldap_connection)) {
  @ldap_close($ldap_connection);
}

?>

<div class="container wrap-narrow">
  <div class="card panel-modern">
    <div class="panel-heading text-center">Invite</div>
    <div class="card-body">

      <?php if (!$EMAIL_SENDING_ENABLED) { ?>
      <div class="alert alert-warning">
        <p class="text-center">SMTP is not configured. Invites are disabled until email delivery is enabled.</p>
      </div>
      <?php } ?>

      <?php if (!empty($errors)) { ?>
      <div class="alert alert-warning">
        <p class="text-center">Invite could not be created:</p>
        <ul>
          <?php foreach ($errors as $error) {
            echo '<li>' . htmlspecialchars((string)$error, ENT_QUOTES, 'UTF-8') . "</li>\n";
          } ?>
        </ul>
      </div>
      <?php } ?>

      <?php if ($success_message !== '') { ?>
      <div class="alert alert-success">
        <p class="text-center"><?php echo htmlspecialchars($success_message, ENT_QUOTES, 'UTF-8'); ?></p>
      </div>
      <?php } ?>

      <?php if (!empty($warnings)) { ?>
      <div class="alert alert-warning">
        <ul>
          <?php foreach ($warnings as $warning) {
            echo '<li>' . htmlspecialchars((string)$warning, ENT_QUOTES, 'UTF-8') . "</li>\n";
          } ?>
        </ul>
      </div>
      <?php } ?>

      <form class="form-horizontal" action="" method="post" autocomplete="off">
        <input type="hidden" name="create_invite" value="1">
        <?php echo csrf_token_field(); ?>

        <div class="form-group" id="uid_div">
          <label for="uid" class="col-sm-3 control-label"><strong>Username</strong><sup>&ast;</sup></label>
          <div class="col-sm-6">
            <input type="text" class="form-control" id="uid" name="uid" value="<?php echo htmlspecialchars($form_uid, ENT_QUOTES, 'UTF-8'); ?>" required>
            <div class="help-min" style="margin-top:6px;">Used as login and to auto-fill first name, last name initial, and display name.</div>
          </div>
        </div>

        <div class="form-group" id="mail_div">
          <label for="mail" class="col-sm-3 control-label"><strong>Email</strong><sup>&ast;</sup></label>
          <div class="col-sm-6">
            <input type="email" class="form-control" id="mail" name="mail" value="<?php echo htmlspecialchars($form_mail, ENT_QUOTES, 'UTF-8'); ?>" required>
            <div class="help-min" style="margin-top:6px;">Invite credentials are sent only to this address.</div>
          </div>
        </div>

        <div class="form-group text-center">
          <button type="submit" class="btn btn-primary btn-pill" <?php echo !$EMAIL_SENDING_ENABLED ? 'disabled' : ''; ?>>Send Invite</button>
        </div>
      </form>

      <div class="help-min text-center" style="margin-top:6px;">
        <sup>&ast;</sup>Required fields. Passwords are generated only on submit and never shown to the inviter.
      </div>
    </div>
  </div>
</div>

<div class="container wrap-narrow">
  <div class="card panel-modern">
    <div class="panel-heading text-center">Previously Invited By You</div>
    <div class="card-body">
      <?php if (empty($invite_history)) { ?>
      <div class="alert alert-info" style="margin:0;">
        <p class="text-center">No invite records found for your account.</p>
      </div>
      <?php } else { ?>
      <div class="table-responsive">
        <table class="table table-dark table-striped table-modern">
          <thead>
            <tr>
              <th>Username</th>
              <th>Email</th>
              <th>Type</th>
              <th>Profile</th>
              <th>Invited At</th>
            </tr>
          </thead>
          <tbody>
            <?php foreach ($invite_history as $invite_event) {
              $invitee_uid = (string)($invite_event['invitee_uid'] ?? '');
              $invitee_email = (string)($invite_event['invitee_email'] ?? '');
              $event_type = strtolower(trim((string)($invite_event['event_type'] ?? 'invite')));
              $event_label = ($event_type === 'auto_root') ? 'Auto-root link' : 'Invite';
              $invite_profile = (string)($invite_event['role_name'] ?? '');
              $created_ts = (int)($invite_event['created_ts'] ?? 0);
              ?>
            <tr>
              <td><code><?php echo htmlspecialchars($invitee_uid, ENT_QUOTES, 'UTF-8'); ?></code></td>
              <td><?php echo htmlspecialchars($invitee_email, ENT_QUOTES, 'UTF-8'); ?></td>
              <td><?php echo htmlspecialchars($event_label, ENT_QUOTES, 'UTF-8'); ?></td>
              <td><?php echo htmlspecialchars($invite_profile === '' ? 'n/a' : $invite_profile, ENT_QUOTES, 'UTF-8'); ?></td>
              <td><?php echo invite_format_event_time($created_ts); ?></td>
            </tr>
            <?php } ?>
          </tbody>
        </table>
      </div>
      <?php } ?>
    </div>
  </div>
</div>

<?php if (!empty($IS_ADMIN)) { ?>
<div class="container">
  <div class="card panel-modern">
    <div class="panel-heading text-center">User Lineage Topology</div>
    <div class="card-body">
      <?php if (empty($lineage_topology['nodes'])) { ?>
      <div class="alert alert-info" style="margin:0;">
        <p class="text-center">No lineage topology data is available yet.</p>
      </div>
      <?php } else { ?>
      <div class="help-min text-center" style="margin-bottom:10px;">
        <?php if (!empty($lineage_topology['root_uid'])) { ?>
          Root: <code><?php echo htmlspecialchars((string)$lineage_topology['root_uid'], ENT_QUOTES, 'UTF-8'); ?></code>
        <?php } else { ?>
          Root: not uniquely defined in LDAP group <code>root</code>
        <?php } ?>
        | visible: <?php echo (int)($lineage_topology['visible_count'] ?? 0); ?>
        | active users: <?php echo (int)($lineage_topology['total_active'] ?? 0); ?>
      </div>

      <div class="lineage-topology-wrap">
        <div class="lineage-topology-canvas" id="lineage_topology_canvas"></div>
      </div>

      <?php
      $unlinked_labels = (array)($lineage_topology['unlinked_labels'] ?? []);
        if (!empty($unlinked_labels)) {
          $preview = array_slice($unlinked_labels, 0, 20);
          ?>
      <div class="help-min text-center" style="margin-top:10px;">
        Unlinked from root: <?php echo (int)count($unlinked_labels); ?>
        (<?php echo htmlspecialchars(implode(', ', $preview), ENT_QUOTES, 'UTF-8'); ?><?php echo count($unlinked_labels) > count($preview) ? ', ...' : ''; ?>)
      </div>
      <?php } ?>

      <style>
        .lineage-topology-wrap {
          width: 100%;
          overflow-x: auto;
          border: 1px solid var(--border-primary);
          border-radius: 14px;
          background:
            linear-gradient(135deg, var(--gradient-header) 0%, var(--gradient-end) 100%),
            var(--bg-secondary);
          box-shadow:
            inset 0 1px 0 var(--gradient-header),
            0 0 16px var(--shadow-glow);
          padding: 12px;
        }
        .lineage-topology-canvas {
          position: relative;
          min-height: 220px;
          min-width: 820px;
        }
        .lineage-topology-canvas svg {
          position: absolute;
          inset: 0;
          width: 100%;
          height: 100%;
          pointer-events: none;
        }
        .lineage-edge-group {
          stroke: var(--border-hover);
          stroke-width: 2;
          fill: none;
        }
        .lineage-node {
          position: absolute;
          width: 168px;
          height: 48px;
          border-radius: 10px;
          border: 1px solid var(--border-primary);
          background:
            linear-gradient(135deg, var(--gradient-header) 0%, var(--gradient-end) 100%),
            var(--bg-tertiary);
          display: flex;
          align-items: center;
          justify-content: center;
          color: var(--text-primary);
          font-size: 13px;
          line-height: 1.2;
          text-align: center;
          padding: 6px 8px;
          box-shadow:
            0 6px 16px rgba(0, 0, 0, 0.35),
            0 0 10px var(--shadow-glow);
        }
        .lineage-node.root {
          border-color: var(--accent);
          box-shadow:
            0 0 0 1px var(--border-hover),
            0 0 18px var(--shadow-glow),
            0 10px 22px rgba(0, 0, 0, 0.35);
          background:
            linear-gradient(135deg, var(--gradient-header) 0%, var(--gradient-end) 100%),
            var(--bg-secondary);
        }
      </style>

      <script>
      (function renderLineageTopology() {
        var topology = <?php echo json_encode($lineage_topology, JSON_UNESCAPED_SLASHES); ?>;
        var canvas = document.getElementById('lineage_topology_canvas');
        if (!canvas || !topology || !Array.isArray(topology.nodes) || topology.nodes.length === 0) {
          return;
        }

        var byId = {};
        topology.nodes.forEach(function(node) {
          byId[node.id] = node;
        });

        var depthMemo = {};
        var depthStack = {};
        function depthOf(nodeId) {
          if (depthMemo[nodeId] !== undefined) {
            return depthMemo[nodeId];
          }
          if (depthStack[nodeId]) {
            return 0;
          }
          depthStack[nodeId] = true;
          var node = byId[nodeId];
          var parentId = (node && node.parent) ? node.parent : null;
          var depth = 0;
          if (parentId && byId[parentId]) {
            depth = depthOf(parentId) + 1;
          }
          depthMemo[nodeId] = depth;
          depthStack[nodeId] = false;
          return depth;
        }

        var levels = {};
        var maxDepth = 0;
        topology.nodes.forEach(function(node) {
          var depth = depthOf(node.id);
          if (!levels[depth]) {
            levels[depth] = [];
          }
          levels[depth].push(node);
          if (depth > maxDepth) {
            maxDepth = depth;
          }
        });

        Object.keys(levels).forEach(function(depthKey) {
          levels[depthKey].sort(function(a, b) {
            return String(a.label || '').localeCompare(String(b.label || ''));
          });
        });

        var nodeW = 168;
        var nodeH = 48;
        var hGap = 44;
        var vGap = 86;
        var padX = 26;
        var padY = 26;
        var maxCols = 1;
        for (var d = 0; d <= maxDepth; d++) {
          var cols = (levels[d] || []).length;
          if (cols > maxCols) {
            maxCols = cols;
          }
        }

        var width = Math.max(860, (padX * 2) + (maxCols * nodeW) + (Math.max(0, maxCols - 1) * hGap));
        var height = Math.max(220, (padY * 2) + ((maxDepth + 1) * nodeH) + (Math.max(0, maxDepth) * vGap));

        canvas.innerHTML = '';
        canvas.style.width = width + 'px';
        canvas.style.height = height + 'px';

        var svgNS = 'http://www.w3.org/2000/svg';
        var edgeSvg = document.createElementNS(svgNS, 'svg');
        edgeSvg.setAttribute('viewBox', '0 0 ' + width + ' ' + height);
        edgeSvg.setAttribute('preserveAspectRatio', 'xMidYMid meet');

        var edgeGroup = document.createElementNS(svgNS, 'g');
        edgeGroup.setAttribute('class', 'lineage-edge-group');
        edgeSvg.appendChild(edgeGroup);
        canvas.appendChild(edgeSvg);

        var positions = {};
        topology.nodes.forEach(function(node) {
          var nodeDepth = depthOf(node.id);
          var row = levels[nodeDepth] || [];
          var nodeIndex = row.findIndex(function(rowNode) {
            return rowNode.id === node.id;
          });
          var rowWidth = (row.length * nodeW) + (Math.max(0, row.length - 1) * hGap);
          var startX = (width - rowWidth) / 2;
          var left = startX + (nodeIndex * (nodeW + hGap));
          var top = padY + (nodeDepth * (nodeH + vGap));

          positions[node.id] = {
            cx: left + (nodeW / 2),
            cy: top + (nodeH / 2),
            top: top,
            left: left,
          };

          var nodeDiv = document.createElement('div');
          nodeDiv.className = 'lineage-node' + (node.is_root ? ' root' : '');
          nodeDiv.style.left = left + 'px';
          nodeDiv.style.top = top + 'px';
          nodeDiv.textContent = String(node.label || node.id);
          canvas.appendChild(nodeDiv);
        });

        topology.nodes.forEach(function(node) {
          if (!node.parent || !positions[node.id] || !positions[node.parent]) {
            return;
          }
          var from = positions[node.parent];
          var to = positions[node.id];
          var line = document.createElementNS(svgNS, 'path');
          var midY = Math.round((from.cy + to.cy) / 2);
          var d = 'M ' + Math.round(from.cx) + ' ' + Math.round(from.top + nodeH)
                + ' L ' + Math.round(from.cx) + ' ' + midY
                + ' L ' + Math.round(to.cx) + ' ' + midY
                + ' L ' + Math.round(to.cx) + ' ' + Math.round(to.top);
          line.setAttribute('d', d);
          edgeGroup.appendChild(line);
        });
      })();
      </script>
      <?php } ?>
    </div>
  </div>
</div>
<?php } ?>

<?php render_footer(); ?>
