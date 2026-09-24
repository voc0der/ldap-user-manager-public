<?php
// www/account_manager/index.php  (modernized styling with TOTAL in header)

set_include_path('.:' . __DIR__ . '/../includes/');

include_once 'web_functions.inc.php';
include_once 'ldap_functions.inc.php';
include_once 'module_functions.inc.php';
include_once 'apprise_helpers.inc.php'; // ⬅️ NEW
include_once 'role_functions.inc.php';

set_page_access('admin');

render_header("$ORGANISATION_NAME account manager", true, 'page-animated-bg');
render_submenu();

$ldap_connection = open_ldap_connection();

if (isset($_POST['delete_user'])) {
  // CSRF Protection
  if (!validate_csrf_token($_POST['csrf_token'] ?? '')) {
    die('CSRF token validation failed. Please refresh the page and try again.');
  }

  // Use raw UID for LDAP operations; keep a separate HTML-escaped copy for UI
  $raw_uid   = urldecode($_POST['delete_user']);
  $safe_uid  = htmlspecialchars($raw_uid, ENT_QUOTES, 'UTF-8');

  // Capture current groups BEFORE deletion (for the Apprise message)
  $pre_groups = ldap_user_group_membership($ldap_connection, $raw_uid);

  // Identify the admin performing the delete
  $admin_uid = $GLOBALS['USER_ID'] ?? ($_SESSION['user_id'] ?? 'unknown');

  // Perform delete using the raw UID
  $del_user = ldap_delete_account($ldap_connection, $raw_uid);

  if ($del_user) {
    // Fire Apprise in your established style
    apprise_notify_user_deleted($raw_uid, $admin_uid, $pre_groups);

    render_alert_banner("User <strong>$safe_uid</strong> was deleted.");
  } else {
    render_alert_banner("User <strong>$safe_uid</strong> wasn't deleted.  See the logs for more information.", 'danger', 15000);
  }
}

$people = ldap_get_user_list($ldap_connection);
$totalUsers = count($people);

// Load Authelia last-login data.
// Use AUTHELIA_DIR when provided, then fall back to local data path.
$authelia_dir = getenv('AUTHELIA_DIR') ?: (realpath(__DIR__ . '/../data/authelia') ?: (__DIR__ . '/../data/authelia'));
$lastlogin_file = rtrim((string)$authelia_dir, '/\\') . '/lastlogin.json';
$lastlogin_data = [];
$lastlogin_data_ci = [];
if (is_readable($lastlogin_file)) {
  $json_content = @file_get_contents($lastlogin_file);
  if ($json_content !== false) {
    $decoded = json_decode($json_content, true);
    if (is_array($decoded)) {
      $payload = (isset($decoded['users']) && is_array($decoded['users'])) ? $decoded['users'] : $decoded;
      if (is_array($payload)) {
        $lastlogin_data = $payload;
        foreach ($payload as $uid => $stamp) {
          if (is_string($uid)) {
            $lastlogin_data_ci[strtolower($uid)] = $stamp;
          }
        }
      }
    }
  }
}

// Helper function to format last login date
function format_lastlogin($datetime_str)
{
  if (empty($datetime_str)) {
    return '<span style="color:#666;">Never</span>';
  }
  try {
    $dt = new DateTime($datetime_str);
    $now = new DateTime();
    // Format as "2025-11-14 00:16" with relative time
    $formatted = $dt->format('Y-m-d H:i');
    $day_delta = (int)$now->setTime(0, 0)->diff($dt->setTime(0, 0))->format('%r%a');
    $fmt_relative = static function (int $count, string $unit, bool $future): string {
      $label = $count . ' ' . $unit . ($count === 1 ? '' : 's');
      return $future ? ('in ' . $label) : ($label . ' ago');
    };

    // Add relative time hint
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

    return '<span title="' . htmlspecialchars($datetime_str, ENT_QUOTES, 'UTF-8') . '">' .
           htmlspecialchars($formatted, ENT_QUOTES, 'UTF-8') .
           '<br><small style="color:#888;">' . htmlspecialchars($relative, ENT_QUOTES, 'UTF-8') . '</small></span>';
  } catch (Exception $e) {
    return '<span style="color:#999;" title="' . htmlspecialchars($datetime_str, ENT_QUOTES, 'UTF-8') . '">Invalid date</span>';
  }
}
?>

<div class="container wrap-narrow">
  <div class="card panel-modern">
    <div class="panel-heading">
      <div class="panel-headline">
        <h3 class="card-title">Users</h3>
        <span class="header-total">Total: <?php echo number_format($totalUsers); ?></span>
      </div>
    </div>

    <div class="card-body">
      <div class="panel-toolbar">
        <div class="panel-toolbar-search">
          <div class="input-group">
            <span class="input-group-addon glyphicon glyphicon-search"></span>
            <input class="form-control" id="search_input" type="text" placeholder="Search users, names, email, groups…">
          </div>
          <div class="help-min">Type to filter the table below.</div>
        </div>
        <div class="panel-toolbar-actions">
          <form action="<?php print $THIS_MODULE_PATH; ?>/new_user.php" method="post">
            <button id="add_group" class="btn btn-primary btn-pill" type="submit">New user</button>
          </form>
        </div>
      </div>

      <div class="table-responsive">
        <table class="table table-dark table-striped table-modern">
          <thead>
            <tr>
              <th>Username</th>
              <th>First name</th>
              <th>Last name</th>
              <th>Email</th>
              <th>Last Login</th>
              <th>Role</th>
            </tr>
          </thead>
          <tbody id="userlist">
<?php
foreach ($people as $account_identifier => $attribs) {
  $group_membership = ldap_user_group_membership($ldap_connection, $account_identifier);
  $this_mail = isset($people[$account_identifier]['mail']) ? $people[$account_identifier]['mail'] : '';
  // Escape all LDAP data for HTML output to prevent XSS
  $safe_account = htmlspecialchars($account_identifier, ENT_QUOTES, 'UTF-8');
  $safe_given = htmlspecialchars($people[$account_identifier]['givenname'] ?? '', ENT_QUOTES, 'UTF-8');
  $safe_sn = htmlspecialchars($people[$account_identifier]['sn'] ?? '', ENT_QUOTES, 'UTF-8');
  $safe_mail = htmlspecialchars($this_mail, ENT_QUOTES, 'UTF-8');
  $safe_groups = htmlspecialchars(implode(', ', $group_membership), ENT_QUOTES, 'UTF-8');
  // Get last login for this user
  $lastlogin_datetime = $lastlogin_data[$account_identifier] ?? ($lastlogin_data_ci[strtolower($account_identifier)] ?? '');
  $lastlogin_formatted = format_lastlogin($lastlogin_datetime);
  // Get role/group display (merged)
  $member_display = roles_format_user_display($group_membership);
  // Avatar URL
  $avatar_url = "{$THIS_MODULE_PATH}/show_user.php?avatar=1&account_identifier=" . urlencode($account_identifier) . '&t=' . time();
  $user_url = "{$THIS_MODULE_PATH}/show_user.php?account_identifier=" . urlencode($account_identifier);
  $message_url = $SERVER_PATH . 'messages/index.php?compose=1&to_uid=' . urlencode($account_identifier);
  $safe_message_url = htmlspecialchars($message_url, ENT_QUOTES, 'UTF-8');
  $mail_cell = $safe_mail !== ''
    ? "<a class='account-email-link' href='$safe_message_url' title='Message $safe_account'><code>$safe_mail</code></a>"
    : $safe_mail;
  print "  <tr>\n";
  print "    <td><a class='user-account-link' href='$user_url'><span class='user-avatar-wrap'><img src='$avatar_url' alt='' class='user-avatar' onerror='this.classList.add(\"is-hidden\");this.nextElementSibling.classList.add(\"is-visible\");'><span class='user-avatar-fallback' aria-hidden='true'>N/A</span></span><span class='user-account-text'>$safe_account</span></a></td>\n";
  print "    <td>$safe_given</td>\n";
  print "    <td>$safe_sn</td>\n";
  print "    <td>$mail_cell</td>\n";
  print "    <td>$lastlogin_formatted</td>\n";
  print "    <td>$member_display</td>\n";
  print "  </tr>\n";
}
?>
          </tbody>
        </table>
      </div>
    </div>
  </div>
</div>

<script>
// simple client-side filter (keeps your original IDs)
lumUI.ready(function(){
  lumUI.bindRowFilter('#search_input', '#userlist tr');
});

// Inject CSS for role popup and user avatars
if (!document.getElementById('role-popup-styles')) {
  const style = document.createElement('style');
  style.id = 'role-popup-styles';
  style.textContent = `
    .user-account-link {
      display: inline-flex;
      align-items: center;
      gap: 0.55rem;
      color: var(--accent);
      text-decoration: none;
    }
    .user-account-link::after {
      display: none !important;
    }
    .user-account-link:hover {
      color: var(--text-primary) !important;
    }
    .user-account-text {
      line-height: 1.2;
    }
    .account-email-link::after {
      display: none !important;
    }
    .user-avatar-wrap {
      width: 32px;
      height: 32px;
      min-width: 32px;
      position: relative;
      display: inline-flex;
      align-items: center;
      justify-content: center;
      border-radius: 4px;
      overflow: hidden;
    }
    .user-avatar {
      width: 100%;
      height: 100%;
      border-radius: 4px;
      object-fit: cover;
      border: 1px solid var(--border-primary, rgba(255,255,255,0.18));
      display: block;
      background: var(--bg-tertiary, #10161f);
    }
    .user-avatar.is-hidden {
      display: none;
    }
    .user-avatar-fallback {
      position: absolute;
      inset: 0;
      display: none;
      align-items: center;
      justify-content: center;
      border-radius: 4px;
      border: 1px dashed var(--border-primary, rgba(255,255,255,0.24));
      background: rgba(255,255,255,0.03);
      color: var(--text-muted, #9aa9b8);
      font-size: 9px;
      font-weight: 700;
      letter-spacing: 0.06em;
      text-transform: uppercase;
    }
    .user-avatar-fallback.is-visible {
      display: flex;
    }
    #lum-role-popup {
      position: fixed;
      z-index: 99999;
      min-width: 280px;
      max-width: 520px;
      background: linear-gradient(
        135deg,
        var(--gradient-header, rgba(127,209,255,0.16)) 0%,
        var(--gradient-end, rgba(18,24,32,0.96)) 100%
      ), var(--bg-tertiary, #121820);
      backdrop-filter: blur(2px);
      border: 1px solid var(--border-hover, rgba(127,209,255,0.35));
      box-shadow: 0 0 24px var(--shadow-glow, rgba(42,139,220,0.35)), inset 0 0 20px rgba(255,255,255,0.04);
      border-radius: 14px;
      padding: 10px 12px 12px 12px;
      color: var(--text-primary, #cfe9ff);
      font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
      display: none;
    }
    #lum-role-popup.visible {
      display: block;
    }
    #lum-role-popup .popup-header {
      display: flex;
      justify-content: space-between;
      align-items: center;
      margin-bottom: 10px;
      padding-bottom: 8px;
      border-bottom: 1px solid var(--border-primary, rgba(127,209,255,0.2));
    }
    #lum-role-popup .popup-title {
      font-size: 15px;
      font-weight: 600;
      letter-spacing: 0.3px;
      color: var(--accent, #7fd1ff);
    }
    #lum-role-popup .popup-close {
      background: transparent;
      border: 1px solid var(--border-primary, rgba(127,209,255,0.3));
      color: var(--accent, #7fd1ff);
      cursor: pointer;
      border-radius: 4px;
      width: 24px;
      height: 24px;
      font-size: 16px;
      line-height: 1;
      padding: 0;
      transition: all 0.2s;
    }
    #lum-role-popup .popup-close:hover {
      background: var(--gradient-header, rgba(127,209,255,0.1));
      border-color: var(--accent, #7fd1ff);
    }
    #lum-role-popup .popup-groups {
      display: flex;
      flex-wrap: wrap;
      gap: 6px;
      margin-top: 8px;
    }
    #lum-role-popup .group-chip {
      background: var(--gradient-header, rgba(127,209,255,0.12));
      border: 1px solid var(--border-primary, rgba(127,209,255,0.25));
      border-radius: 12px;
      padding: 4px 10px;
      font-size: 12px;
      color: var(--text-primary, #cfe9ff);
      white-space: nowrap;
      transition: all 0.2s;
    }
    #lum-role-popup .group-chip:hover {
      background: var(--nav-active-bg, rgba(127,209,255,0.2));
      border-color: var(--border-hover, rgba(127,209,255,0.4));
    }
    #lum-role-popup-overlay {
      position: fixed;
      top: 0;
      left: 0;
      right: 0;
      bottom: 0;
      z-index: 99998;
      display: none;
    }
    #lum-role-popup-overlay.visible {
      display: block;
    }
  `;
  document.head.appendChild(style);
}

// Popup modal for showing role groups
var rolePopupKeyHandler = null;

function removeRolePopup() {
  document.querySelectorAll('#lum-role-popup, #lum-role-popup-overlay').forEach(function(el) {
    el.remove();
  });
}

function showRolePopup(element) {
  var roleName = element.getAttribute('data-role-name') || '';
  var roleGroups = element.getAttribute('data-role-groups') || '';
  var groupsArray = roleGroups.split(', ');

  // Remove existing popup if any
  removeRolePopup();
  if (rolePopupKeyHandler) {
    document.removeEventListener('keydown', rolePopupKeyHandler);
  }

  // Create overlay
  var overlay = document.createElement('div');
  overlay.id = 'lum-role-popup-overlay';
  overlay.className = 'visible';

  // Create popup
  var popup = document.createElement('div');
  popup.id = 'lum-role-popup';

  // Header
  var header = document.createElement('div');
  header.className = 'popup-header';
  var title = document.createElement('div');
  title.className = 'popup-title';
  title.textContent = 'Role: ' + roleName;
  var closeButton = document.createElement('button');
  closeButton.className = 'popup-close';
  closeButton.title = 'Close';
  closeButton.textContent = '×';
  header.appendChild(title);
  header.appendChild(closeButton);
  popup.appendChild(header);

  // Groups container
  var groupsContainer = document.createElement('div');
  groupsContainer.className = 'popup-groups';
  groupsArray.forEach(function(group) {
    var chip = document.createElement('div');
    chip.className = 'group-chip';
    chip.textContent = group.trim();
    groupsContainer.appendChild(chip);
  });
  popup.appendChild(groupsContainer);

  // Add to page
  document.body.appendChild(overlay);
  document.body.appendChild(popup);

  // Position popup near the clicked element
  var rect = element.getBoundingClientRect();
  var popupWidth = 320;
  var left = rect.left + (rect.width / 2) - (popupWidth / 2);
  var top = rect.bottom + 10;

  // Adjust if off-screen
  if (left + popupWidth > window.innerWidth - 20) {
    left = window.innerWidth - popupWidth - 20;
  }
  if (left < 20) {
    left = 20;
  }
  if (top + 200 > window.innerHeight) {
    top = rect.top - 200 - 10;
  }

  popup.style.left = left + 'px';
  popup.style.top = top + 'px';

  // Show popup
  setTimeout(function() {
    popup.classList.add('visible');
  }, 10);

  // Close handlers
  overlay.addEventListener('click', closeRolePopup);
  closeButton.addEventListener('click', closeRolePopup);
  rolePopupKeyHandler = function(e) {
    if (e.key === 'Escape') closeRolePopup();
  };
  document.addEventListener('keydown', rolePopupKeyHandler);
}

function closeRolePopup() {
  var popup = document.getElementById('lum-role-popup');
  if (popup) {
    popup.classList.remove('visible');
  }
  setTimeout(removeRolePopup, 200);
  if (rolePopupKeyHandler) {
    document.removeEventListener('keydown', rolePopupKeyHandler);
    rolePopupKeyHandler = null;
  }
}
</script>

<?php
ldap_close($ldap_connection);
render_footer();
?>
