<?php
declare(strict_types=1);

set_include_path('.:' . __DIR__ . '/../includes/');

require_once 'web_functions.inc.php';
require_once 'ldap_functions.inc.php';
require_once 'messages_functions.inc.php';

@session_start();
set_page_access('auth');

header('Content-Type: application/json');

function messages_api_out(array $payload, int $status = 200): void
{
  http_response_code($status);
  echo json_encode($payload, JSON_UNESCAPED_SLASHES);
  exit;
}

function messages_api_clean_box(string $value): string
{
  $value = strtolower(trim($value));
  return $value === 'outbox' ? 'outbox' : 'inbox';
}

function messages_api_clean_id(string $value): string
{
  $value = trim($value);
  if ($value === '') {
    return '';
  }
  return preg_match('/^[A-Za-z0-9._:-]{1,80}$/', $value) ? $value : '';
}

function messages_api_user_directory(): array
{
  global $LDAP;

  $connection = null;
  try {
    $connection = open_ldap_connection();
  } catch (\Throwable $e) {
    $connection = null;
  }

  if (!$connection) {
    return ['ok' => false, 'error' => 'Unable to open LDAP connection to resolve users.'];
  }

  $account_attr = (string)($LDAP['account_attribute'] ?? 'uid');
  $fields = array_unique([$account_attr, 'givenname', 'sn', 'displayname', 'mail']);
  $people = ldap_get_user_list($connection, 0, null, 'asc', $account_attr, '', $fields);
  $admins_group = trim((string)($LDAP['admins_group'] ?? ''));
  $admins = [];
  if ($admins_group !== '' && function_exists('ldap_get_group_members')) {
    $admins = (array)ldap_get_group_members($connection, $admins_group, 0, null, 'asc');
  }

  if (is_resource($connection) || is_object($connection)) {
    @ldap_close($connection);
  }

  $admin_lookup = [];
  foreach ($admins as $admin_uid) {
    $admin_key = messages_normalize_uid_key((string)$admin_uid);
    if ($admin_key !== '') {
      $admin_lookup[$admin_key] = true;
    }
  }

  $users = [];
  $map = [];
  foreach ((array)$people as $uid => $attribs) {
    $uid = trim((string)$uid);
    if ($uid === '') {
      continue;
    }

    $given = trim((string)($attribs['givenname'] ?? ''));
    $sn = trim((string)($attribs['sn'] ?? ''));
    $display = trim((string)($attribs['displayname'] ?? ''));
    if ($display === '') {
      $display = trim($given . ' ' . $sn);
    }
    if ($display === '') {
      $display = $uid;
    }

    $mail = trim((string)($attribs['mail'] ?? ''));
    $row = [
      'uid' => $uid,
      'display' => $display,
      'mail' => $mail,
      'is_admin' => !empty($admin_lookup[messages_normalize_uid_key($uid)]),
    ];
    $users[] = $row;
    $map[messages_normalize_uid_key($uid)] = $row;
  }

  usort($users, static function (array $a, array $b): int {
    return strnatcasecmp((string)$a['uid'], (string)$b['uid']);
  });

  return ['ok' => true, 'users' => $users, 'map' => $map];
}

function messages_api_row(array $message, string $box, bool $is_admin): array
{
  $created_ts = (int)($message['created_ts'] ?? 0);
  $read_ts = (int)($message['read_ts'] ?? 0);
  return [
    'id' => (string)($message['id'] ?? ''),
    'from_uid' => (string)($message['from_uid'] ?? ''),
    'from_display' => (string)($message['from_display'] ?? ''),
    'to_uid' => (string)($message['to_uid'] ?? ''),
    'to_display' => (string)($message['to_display'] ?? ''),
    'preview' => messages_make_preview((string)($message['body'] ?? ''), 120),
    'created_ts' => $created_ts,
    'created_at' => ($created_ts > 0 ? gmdate('c', $created_ts) : ''),
    'is_unread' => ($read_ts <= 0),
    'read_ts' => $read_ts,
    'read_at' => ($read_ts > 0 ? gmdate('c', $read_ts) : ''),
    'read_visible' => ($box === 'inbox' || ($box === 'outbox' && $is_admin)),
    'can_delete' => ($box === 'inbox' || ($box === 'outbox' && $is_admin)),
  ];
}

function messages_api_message_view(array $message, string $box, bool $is_admin): array
{
  $base = messages_api_row($message, $box, $is_admin);
  $base['body'] = (string)($message['body'] ?? '');
  $base['from_email'] = (string)($message['from_email'] ?? '');
  $base['to_email'] = (string)($message['to_email'] ?? '');
  return $base;
}

function messages_api_send_email_notification(array $message): array
{
  global $EMAIL_SENDING_ENABLED, $SMTP, $new_message_mail_subject, $new_message_mail_body;

  $recipient_email = trim((string)($message['to_email'] ?? ''));
  if ($recipient_email === '') {
    return ['attempted' => false, 'sent' => false, 'error' => 'Recipient has no email address in LDAP.'];
  }

  $smtp_host = trim((string)($SMTP['host'] ?? ''));
  if (empty($EMAIL_SENDING_ENABLED) || $smtp_host === '') {
    return ['attempted' => false, 'sent' => false, 'error' => 'SMTP is not configured.'];
  }

  include_once 'mail_functions.inc.php';

  $subject_template = (string)($new_message_mail_subject ?? 'You have a new message on {organisation}.');
  $body_template = (string)($new_message_mail_body ?? '');
  if ($body_template === '') {
    $body_template = 'You have a new message from {sender_uid} on {organisation}.<p>{message_html}</p><p>Open {messages_url}</p>';
  }

  if (function_exists('parse_new_message_mail_text')) {
    $subject = parse_new_message_mail_text($subject_template, [
      'sender_uid' => (string)($message['from_uid'] ?? ''),
      'recipient_uid' => (string)($message['to_uid'] ?? ''),
      'message' => (string)($message['body'] ?? ''),
    ]);
    $body = parse_new_message_mail_text($body_template, [
      'sender_uid' => (string)($message['from_uid'] ?? ''),
      'recipient_uid' => (string)($message['to_uid'] ?? ''),
      'message' => (string)($message['body'] ?? ''),
    ]);
  } else {
    $subject = $subject_template;
    $body = $body_template;
  }

  $recipient_name = (string)($message['to_display'] ?? $message['to_uid'] ?? '');
  $sent = send_email($recipient_email, $recipient_name, $subject, $body);
  if ($sent) {
    return ['attempted' => true, 'sent' => true, 'error' => ''];
  }

  return ['attempted' => true, 'sent' => false, 'error' => 'send_email failed'];
}

$current_uid = trim((string)($GLOBALS['USER_ID'] ?? ($_SESSION['user_id'] ?? '')));
$is_admin = !empty($GLOBALS['IS_ADMIN']);

if ($current_uid === '') {
  messages_api_out(['ok' => false, 'error' => 'Unable to resolve authenticated user.'], 403);
}

$config_error = messages_configuration_error();
$setup_help = messages_setup_instructions();
$action = strtolower(trim((string)($_GET['action'] ?? $_POST['op'] ?? 'bootstrap')));

if ($action === 'bootstrap') {
  if ($config_error !== '') {
    messages_api_out([
      'ok' => true,
      'enabled' => false,
      'error' => $config_error,
      'setup' => $setup_help,
      'current_uid' => $current_uid,
      'is_admin' => $is_admin,
    ]);
  }

  $loaded = messages_load_store();
  if (empty($loaded['ok'])) {
    messages_api_out(['ok' => false, 'error' => $loaded['error'] ?? 'Unable to load message store.'], 500);
  }

  $directory = messages_api_user_directory();
  if (empty($directory['ok'])) {
    messages_api_out(['ok' => false, 'error' => $directory['error'] ?? 'Unable to load user directory.'], 500);
  }

  $users = (array)($directory['users'] ?? []);
  if (!$is_admin) {
    $users = array_values(array_filter($users, static function (array $row): bool {
      return !empty($row['is_admin']);
    }));
  }

  $counts = messages_counts_for_uid((array)($loaded['state'] ?? []), $current_uid);
  messages_api_out([
    'ok' => true,
    'enabled' => true,
    'current_uid' => $current_uid,
    'is_admin' => $is_admin,
    'users' => $users,
    'counts' => $counts,
    'max_body_length' => messages_max_body_length(),
  ]);
}

if ($config_error !== '') {
  messages_api_out([
    'ok' => false,
    'error' => $config_error,
    'setup' => $setup_help,
  ], 503);
}

if ($action === 'list') {
  $box = messages_api_clean_box((string)($_GET['box'] ?? 'inbox'));
  $loaded = messages_load_store();
  if (empty($loaded['ok'])) {
    messages_api_out(['ok' => false, 'error' => $loaded['error'] ?? 'Unable to load messages.'], 500);
  }

  $list = messages_list_for_user((array)($loaded['doc'] ?? []), $current_uid, $box);
  $rows = [];
  foreach ($list as $message) {
    $rows[] = messages_api_row((array)$message, $box, $is_admin);
  }

  messages_api_out([
    'ok' => true,
    'box' => $box,
    'messages' => $rows,
    'counts' => messages_counts_for_uid((array)($loaded['state'] ?? []), $current_uid),
  ]);
}

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
  messages_api_out(['ok' => false, 'error' => 'Method not allowed.'], 405);
}

csrf_verify_or_exit();

if ($action === 'view') {
  $box = messages_api_clean_box((string)($_POST['box'] ?? 'inbox'));
  $id = messages_api_clean_id((string)($_POST['id'] ?? ''));
  if ($id === '') {
    messages_api_out(['ok' => false, 'error' => 'Missing message id.'], 400);
  }

  $op = messages_with_locked_store(static function (array &$doc) use ($box, $id, $current_uid): array {
    $uid_key = messages_normalize_uid_key($current_uid);
    foreach ($doc['messages'] as &$message) {
      if (!is_array($message) || (string)($message['id'] ?? '') !== $id) {
        continue;
      }

      $to_key = messages_normalize_uid_key((string)($message['to_uid'] ?? ''));
      $from_key = messages_normalize_uid_key((string)($message['from_uid'] ?? ''));
      $sender_deleted_ts = (int)($message['sender_deleted_ts'] ?? 0);
      $deleted_ts = (int)($message['recipient_deleted_ts'] ?? 0);

      if ($box === 'inbox') {
        if ($to_key !== $uid_key || $deleted_ts > 0) {
          return ['ok' => false, 'error' => 'Message not found.'];
        }
        $changed = false;
        if ((int)($message['read_ts'] ?? 0) <= 0) {
          $message['read_ts'] = time();
          $changed = true;
        }
        return ['ok' => true, 'changed' => $changed, 'data' => ['message' => $message]];
      }

      if ($from_key !== $uid_key) {
        return ['ok' => false, 'error' => 'Message not found.'];
      }
      if ($sender_deleted_ts > 0) {
        return ['ok' => false, 'error' => 'Message not found.'];
      }

      return ['ok' => true, 'changed' => false, 'data' => ['message' => $message]];
    }

    return ['ok' => false, 'error' => 'Message not found.'];
  });

  if (empty($op['ok'])) {
    messages_api_out(['ok' => false, 'error' => $op['error'] ?? 'Unable to open message.'], 404);
  }

  $message = (array)($op['data']['message'] ?? []);
  messages_api_out([
    'ok' => true,
    'message' => messages_api_message_view($message, $box, $is_admin),
  ]);
}

if ($action === 'delete') {
  $box = messages_api_clean_box((string)($_POST['box'] ?? 'inbox'));
  $id = messages_api_clean_id((string)($_POST['id'] ?? ''));
  if ($id === '') {
    messages_api_out(['ok' => false, 'error' => 'Missing message id.'], 400);
  }

  $op = messages_with_locked_store(static function (array &$doc) use ($id, $box, $current_uid, $is_admin): array {
    $uid_key = messages_normalize_uid_key($current_uid);
    foreach ($doc['messages'] as &$message) {
      if (!is_array($message) || (string)($message['id'] ?? '') !== $id) {
        continue;
      }

      $to_key = messages_normalize_uid_key((string)($message['to_uid'] ?? ''));
      $from_key = messages_normalize_uid_key((string)($message['from_uid'] ?? ''));
      $sender_deleted_ts = (int)($message['sender_deleted_ts'] ?? 0);
      $deleted_ts = (int)($message['recipient_deleted_ts'] ?? 0);

      if ($box === 'inbox') {
        if ($to_key !== $uid_key || $deleted_ts > 0) {
          return ['ok' => false, 'error' => 'Message not found in your inbox.'];
        }

        $message['recipient_deleted_ts'] = time();
        return ['ok' => true, 'changed' => true];
      }

      if (!$is_admin) {
        return ['ok' => false, 'error' => 'Only administrators can delete outbox items.'];
      }
      if ($from_key !== $uid_key || $sender_deleted_ts > 0) {
        return ['ok' => false, 'error' => 'Message not found in your outbox.'];
      }

      $message['sender_deleted_ts'] = time();
      return ['ok' => true, 'changed' => true];
    }

    if ($box === 'outbox') {
      return ['ok' => false, 'error' => 'Message not found in your outbox.'];
    }
    return ['ok' => false, 'error' => 'Message not found in your inbox.'];
  });

  if (empty($op['ok'])) {
    $error = (string)($op['error'] ?? 'Unable to delete message.');
    $status = (strpos($error, 'Only administrators') !== false) ? 403 : 404;
    messages_api_out(['ok' => false, 'error' => $error], $status);
  }

  $counts = messages_counts_for_uid(messages_compute_state((array)($op['doc'] ?? [])), $current_uid);
  messages_api_out(['ok' => true, 'counts' => $counts]);
}

if ($action === 'send') {
  $to_uid_raw = trim((string)($_POST['to_uid'] ?? ''));
  $body = trim((string)($_POST['body'] ?? ''));

  if ($to_uid_raw === '') {
    messages_api_out(['ok' => false, 'error' => 'Recipient is required.'], 400);
  }
  if ($body === '') {
    messages_api_out(['ok' => false, 'error' => 'Message body is required.'], 400);
  }

  if (function_exists('mb_strlen')) {
    $too_long = mb_strlen($body, 'UTF-8') > messages_max_body_length();
  } else {
    $too_long = strlen($body) > messages_max_body_length();
  }
  if ($too_long) {
    messages_api_out(['ok' => false, 'error' => 'Message is too long.'], 400);
  }

  $directory = messages_api_user_directory();
  if (empty($directory['ok'])) {
    messages_api_out(['ok' => false, 'error' => $directory['error'] ?? 'Unable to load recipients.'], 500);
  }
  $map = (array)($directory['map'] ?? []);
  $to_key = messages_normalize_uid_key($to_uid_raw);
  $from_key = messages_normalize_uid_key($current_uid);

  $to_row = (array)($map[$to_key] ?? []);
  if (empty($to_row['uid'])) {
    messages_api_out(['ok' => false, 'error' => 'Recipient not found in LDAP.'], 400);
  }
  if (!$is_admin && empty($to_row['is_admin'])) {
    messages_api_out(['ok' => false, 'error' => 'You can only send messages to administrators.'], 403);
  }
  $from_row = (array)($map[$from_key] ?? ['uid' => $current_uid, 'display' => $current_uid, 'mail' => '']);

  $message = [
    'id' => messages_generate_message_id(),
    'from_uid' => (string)($from_row['uid'] ?? $current_uid),
    'from_display' => (string)($from_row['display'] ?? $current_uid),
    'from_email' => (string)($from_row['mail'] ?? ''),
    'to_uid' => (string)($to_row['uid'] ?? $to_uid_raw),
    'to_display' => (string)($to_row['display'] ?? $to_uid_raw),
    'to_email' => (string)($to_row['mail'] ?? ''),
    'body' => $body,
    'created_ts' => time(),
    'read_ts' => 0,
    'sender_deleted_ts' => 0,
    'recipient_deleted_ts' => 0,
  ];

  $op = messages_with_locked_store(static function (array &$doc) use ($message): array {
    $doc['messages'][] = $message;
    return ['ok' => true, 'changed' => true, 'data' => ['id' => $message['id']]];
  });

  if (empty($op['ok'])) {
    messages_api_out(['ok' => false, 'error' => $op['error'] ?? 'Unable to send message.'], 500);
  }

  $mail_result = messages_api_send_email_notification($message);
  $counts = messages_counts_for_uid(messages_compute_state((array)($op['doc'] ?? [])), $current_uid);

  messages_api_out([
    'ok' => true,
    'id' => $message['id'],
    'counts' => $counts,
    'mail' => $mail_result,
  ]);
}

messages_api_out(['ok' => false, 'error' => 'Unknown operation.'], 400);
