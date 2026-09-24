<?php
/**
 * Invite audit helpers.
 * Stores immutable invite events and provides read helpers for UI.
 */

function invite_data_path(): string
{
  $base = getenv('DATA_DIR');
  if (!$base) {
    $base = realpath(__DIR__ . '/../../data')
      ?: (realpath(__DIR__ . '/../data') ?: (__DIR__ . '/../../data'));
  }
  return rtrim((string)$base, '/\\') . '/invites/audit.json';
}

function invite_load_events(): array
{
  $path = invite_data_path();
  if (!is_file($path)) {
    return ['schema' => 'lum-invites@v1', 'events' => []];
  }

  $raw = @file_get_contents($path);
  if ($raw === false || $raw === '') {
    return ['schema' => 'lum-invites@v1', 'events' => []];
  }

  $decoded = json_decode($raw, true);
  if (!is_array($decoded)) {
    return ['schema' => 'lum-invites@v1', 'events' => []];
  }
  if (!isset($decoded['events']) || !is_array($decoded['events'])) {
    $decoded['events'] = [];
  }
  if (!isset($decoded['schema']) || !is_string($decoded['schema'])) {
    $decoded['schema'] = 'lum-invites@v1';
  }
  return $decoded;
}

function invite_record_event(
  string $inviter_uid,
  string $invitee_uid,
  string $invitee_email,
  string $role_id,
  string $role_name,
  array $groups,
  string $event_type = 'invite'
): string|false {
  $inviter_uid = trim($inviter_uid);
  $invitee_uid = trim($invitee_uid);
  $invitee_email = trim($invitee_email);
  $role_id = trim($role_id);
  $role_name = trim($role_name);
  $event_type = strtolower(trim($event_type));
  if ($event_type === '' || !preg_match('/^[a-z0-9_-]{1,32}$/', $event_type)) {
    $event_type = 'invite';
  }

  if ($inviter_uid === '' || $invitee_uid === '') {
    return false;
  }

  $normalized_groups = [];
  foreach ($groups as $group_name) {
    $group_name = trim((string)$group_name);
    if ($group_name !== '') {
      $normalized_groups[$group_name] = true;
    }
  }

  try {
    $event_id = time() . '-' . bin2hex(random_bytes(4));
  } catch (\Throwable $e) {
    $event_id = time() . '-fallback';
  }

  $event = [
    'event_id' => $event_id,
    'created_ts' => time(),
    'event_type' => $event_type,
    'inviter_uid' => $inviter_uid,
    'invitee_uid' => $invitee_uid,
    'invitee_email' => $invitee_email,
    'role_id' => $role_id,
    'role_name' => $role_name,
    'groups' => array_values(array_keys($normalized_groups)),
  ];

  $path = invite_data_path();
  $dir = dirname($path);
  if (!is_dir($dir)) {
    @mkdir($dir, 0750, true);
  }

  $lock_path = $path . '.lock';
  $lock_handle = @fopen($lock_path, 'c');
  if (!$lock_handle) {
    return false;
  }

  $saved = false;
  try {
    if (!flock($lock_handle, LOCK_EX)) {
      return false;
    }

    $data = invite_load_events();
    $data['schema'] = 'lum-invites@v1';
    $data['events'][] = $event;
    $data['updated_ts'] = time();

    $json = json_encode($data, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);
    if (!is_string($json)) {
      return false;
    }

    $tmp = $path . '.tmp';
    if (@file_put_contents($tmp, $json, LOCK_EX) === false) {
      return false;
    }
    @chmod($tmp, 0640);
    $saved = @rename($tmp, $path);
    if ($saved) {
      @chmod($path, 0640);
    }
  } finally {
    @flock($lock_handle, LOCK_UN);
    @fclose($lock_handle);
  }

  return $saved ? $event_id : false;
}

function invite_delete_event(string $event_id): bool
{
  $event_id = trim($event_id);
  if ($event_id === '') {
    return false;
  }

  $path = invite_data_path();
  $dir = dirname($path);
  if (!is_dir($dir)) {
    return true;
  }

  $lock_path = $path . '.lock';
  $lock_handle = @fopen($lock_path, 'c');
  if (!$lock_handle) {
    return false;
  }

  $saved = false;
  try {
    if (!flock($lock_handle, LOCK_EX)) {
      return false;
    }

    $data = invite_load_events();
    $before = count($data['events']);
    $data['events'] = array_values(array_filter(
      $data['events'],
      static function ($event) use ($event_id): bool {
        if (!is_array($event)) {
          return true;
        }
        return trim((string)($event['event_id'] ?? '')) !== $event_id;
      },
    ));
    $after = count($data['events']);
    if ($after === $before) {
      return true;
    }

    $data['updated_ts'] = time();
    $json = json_encode($data, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);
    if (!is_string($json)) {
      return false;
    }

    $tmp = $path . '.tmp';
    if (@file_put_contents($tmp, $json, LOCK_EX) === false) {
      return false;
    }
    @chmod($tmp, 0640);
    $saved = @rename($tmp, $path);
    if ($saved) {
      @chmod($path, 0640);
    }
  } finally {
    @flock($lock_handle, LOCK_UN);
    @fclose($lock_handle);
  }

  return $saved;
}

function invite_get_latest_for_invitee(string $invitee_uid): ?array
{
  $invitee_uid = strtolower(trim($invitee_uid));
  if ($invitee_uid === '') {
    return null;
  }

  $data = invite_load_events();
  $latest = null;
  $latest_ts = -1;

  foreach ($data['events'] as $event) {
    if (!is_array($event)) {
      continue;
    }
    $target_uid = strtolower(trim((string)($event['invitee_uid'] ?? '')));
    if ($target_uid !== $invitee_uid) {
      continue;
    }

    $this_ts = (int)($event['created_ts'] ?? 0);
    if ($this_ts >= $latest_ts) {
      $latest_ts = $this_ts;
      $latest = $event;
    }
  }

  return $latest;
}

function invite_list_for_inviter(string $inviter_uid, int $limit = 100, array $event_types = []): array
{
  $inviter_uid = strtolower(trim($inviter_uid));
  if ($inviter_uid === '') {
    return [];
  }

  $type_filter = [];
  foreach ($event_types as $event_type) {
    $event_type = strtolower(trim((string)$event_type));
    if ($event_type !== '') {
      $type_filter[$event_type] = true;
    }
  }

  $data = invite_load_events();
  $events = [];

  foreach ($data['events'] as $event) {
    if (!is_array($event)) {
      continue;
    }
    $owner_uid = strtolower(trim((string)($event['inviter_uid'] ?? '')));
    if ($owner_uid !== $inviter_uid) {
      continue;
    }
    $event_type = strtolower(trim((string)($event['event_type'] ?? 'invite')));
    if (!empty($type_filter) && !isset($type_filter[$event_type])) {
      continue;
    }
    $events[] = $event;
  }

  usort($events, static function (array $a, array $b): int {
    return ((int)($b['created_ts'] ?? 0)) <=> ((int)($a['created_ts'] ?? 0));
  });

  return array_slice($events, 0, max(1, $limit));
}
