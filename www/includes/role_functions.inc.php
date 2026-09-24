<?php
/**
 * Roles helper functions
 * Provides CRUD operations and matching logic for saved roles
 */

// Data file path
function get_roles_data_path(): string
{
  $base = getenv('DATA_DIR') ?: realpath(__DIR__ . '/../data');
  return $base . '/roles/presets.json';
}

/**
 * Load all role presets
 * @return array ['schema' => string, 'roles' => array]
 */
function roles_load_presets(): array
{
  $path = get_roles_data_path();
  if (!is_file($path)) {
    return ['schema' => 'lum-preset-roles@v1', 'roles' => []];
  }

  $raw = @file_get_contents($path);
  if ($raw === false) {
    return ['schema' => 'lum-preset-roles@v1', 'roles' => []];
  }

  $data = json_decode($raw, true);
  if (!is_array($data)) {
    return ['schema' => 'lum-preset-roles@v1', 'roles' => []];
  }

  return $data;
}

/**
 * Save role presets to disk
 * @param array $data Full data structure with schema and roles
 * @return bool Success
 */
function roles_save_presets(array $data): bool
{
  $path = get_roles_data_path();
  $dir = dirname($path);

  if (!is_dir($dir)) {
    @mkdir($dir, 0750, true);
  }

  $data['updated_ts'] = time();
  $json = json_encode($data, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);
  $result = @file_put_contents($path, $json);

  if ($result !== false) {
    @chmod($path, 0640);
    return true;
  }

  return false;
}

/**
 * Get single role by ID
 * @param string $role_id
 * @return array|null Role data or null if not found
 */
function roles_get_by_id(string $role_id): ?array
{
  $data = roles_load_presets();
  foreach (($data['roles'] ?? []) as $role) {
    if (($role['id'] ?? '') === $role_id) {
      return $role;
    }
  }
  return null;
}

/**
 * Create new role preset
 * @param string $name Role name
 * @param array $groups Array of group CNs
 * @param string $description Optional description
 * @param int $priority Role priority (lower = higher priority, default 100)
 * @return string|false New role ID or false on failure
 */
function roles_create(string $name, array $groups, string $description = '', int $priority = 100): string|false
{
  $name = trim($name);
  if ($name === '' || empty($groups)) {
    return false;
  }

  $data = roles_load_presets();

  // Generate unique ID
  $id = time() . '-' . bin2hex(random_bytes(4));

  $new_role = [
    'id' => $id,
    'name' => $name,
    'description' => $description,
    'groups' => array_values(array_unique($groups)),
    'priority' => max(1, min(999, $priority)), // Clamp to 1-999
    'created_ts' => time(),
    'updated_ts' => time(),
  ];

  if (!isset($data['roles'])) {
    $data['roles'] = [];
  }
  $data['roles'][] = $new_role;

  if (!isset($data['created_ts'])) {
    $data['created_ts'] = time();
  }

  return roles_save_presets($data) ? $id : false;
}

/**
 * Update existing role
 * @param string $role_id Role ID
 * @param string $name New name
 * @param array $groups New groups
 * @param string $description New description
 * @param int $priority Role priority (lower = higher priority)
 * @return bool Success
 */
function roles_update(string $role_id, string $name, array $groups, string $description = '', int $priority = 100): bool
{
  $name = trim($name);
  if ($name === '' || empty($groups)) {
    return false;
  }

  $data = roles_load_presets();
  $found = false;

  foreach (($data['roles'] ?? []) as $idx => $role) {
    if (($role['id'] ?? '') === $role_id) {
      $data['roles'][$idx]['name'] = $name;
      $data['roles'][$idx]['description'] = $description;
      $data['roles'][$idx]['groups'] = array_values(array_unique($groups));
      $data['roles'][$idx]['priority'] = max(1, min(999, $priority));
      $data['roles'][$idx]['updated_ts'] = time();
      $found = true;
      break;
    }
  }

  return $found ? roles_save_presets($data) : false;
}

/**
 * Delete role by ID
 * @param string $role_id Role ID
 * @return bool Success
 */
function roles_delete(string $role_id): bool
{
  $data = roles_load_presets();
  $original_count = count($data['roles'] ?? []);

  $data['roles'] = array_values(array_filter(
    $data['roles'] ?? [],
    fn ($role) => ($role['id'] ?? '') !== $role_id,
  ));

  if (count($data['roles']) < $original_count) {
    return roles_save_presets($data);
  }

  return false;
}

/**
 * Match user groups to roles
 * Returns array of matching roles with match quality
 *
 * @param array $user_groups User's group memberships
 * @return array [['role' => array, 'match' => 'exact'|'superset', 'extra_groups' => array], ...]
 */
function roles_match_user_groups(array $user_groups): array
{
  $data = roles_load_presets();
  $matches = [];

  $user_groups_lc = array_map('strtolower', $user_groups);

  foreach (($data['roles'] ?? []) as $role) {
    $role_groups = $role['groups'] ?? [];
    $role_groups_lc = array_map('strtolower', $role_groups);

    // Check if user has ALL role groups (case-insensitive)
    $missing = array_diff($role_groups_lc, $user_groups_lc);

    if (empty($missing)) {
      // User has all role groups
      $extra = array_diff($user_groups_lc, $role_groups_lc);

      // Get original-case extra groups
      $extra_groups = [];
      foreach ($user_groups as $ug) {
        if (in_array(strtolower($ug), $extra, true)) {
          $extra_groups[] = $ug;
        }
      }

      $matches[] = [
        'role' => $role,
        'match' => empty($extra) ? 'exact' : 'superset',
        'extra_groups' => $extra_groups,
      ];
    }
  }

  // Sort by priority (lower number = higher priority)
  usort($matches, function ($a, $b) {
    $pri_a = (int)($a['role']['priority'] ?? 100);
    $pri_b = (int)($b['role']['priority'] ?? 100);
    if ($pri_a !== $pri_b) {
      return $pri_a <=> $pri_b;
    }
    // If same priority, sort by name
    return strcasecmp($a['role']['name'], $b['role']['name']);
  });

  return $matches;
}

/**
 * Format role display for user list
 * Shows highest priority role OR all groups if no match
 * @param array $user_groups User's group memberships
 * @return string HTML string for role or groups
 */
function roles_format_user_display(array $user_groups): string
{
  $matches = roles_match_user_groups($user_groups);

  if (empty($matches)) {
    // No role match - show all groups
    return htmlspecialchars(implode(', ', $user_groups), ENT_QUOTES, 'UTF-8');
  }

  // Show highest priority role (first in sorted array)
  $highest = $matches[0];
  $role_name = htmlspecialchars($highest['role']['name'], ENT_QUOTES, 'UTF-8');
  // Show ALL user groups in popup, not just role's groups
  $user_group_list = htmlspecialchars(implode(', ', $user_groups), ENT_QUOTES, 'UTF-8');
  $role_id = htmlspecialchars($highest['role']['id'], ENT_QUOTES, 'UTF-8');

  // Clickable role badge with data attributes for popup
  return "<span class='label label-info role-badge' style='cursor:pointer;' " .
         "data-role-name='$role_name' " .
         "data-role-groups='$user_group_list' " .
         "onclick='showRolePopup(this)' " .
         "title='Click to see groups'>$role_name</span>";
}
