<?php
/**
 * Messages storage helpers.
 * - Encrypted-at-rest payload in DATA_DIR/messages/store.enc
 * - Event-driven state updates in DATA_DIR/messages/state.json
 * - No background polling/scanning
 */

if (!function_exists('messages_data_dir')) {
  function messages_data_dir(): string
  {
    $base = getenv('DATA_DIR');
    if (!$base) {
      $base = realpath(__DIR__ . '/../../data')
        ?: (realpath(__DIR__ . '/../data') ?: (__DIR__ . '/../../data'));
    }
    return rtrim((string)$base, '/\\') . '/messages';
  }
}

if (!function_exists('messages_store_path')) {
  function messages_store_path(): string
  {
    return messages_data_dir() . '/store.enc';
  }
}

if (!function_exists('messages_state_path')) {
  function messages_state_path(): string
  {
    return messages_data_dir() . '/state.json';
  }
}

if (!function_exists('messages_store_schema')) {
  function messages_store_schema(): string
  {
    return 'lum-messages@v1';
  }
}

if (!function_exists('messages_state_schema')) {
  function messages_state_schema(): string
  {
    return 'lum-messages-state@v1';
  }
}

if (!function_exists('messages_empty_store')) {
  function messages_empty_store(): array
  {
    return [
      'schema' => messages_store_schema(),
      'updated_ts' => 0,
      'messages' => [],
    ];
  }
}

if (!function_exists('messages_setup_instructions')) {
  function messages_setup_instructions(): array
  {
    return [
      'Set MESSAGES_ENCRYPTION_KEY in your environment.',
      'Use a long random secret (recommended: at least 32 bytes).',
      'Example generation command: openssl rand -base64 32',
      'Recommended format: MESSAGES_ENCRYPTION_KEY=base64:<generated-value>',
      'Optional mail template: NEW_MESSAGE_EMAIL_BODY (and NEW_MESSAGE_EMAIL_SUBJECT).',
    ];
  }
}

if (!function_exists('messages_crypto_algorithm')) {
  function messages_crypto_algorithm(): string
  {
    if (function_exists('sodium_crypto_secretbox') && defined('SODIUM_CRYPTO_SECRETBOX_NONCEBYTES')) {
      return 'secretbox';
    }

    if (function_exists('openssl_encrypt') && function_exists('openssl_get_cipher_methods')) {
      $methods = array_map('strtolower', (array)openssl_get_cipher_methods());
      if (in_array('aes-256-gcm', $methods, true)) {
        return 'aes-256-gcm';
      }
    }

    return '';
  }
}

if (!function_exists('messages_configuration_error')) {
  function messages_configuration_error(): string
  {
    $raw = trim((string)(getenv('MESSAGES_ENCRYPTION_KEY') ?: ''));
    if ($raw === '') {
      return 'MESSAGES_ENCRYPTION_KEY is not configured.';
    }

    if (strpos($raw, 'base64:') === 0) {
      $decoded = base64_decode(substr($raw, 7), true);
      if (!is_string($decoded) || strlen($decoded) < 16) {
        return 'MESSAGES_ENCRYPTION_KEY base64 payload is invalid or too short.';
      }
    } elseif (strlen($raw) < 16) {
      return 'MESSAGES_ENCRYPTION_KEY is too short. Use at least 16 characters (32+ recommended).';
    }

    if (messages_crypto_algorithm() === '') {
      return 'No supported crypto backend found (requires sodium secretbox or openssl aes-256-gcm).';
    }

    return '';
  }
}

if (!function_exists('messages_is_enabled')) {
  function messages_is_enabled(): bool
  {
    return messages_configuration_error() === '';
  }
}

if (!function_exists('messages_encryption_key_binary')) {
  function messages_encryption_key_binary(): ?string
  {
    static $cached_raw = null;
    static $cached_key = null;

    $raw = trim((string)(getenv('MESSAGES_ENCRYPTION_KEY') ?: ''));
    if ($cached_raw === $raw) {
      return $cached_key;
    }
    $cached_raw = $raw;
    $cached_key = null;

    if ($raw === '') {
      return null;
    }

    $material = $raw;
    if (strpos($raw, 'base64:') === 0) {
      $decoded = base64_decode(substr($raw, 7), true);
      if (!is_string($decoded) || strlen($decoded) < 16) {
        return null;
      }
      $material = $decoded;
    } elseif (strlen($raw) < 16) {
      return null;
    }

    $cached_key = hash('sha256', $material, true);
    return $cached_key;
  }
}

if (!function_exists('messages_encrypt_plaintext')) {
  function messages_encrypt_plaintext(string $plaintext): ?array
  {
    $key = messages_encryption_key_binary();
    if ($key === null) {
      return null;
    }

    $alg = messages_crypto_algorithm();
    if ($alg === 'secretbox') {
      $nonce = random_bytes(SODIUM_CRYPTO_SECRETBOX_NONCEBYTES);
      $cipher = sodium_crypto_secretbox($plaintext, $nonce, $key);
      return [
        'schema' => 'lum-messages-sealed@v1',
        'alg' => 'secretbox',
        'nonce' => base64_encode($nonce),
        'ciphertext' => base64_encode($cipher),
      ];
    }

    if ($alg === 'aes-256-gcm') {
      $iv = random_bytes(12);
      $tag = '';
      $cipher = openssl_encrypt($plaintext, 'aes-256-gcm', $key, OPENSSL_RAW_DATA, $iv, $tag, '', 16);
      if ($cipher === false || !is_string($tag) || $tag === '') {
        return null;
      }
      return [
        'schema' => 'lum-messages-sealed@v1',
        'alg' => 'aes-256-gcm',
        'iv' => base64_encode($iv),
        'tag' => base64_encode($tag),
        'ciphertext' => base64_encode($cipher),
      ];
    }

    return null;
  }
}

if (!function_exists('messages_decrypt_payload')) {
  function messages_decrypt_payload(array $sealed): ?string
  {
    $key = messages_encryption_key_binary();
    if ($key === null) {
      return null;
    }

    $alg = (string)($sealed['alg'] ?? '');
    $cipher_b64 = (string)($sealed['ciphertext'] ?? '');
    $cipher = base64_decode($cipher_b64, true);
    if (!is_string($cipher)) {
      return null;
    }

    if ($alg === 'secretbox') {
      $nonce = base64_decode((string)($sealed['nonce'] ?? ''), true);
      if (!is_string($nonce) || strlen($nonce) !== SODIUM_CRYPTO_SECRETBOX_NONCEBYTES) {
        return null;
      }
      $plain = sodium_crypto_secretbox_open($cipher, $nonce, $key);
      return is_string($plain) ? $plain : null;
    }

    if ($alg === 'aes-256-gcm') {
      $iv = base64_decode((string)($sealed['iv'] ?? ''), true);
      $tag = base64_decode((string)($sealed['tag'] ?? ''), true);
      if (!is_string($iv) || !is_string($tag)) {
        return null;
      }
      $plain = openssl_decrypt($cipher, 'aes-256-gcm', $key, OPENSSL_RAW_DATA, $iv, $tag);
      return is_string($plain) ? $plain : null;
    }

    return null;
  }
}

if (!function_exists('messages_normalize_uid_key')) {
  function messages_normalize_uid_key(string $uid): string
  {
    return strtolower(trim($uid));
  }
}

if (!function_exists('messages_normalize_store_doc')) {
  function messages_normalize_store_doc(array $doc): array
  {
    $out = messages_empty_store();
    $out['updated_ts'] = (int)($doc['updated_ts'] ?? 0);

    foreach ((array)($doc['messages'] ?? []) as $message) {
      if (!is_array($message)) {
        continue;
      }

      $id = trim((string)($message['id'] ?? ''));
      $from_uid = trim((string)($message['from_uid'] ?? ''));
      $to_uid = trim((string)($message['to_uid'] ?? ''));
      if ($id === '' || $from_uid === '' || $to_uid === '') {
        continue;
      }

      $body = trim((string)($message['body'] ?? ''));
      if ($body === '') {
        continue;
      }

      $created_ts = (int)($message['created_ts'] ?? 0);
      if ($created_ts <= 0) {
        $created_ts = time();
      }

      $out['messages'][] = [
        'id' => $id,
        'from_uid' => $from_uid,
        'from_display' => trim((string)($message['from_display'] ?? $from_uid)),
        'from_email' => trim((string)($message['from_email'] ?? '')),
        'to_uid' => $to_uid,
        'to_display' => trim((string)($message['to_display'] ?? $to_uid)),
        'to_email' => trim((string)($message['to_email'] ?? '')),
        'body' => $body,
        'created_ts' => $created_ts,
        'read_ts' => max(0, (int)($message['read_ts'] ?? 0)),
        'sender_deleted_ts' => max(0, (int)($message['sender_deleted_ts'] ?? 0)),
        'recipient_deleted_ts' => max(0, (int)($message['recipient_deleted_ts'] ?? 0)),
      ];
    }

    return $out;
  }
}

if (!function_exists('messages_sort_newest_first')) {
  function messages_sort_newest_first(array &$messages): void
  {
    usort($messages, static function (array $a, array $b): int {
      $ts_cmp = ((int)($b['created_ts'] ?? 0)) <=> ((int)($a['created_ts'] ?? 0));
      if ($ts_cmp !== 0) {
        return $ts_cmp;
      }
      return strnatcasecmp((string)($b['id'] ?? ''), (string)($a['id'] ?? ''));
    });
  }
}

if (!function_exists('messages_compute_state')) {
  function messages_compute_state(array $doc): array
  {
    $state = [
      'schema' => messages_state_schema(),
      'updated_ts' => time(),
      'total_messages' => 0,
      'users' => [],
    ];

    foreach ((array)($doc['messages'] ?? []) as $message) {
      if (!is_array($message)) {
        continue;
      }

      $state['total_messages']++;

      $to_key = messages_normalize_uid_key((string)($message['to_uid'] ?? ''));
      $from_key = messages_normalize_uid_key((string)($message['from_uid'] ?? ''));
      $to_uid = trim((string)($message['to_uid'] ?? ''));
      $from_uid = trim((string)($message['from_uid'] ?? ''));
      $sender_deleted_ts = (int)($message['sender_deleted_ts'] ?? 0);
      $deleted_ts = (int)($message['recipient_deleted_ts'] ?? 0);
      $read_ts = (int)($message['read_ts'] ?? 0);

      if ($to_key !== '') {
        if (!isset($state['users'][$to_key])) {
          $state['users'][$to_key] = [
            'uid' => $to_uid,
            'inbox' => 0,
            'outbox' => 0,
            'unread' => 0,
          ];
        }
        if ($deleted_ts <= 0) {
          $state['users'][$to_key]['inbox']++;
          if ($read_ts <= 0) {
            $state['users'][$to_key]['unread']++;
          }
        }
      }

      if ($from_key !== '') {
        if (!isset($state['users'][$from_key])) {
          $state['users'][$from_key] = [
            'uid' => $from_uid,
            'inbox' => 0,
            'outbox' => 0,
            'unread' => 0,
          ];
        }
        if ($sender_deleted_ts <= 0) {
          $state['users'][$from_key]['outbox']++;
        }
      }
    }

    ksort($state['users']);
    return $state;
  }
}

if (!function_exists('messages_write_state_file')) {
  function messages_write_state_file(array $doc): void
  {
    $state = messages_compute_state($doc);
    $path = messages_state_path();
    $dir = dirname($path);
    if (!is_dir($dir)) {
      @mkdir($dir, 0750, true);
    }

    $json = json_encode($state, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);
    if (!is_string($json)) {
      return;
    }

    $tmp = $path . '.tmp';
    if (@file_put_contents($tmp, $json, LOCK_EX) === false) {
      return;
    }
    @chmod($tmp, 0640);
    if (@rename($tmp, $path)) {
      @chmod($path, 0640);
    }
  }
}

if (!function_exists('messages_runtime_cache')) {
  function &messages_runtime_cache(): array
  {
    static $cache = [
      'loaded' => false,
      'mtime' => -1,
      'doc' => null,
      'state' => null,
    ];
    return $cache;
  }
}

if (!function_exists('messages_set_cache_doc')) {
  function messages_set_cache_doc(array $doc): void
  {
    $path = messages_store_path();
    $mtime = is_file($path) ? (int)(@filemtime($path) ?: 0) : 0;
    $state = messages_compute_state($doc);
    $cache = &messages_runtime_cache();
    $cache['loaded'] = true;
    $cache['mtime'] = $mtime;
    $cache['doc'] = $doc;
    $cache['state'] = $state;
  }
}

if (!function_exists('messages_load_store_from_disk')) {
  function messages_load_store_from_disk(string $path): array
  {
    if (!is_file($path)) {
      return ['ok' => true, 'doc' => messages_empty_store()];
    }

    $raw = @file_get_contents($path);
    if ($raw === false || trim($raw) === '') {
      return ['ok' => true, 'doc' => messages_empty_store()];
    }

    $sealed = json_decode($raw, true);
    if (!is_array($sealed)) {
      return ['ok' => false, 'error' => 'Message store is not valid JSON.'];
    }

    $plaintext = messages_decrypt_payload($sealed);
    if (!is_string($plaintext)) {
      return ['ok' => false, 'error' => 'Message store could not be decrypted with current key.'];
    }

    $decoded = json_decode($plaintext, true);
    if (!is_array($decoded)) {
      return ['ok' => false, 'error' => 'Decrypted message store payload is invalid JSON.'];
    }

    return ['ok' => true, 'doc' => messages_normalize_store_doc($decoded)];
  }
}

if (!function_exists('messages_load_store')) {
  function messages_load_store(bool $force = false): array
  {
    if (!messages_is_enabled()) {
      return ['ok' => false, 'error' => messages_configuration_error()];
    }

    $path = messages_store_path();
    $mtime = is_file($path) ? (int)(@filemtime($path) ?: 0) : 0;
    $cache = &messages_runtime_cache();

    if (
      !$force
      && !empty($cache['loaded'])
      && (int)$cache['mtime'] === $mtime
      && is_array($cache['doc'])
      && is_array($cache['state'])
    ) {
      return ['ok' => true, 'doc' => $cache['doc'], 'state' => $cache['state']];
    }

    $loaded = messages_load_store_from_disk($path);
    if (empty($loaded['ok'])) {
      return ['ok' => false, 'error' => (string)($loaded['error'] ?? 'Unable to load messages store.')];
    }

    $doc = (array)($loaded['doc'] ?? messages_empty_store());
    $state = messages_compute_state($doc);
    $cache['loaded'] = true;
    $cache['mtime'] = $mtime;
    $cache['doc'] = $doc;
    $cache['state'] = $state;

    return ['ok' => true, 'doc' => $doc, 'state' => $state];
  }
}

if (!function_exists('messages_save_store_to_disk')) {
  function messages_save_store_to_disk(string $path, array $doc): array
  {
    $doc = messages_normalize_store_doc($doc);
    $doc['updated_ts'] = time();

    $plaintext = json_encode($doc, JSON_UNESCAPED_SLASHES);
    if (!is_string($plaintext)) {
      return ['ok' => false, 'error' => 'Failed to serialize message store.'];
    }

    $sealed = messages_encrypt_plaintext($plaintext);
    if (!is_array($sealed)) {
      return ['ok' => false, 'error' => 'Failed to encrypt message store payload.'];
    }

    $sealed_json = json_encode($sealed, JSON_UNESCAPED_SLASHES);
    if (!is_string($sealed_json)) {
      return ['ok' => false, 'error' => 'Failed to serialize encrypted message payload.'];
    }

    $tmp = $path . '.tmp';
    if (@file_put_contents($tmp, $sealed_json, LOCK_EX) === false) {
      return ['ok' => false, 'error' => 'Failed writing temporary encrypted message store.'];
    }
    @chmod($tmp, 0640);

    if (!@rename($tmp, $path)) {
      @unlink($tmp);
      return ['ok' => false, 'error' => 'Failed replacing encrypted message store.'];
    }
    @chmod($path, 0640);

    messages_write_state_file($doc);
    messages_set_cache_doc($doc);

    return ['ok' => true, 'doc' => $doc];
  }
}

if (!function_exists('messages_with_locked_store')) {
  function messages_with_locked_store(callable $mutator): array
  {
    if (!messages_is_enabled()) {
      return ['ok' => false, 'error' => messages_configuration_error()];
    }

    $path = messages_store_path();
    $dir = dirname($path);
    if (!is_dir($dir)) {
      if (!@mkdir($dir, 0750, true) && !is_dir($dir)) {
        return ['ok' => false, 'error' => 'Unable to create messages data directory.'];
      }
    }

    $lock_path = $path . '.lock';
    $lock_handle = @fopen($lock_path, 'c');
    if (!$lock_handle) {
      return ['ok' => false, 'error' => 'Unable to open messages lock file.'];
    }
    @chmod($lock_path, 0640);

    try {
      if (!flock($lock_handle, LOCK_EX)) {
        return ['ok' => false, 'error' => 'Unable to acquire messages lock.'];
      }

      $loaded = messages_load_store_from_disk($path);
      if (empty($loaded['ok'])) {
        return ['ok' => false, 'error' => (string)($loaded['error'] ?? 'Unable to load encrypted message store.')];
      }

      $doc = (array)($loaded['doc'] ?? messages_empty_store());
      $op = $mutator($doc);
      if (!is_array($op)) {
        return ['ok' => false, 'error' => 'Message operation returned an invalid response.'];
      }
      if (empty($op['ok'])) {
        return ['ok' => false, 'error' => (string)($op['error'] ?? 'Message operation failed.')];
      }

      $changed = !empty($op['changed']);
      if ($changed) {
        $saved = messages_save_store_to_disk($path, $doc);
        if (empty($saved['ok'])) {
          return ['ok' => false, 'error' => (string)($saved['error'] ?? 'Unable to save encrypted message store.')];
        }
        $doc = (array)($saved['doc'] ?? $doc);
      } else {
        messages_set_cache_doc($doc);
      }

      return [
        'ok' => true,
        'doc' => $doc,
        'data' => $op['data'] ?? null,
      ];
    } finally {
      @flock($lock_handle, LOCK_UN);
      @fclose($lock_handle);
    }
  }
}

if (!function_exists('messages_generate_message_id')) {
  function messages_generate_message_id(): string
  {
    try {
      return gmdate('Ymd\THis\Z') . '-' . bin2hex(random_bytes(6));
    } catch (\Throwable $e) {
      return gmdate('Ymd\THis\Z') . '-' . uniqid('msg', true);
    }
  }
}

if (!function_exists('messages_max_body_length')) {
  function messages_max_body_length(): int
  {
    $raw = (int)(getenv('MESSAGES_MAX_BODY_LENGTH') ?: 5000);
    if ($raw < 200) {
      return 200;
    }
    if ($raw > 20000) {
      return 20000;
    }
    return $raw;
  }
}

if (!function_exists('messages_make_preview')) {
  function messages_make_preview(string $body, int $max = 100): string
  {
    $body = preg_replace('/\[\/?(?:b|u|code|quote|url(?:=[^\]\r\n]+)?)\]/iu', '', $body) ?? $body;
    $normalized = preg_replace('/\s+/u', ' ', trim($body));
    if ($normalized === null) {
      $normalized = trim($body);
    }
    if ($normalized === '') {
      return '';
    }
    if (function_exists('mb_strlen') && function_exists('mb_substr')) {
      if (mb_strlen($normalized, 'UTF-8') <= $max) {
        return $normalized;
      }
      return rtrim(mb_substr($normalized, 0, $max, 'UTF-8')) . '...';
    }

    if (strlen($normalized) <= $max) {
      return $normalized;
    }
    return rtrim(substr($normalized, 0, $max)) . '...';
  }
}

if (!function_exists('messages_list_for_user')) {
  function messages_list_for_user(array $doc, string $uid, string $box): array
  {
    $uid_key = messages_normalize_uid_key($uid);
    $box = strtolower(trim($box)) === 'outbox' ? 'outbox' : 'inbox';
    $out = [];

    foreach ((array)($doc['messages'] ?? []) as $message) {
      if (!is_array($message)) {
        continue;
      }
      $to_key = messages_normalize_uid_key((string)($message['to_uid'] ?? ''));
      $from_key = messages_normalize_uid_key((string)($message['from_uid'] ?? ''));
      $deleted_ts = (int)($message['recipient_deleted_ts'] ?? 0);
      $sender_deleted_ts = (int)($message['sender_deleted_ts'] ?? 0);

      if ($box === 'inbox') {
        if ($to_key !== $uid_key || $deleted_ts > 0) {
          continue;
        }
      } else {
        if ($from_key !== $uid_key || $sender_deleted_ts > 0) {
          continue;
        }
      }

      $out[] = $message;
    }

    messages_sort_newest_first($out);
    return $out;
  }
}

if (!function_exists('messages_counts_for_uid')) {
  function messages_counts_for_uid(array $state, string $uid): array
  {
    $uid_key = messages_normalize_uid_key($uid);
    $row = (array)($state['users'][$uid_key] ?? []);
    return [
      'inbox' => (int)($row['inbox'] ?? 0),
      'outbox' => (int)($row['outbox'] ?? 0),
      'unread' => (int)($row['unread'] ?? 0),
    ];
  }
}
