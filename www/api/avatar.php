<?php
declare(strict_types=1);

set_include_path('.:' . __DIR__ . '/../includes/');

require_once 'web_functions.inc.php';
require_once 'ldap_functions.inc.php';

set_page_access('user');

header('X-Content-Type-Options: nosniff');

$account_identifier = $USER_ID ?? '';
if ($account_identifier === '') {
  http_response_code(404);
  exit;
}

$ldap_connection = open_ldap_connection();
$uid_attr = $LDAP['account_attribute'];
$filter = "({$uid_attr}=" . ldap_escape($account_identifier, '', LDAP_ESCAPE_FILTER) . ')';
$attrs = ['jpegPhoto', 'thumbnailPhoto', 'photo'];
$search_result = @ldap_search($ldap_connection, $LDAP['user_dn'], $filter, $attrs);

if (!$search_result) {
  http_response_code(500);
  exit;
}

$entries = @ldap_get_entries($ldap_connection, $search_result);
if (!is_array($entries) || ($entries['count'] ?? 0) < 1) {
  http_response_code(404);
  exit;
}

$entry = $entries[0];
$photo = $entry['jpegphoto'][0] ?? ($entry['thumbnailphoto'][0] ?? ($entry['photo'][0] ?? null));
if (!$photo) {
  http_response_code(404);
  exit;
}

// Raster formats only: an SVG served inline from this origin could carry script.
$mime = 'image/jpeg';
if (function_exists('finfo_open')) {
  $finfo = finfo_open(FILEINFO_MIME_TYPE);
  if ($finfo) {
    $detected = @finfo_buffer($finfo, $photo);
    if (in_array($detected, ['image/jpeg', 'image/png', 'image/gif', 'image/webp'], true)) {
      $mime = $detected;
    }
    @finfo_close($finfo);
  }
}

$etag = '"' . sha1($account_identifier . ':' . $photo) . '"';
header('Cache-Control: private, max-age=300');
header('ETag: ' . $etag);
if (isset($_SERVER['HTTP_IF_NONE_MATCH']) && trim((string)$_SERVER['HTTP_IF_NONE_MATCH']) === $etag) {
  http_response_code(304);
  exit;
}

header('Content-Type: ' . $mime);
header('Content-Length: ' . strlen($photo));
echo $photo;
