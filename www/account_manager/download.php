<?php

set_include_path('.:' . __DIR__ . '/../includes/');
include_once 'web_functions.inc.php';
include_once 'ldap_functions.inc.php';
include_once 'module_functions.inc.php';
set_page_access('admin');

if (!isset($_GET['resource_identifier']) or !isset($_GET['attribute'])) {
  exit(0);
} else {
  // Whitelist of allowed downloadable attributes to prevent unauthorized data access
  $allowed_attributes = [
    'jpegphoto',
    'jpegPhoto',
    'thumbnailphoto',
    'thumbnailPhoto',
    'photo',
    'userCertificate',
    'userCertificate;binary',
    'audio',
    'userSMIMECertificate',
  ];

  $requested_attribute = $_GET['attribute'];

  // Case-insensitive check for allowed attributes
  $attribute_allowed = false;
  foreach ($allowed_attributes as $allowed) {
    if (strcasecmp($requested_attribute, $allowed) === 0) {
      $attribute_allowed = true;
      break;
    }
  }

  if (!$attribute_allowed) {
    http_response_code(403);
    die('Access denied: Invalid attribute requested');
  }

  $this_resource = ldap_escape($_GET['resource_identifier'], '', LDAP_ESCAPE_FILTER);
  $this_attribute = ldap_escape($requested_attribute, '', LDAP_ESCAPE_FILTER);
}


$exploded = ldap_explode_dn($this_resource, 0);
$filter = $exploded[0];
$ldap_connection = open_ldap_connection();
$ldap_search_query = "($filter)";
$ldap_search = ldap_search($ldap_connection, $this_resource, $ldap_search_query, [$this_attribute]);

if ($ldap_search) {

  $records = ldap_get_entries($ldap_connection, $ldap_search);
  if ($records['count'] == 1) {
    $this_record = $records[0];
    if (isset($this_record[$this_attribute][0])) {
      // Sanitize filename to prevent header injection
      $safe_filename = preg_replace('/[^a-zA-Z0-9._-]/', '_', $this_resource . '.' . $this_attribute);

      header('Content-Type: application/octet-stream');
      header('Cache-Control: no-cache private');
      header('Content-Transfer-Encoding: Binary');
      header("Content-disposition: attachment; filename=\"{$safe_filename}\"");
      header('Content-Length: ' . strlen($this_record[$this_attribute][0]));
      print $this_record[$this_attribute][0];
    }
  }

}
