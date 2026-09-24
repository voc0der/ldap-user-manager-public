<?php

$log_prefix = '';

# User account defaults

$DEFAULT_USER_GROUP = (getenv('DEFAULT_USER_GROUP') ? getenv('DEFAULT_USER_GROUP') : 'everybody');
$DEFAULT_USER_SHELL = (getenv('DEFAULT_USER_SHELL') ? getenv('DEFAULT_USER_SHELL') : '/bin/bash');
$ENFORCE_SAFE_SYSTEM_NAMES = ((strcasecmp(getenv('ENFORCE_SAFE_SYSTEM_NAMES'), 'FALSE') == 0) ? false : true);
$USERNAME_FORMAT = (getenv('USERNAME_FORMAT') ? getenv('USERNAME_FORMAT') : '{first_name}{last_name}');
$USERNAME_REGEX  = (getenv('USERNAME_REGEX') ? getenv('USERNAME_REGEX') : '^[a-z][a-zA-Z0-9\._-]{3,32}$');   #We use the username regex for groups too.

if (getenv('PASSWORD_HASH')) {
  $PASSWORD_HASH = strtoupper(getenv('PASSWORD_HASH'));
}
$ACCEPT_WEAK_PASSWORDS = ((strcasecmp(getenv('ACCEPT_WEAK_PASSWORDS'), 'TRUE') == 0) ? true : false);

$min_uid = 2000;
$min_gid = 2000;


#Default attributes and objectclasses

$LDAP['account_attribute'] = (getenv('LDAP_ACCOUNT_ATTRIBUTE') ? getenv('LDAP_ACCOUNT_ATTRIBUTE') : 'uid');
$LDAP['account_objectclasses'] = [ 'person', 'inetOrgPerson', 'posixAccount' ];
$LDAP['default_attribute_map'] = [
   'givenname' => [
       'label' => 'First name',
       'onkeyup' => "update_username(); update_email(); update_cn(); update_homedir(); check_email_validity(document.getElementById('mail').value);",
       'required' => true,
   ],
   'sn' => [
       'label' => 'Last name',
       'onkeyup' => "update_username(); update_email(); update_cn(); update_homedir(); check_email_validity(document.getElementById('mail').value);",
       'required' => true,
   ],
   'uid' => [
       'label' => 'Username',
       'onkeyup' => "check_entity_name_validity(document.getElementById('uid').value,'uid_div'); update_email(); update_homedir(); check_email_validity(document.getElementById('mail').value);",
   ],
   'displayname' => [
       'label' => 'Display name',
   ],
   'cn' => [
       'label' => 'Common name',
       'onkeyup' => 'auto_cn_update = false;',
   ],
   'mail' => [
       'label' => 'Email',
       'onkeyup' => "auto_email_update = false; check_email_validity(document.getElementById('mail').value);",
   ],
];

$LDAP['group_attribute'] = (getenv('LDAP_GROUP_ATTRIBUTE') ? getenv('LDAP_GROUP_ATTRIBUTE') : 'cn');
$LDAP['group_objectclasses'] = [ 'top', 'posixGroup' ]; #groupOfUniqueNames is added automatically if rfc2307bis is available.

$LDAP['default_group_attribute_map'] = [ 'description' => ['label' => 'Description']];

$SHOW_POSIX_ATTRIBUTES = ((strcasecmp(getenv('SHOW_POSIX_ATTRIBUTES'), 'TRUE') == 0) ? true : false);

if ($SHOW_POSIX_ATTRIBUTES != true) {
  if ($LDAP['account_attribute'] == 'uid') {
    unset($LDAP['default_attribute_map']['cn']);
  } else {
    unset($LDAP['default_attribute_map']['uid']);
  }
} else {
  $LDAP['default_attribute_map']['uidnumber']  = ['label' => 'UID'];
  $LDAP['default_attribute_map']['gidnumber']  = ['label' => 'GID'];
  $LDAP['default_attribute_map']['homedirectory']  = ['label' => 'Home directory', 'onkeyup' => 'auto_homedir_update = false;'];
  $LDAP['default_attribute_map']['loginshell']  = ['label' => 'Shell', 'default' => $DEFAULT_USER_SHELL];
  $LDAP['default_group_attribute_map']['gidnumber'] = ['label' => 'Group ID number'];
}


## LDAP server

$LDAP['uri'] = getenv('LDAP_URI');
$LDAP['base_dn'] = getenv('LDAP_BASE_DN');
$LDAP['admin_bind_dn'] = getenv('LDAP_ADMIN_BIND_DN');
$LDAP['admin_bind_pwd'] = getenv('LDAP_ADMIN_BIND_PWD');
$LDAP['connection_type'] = 'plain';
$LDAP['require_starttls'] = ((strcasecmp(getenv('LDAP_REQUIRE_STARTTLS'), 'TRUE') == 0) ? true : false);
$LDAP['ignore_cert_errors'] = ((strcasecmp(getenv('LDAP_IGNORE_CERT_ERRORS'), 'TRUE') == 0) ? true : false);
$LDAP['rfc2307bis_check_run'] = false;


# Various advanced LDAP settings

$LDAP['admins_group'] = getenv('LDAP_ADMINS_GROUP');
$LDAP['group_ou'] = (getenv('LDAP_GROUP_OU') ? getenv('LDAP_GROUP_OU') : 'groups');
$LDAP['user_ou'] = (getenv('LDAP_USER_OU') ? getenv('LDAP_USER_OU') : 'people');
$LDAP['forced_rfc2307bis'] = ((strcasecmp(getenv('FORCE_RFC2307BIS'), 'TRUE') == 0) ? true : false);

if (getenv('LDAP_ACCOUNT_ADDITIONAL_OBJECTCLASSES')) {
  $account_additional_objectclasses = strtolower(getenv('LDAP_ACCOUNT_ADDITIONAL_OBJECTCLASSES'));
}
if (getenv('LDAP_ACCOUNT_ADDITIONAL_ATTRIBUTES')) {
  $LDAP['account_additional_attributes'] = getenv('LDAP_ACCOUNT_ADDITIONAL_ATTRIBUTES');
}

if (getenv('LDAP_GROUP_ADDITIONAL_OBJECTCLASSES')) {
  $group_additional_objectclasses = getenv('LDAP_GROUP_ADDITIONAL_OBJECTCLASSES');
}
if (getenv('LDAP_GROUP_ADDITIONAL_ATTRIBUTES')) {
  $LDAP['group_additional_attributes'] = getenv('LDAP_GROUP_ADDITIONAL_ATTRIBUTES');
}

if (getenv('LDAP_GROUP_MEMBERSHIP_ATTRIBUTE')) {
  $LDAP['group_membership_attribute'] = getenv('LDAP_GROUP_MEMBERSHIP_ATTRIBUTE');
}
if (getenv('LDAP_GROUP_MEMBERSHIP_USES_UID')) {
  if (strtoupper(getenv('LDAP_GROUP_MEMBERSHIP_USES_UID')) == 'TRUE') {
    $LDAP['group_membership_uses_uid']  = true;
  }
  if (strtoupper(getenv('LDAP_GROUP_MEMBERSHIP_USES_UID')) == 'FALSE') {
    $LDAP['group_membership_uses_uid']  = false;
  }
}

$LDAP['group_dn'] = "ou={$LDAP['group_ou']},{$LDAP['base_dn']}";
$LDAP['user_dn'] = "ou={$LDAP['user_ou']},{$LDAP['base_dn']}";

if (isset($account_additional_objectclasses) and $account_additional_objectclasses != '') {
  $LDAP['account_objectclasses'] = array_merge($LDAP['account_objectclasses'], explode(',', $account_additional_objectclasses));
}
if (isset($group_additional_objectclasses) and $group_additional_objectclasses != '') {
  $LDAP['group_objectclasses'] = array_merge($LDAP['group_objectclasses'], explode(',', $group_additional_objectclasses));
}

# Interface customisation

$ORGANISATION_NAME = (getenv('ORGANISATION_NAME') ? getenv('ORGANISATION_NAME') : 'LDAP');
$SITE_NAME = (getenv('SITE_NAME') ? getenv('SITE_NAME') : "$ORGANISATION_NAME user manager");

$SITE_LOGIN_LDAP_ATTRIBUTE = (getenv('SITE_LOGIN_LDAP_ATTRIBUTE') ? getenv('SITE_LOGIN_LDAP_ATTRIBUTE') : $LDAP['account_attribute']);
$SITE_LOGIN_FIELD_LABEL = (getenv('SITE_LOGIN_FIELD_LABEL') ? getenv('SITE_LOGIN_FIELD_LABEL') : 'Username');

$SERVER_HOSTNAME = (getenv('SERVER_HOSTNAME') ? getenv('SERVER_HOSTNAME') : 'ldapusermanager.org');
$SERVER_PATH = (getenv('SERVER_PATH') ? getenv('SERVER_PATH') : '/');

$SESSION_TIMEOUT = (getenv('SESSION_TIMEOUT') ? getenv('SESSION_TIMEOUT') : 10);

$NO_HTTPS = ((strcasecmp(getenv('NO_HTTPS'), 'TRUE') == 0) ? true : false);

$REMOTE_HTTP_HEADERS_LOGIN = ((strcasecmp(getenv('REMOTE_HTTP_HEADERS_LOGIN'), 'TRUE') == 0) ? true : false);

# OIDC / Authelia login (Authorization Code + PKCE)
$OIDC_ISSUER_URL = trim((string)(getenv('OIDC_ISSUER_URL') ?: ''));
$OIDC_CLIENT_ID = trim((string)(getenv('OIDC_CLIENT_ID') ?: ''));
$OIDC_CLIENT_SECRET = (getenv('OIDC_CLIENT_SECRET') !== false ? (string)getenv('OIDC_CLIENT_SECRET') : '');
$OIDC_REDIRECT_URI = trim((string)(getenv('OIDC_REDIRECT_URI') ?: ''));
$OIDC_DISCOVERY_URL = trim((string)(getenv('OIDC_DISCOVERY_URL') ?: ''));
$OIDC_SCOPES = trim((string)(getenv('OIDC_SCOPES') ?: 'openid profile email groups'));
$OIDC_USERNAME_CLAIM = trim((string)(getenv('OIDC_USERNAME_CLAIM') ?: 'preferred_username'));
$OIDC_GROUPS_CLAIM = trim((string)(getenv('OIDC_GROUPS_CLAIM') ?: 'groups'));
$OIDC_EMAIL_CLAIM = trim((string)(getenv('OIDC_EMAIL_CLAIM') ?: 'email'));
$OIDC_REQUIRE_LDAP_USER = ((strcasecmp((string)(getenv('OIDC_REQUIRE_LDAP_USER') ?: 'TRUE'), 'FALSE') == 0) ? false : true);
$OIDC_LDAP_LOOKUP_ATTRIBUTE = trim((string)(getenv('OIDC_LDAP_LOOKUP_ATTRIBUTE') ?: $SITE_LOGIN_LDAP_ATTRIBUTE));
$OIDC_LDAP_EMAIL_ATTRIBUTE = trim((string)(getenv('OIDC_LDAP_EMAIL_ATTRIBUTE') ?: 'mail'));
$OIDC_END_SESSION_ENDPOINT = trim((string)(getenv('OIDC_END_SESSION_ENDPOINT') ?: ''));
$OIDC_POST_LOGOUT_REDIRECT_URI = trim((string)(getenv('OIDC_POST_LOGOUT_REDIRECT_URI') ?: ''));
$OIDC_HTTP_TIMEOUT = (int)(getenv('OIDC_HTTP_TIMEOUT') ?: 10);
if ($OIDC_HTTP_TIMEOUT < 2 || $OIDC_HTTP_TIMEOUT > 120) {
  $OIDC_HTTP_TIMEOUT = 10;
}
$OIDC_TLS_SKIP_VERIFY = ((strcasecmp((string)(getenv('OIDC_TLS_SKIP_VERIFY') ?: ''), 'TRUE') == 0) ? true : false);
$OIDC_ENABLED = ($OIDC_ISSUER_URL !== '' && $OIDC_CLIENT_ID !== '');

# Sending email

$SMTP['host'] = getenv('SMTP_HOSTNAME');
$SMTP['user'] = (getenv('SMTP_USERNAME') ? getenv('SMTP_USERNAME') : null);
$SMTP['pass'] = (getenv('SMTP_PASSWORD') ? getenv('SMTP_PASSWORD') : null);
$SMTP['port'] = (getenv('SMTP_HOST_PORT') ? getenv('SMTP_HOST_PORT') : 25);
$SMTP['helo'] = (getenv('SMTP_HELO_HOST') ? getenv('SMTP_HELO_HOST') : null);
$SMTP['ssl']  = ((strcasecmp(getenv('SMTP_USE_SSL'), 'TRUE') == 0) ? true : false);
$SMTP['tls']  = ((strcasecmp(getenv('SMTP_USE_TLS'), 'TRUE') == 0) ? true : false);
if ($SMTP['tls'] == true) {
  $SMTP['ssl'] = false;
}

$EMAIL_DOMAIN = (getenv('EMAIL_DOMAIN') ? getenv('EMAIL_DOMAIN') : null);

$default_email_from_domain = ($EMAIL_DOMAIN ? $EMAIL_DOMAIN : 'ldapusermanger.org');

$EMAIL['from_address'] = (getenv('EMAIL_FROM_ADDRESS') ? getenv('EMAIL_FROM_ADDRESS') : 'admin@' . $default_email_from_domain);
$EMAIL['from_name'] = (getenv('EMAIL_FROM_NAME') ? getenv('EMAIL_FROM_NAME') : $SITE_NAME);

if ($SMTP['host'] != '') {
  $EMAIL_SENDING_ENABLED = true;
} else {
  $EMAIL_SENDING_ENABLED = false;
}

# Account requests

$ACCOUNT_REQUESTS_ENABLED = ((strcasecmp(getenv('ACCOUNT_REQUESTS_ENABLED'), 'TRUE') == 0) ? true : false);
if (($EMAIL_SENDING_ENABLED == false) && ($ACCOUNT_REQUESTS_ENABLED == true)) {
  $ACCOUNT_REQUESTS_ENABLED = false;
  error_log("$log_prefix Config: ACCOUNT_REQUESTS_ENABLED was set to TRUE but SMTP_HOSTNAME wasn't set, so account requesting has been disabled as we can't send out the request email", 0);
}

$ACCOUNT_REQUESTS_ALWAYS_SHOW = ((strcasecmp(getenv('ACCOUNT_REQUESTS_ALWAYS_SHOW'), 'TRUE') == 0) ? true : false);
if ($ACCOUNT_REQUESTS_ENABLED == false) {
  $ACCOUNT_REQUESTS_ALWAYS_SHOW = false;
}
$ACCOUNT_REQUESTS_EMAIL = (getenv('ACCOUNT_REQUESTS_EMAIL') ? getenv('ACCOUNT_REQUESTS_EMAIL') : $EMAIL['from_address']);


# Debugging

$LDAP_DEBUG = ((strcasecmp(getenv('LDAP_DEBUG'), 'TRUE') == 0) ? true : false);
$LDAP_VERBOSE_CONNECTION_LOGS = ((strcasecmp(getenv('LDAP_VERBOSE_CONNECTION_LOGS'), 'TRUE') == 0) ? true : false);
$SESSION_DEBUG = ((strcasecmp(getenv('SESSION_DEBUG'), 'TRUE') == 0) ? true : false);
$SMTP['debug_level'] = getenv('SMTP_LOG_LEVEL');
if (!is_numeric($SMTP['debug_level']) or $SMTP['debug_level'] > 4 or $SMTP['debug_level'] < 0) {
  $SMTP['debug_level'] = 0;
}

# Sanity checking

$CUSTOM_LOGO = (getenv('CUSTOM_LOGO') ? getenv('CUSTOM_LOGO') : false);
$CUSTOM_STYLES = (getenv('CUSTOM_STYLES') ? getenv('CUSTOM_STYLES') : false);

$errors = '';

if (empty($LDAP['uri'])) {
  $errors .= "<div class='alert alert-warning'><p class='text-center'>LDAP_URI isn't set</p></div>\n";
}
if (empty($LDAP['base_dn'])) {
  $errors .= "<div class='alert alert-warning'><p class='text-center'>LDAP_BASE_DN isn't set</p></div>\n";
}
if (empty($LDAP['admin_bind_dn'])) {
  $errors .= "<div class='alert alert-warning'><p class='text-center'>LDAP_ADMIN_BIND_DN isn't set</p></div>\n";
}
if (empty($LDAP['admin_bind_pwd'])) {
  $errors .= "<div class='alert alert-warning'><p class='text-center'>LDAP_ADMIN_BIND_PWD isn't set</p></div>\n";
}
if (empty($LDAP['admins_group'])) {
  $errors .= "<div class='alert alert-warning'><p class='text-center'>LDAP_ADMINS_GROUP isn't set</p></div>\n";
}

if ($errors != '') {
  render_header('Fatal errors', false);
  print $errors;
  render_footer();
  exit(1);
}
