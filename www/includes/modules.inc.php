<?php

#Modules and how they can be accessed.

#access:
#auth = need to be logged-in to see it
#hidden_on_login = only visible when not logged in
#admin = need to be logged in as an admin to see it
#always = always visible

$MODULES = [
                   'log_in'          => 'hidden_on_login',
                   'change_password' => 'auth',
                   'account_manager' => 'admin',
                   'invite'          => 'auth',
                   'lease_ip'        => 'auth',
                   'mtls_certificate' => 'auth',
                   'messages'        => 'auth',
                 ];
// Optional per-module group gates (require ANY of these groups to see menu entry)
$MODULE_GROUP_GATES = [
  'invite'           => [getenv('INVITE_ACCESS_GROUP') ?: 'invite'],     // invite flow requires membership in INVITE_ACCESS_GROUP
  'lease_ip'         => [getenv('LEASE_IP_ACCESS_GROUP') ?: 'lease_ip'], // only show Lease IP if in LEASE_IP_ACCESS_GROUP
  'mtls_certificate' => ['mtls'],                                        // only show mTLS Certificate if in `mtls`
];

if ($ACCOUNT_REQUESTS_ENABLED == true) {
  if ($ACCOUNT_REQUESTS_ALWAYS_SHOW == true) {
    $MODULES['request_account'] = 'always';
  } else {
    $MODULES['request_account'] = 'hidden_on_login';
  }
}
if (!$REMOTE_HTTP_HEADERS_LOGIN || (!empty($OIDC_ENABLED) && $OIDC_ENABLED === true)) {
  $MODULES['log_out'] = 'auth';
}
