<?php

require_once '/opt/ldap_user_manager/vendor/autoload.php';

#Default email text

$new_account_mail_subject = (getenv('NEW_ACCOUNT_EMAIL_SUBJECT') ? getenv('NEW_ACCOUNT_EMAIL_SUBJECT') : 'Your {organisation} account has been created.');
$new_account_mail_body = getenv('NEW_ACCOUNT_EMAIL_BODY') ?: <<<EoNA
You've been set up with an account for {organisation}.  Your credentials are:
<p>
Login: {login}<br>
Password: {password}
<p>
You should log into <a href="{change_password_url}">{change_password_url}</a> and change the password as soon as possible.
EoNA;

$reset_password_mail_subject = (getenv('RESET_PASSWORD_EMAIL_SUBJECT') ? getenv('RESET_PASSWORD_EMAIL_SUBJECT') : 'Your {organisation} password has been reset.');
$reset_password_mail_body = getenv('RESET_PASSWORD_EMAIL_BODY') ?: <<<EoRP
Your password for {organisation} has been reset.  Your new password is {password}
<p>
You should log into <a href="{change_password_url}">{change_password_url}</a> and change this password as soon as possible.
EoRP;

$new_message_mail_subject = (getenv('NEW_MESSAGE_EMAIL_SUBJECT') ? getenv('NEW_MESSAGE_EMAIL_SUBJECT') : 'New message from {sender_uid} on {organisation}');
$new_message_mail_body = getenv('NEW_MESSAGE_EMAIL_BODY') ?: <<<EoNM
You have a new message from <strong>{sender_uid}</strong> on {organisation}.
<p>{message_html}</p>
<p>Open <a href="{messages_url}">{messages_url}</a> to view your inbox.</p>
EoNM;

function resolve_template_domain_name(): string
{
  global $SERVER_HOSTNAME;

  $domain_name = trim((string)(getenv('DOMAIN_NAME') ?: ''));
  if ($domain_name === '') {
    $domain_name = trim((string)(getenv('EMAIL_DOMAIN') ?: ''));
  }
  if ($domain_name === '') {
    $domain_name = trim((string)$SERVER_HOSTNAME);
  }

  return $domain_name;
}


function parse_mail_text($template, $password, $login, $first_name, $last_name)
{

  global $ORGANISATION_NAME, $SITE_PROTOCOL, $SERVER_HOSTNAME, $SERVER_PATH;
  $domain_name = resolve_template_domain_name();

  $template = str_replace('{password}', $password, $template);
  $template = str_replace('{login}', $login, $template);
  $template = str_replace('{first_name}', $first_name, $template);
  $template = str_replace('{last_name}', $last_name, $template);

  $template = str_replace('{organisation}', $ORGANISATION_NAME, $template);
  $template = str_replace('{site_url}', "{$SITE_PROTOCOL}{$SERVER_HOSTNAME}{$SERVER_PATH}", $template);
  $template = str_replace('{change_password_url}', "{$SITE_PROTOCOL}{$SERVER_HOSTNAME}{$SERVER_PATH}change_password", $template);
  $template = str_replace('{DOMAIN_NAME}', $domain_name, $template);
  $template = str_replace('{domain_name}', $domain_name, $template);

  return $template;

}

function parse_new_message_mail_text(string $template, array $context = []): string
{
  global $ORGANISATION_NAME, $SITE_PROTOCOL, $SERVER_HOSTNAME, $SERVER_PATH;

  $sender_uid = trim((string)($context['sender_uid'] ?? ''));
  $recipient_uid = trim((string)($context['recipient_uid'] ?? ''));
  $message = (string)($context['message'] ?? '');

  $sender_uid_safe = htmlspecialchars($sender_uid, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
  $recipient_uid_safe = htmlspecialchars($recipient_uid, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
  $message_safe = htmlspecialchars($message, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
  $message_html = nl2br($message_safe, false);
  $domain_name_safe = htmlspecialchars(resolve_template_domain_name(), ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');

  $site_url = "{$SITE_PROTOCOL}{$SERVER_HOSTNAME}{$SERVER_PATH}";
  $messages_url = "{$SITE_PROTOCOL}{$SERVER_HOSTNAME}{$SERVER_PATH}messages/";

  $template = str_replace('{organisation}', htmlspecialchars((string)$ORGANISATION_NAME, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8'), $template);
  $template = str_replace('{site_url}', htmlspecialchars($site_url, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8'), $template);
  $template = str_replace('{messages_url}', htmlspecialchars($messages_url, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8'), $template);
  $template = str_replace('{DOMAIN_NAME}', $domain_name_safe, $template);
  $template = str_replace('{domain_name}', $domain_name_safe, $template);
  $template = str_replace('{sender_uid}', $sender_uid_safe, $template);
  $template = str_replace('{recipient_uid}', $recipient_uid_safe, $template);
  $template = str_replace('{message_html}', $message_html, $template);
  $template = str_replace('{message}', $message_safe, $template);

  return $template;
}

function send_email($recipient_email, $recipient_name, $subject, $body)
{

  global $EMAIL, $SMTP, $log_prefix;

  $mail = new PHPMailer\PHPMailer\PHPMailer();
  $mail->CharSet = 'UTF-8';
  $mail->isSMTP();

  $mail->SMTPDebug = $SMTP['debug_level'];
  $mail->Debugoutput = function ($message, $level) {
    error_log("$log_prefix SMTP (level $level): $message");
  };

  $mail->Host = $SMTP['host'];
  $mail->Port = $SMTP['port'];

  if (isset($SMTP['helo'])) {
    $mail->Helo = $SMTP['helo'];
  }

  if (isset($SMTP['user'])) {
    $mail->SMTPAuth = true;
    $mail->Username = $SMTP['user'];
    $mail->Password = $SMTP['pass'];
  }

  if ($SMTP['tls'] == true) {
    $mail->SMTPSecure = 'tls';
  }
  if ($SMTP['ssl'] == true) {
    $mail->SMTPSecure = 'ssl';
  }

  $mail->SMTPAutoTLS = false;
  $mail->setFrom($EMAIL['from_address'], $EMAIL['from_name']);
  $mail->addAddress($recipient_email, $recipient_name);
  $mail->Subject = $subject;
  $mail->Body = $body;
  $mail->IsHTML(true);

  if (!$mail->Send()) {
    error_log("$log_prefix SMTP: Unable to send email: " . $mail->ErrorInfo);
    return false;
  } else {
    error_log("$log_prefix SMTP: sent an email to $recipient_email ($recipient_name)");
    return true;
  }

}
