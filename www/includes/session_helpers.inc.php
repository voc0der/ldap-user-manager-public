<?php

if (!function_exists('lum_start_session')) {
  /**
   * Start a session safely. Returns true when a session is active.
   */
  function lum_start_session(array $cookie_params = []): bool
  {
    if (session_status() === PHP_SESSION_ACTIVE) {
      return true;
    }

    if (headers_sent()) {
      return false;
    }

    if (!empty($cookie_params)) {
      @session_set_cookie_params($cookie_params);
    }

    @session_start();

    return session_status() === PHP_SESSION_ACTIVE;
  }
}
