<?php

// Start output buffering to prevent any unwanted output
ob_start();

require_once(__DIR__ . '/../includes/web_functions.inc.php');
require_once(__DIR__ . '/../includes/config.inc.php');

set_page_access('user');

// Access global variables
global $USER_ID;

// Discard any output from includes and set JSON header
ob_end_clean();
header('Content-Type: application/json');

// Define the preferences directory (relative to application root)
$PREFS_DIR = dirname(__DIR__) . '/data/user_preferences';
$prefs_file = $PREFS_DIR . '/' . hash('sha256', $USER_ID) . '.json';

// Ensure preferences directory exists
if (!is_dir($PREFS_DIR)) {
  $old_umask = umask(0077);
  @mkdir($PREFS_DIR, 0700, true);
  umask($old_umask);
}

// Handle GET request - Load theme preference
if ($_SERVER['REQUEST_METHOD'] === 'GET') {
  $theme = 'green-cyberpunk'; // Default theme

  if (file_exists($prefs_file)) {
    $prefs = json_decode(file_get_contents($prefs_file), true);
    if (isset($prefs['theme'])) {
      $theme = $prefs['theme'];
    }
  }

  echo json_encode(['success' => true, 'theme' => $theme]);
  exit();
}

// Handle POST request - Save theme preference
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
  // Validate CSRF token
  csrf_verify_or_exit();

  $input = json_decode(file_get_contents('php://input'), true);

  if (!isset($input['theme'])) {
    http_response_code(400);
    echo json_encode(['success' => false, 'error' => 'Theme parameter is required']);
    exit();
  }

  $theme = $input['theme'];
  $valid_themes = ['green-cyberpunk', 'oled-black', 'standard', 'cyberpunk-red'];

  if (!in_array($theme, $valid_themes)) {
    http_response_code(400);
    echo json_encode(['success' => false, 'error' => 'Invalid theme']);
    exit();
  }

  // Load existing preferences or create new
  $prefs = [];
  if (file_exists($prefs_file)) {
    $prefs = json_decode(file_get_contents($prefs_file), true) ?: [];
  }

  // Update theme preference
  $prefs['theme'] = $theme;

  // Save preferences
  if (file_put_contents($prefs_file, json_encode($prefs, JSON_PRETTY_PRINT))) {
    echo json_encode(['success' => true, 'theme' => $theme]);
  } else {
    http_response_code(500);
    echo json_encode(['success' => false, 'error' => 'Failed to save theme preference']);
  }
  exit();
}

// Method not allowed
http_response_code(405);
echo json_encode(['success' => false, 'error' => 'Method not allowed']);
exit();
