<?php

set_include_path('.:' . __DIR__ . '/../includes/');

include_once 'web_functions.inc.php';

$scope = strtolower(trim((string)($_GET['scope'] ?? '')));
if (!in_array($scope, ['local', 'global', 'auto'], true)) {
  $scope = 'normal';
}

log_out($scope);
