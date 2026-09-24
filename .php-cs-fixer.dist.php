<?php

$finder = (new PhpCsFixer\Finder())
  ->in(__DIR__ . '/www')
  ->name('*.php')
  ->name('*.inc.php');

return (new PhpCsFixer\Config())
  ->setRules([
    '@PSR12' => true,
    'indentation_type' => true,
    'array_syntax' => ['syntax' => 'short'],
    'no_unused_imports' => true,
    'single_quote' => true,
    'trailing_comma_in_multiline' => ['elements' => ['arrays', 'arguments']],
    'no_trailing_whitespace' => true,
    'no_whitespace_in_blank_line' => true,
    'single_blank_line_at_eof' => true,
    'blank_line_after_opening_tag' => false,
    'no_blank_lines_after_class_opening' => true,
    'concat_space' => ['spacing' => 'one'],
  ])
  ->setIndent('  ')
  ->setLineEnding("\n")
  ->setFinder($finder);
