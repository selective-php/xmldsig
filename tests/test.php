<?php

// Debug from console
// set XDEBUG_CONFIG="idekey=xdebug"
// php test.php

require_once __DIR__ . '/../vendor/autoload.php';

echo PHP_VERSION . "\n";

chdir('../');
system('composer test');

exit;

exit;
$phpunit = new \PHPUnit\TextUI\TestRunner();

try {
    $testResults = $phpunit->run($phpunit->getTest(__DIR__, 'Test.php'), [], [], false);
} catch (\PHPUnit\Framework\Exception $e) {
    echo $e->getMessage() . "\n";
    echo 'Unit tests failed.';
}
