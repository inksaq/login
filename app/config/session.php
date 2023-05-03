<?php

// Set session options
$sessionOptions = [
    'use_cookies' => 1,
    'use_only_cookies' => 1,
    'cookie_lifetime' => 0,
    'cookie_secure' => 0,
    'cookie_httponly' => 1,
    'use_strict_mode' => 1,
    'entropy_file' => '/dev/urandom',
    'entropy_length' => 32,
    'hash_function' => 'sha256',
    'hash_bits_per_character' => 5,
    'gc_maxlifetime' => 1440,
];

// Apply session options
foreach ($sessionOptions as $key => $value) {
    ini_set('session.' . $key, $value);
}

// Start the session
session_start();
?>
