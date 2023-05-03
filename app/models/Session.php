<?php

namespace App\Models;

class Session
{
    private $name;

    public function __construct(string $name)
    {
        $this->name = $name;

        // Set session options
        $sessionOptions = [
            'use_cookies' => 1,
            'use_only_cookies' => 1,
            'cookie_lifetime' => 0,
            'cookie_secure' => 1,
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

        // Set session name
        session_name($name);

        // Start the session
        session_start();

        // Regenerate session ID periodically
        if (rand(1, 100) <= 5) {
            session_regenerate_id(true);
        }

        // Prevent session fixation attacks
        $this->preventSessionFixation();

        // Prevent session hijacking attacks
        $this->preventSessionHijacking();
    }

    public function set(string $key, $value): void
    {
        $_SESSION[$key] = $value;
    }

    public function get(string $key)
    {
        return $_SESSION[$key] ?? null;
    }

    public function remove(string $key): void
    {
        unset($_SESSION[$key]);
    }

    public function has(string $key): bool
    {
        return isset($_SESSION[$key]);
    }

    private function preventSessionFixation(): void
    {
        if (!$this->has('initiated')) {
            session_regenerate_id(true);
            $this->set('initiated', true);
        }
    }

    private function preventSessionHijacking(): void
    {
        $ipAddress = $_SERVER['REMOTE_ADDR'] ?? null;
        $userAgent = $_SERVER['HTTP_USER_AGENT'] ?? null;

        if ($ipAddress && $userAgent) {
            $sessionId = session_id();
            $hash = hash('sha256', $ipAddress . $userAgent . $sessionId);

            $this->set('fingerprint', $hash);

            if ($this->get('fingerprint') !== $hash) {
                session_regenerate_id(true);
                $this->set('fingerprint', $hash);
            }
        }
    }
}
?>
