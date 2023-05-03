<?php
namespace App\Models;

use MongoDB\BSON\ObjectId;

class User
{
    private ?ObjectId $_id;
    private string $name;
    private string $email;
    private string $passwordHash;
    private string $uuid;
    private bool $emailVerified;
    private ?string $verificationToken;

    public function __construct($id = null, $name = '', $email = '', $passwordHash = '', $uuid = '', $emailVerified = false, $verificationToken = null)
    {
        $this->_id = $id ? new ObjectId($id) : null;
        $this->name = $name;
        $this->email = $email;
        $this->passwordHash = $passwordHash;
        $this->uuid = $uuid;
        $this->emailVerified = $emailVerified;
        $this->verificationToken = $verificationToken;
    }

    public function getId(): ?string
    {
        return $this->_id ? (string) $this->_id : null;
    }

    public function setId(string $id): void
    {
        $this->_id = new ObjectId($id);
    }

    public function getName(): string
    {
        return $this->name;
    }

    public function setName(string $name): void
    {
        $this->name = $name;
    }

    public function getEmail(): string
    {
        return $this->email;
    }

    public function setEmail(string $email): void
    {
        $this->email = $email;
    }

    public function getPasswordHash(): string
    {
        return $this->passwordHash;
    }

    public function setPasswordHash(string $passwordHash): void
    {
        $this->passwordHash = $passwordHash;
    }

    public function getUuid(): string
    {
        return $this->uuid;
    }

    public function setUuid(string $uuid): void
    {
        $this->uuid = $uuid;
    }

    public function isEmailVerified(): bool
    {
        return $this->emailVerified;
    }

    public function setEmailVerified(bool $emailVerified): void
    {
        $this->emailVerified = $emailVerified;
    }

    public function getVerificationToken(): ?string
    {
        return $this->verificationToken;
    }

    public function setVerificationToken(?string $verificationToken): void
    {
        $this->verificationToken = $verificationToken;
    }
}
?>
