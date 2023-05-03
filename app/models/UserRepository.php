<?php
namespace App\Models;

use MongoDB\BSON\ObjectId;

class UserRepository
{
    private $db;

    public function __construct($database)
    {
        $this->db = $database;
    }

    public function createUser(User $user)
    {
        $userData = [
            '_id' => new ObjectId(),
            'name' => $user->getName(),
            'email' => $user->getEmail(),
            'password_hash' => $user->getPasswordHash(),
            'uuid' => $user->getUuid(),
            'email_verified' => $user->isEmailVerified(),
            'verification_token' => $user->getVerificationToken(),
            'created_at' => new \MongoDB\BSON\UTCDateTime(),
        ];

        return $this->db->users->insertOne($userData);
    }

    public function getUserByEmail(string $email): ?User
    {
        $userData = $this->db->users->findOne(['email' => $email]);

        if ($userData === null) {
            return null;
        }

        return $this->mapDataToUser($userData);
    }

    public function getUserById(string $id): ?User
    {
        $userData = $this->db->users->findOne(['_id' => new ObjectId($id)]);

        if ($userData === null) {
            return null;
        }

        return $this->mapDataToUser($userData);
    }

    public function updateUser(User $user): bool
    {
        $updateData = [
            'name' => $user->getName(),
            'email' => $user->getEmail(),
            'password_hash' => $user->getPasswordHash(),
            'uuid' => $user->getUuid(),
            'email_verified' => $user->isEmailVerified(),
            'verification_token' => $user->getVerificationToken(),
        ];

        $update = ['$set' => $updateData];

        $result = $this->db->users->updateOne(['_id' => new ObjectId($user->getId())], $update);

        return $result->getMatchedCount() > 0;
    }

    public function removeVerificationToken(string $id): bool
    {
        $update = [
            '$unset' => ['verification_token' => ''],
            '$set' => ['email_verified' => true],
        ];

        $result = $this->db->users->updateOne(['_id' => new ObjectId($id)], $update);

        return $result->getMatchedCount() > 0;
    }

    public function getAllUsers(): array
    {
        $usersData = $this->db->users->find();

        $users = [];

        foreach ($usersData as $userData) {
            $users[] = $this->mapDataToUser($userData);
        }

        return $users;
    }

    private function mapDataToUser(array $userData): User
    {
        return new User(
            (string) $userData['_id'],
            $userData['name'],
            $userData['email'],
            $userData['password_hash'],
            $userData['uuid'],
            $userData['email_verified'],
            $userData['verification_token']
        );
    }
}
  ?>
