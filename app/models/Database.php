<?php

namespace App\Models;

use MongoDB\Client;
use MongoDB\Database as MongoDatabase;

class Database
{
    private static MongoDatabase $database;

    public static function connect(string $uri, string $databaseName)
    {
        $client = new Client($uri);
        self::$database = $client->selectDatabase($databaseName);
    }

    public static function getDatabase(): MongoDatabase
    {
        if (!isset(self::$database)) {
            throw new \RuntimeException('Database not connected');
        }
        return self::$database;
    }
}
?>
