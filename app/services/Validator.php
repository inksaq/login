<?php
namespace App\Services;

class Validator
{
    public function validateEmail($email)
    {
        return filter_var($email, FILTER_VALIDATE_EMAIL) !== false;
    }

    public function validatePassword($password)
    {
        // Password must be at least 8 characters long and contain at least one lowercase letter, one uppercase letter, and one digit
        return preg_match('/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)[a-zA-Z\d]{8,}$/', $password) === 1;
    }
}
 ?>
