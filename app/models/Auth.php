<?php
namespace App\Models;

use App\Services\Mailer;

class Auth
{
    private $userRepository;
    private $session;
    private $mailer;

    public function __construct(UserRepository $userRepository, Session $session, Mailer $mailer)
    {
        $this->userRepository = $userRepository;
        $this->session = $session;
        $this->mailer = $mailer;
    }

    public function login($email, $password)
    {
        // Find user in database by email
        $user = $this->userRepository->findByEmail($email);

        // Verify password
        if ($user && password_verify($password, $user->getPassword())) {
            // Password is correct, set session variable to keep user logged in
            $this->session->set('user_id', $user->getId());

            return true;
        }

        return false;
    }

    public function logout()
    {
        // Clear session variable to log out user
        $this->session->remove('user_id');
    }

    public function isLoggedIn()
    {
        // Check if session variable exists to determine if user is logged in
        return $this->session->has('user_id');
    }

    public function sendVerificationEmail($user)
    {
        // Generate random token for email verification
        $token = bin2hex(random_bytes(16));

        // Save token in user record
        $user->setVerificationToken($token);
        $this->userRepository->save($user);

        // Send verification email to user
        $subject = 'Verify your email address';
        $body = 'Click the following link to verify your email address: ' .
            $_SERVER['HTTP_HOST'] . '/auth?action=verify&token=' . $token;
        //$this->mailer->send($user->getEmail(), $subject, $body);
    }

    public function verifyEmail($token)
    {
        // Find user by verification token
        $user = $this->userRepository->findByVerificationToken($token);

        // If user is found, mark as verified and remove verification token
        if ($user) {
            $user->setIsVerified(true);
            $user->setVerificationToken(null);
            $this->userRepository->save($user);
            return true;
        }

        return false;
    }

    public function sendPasswordResetEmail($user)
    {
        // Generate random token for password reset
        $token = bin2hex(random_bytes(16));

        // Save token in user record
        $user->setPasswordResetToken($token);
        $this->userRepository->save($user);

        // Send password reset email to user
        $subject = 'Reset your password';
        $body = 'Click the following link to reset your password: ' .
            $_SERVER['HTTP_HOST'] . '/auth?action=reset&token=' . $token;
        //$this->mailer->send($user->getEmail(), $subject, $body);
    }

    public function resetPassword($token, $newPassword)
    {
        // Find user by password reset token
        $user = $this->userRepository->findByPasswordResetToken($token);

        // If user is found, update password and remove reset token
        if ($user) {
            $user->setPassword(password_hash($newPassword, PASSWORD_DEFAULT));
            $user->setPasswordResetToken(null);
            $this->userRepository->save($user);
            return true;
        }

        return false;
    }
}
?>
