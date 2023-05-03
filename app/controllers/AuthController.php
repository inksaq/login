<?php

namespace App\Controllers;

use App\Models\UserRepository;
use App\Services\Validator;
use App\Services\View;
use App\Services\Mailer;
use App\Models\Auth;

class AuthController implements Controller
{
    protected $userRepository;
    protected $view;
    protected $validator;
    protected $mailer;
    protected $auth;

    public function __construct(UserRepository $userRepository, View $view, Validator $validator, Mailer $mailer, Auth $auth)
    {
        $this->userRepository = $userRepository;
        $this->view = $view;
        $this->validator = $validator;
        $this->mailer = $mailer;
        $this->auth = $auth;
    }

    public function handleRequest()
    {
        $action = $_GET['action'] ?? 'login';

        switch ($action) {
            case 'login':
                return $this->login();
            case 'logout':
                return $this->logout();
            case 'signup':
                return $this->signup();
            case 'verify':
                return $this->verify();
            case 'reset':
                return $this->resetPassword();
            case 'sendReset':
                return $this->sendPasswordResetEmail();
            default:
                return $this->login();
        }
    }

    public function login()
    {
        if (isset($_SESSION['user'])) {
            return header('Location: /u');
        }

        $errors = [];

        if ($_SERVER['REQUEST_METHOD'] === 'POST') {
            $email = $_POST['email'];
            $password = $_POST['password'];

            if ($this->userRepository->checkCredentials($email, $password)) {
                $_SESSION['user'] = $this->userRepository->findByEmail($email);
                return header('Location: /u');
            } else {
                $errors[] = 'Invalid email or password';
            }
        }

        return $this->view->render('auth/login', ['errors' => $errors]);
    }

    public function logout()
    {
        $this->session->remove('user');
        session_destroy();
        return header('Location: /auth/login');
    }

    public function signup()
{
    // If the user is already logged in, redirect them to the user home page.
    if ($this->session->has('user')) {
        return header('Location: /u');
    }

    // Initialize an empty errors array and successMessage variable.
    $errors = [];
    $successMessage = '';

    // Check if the request method is POST.
    if ($_SERVER['REQUEST_METHOD'] === 'POST') {
        // Retrieve the email, password, and passwordConfirm values from the form submission.
        $email = $_POST['email'];
        $password = $_POST['password'];
        $passwordConfirm = $_POST['passwordConfirm'];

        // Validate the submitted email.
        if (!$this->validator->isValidEmail($email)) {
            $errors[] = 'Invalid email address';
        }

        // Validate the submitted password.
        if (!$this->validator->isValidPassword($password)) {
            $errors[] = 'Password must be at least 8 characters long';
        }

        // Check if the submitted passwords match.
        if ($password !== $passwordConfirm) {
            $errors[] = 'Passwords do not match';
        }

        // If there are no errors, proceed with the user registration process.
        if (empty($errors)) {
            // Check if a user with the submitted email already exists in the database.
            $existingUser = $this->userRepository->findByEmail($email);
            if ($existingUser) {
                $errors[] = 'A user with this email already exists';
            } else {
                // Create a new user in the database with the submitted email and password.
                $user = $this->userRepository->create($email, $password);
                // Send a verification email to the newly registered user.
                $this->mailer->sendVerificationEmail($user);
                // Set a success message to be displayed on the signup page.
                $successMessage = 'Please check your email to verify your account';
            }
        }
    }

    // Render the signup view with the errors and successMessage variables.
    return $this->view->render('auth/signup', ['errors' => $errors, 'successMessage' => $successMessage]);
}

    public function verify()
    {
        $token = $_GET['token'];

        $user = $this->userRepository->findByVerificationToken($token);
        if ($user) {
            $this->userRepository->removeVerificationToken($user);
            $this->userRepository->setVerified($user);
            $this->session->set('user', $user);
            return header('Location: /u');
        } else {
            return $this->view->render('auth/verify', ['error' => 'Invalid or expired token']);
        }
    }

public function sendPasswordResetEmail()
{
    $email = $_POST['email'];
    $user = $this->userRepository->findByEmail($email);

    if ($user) {
        $this->auth->sendPasswordResetEmail($user);
        $message = 'Please check your email for instructions to reset your password.';
    } else {
        $message = 'User with this email address was not found.';
    }

    return $this->view->render('auth/reset_password', ['message' => $message]);
}

public function resetPassword()
{
    $token = $_GET['token'];
    $newPassword = $_POST['password'];

    if ($this->auth->resetPassword($token, $newPassword)) {
        $message = 'Password successfully reset. You can now log in with your new password.';
    } else {
        $message = 'Password reset failed. The reset token may have expired or been used already.';
    }

    return $this->view->render('auth/reset_password', ['message' => $message]);
}

}

?>
