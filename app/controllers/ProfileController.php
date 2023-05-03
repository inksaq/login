<?php

namespace App\Controllers;

use App\Models\UserRepository;
use App\Services\View;
use App\Services\Validator;

class ProfileController implements Controller
{
    protected $userRepository;
    protected $view;
    protected $validator;

    public function __construct(UserRepository $userRepository, View $view, Validator $validator)
    {
        $this->userRepository = $userRepository;
        $this->view = $view;
        $this->validator = $validator;
    }

    public function handleRequest()
    {
        $action = $_GET['action'] ?? 'user';

        switch ($action) {
            case 'user':
                return $this->user();
            case 'settings':
                return $this->settings();
            case 'saveSettings':
                return $this->saveSettings();
            default:
                return $this->user();
        }
    }

    public function user()
    {
        $user = $_SESSION['user'];
        return $this->view->render('profile/user', ['user' => $user]);
    }

    public function settings()
    {
        $user = $_SESSION['user'];
        return $this->view->render('profile/settings', ['user' => $user]);
    }

    public function saveSettings()
    {
        $user = $_SESSION['user'];

        if ($_SERVER['REQUEST_METHOD'] === 'POST') {
            $name = $_POST['name'];
            $email = $_POST['email'];
            $password = $_POST['password'];
            $passwordConfirm = $_POST['passwordConfirm'];

            if (!$this->validator->isValidEmail($email)) {
                $errors[] = 'Invalid email address';
            }

            if (!$this->validator->isValidPassword($password)) {
                $errors[] = 'Password must be at least 8 characters long';
            }

            if ($password !== $passwordConfirm) {
                $errors[] = 'Passwords do not match';
            }

            if (empty($errors)) {
                $this->userRepository->update($user->getId(), $name, $email, $password);
                $_SESSION['user'] = $this->userRepository->findById($user->getId());
                $successMessage = 'Settings saved successfully';
            }
        }

        return $this->view->render('profile/settings', ['user' => $user, 'successMessage' => $successMessage ?? '', 'errors' => $errors ?? []]);
    }
}
?>
