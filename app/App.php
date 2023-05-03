<?php
namespace App;

use App\Controllers\AuthController;
use App\Controllers\HomeController;
use App\Controllers\ProfileController;
use App\Models\UserRepository;
use App\Models\Auth;
use App\Models\Database;
use App\Models\Session;
use App\Services\Router;
use App\Services\Validator;
use App\Services\View;
use App\Services\Mailer;

class App
{
protected $router;

public function __construct()
{
    Database::connect('mongodb://localhost:27017/', 'test');

}

public function run(){
  $headerPath = dirname(__DIR__) . '/app/views/partials/header.php';
      $footerPath = dirname(__DIR__) . '/app/views/partials/footer.php';
      $view = new View($headerPath, $footerPath);
    $userRepository = new UserRepository(new Database());
    $this->router = new Router($view);

    $session = new Session('test');

        $validator = new Validator();
        $mailer = new Mailer();
        $auth = new Auth($userRepository, $session, $mailer);

        $authController = new AuthController($userRepository, $view, $validator, $mailer, $auth);
        $homeController = new HomeController($view);
        $profileController = new ProfileController($userRepository, $view, $validator);

        $this->router->get('/auth/login', [$authController, 'login']);
        $this->router->post('/auth/login', [$authController, 'login']);
        $this->router->get('/auth/logout', [$authController, 'logout']);
        $this->router->get('/auth/signup', [$authController, 'signup']);
        $this->router->post('/auth/signup', [$authController, 'signup']);
        $this->router->get('/auth/verify', [$authController, 'verify']);
        $this->router->get('/auth/reset', [$authController, 'reset']);
        $this->router->post('/auth/reset', [$authController, 'reset']);
        $this->router->get('/auth/sendReset', [$authController, 'sendReset']);
        $this->router->post('/auth/sendReset', [$authController, 'sendReset']);

        $this->router->get('/', [$homeController, 'index']);
        $this->router->get('/portal', [$homeController, 'portal']);
        $this->router->get('/about', [$homeController, 'about']);

        $this->router->get('/u', [$profileController, 'user']);
        $this->router->get('/u/settings', [$profileController, 'settings']);
        $this->router->post('/u/settings', [$profileController, 'saveSettings']);

        $this->router->dispatch();
    }
}
?>
