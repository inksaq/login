<?php

namespace App\Controllers;

use App\Services\View;

class HomeController implements Controller
{
    protected $view;

    public function __construct(View $view)
    {
        $this->view = $view;
    }

    public function handleRequest()
    {
        $action = $_GET['action'] ?? 'index';

        switch ($action) {
            case 'portal':
                return $this->loginPortal();
            case 'about':
                return $this->about();
            default:
                return $this->index();
        }
    }

    public function index()
    {
        return $this->view->render('home/index');
    }

    public function loginPortal()
    {
      return $this->view->render('home/portal');
    }

    public function about()
    {
        return $this->view->render('home/about');
    }
}

?>
