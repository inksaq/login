<?php

namespace App\Services;

use App\Controllers\Controller;
use App\Services\View;

class Router
{
    protected $routes = [];

    private $view;

    public function __construct(View $view)
    {
        $this->view = $view;
    }

    public function addRoute($method, $path, $handler)
    {
        $this->routes[] = ['method' => $method, 'path' => $path, 'handler' => $handler];
    }

    public function get($path, $handler)
    {
        $this->addRoute('GET', $path, $handler);
    }

    public function post($path, $handler)
    {
        $this->addRoute('POST', $path, $handler);
    }

    public function dispatch()
    {
        $uri = $_SERVER['REQUEST_URI'];
        $method = $_SERVER['REQUEST_METHOD'];

        foreach ($this->routes as $route) {
            $routeMethod = $route['method'];
            $routePath = $route['path'];
            $handler = $route['handler'];

            $pattern = '/^' . str_replace('/', '\/', $routePath) . '$/';

            if ($method == $routeMethod && preg_match($pattern, $uri, $matches)) {
                array_shift($matches);
                $controller = new $handler[0]($this->view); // Pass the View object when creating controller instances
                $method = $handler[1];
                $controller->$method(...$matches);
                return;
            }
        }

        // If no route is found, throw a 404 error
        throw new \Exception('Page not found');
    }
}
?>
