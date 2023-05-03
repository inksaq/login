<?php

namespace App\Services;

class View
{
    private string $headerTemplate;
    private string $footerTemplate;

    public function __construct(string $headerTemplate, string $footerTemplate)
    {
        $this->headerTemplate = $headerTemplate;
        $this->footerTemplate = $footerTemplate;
    }

    public function render(string $contentTemplate, array $context = []): void
    {
        // Start output buffering
        ob_start();

        // Render the header
        require $this->headerTemplate;

        // Render the content
        extract($context);
        $contentPath = dirname(__DIR__) . '/views/' . $contentTemplate . '.php';
        require $contentPath;

        // Render the footer
        require $this->footerTemplate;

        // End output buffering and output the result
        ob_end_flush();
    }

    public function parseAction(): string
    {
        if (isset($_GET['action'])) {
            return $_GET['action'];
        } else {
            return '';
        }
    }

    public function parseToken(): ?string
    {
        if (isset($_GET['token'])) {
            return $_GET['token'];
        } else {
            return null;
        }
    }
}
?>
