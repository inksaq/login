<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title><?php echo $title ?></title>
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <link href="//fonts.googleapis.com/css?family=Raleway:400,300,600" rel="stylesheet" type="text/css">
    <link rel="stylesheet" href="/css/normalize.css">
    <link rel="stylesheet" href="/css/skeleton.css">
    <link rel="stylesheet" href="/css/custom.css">
    <link rel="stylesheet" href="/css/forum-framework.css">
    <link rel="icon" type="image/png" href="/images/favicon.png">
</head>
<body>
    <nav class="navbar">
        <a href="#">Website Title</a>
        <div class="dropdown">
  <button class="dropdown-btn">Dropdown 1</button>
  <div class="dropdown-content">
    <a href="#">Link 1</a>
    <a href="#">Link 2</a>
    <a href="#">Link 3</a>
  </div>
</div>

<div class="dropdown">
  <button class="dropdown-btn">Dropdown 2</button>
  <div class="dropdown-content">
    <a href="#">Link 4</a>
    <a href="#">Link 5</a>
    <a href="#">Link 6</a>
  </div>
</div>
<a href="#" id="loginPortalBtn">
  <svg class="padlock" viewBox="0 0 24 24" width="24" height="24" stroke="currentColor" stroke-width="2" fill="none" stroke-linecap="round" stroke-linejoin="round">
    <rect x="3" y="11" width="18" height="11" rx="2" ry="2"></rect>
    <path d="M7 11V7a5 5 0 0 1 10 0v4"></path>
  </svg>
</a>



    </nav>

    <script>
        document.addEventListener('DOMContentLoaded', () => {
            const loginPortal = document.getElementById('loginPortal');
            const loginPortalBtn = document.getElementById('loginPortalBtn');

            loginPortalBtn.addEventListener('click', (event) => {
                event.preventDefault();
                loginPortal.style.display = 'block';
            });

            document.addEventListener('keydown', (event) => {
                if (event.key === 'Escape') {
                    loginPortal.style.display = 'none';
                }
            });
        });
    </script>
