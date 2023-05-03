<div id="overlay" class="overlay"></div>
<div id="loginPortal" style="display: none;">
  <div class="login-container">
    <div id="login" class="background">
      <button id="toggleFormsBtn">Switch to Signup</button>

      <div id="loginForm" style="display:block;">
        <?php require_once __DIR__ . '/login.php'; ?>
      </div>

      <div id="signupForm" style="display:none;">
        <?php require_once __DIR__ . '/signup.php'; ?>
      </div>
    </div>
  </div>
</div>
</div>

<script>
  const toggleFormsBtn = document.getElementById('toggleFormsBtn');
  const loginForm = document.getElementById('loginForm');
  const signupForm = document.getElementById('signupForm');

  toggleFormsBtn.addEventListener('click', () => {
    if (loginForm.style.display === 'block') {
      loginForm.style.display = 'none';
      signupForm.style.display = 'block';
      toggleFormsBtn.textContent = 'Switch to Login';
    } else {
      loginForm.style.display = 'block';
      signupForm.style.display = 'none';
      toggleFormsBtn.textContent = 'Switch to Signup';
    }
  });

  const overlay = document.getElementById('overlay');

  loginPortalBtn.addEventListener('click', () => {
    overlay.style.display = 'block';
    loginPortal.style.display = 'block';
  });

  // Add a click event listener to close the login portal when the overlay is clicked
  overlay.addEventListener('click', () => {
    overlay.style.display = 'none';
    loginPortal.style.display = 'none';
  });

  // Update the Escape key event listener
  document.addEventListener('keydown', (event) => {
    if (event.key === 'Escape') {
      overlay.style.display = 'none';
      loginPortal.style.display = 'none';
    }
  });
</script>
<script src="/js/loginportal.js"></script>
