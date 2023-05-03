<?php require_once __DIR__ . '/../includes/header.php'; ?>


<div class="login-container">
  <div id="login" class="background">
<button id="toggleTokenBtn" data-action="renew">Renew Token</button>

    <div id="verifyTokenForm" style="display: <?php echo $form === 'verify' ? 'block' : 'none'; ?>;">
        <?php require_once __DIR__ . '/../../views/auth/verifyToken.php'; ?>
    </div>

    <div id="renewTokenForm" style="display: <?php echo $form === 'renew' ? 'block' : 'none'; ?>;">
        <?php require_once __DIR__ . '/../../views/auth/renewToken.php'; ?>
    </div>

    <script>
const toggleTokenBtn = document.getElementById('toggleTokenBtn');
const verifyTokenForm = document.getElementById('verifyTokenForm');
const renewTokenForm = document.getElementById('renewTokenForm');

toggleTokenBtn.addEventListener('click', () => {
    const action = toggleTokenBtn.getAttribute('data-action');
    updateDisplay(action);
});

function updateDisplay(action) {
    if (action === 'renew') {
        verifyTokenForm.style.display = 'none';
        renewTokenForm.style.display = 'block';
        toggleTokenBtn.textContent = 'Verify Token';
        toggleTokenBtn.setAttribute('data-action', 'verify');
        updateUrl('renew');
    } else {
        verifyTokenForm.style.display = 'block';
        renewTokenForm.style.display = 'none';
        toggleTokenBtn.textContent = 'Renew Token';
        toggleTokenBtn.setAttribute('data-action', 'renew');
        updateUrl('verify');
    }
}

function updateUrl(action) {
    const newUrl = new URL(window.location.href);
    newUrl.searchParams.set('action', action);
    history.pushState({}, '', newUrl);
}

// Update display on page load
const urlParams = new URLSearchParams(window.location.search);
const action = urlParams.get('action');
if (action === 'renew' || action === 'verify') {
    updateDisplay(action);
}
    </script>
  </div>
</div>
<?php require_once __DIR__ . '/../includes/footer.php'; ?>
