const loginPortal = document.getElementById('loginPortal');
const loginPortalBtn = document.getElementById('loginPortalBtn');

loginPortalBtn.addEventListener('click', () => {
    loginPortal.style.display = 'block';
});

document.addEventListener('keydown', (event) => {
    if (event.key === 'Escape') {
        loginPortal.style.display = 'none';
    }
});

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
