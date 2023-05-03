<div id="login" class="background">
<form method="post" action="/auth/signup">
    <h1>Signup</h1>
		<?php if (isset($errorMessage) && !empty($errorMessage)) : ?>
				<div class="alert alert-danger"><?= $errorMessage ?></div>
		<?php endif; ?>
    <label for="email">Email:</label>
    <input type="email" name="email" id="email" required><br>
    <label for="password">Password:</label>
    <input type="password" name="password" id="password" required><br>
    <label for="confirm_password">Confirm Password:</label>
    <input type="password" name="confirm_password" id="confirm_password" required><br>
    <button type="submit">Signup</button>
</form>
</div>
