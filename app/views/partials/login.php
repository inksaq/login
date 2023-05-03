<div id="login" class="background">
<h1>Login</h1>
<?php if (isset($errorMessage) && !empty($errorMessage)) : ?>
		<div class="alert alert-danger"><?= $errorMessage ?></div>
<?php endif; ?>
<form method="post" action="/auth/login">
	<label for="email">Email:</label>
	<input type="email" name="email" required><br>
<label for="password">Password:</label>
	<input type="password" name="password" required><br>

 <button type="submit" name="submit">Login</button><br>
</form>
</div>
