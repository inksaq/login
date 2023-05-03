<?php if (isset($successMessage) && !empty($successMessage)) : ?>
    <p class="alert alert-success"><?= $successMessage ?></p>
	<?php endif; ?>
	<?php if (isset($errorMessage) && !empty($errorMessage)) : ?>
    <p class="alert alert-danger"><?= $errorMessage ?></p>
	<?php endif; ?>
<form action="/token?action=renew" method="post" id="renewTokenForm">
            <div class="form-group">
                <label for="email">Email</label>
                <input type="email" name="email" id="email" class="form-control" placeholder="account's email">
            </div>

            <div class="form-group">
                <button type="submit" class="btn btn-primary">Request New Token</button>
            </div>
        </form>
