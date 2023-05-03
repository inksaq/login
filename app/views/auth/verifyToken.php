<?php if (isset($successMessage) && !empty($successMessage)) : ?>
    <p class="alert alert-success"><?= $successMessage ?></p>
	<?php endif; ?>
	<?php if (isset($errorMessage) && !empty($errorMessage)) : ?>
    <p class="alert alert-danger"><?= $errorMessage ?></p>
	<?php endif; ?>

<form action="/token?action=verify" method="post">
            <div class="form-group">
                <label for="token">Token</label>
                <input type="text" name="token" id="token" class="form-control" placeholder="verification token">
            </div>

            <div class="form-group">
                <button type="submit" class="btn btn-primary">Submit</button>
            </div>
        </form>
