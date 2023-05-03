<?php require_once __DIR__ . '/../includes/header.php'; ?>

<div class="profile-container">
    <h2>User Profile</h2>
    <p>ID: <?php echo $user->getId(); ?></p>
    <p>Email: <?php echo $user->getEmail(); ?></p>
    <!-- Add more user details as needed -->
</div>

<?php require_once __DIR__ . '/../includes/footer.php'; ?>
