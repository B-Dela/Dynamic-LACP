<?php
ob_start(); // Start output buffering to prevent header errors
require_once '../db_connect.php';

// session_start() is called in db_connect.php if needed.
// However, to be safe and explicit:
if (session_status() == PHP_SESSION_NONE) {
    session_start();
}

if (isset($_POST['login'])) {
    $username = trim($_POST['username']);
    $password = $_POST['password'];

    // Basic validation
    if (empty($username) || empty($password)) {
        $_SESSION['error'] = 'Please fill in all fields';
        header('Location: index.php');
        exit();
    }

    try {
        $stmt = $pdo->prepare("SELECT * FROM admin WHERE username = :username");
        $stmt->execute(['username' => $username]);
        $user = $stmt->fetch();

        if ($user && password_verify($password, $user['password'])) {
            // Regenerate session ID for security
            session_regenerate_id(true);

            $_SESSION['admin_id'] = $user['id'];
            $_SESSION['username'] = $user['username'];
            header('Location: dashboard.php');
            exit();
        } else {
            $_SESSION['error'] = 'Invalid username or password';
            header('Location: index.php');
            exit();
        }
    } catch (PDOException $e) {
        $_SESSION['error'] = 'Database error: ' . $e->getMessage();
        header('Location: index.php');
        exit();
    }
} else {
    header('Location: index.php');
    exit();
}
ob_end_flush();
?>
