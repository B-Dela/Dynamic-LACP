<?php
session_start();
require_once 'db_connect.php';

if (!isset($_SESSION['station_id'])) {
    header('Location: index.php');
    exit();
}

if (isset($_POST['verify_voter'])) {
    $voter_id = trim($_POST['voter_id']);

    if (!empty($voter_id)) {
        try {
            $stmt = $pdo->prepare("SELECT * FROM voters WHERE voter_id = :voter_id");
            $stmt->execute(['voter_id' => $voter_id]);
            $voter = $stmt->fetch();

            if ($voter) {
                if ($voter['has_voted']) {
                    $_SESSION['error'] = "You have already voted";
                } else {
                    $_SESSION['voter_session'] = $voter['id'];
                    $_SESSION['voter_name'] = $voter['fullname'];
                    $_SESSION['voter_id_num'] = $voter['voter_id'];
                    header('Location: vote.php');
                    exit();
                }
            } else {
                $_SESSION['error'] = "Voter not found";
            }
        } catch (PDOException $e) {
            $_SESSION['error'] = "Database error: " . $e->getMessage();
        }
    } else {
        $_SESSION['error'] = "Please enter a Voter ID";
    }
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Station Dashboard - BOA AMPONSEM SHS</title>
    <link rel="stylesheet" href="style.css">
    <style>
        body { font-family: Arial, sans-serif; background-color: #f4f6f9; display: flex; justify-content: center; align-items: center; height: 100vh; margin: 0; }
        .container { background: white; padding: 40px; border-radius: 8px; box-shadow: 0 4px 6px rgba(0,0,0,0.1); width: 100%; max-width: 500px; text-align: center; }
        h1 { margin-bottom: 20px; color: #333; }
        .form-group { margin-bottom: 20px; }
        input { width: 100%; padding: 15px; font-size: 1.2rem; border: 2px solid #ddd; border-radius: 4px; box-sizing: border-box; text-align: center; }
        .btn { width: 100%; padding: 15px; font-size: 1.2rem; background-color: #28a745; color: white; border: none; border-radius: 4px; cursor: pointer; }
        .btn:hover { background-color: #218838; }
        .logout { display: inline-block; margin-top: 20px; color: #dc3545; text-decoration: none; }
        .alert { padding: 15px; margin-bottom: 20px; border-radius: 4px; }
        .alert-error { background-color: #f8d7da; color: #721c24; border: 1px solid #f5c6cb; }
        .alert-success { background-color: #d4edda; color: #155724; border: 1px solid #c3e6cb; }
    </style>
</head>
<body>
    <div class="container">
        <h1><?php echo htmlspecialchars($_SESSION['station_name']); ?></h1>
        <p>Enter Voter ID to start voting process</p>

        <?php if (isset($_SESSION['error'])): ?>
            <div class="alert alert-error"><?php echo $_SESSION['error']; unset($_SESSION['error']); ?></div>
        <?php endif; ?>
        <?php if (isset($_SESSION['success'])): ?>
            <div class="alert alert-success"><?php echo $_SESSION['success']; unset($_SESSION['success']); ?></div>
        <?php endif; ?>

        <form action="station_dashboard.php" method="POST">
            <div class="form-group">
                <input type="text" name="voter_id" placeholder="Voter ID (e.g., 1A1001)" required autofocus autocomplete="off">
            </div>
            <button type="submit" name="verify_voter" class="btn">Verify & Vote</button>
        </form>

        <a href="logout.php" class="logout">Logout</a>
    </div>
</body>
</html>
