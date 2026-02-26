<?php
session_start();
require_once '../db_connect.php';

if (!isset($_SESSION['admin_id'])) {
    header('Location: index.php');
    exit();
}

if (isset($_POST['reset_votes'])) {
    try {
        $pdo->exec("DELETE FROM votes");
        $pdo->exec("UPDATE voters SET has_voted = 0");
        $_SESSION['success'] = "Votes reset successfully";
    } catch (PDOException $e) {
        $_SESSION['error'] = "Error resetting votes: " . $e->getMessage();
    }
    header('Location: reset.php');
    exit();
}

if (isset($_POST['reset_all'])) {
    try {
        $pdo->exec("DELETE FROM votes");
        $pdo->exec("DELETE FROM voters");
        $pdo->exec("DELETE FROM candidates");
        // Optionally reset IDs or truncate tables
        $pdo->exec("TRUNCATE TABLE votes");
        $pdo->exec("TRUNCATE TABLE voters");
        $pdo->exec("TRUNCATE TABLE candidates");
        $_SESSION['success'] = "System reset successfully (Votes, Voters, Candidates cleared)";
    } catch (PDOException $e) {
        $_SESSION['error'] = "Error resetting system: " . $e->getMessage();
    }
    header('Location: reset.php');
    exit();
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>System Reset - BOA AMPONSEM SHS</title>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css">
    <link rel="stylesheet" href="../style.css">
    <style>
        body { font-family: Arial, sans-serif; margin: 0; padding: 0; background-color: #f4f6f9; }
        .wrapper { display: flex; min-height: 100vh; }
        .sidebar { width: 250px; background-color: #343a40; color: #fff; padding-top: 20px; flex-shrink: 0; }
        .sidebar h2 { text-align: center; margin-bottom: 30px; font-size: 1.5rem; }
        .sidebar ul { list-style: none; padding: 0; }
        .sidebar ul li { padding: 10px 20px; border-bottom: 1px solid #4b545c; }
        .sidebar ul li a { color: #c2c7d0; text-decoration: none; display: block; }
        .sidebar ul li a:hover { color: #fff; background-color: #494e53; }
        .sidebar ul li.active { background-color: #007bff; }
        .sidebar ul li.active a { color: #fff; }
        .main-content { flex-grow: 1; padding: 20px; }
        .header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 20px; background: white; padding: 15px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        .card { background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); margin-bottom: 20px; text-align: center; }
        .btn { padding: 0.75rem 1.5rem; color: white; border: none; border-radius: 4px; cursor: pointer; font-size: 1rem; margin: 10px; }
        .btn-warning { background-color: #ffc107; color: #212529; }
        .btn-danger { background-color: #dc3545; }
        .alert { padding: 15px; margin-bottom: 20px; border: 1px solid transparent; border-radius: 4px; text-align: left; }
        .alert-success { color: #155724; background-color: #d4edda; border-color: #c3e6cb; }
        .alert-danger { color: #721c24; background-color: #f8d7da; border-color: #f5c6cb; }
    </style>
</head>
<body>
    <div class="wrapper">
        <nav class="sidebar">
            <h2>Admin Panel</h2>
            <ul>
                <li><a href="dashboard.php"><i class="fas fa-tachometer-alt"></i> Dashboard</a></li>
                <li><a href="voters.php"><i class="fas fa-users"></i> Voters</a></li>
                <li><a href="candidates.php"><i class="fas fa-user-tie"></i> Candidates</a></li>
                <li><a href="portfolios.php"><i class="fas fa-list"></i> Portfolios</a></li>
                <li><a href="classes.php"><i class="fas fa-school"></i> Classes</a></li>
                <li><a href="stations.php"><i class="fas fa-building"></i> Polling Stations</a></li>
                <li><a href="results.php"><i class="fas fa-chart-pie"></i> Results</a></li>
                <li class="active"><a href="reset.php"><i class="fas fa-cogs"></i> System Reset</a></li>
                <li><a href="logout.php"><i class="fas fa-sign-out-alt"></i> Logout</a></li>
            </ul>
        </nav>
        <div class="main-content">
            <header class="header">
                <h1>System Reset</h1>
            </header>

            <?php if (isset($_SESSION['success'])): ?>
                <div class="alert alert-success"><?php echo $_SESSION['success']; unset($_SESSION['success']); ?></div>
            <?php endif; ?>
            <?php if (isset($_SESSION['error'])): ?>
                <div class="alert alert-danger"><?php echo $_SESSION['error']; unset($_SESSION['error']); ?></div>
            <?php endif; ?>

            <div class="card">
                <h3>Reset Votes Only</h3>
                <p>This will delete all votes and reset voter status to "Not Voted". Voters and Candidates will remain.</p>
                <form action="reset.php" method="POST" onsubmit="return confirm('Are you sure you want to reset all votes? This action cannot be undone.');">
                    <button type="submit" name="reset_votes" class="btn btn-warning">Reset Votes</button>
                </form>
            </div>

            <div class="card">
                <h3>Full System Reset</h3>
                <p>This will delete ALL votes, voters, and candidates. Only admin accounts, classes, portfolios, and stations will remain.</p>
                <form action="reset.php" method="POST" onsubmit="return confirm('WARNING: Are you sure you want to delete EVERYTHING? This cannot be undone.');">
                    <button type="submit" name="reset_all" class="btn btn-danger">Reset Everything</button>
                </form>
            </div>
        </div>
    </div>
</body>
</html>
