<?php
session_start();
require_once '../db_connect.php';

if (!isset($_SESSION['admin_id'])) {
    header('Location: index.php');
    exit();
}

// Fetch stats
try {
    $voters_count = $pdo->query("SELECT COUNT(*) FROM voters")->fetchColumn();
    $candidates_count = $pdo->query("SELECT COUNT(*) FROM candidates")->fetchColumn();
    $portfolios_count = $pdo->query("SELECT COUNT(*) FROM portfolios")->fetchColumn();
    $votes_count = $pdo->query("SELECT COUNT(*) FROM voters WHERE has_voted = 1")->fetchColumn();
} catch (PDOException $e) {
    die("Database error: " . $e->getMessage());
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Admin Dashboard - BOA AMPONSEM SHS</title>
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
        .stats-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; }
        .stat-card { background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); text-align: center; }
        .stat-card h3 { margin: 0; font-size: 2rem; color: #333; }
        .stat-card p { color: #666; margin: 5px 0 0; }
        .stat-card .icon { font-size: 3rem; margin-bottom: 10px; color: #007bff; }
    </style>
</head>
<body>
    <div class="wrapper">
        <nav class="sidebar">
            <h2>Admin Panel</h2>
            <ul>
                <li class="active"><a href="dashboard.php"><i class="fas fa-tachometer-alt"></i> Dashboard</a></li>
                <li><a href="votes.php"><i class="fas fa-chart-pie"></i> Votes</a></li>
                <li><a href="voters.php"><i class="fas fa-users"></i> Voters</a></li>
                <li><a href="candidates.php"><i class="fas fa-user-tie"></i> Candidates</a></li>
                <li><a href="portfolios.php"><i class="fas fa-list"></i> Portfolios</a></li>
                <li><a href="classes.php"><i class="fas fa-school"></i> Classes</a></li>
                <li><a href="stations.php"><i class="fas fa-building"></i> Polling Stations</a></li>
                <li><a href="reset.php"><i class="fas fa-cogs"></i> System Reset</a></li>
                <li><a href="logout.php"><i class="fas fa-sign-out-alt"></i> Logout</a></li>
            </ul>
        </nav>
        <div class="main-content">
            <header class="header">
                <h1>Dashboard</h1>
                <div>Welcome, <?php echo htmlspecialchars($_SESSION['username']); ?></div>
            </header>

            <div class="stats-grid">
                <div class="stat-card">
                    <div class="icon"><i class="fas fa-list"></i></div>
                    <h3><?php echo $portfolios_count; ?></h3>
                    <p>Total Portfolios</p>
                </div>
                <div class="stat-card">
                    <div class="icon"><i class="fas fa-users"></i></div>
                    <h3><?php echo $candidates_count; ?></h3>
                    <p>Total Candidates</p>
                </div>
                <div class="stat-card">
                    <div class="icon"><i class="fas fa-user-friends"></i></div>
                    <h3><?php echo $voters_count; ?></h3>
                    <p>Total Voters</p>
                </div>
                <div class="stat-card">
                    <div class="icon"><i class="fas fa-vote-yea"></i></div>
                    <h3><?php echo $votes_count; ?></h3>
                    <p>Votes Cast</p>
                </div>
            </div>
        </div>
    </div>
</body>
</html>
