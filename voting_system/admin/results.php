<?php
session_start();
require_once '../db_connect.php';

if (!isset($_SESSION['admin_id'])) {
    header('Location: index.php');
    exit();
}

// Fetch results
$sql = "SELECT c.*, p.portfolio_name,
        (SELECT COUNT(*) FROM votes v WHERE v.candidate_id = c.id) as vote_count
        FROM candidates c
        JOIN portfolios p ON c.portfolio_id = p.id
        ORDER BY p.id ASC, vote_count DESC";
$stmt = $pdo->query($sql);
$candidates = $stmt->fetchAll(PDO::FETCH_ASSOC);

// Group by Portfolio
$results = [];
foreach ($candidates as $c) {
    $results[$c['portfolio_name']][] = $c;
}

// Calculate total votes per portfolio (to get percentage)
$portfolio_totals = [];
foreach ($results as $p_name => $cands) {
    $total = 0;
    foreach ($cands as $c) {
        $total += $c['vote_count'];
    }
    $portfolio_totals[$p_name] = $total;
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Results - BOA AMPONSEM SHS</title>
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
        .result-card { background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); margin-bottom: 20px; }
        .result-card h3 { border-bottom: 2px solid #007bff; padding-bottom: 10px; margin-bottom: 20px; color: #333; }
        .candidate-row { display: flex; align-items: center; margin-bottom: 15px; padding: 10px; border-bottom: 1px solid #eee; }
        .candidate-row:last-child { border-bottom: none; }
        .candidate-img { width: 60px; height: 60px; object-fit: cover; border-radius: 50%; margin-right: 20px; }
        .candidate-info { flex-grow: 1; }
        .candidate-name { font-size: 1.1rem; font-weight: bold; }
        .vote-count { font-size: 1.2rem; font-weight: bold; color: #007bff; }
        .progress-bar-bg { background-color: #e9ecef; height: 10px; border-radius: 5px; margin-top: 5px; overflow: hidden; }
        .progress-bar { height: 100%; background-color: #28a745; }
        .winner-badge { background-color: #ffc107; color: #333; padding: 2px 8px; border-radius: 4px; font-size: 0.8rem; margin-left: 10px; }
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
                <li class="active"><a href="results.php"><i class="fas fa-chart-pie"></i> Results</a></li>
                <li><a href="reset.php"><i class="fas fa-cogs"></i> System Reset</a></li>
                <li><a href="logout.php"><i class="fas fa-sign-out-alt"></i> Logout</a></li>
            </ul>
        </nav>
        <div class="main-content">
            <header class="header">
                <h1>Election Results</h1>
                <button onclick="window.print()" class="btn" style="background:#007bff; color:white; border:none; padding:10px 20px; border-radius:4px; cursor:pointer;"><i class="fas fa-print"></i> Print Results</button>
            </header>

            <?php foreach ($results as $portfolio_name => $candidates_list): ?>
                <div class="result-card">
                    <h3><?php echo htmlspecialchars($portfolio_name); ?></h3>
                    <?php
                    $total_votes = $portfolio_totals[$portfolio_name];
                    $max_votes = 0;
                    if (!empty($candidates_list)) {
                        $max_votes = $candidates_list[0]['vote_count']; // Since ordered by DESC
                    }

                    foreach ($candidates_list as $index => $candidate):
                        $percentage = ($total_votes > 0) ? round(($candidate['vote_count'] / $total_votes) * 100, 1) : 0;
                        $is_winner = ($candidate['vote_count'] == $max_votes && $max_votes > 0);
                    ?>
                        <div class="candidate-row">
                            <img src="../<?php echo $candidate['photo']; ?>" class="candidate-img" alt="Photo">
                            <div class="candidate-info">
                                <div class="candidate-name">
                                    <?php echo htmlspecialchars($candidate['fullname']); ?>
                                    <?php if ($is_winner && $index == 0): ?>
                                        <span class="winner-badge"><i class="fas fa-trophy"></i> Winner</span>
                                    <?php endif; ?>
                                </div>
                                <div><?php echo $candidate['gender']; ?></div>
                                <div class="progress-bar-bg">
                                    <div class="progress-bar" style="width: <?php echo $percentage; ?>%"></div>
                                </div>
                            </div>
                            <div class="vote-count">
                                <?php echo $candidate['vote_count']; ?> votes<br>
                                <span style="font-size:0.8rem; color:#666;"><?php echo $percentage; ?>%</span>
                            </div>
                        </div>
                    <?php endforeach; ?>
                </div>
            <?php endforeach; ?>

            <?php if (empty($results)): ?>
                <p style="text-align:center; color:#666; margin-top:50px;">No results found.</p>
            <?php endif; ?>
        </div>
    </div>
</body>
</html>
