<?php
session_start();
require_once 'db_connect.php';

if (!isset($_SESSION['voter_session'])) {
    header('Location: station_dashboard.php');
    exit();
}

// Fetch all portfolios
$stmt = $pdo->query("SELECT * FROM portfolios ORDER BY id ASC");
$portfolios = $stmt->fetchAll();

// Fetch all candidates
$stmt = $pdo->query("SELECT * FROM candidates ORDER BY portfolio_id, gender, fullname");
$candidates = $stmt->fetchAll(PDO::FETCH_ASSOC);

// Re-organize candidates: [portfolio_id][gender] = [list]
$candidates_by_portfolio = [];
foreach ($candidates as $c) {
    $candidates_by_portfolio[$c['portfolio_id']][$c['gender']][] = $c;
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Vote - BOA AMPONSEM SHS</title>
    <link rel="stylesheet" href="style.css">
    <style>
        body { font-family: Arial, sans-serif; background-color: #f4f6f9; padding: 20px; }
        .container { max-width: 960px; margin: 0 auto; background: white; padding: 20px; border-radius: 8px; box-shadow: 0 4px 6px rgba(0,0,0,0.1); }
        h1, h2, h3 { color: #333; text-align: center; }
        .portfolio-section { margin-bottom: 40px; border-bottom: 2px solid #eee; padding-bottom: 20px; }
        .gender-section { margin-bottom: 20px; }
        .gender-title { font-size: 1.2rem; font-weight: bold; color: #555; margin-bottom: 10px; text-transform: uppercase; border-left: 5px solid #007bff; padding-left: 10px; }
        .candidates-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(200px, 1fr)); gap: 20px; }
        .candidate-card { border: 1px solid #ddd; border-radius: 8px; padding: 15px; text-align: center; cursor: pointer; transition: transform 0.2s, box-shadow 0.2s; }
        .candidate-card:hover { transform: translateY(-5px); box-shadow: 0 5px 15px rgba(0,0,0,0.1); }
        .candidate-card img { width: 100px; height: 100px; object-fit: cover; border-radius: 50%; margin-bottom: 10px; }
        .candidate-card h4 { margin: 10px 0; font-size: 1rem; }
        .candidate-card input[type="radio"] { transform: scale(1.5); margin-top: 10px; }
        .submit-btn { display: block; width: 100%; padding: 15px; background-color: #28a745; color: white; border: none; border-radius: 8px; font-size: 1.5rem; cursor: pointer; margin-top: 40px; }
        .submit-btn:hover { background-color: #218838; }
        .voter-info { background: #e9ecef; padding: 10px; border-radius: 4px; text-align: center; margin-bottom: 20px; }
    </style>
</head>
<body>
    <div class="container">
        <h1>Voting Ballot</h1>
        <div class="voter-info">
            <strong>Voter:</strong> <?php echo htmlspecialchars($_SESSION['voter_name']); ?> |
            <strong>ID:</strong> <?php echo htmlspecialchars($_SESSION['voter_id_num']); ?>
        </div>

        <form action="submit_vote.php" method="POST">
            <?php foreach ($portfolios as $portfolio): ?>
                <div class="portfolio-section">
                    <h2><?php echo htmlspecialchars($portfolio['portfolio_name']); ?></h2>

                    <?php
                    $p_id = $portfolio['id'];
                    $has_candidates = false;

                    if (isset($candidates_by_portfolio[$p_id])) {
                        foreach (['Boy', 'Girl'] as $gender) {
                            if (isset($candidates_by_portfolio[$p_id][$gender])) {
                                $has_candidates = true;
                                echo '<div class="gender-section">';
                                echo '<div class="gender-title">' . $gender . 's</div>';
                                echo '<div class="candidates-grid">';
                                foreach ($candidates_by_portfolio[$p_id][$gender] as $candidate) {
                                    ?>
                                    <label class="candidate-card">
                                        <img src="<?php echo htmlspecialchars($candidate['photo']); ?>" alt="Photo">
                                        <h4><?php echo htmlspecialchars($candidate['fullname']); ?></h4>
                                        <input type="radio" name="vote[<?php echo $p_id; ?>]" value="<?php echo $candidate['id']; ?>">
                                    </label>
                                    <?php
                                }
                                echo '</div></div>';
                            }
                        }
                    }

                    if (!$has_candidates) {
                        echo '<p style="text-align:center; color:#777;">No candidates.</p>';
                    }
                    ?>
                </div>
            <?php endforeach; ?>

            <button type="submit" name="submit_vote" class="submit-btn" onclick="return confirm('Confirm vote submission? You cannot change it later.')">Submit Vote</button>
        </form>
    </div>
</body>
</html>
