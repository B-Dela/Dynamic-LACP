<?php
session_start();
require_once '../db_connect.php';

if (!isset($_SESSION['admin_id'])) {
    header('Location: index.php');
    exit();
}

// Handle Add Portfolio
if (isset($_POST['add_portfolio'])) {
    $portfolio_name = trim($_POST['portfolio_name']);
    $short_code = trim($_POST['short_code']);

    if (!empty($portfolio_name) && !empty($short_code)) {
        try {
            $stmt = $pdo->prepare("INSERT INTO portfolios (portfolio_name, short_code) VALUES (:portfolio_name, :short_code)");
            $stmt->execute(['portfolio_name' => $portfolio_name, 'short_code' => $short_code]);
            $_SESSION['success'] = "Portfolio added successfully";
        } catch (PDOException $e) {
            $_SESSION['error'] = "Error adding portfolio: " . $e->getMessage();
        }
    } else {
        $_SESSION['error'] = "All fields are required";
    }
    header('Location: portfolios.php');
    exit();
}

// Handle Delete Portfolio
if (isset($_GET['delete'])) {
    $id = $_GET['delete'];
    try {
        $stmt = $pdo->prepare("DELETE FROM portfolios WHERE id = :id");
        $stmt->execute(['id' => $id]);
        $_SESSION['success'] = "Portfolio deleted successfully";
    } catch (PDOException $e) {
        $_SESSION['error'] = "Error deleting portfolio: " . $e->getMessage();
    }
    header('Location: portfolios.php');
    exit();
}

// Fetch Portfolios
$portfolios = $pdo->query("SELECT * FROM portfolios ORDER BY portfolio_name ASC")->fetchAll();
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Manage Portfolios - BOA AMPONSEM SHS</title>
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
        .card { background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); margin-bottom: 20px; }
        .form-group { margin-bottom: 1rem; }
        .form-group label { display: block; margin-bottom: 0.5rem; }
        .form-group input { width: 100%; padding: 0.75rem; border: 1px solid #ddd; border-radius: 4px; box-sizing: border-box; }
        .btn { padding: 0.75rem 1.5rem; background-color: #007bff; color: white; border: none; border-radius: 4px; cursor: pointer; }
        .btn-danger { background-color: #dc3545; }
        table { width: 100%; border-collapse: collapse; margin-top: 20px; }
        th, td { padding: 12px; text-align: left; border-bottom: 1px solid #ddd; }
        th { background-color: #f8f9fa; }
        .alert { padding: 15px; margin-bottom: 20px; border: 1px solid transparent; border-radius: 4px; }
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
                <li class="active"><a href="portfolios.php"><i class="fas fa-list"></i> Portfolios</a></li>
                <li><a href="classes.php"><i class="fas fa-school"></i> Classes</a></li>
                <li><a href="stations.php"><i class="fas fa-building"></i> Polling Stations</a></li>
                <li><a href="results.php"><i class="fas fa-chart-pie"></i> Results</a></li>
                <li><a href="reset.php"><i class="fas fa-cogs"></i> System Reset</a></li>
                <li><a href="logout.php"><i class="fas fa-sign-out-alt"></i> Logout</a></li>
            </ul>
        </nav>
        <div class="main-content">
            <header class="header">
                <h1>Manage Portfolios</h1>
            </header>

            <?php if (isset($_SESSION['success'])): ?>
                <div class="alert alert-success"><?php echo $_SESSION['success']; unset($_SESSION['success']); ?></div>
            <?php endif; ?>
            <?php if (isset($_SESSION['error'])): ?>
                <div class="alert alert-danger"><?php echo $_SESSION['error']; unset($_SESSION['error']); ?></div>
            <?php endif; ?>

            <div class="card">
                <h3>Add New Portfolio</h3>
                <form action="portfolios.php" method="POST">
                    <div class="form-group">
                        <label>Portfolio Name (e.g., School Prefect)</label>
                        <input type="text" name="portfolio_name" required>
                    </div>
                    <div class="form-group">
                        <label>Short Code (e.g., SP)</label>
                        <input type="text" name="short_code" required maxlength="10">
                    </div>
                    <button type="submit" name="add_portfolio" class="btn">Add Portfolio</button>
                </form>
            </div>

            <div class="card">
                <h3>Existing Portfolios</h3>
                <table>
                    <thead>
                        <tr>
                            <th>ID</th>
                            <th>Portfolio Name</th>
                            <th>Short Code</th>
                            <th>Action</th>
                        </tr>
                    </thead>
                    <tbody>
                        <?php foreach ($portfolios as $portfolio): ?>
                        <tr>
                            <td><?php echo $portfolio['id']; ?></td>
                            <td><?php echo htmlspecialchars($portfolio['portfolio_name']); ?></td>
                            <td><?php echo htmlspecialchars($portfolio['short_code']); ?></td>
                            <td>
                                <a href="portfolios.php?delete=<?php echo $portfolio['id']; ?>" class="btn btn-danger" onclick="return confirm('Are you sure?')">Delete</a>
                            </td>
                        </tr>
                        <?php endforeach; ?>
                    </tbody>
                </table>
            </div>
        </div>
    </div>
</body>
</html>
