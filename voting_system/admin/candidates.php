<?php
session_start();
require_once '../db_connect.php';

if (!isset($_SESSION['admin_id'])) {
    header('Location: index.php');
    exit();
}

// Handle Add Candidate
if (isset($_POST['add_candidate'])) {
    $fullname = trim($_POST['fullname']);
    $gender = $_POST['gender'];
    $portfolio_id = $_POST['portfolio_id'];

    // Photo Upload
    $photo_name = $_FILES['photo']['name'];
    $target_dir = "../uploads/";
    $target_file = $target_dir . basename($photo_name);
    $uploadOk = 1;
    $imageFileType = strtolower(pathinfo($target_file, PATHINFO_EXTENSION));

    // Basic Validation
    if (empty($fullname) || empty($gender) || empty($portfolio_id) || empty($photo_name)) {
        $_SESSION['error'] = "All fields are required";
    } else {
        // Generate Candidate ID
        try {
            // Get Short Code
            $stmt = $pdo->prepare("SELECT short_code FROM portfolios WHERE id = ?");
            $stmt->execute([$portfolio_id]);
            $short_code = $stmt->fetchColumn();

            if (!$short_code) {
                throw new Exception("Invalid Portfolio");
            }

            $gender_code = ($gender == 'Boy') ? 'B' : 'G';
            $prefix = $short_code . $gender_code;

            // Find last number
            $stmt = $pdo->prepare("SELECT candidate_id FROM candidates WHERE candidate_id LIKE ? ORDER BY LENGTH(candidate_id) DESC, candidate_id DESC LIMIT 1");
            $stmt->execute([$prefix . '%']);
            $last_id = $stmt->fetchColumn();

            if ($last_id) {
                $last_num = intval(substr($last_id, strlen($prefix)));
                $next_num = $last_num + 1;
            } else {
                $next_num = 1;
            }
            $candidate_id = $prefix . str_pad($next_num, 2, '0', STR_PAD_LEFT);

            // Upload Photo
            if (move_uploaded_file($_FILES['photo']['tmp_name'], $target_file)) {
                $photo_path = 'uploads/' . basename($photo_name); // Relative path for DB

                // Insert
                $stmt = $pdo->prepare("INSERT INTO candidates (candidate_id, fullname, gender, portfolio_id, photo) VALUES (:candidate_id, :fullname, :gender, :portfolio_id, :photo)");
                $stmt->execute([
                    'candidate_id' => $candidate_id,
                    'fullname' => $fullname,
                    'gender' => $gender,
                    'portfolio_id' => $portfolio_id,
                    'photo' => $photo_path
                ]);
                $_SESSION['success'] = "Candidate added successfully. ID: " . $candidate_id;
            } else {
                $_SESSION['error'] = "Failed to upload photo";
            }

        } catch (Exception $e) {
            $_SESSION['error'] = "Error: " . $e->getMessage();
        }
    }
    header('Location: candidates.php');
    exit();
}

// Handle Delete Candidate
if (isset($_GET['delete'])) {
    $id = $_GET['delete'];
    try {
        $stmt = $pdo->prepare("DELETE FROM candidates WHERE id = :id");
        $stmt->execute(['id' => $id]);
        $_SESSION['success'] = "Candidate deleted successfully";
    } catch (PDOException $e) {
        $_SESSION['error'] = "Error deleting candidate: " . $e->getMessage();
    }
    header('Location: candidates.php');
    exit();
}

// Fetch Candidates with Portfolio Name
$sql = "SELECT c.*, p.portfolio_name FROM candidates c JOIN portfolios p ON c.portfolio_id = p.id ORDER BY p.portfolio_name, c.gender, c.fullname";
$candidates = $pdo->query($sql)->fetchAll();

// Fetch Portfolios for Dropdown
$portfolios = $pdo->query("SELECT * FROM portfolios ORDER BY portfolio_name ASC")->fetchAll();
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Manage Candidates - BOA AMPONSEM SHS</title>
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
        .form-group input, .form-group select { width: 100%; padding: 0.75rem; border: 1px solid #ddd; border-radius: 4px; box-sizing: border-box; }
        .btn { padding: 0.75rem 1.5rem; background-color: #007bff; color: white; border: none; border-radius: 4px; cursor: pointer; }
        .btn-danger { background-color: #dc3545; }
        table { width: 100%; border-collapse: collapse; margin-top: 20px; }
        th, td { padding: 12px; text-align: left; border-bottom: 1px solid #ddd; }
        th { background-color: #f8f9fa; }
        .alert { padding: 15px; margin-bottom: 20px; border: 1px solid transparent; border-radius: 4px; }
        .alert-success { color: #155724; background-color: #d4edda; border-color: #c3e6cb; }
        .alert-danger { color: #721c24; background-color: #f8d7da; border-color: #f5c6cb; }
        .candidate-img { width: 50px; height: 50px; object-fit: cover; border-radius: 50%; }
    </style>
</head>
<body>
    <div class="wrapper">
        <nav class="sidebar">
            <h2>Admin Panel</h2>
            <ul>
                <li><a href="dashboard.php"><i class="fas fa-tachometer-alt"></i> Dashboard</a></li>
                <li><a href="voters.php"><i class="fas fa-users"></i> Voters</a></li>
                <li class="active"><a href="candidates.php"><i class="fas fa-user-tie"></i> Candidates</a></li>
                <li><a href="portfolios.php"><i class="fas fa-list"></i> Portfolios</a></li>
                <li><a href="classes.php"><i class="fas fa-school"></i> Classes</a></li>
                <li><a href="stations.php"><i class="fas fa-building"></i> Polling Stations</a></li>
                <li><a href="results.php"><i class="fas fa-chart-pie"></i> Results</a></li>
                <li><a href="reset.php"><i class="fas fa-cogs"></i> System Reset</a></li>
                <li><a href="logout.php"><i class="fas fa-sign-out-alt"></i> Logout</a></li>
            </ul>
        </nav>
        <div class="main-content">
            <header class="header">
                <h1>Manage Candidates</h1>
            </header>

            <?php if (isset($_SESSION['success'])): ?>
                <div class="alert alert-success"><?php echo $_SESSION['success']; unset($_SESSION['success']); ?></div>
            <?php endif; ?>
            <?php if (isset($_SESSION['error'])): ?>
                <div class="alert alert-danger"><?php echo $_SESSION['error']; unset($_SESSION['error']); ?></div>
            <?php endif; ?>

            <div class="card">
                <h3>Add New Candidate</h3>
                <form action="candidates.php" method="POST" enctype="multipart/form-data">
                    <div class="form-group">
                        <label>Full Name</label>
                        <input type="text" name="fullname" required>
                    </div>
                    <div class="form-group">
                        <label>Gender</label>
                        <select name="gender" required>
                            <option value="">Select Gender</option>
                            <option value="Boy">Boy</option>
                            <option value="Girl">Girl</option>
                        </select>
                    </div>
                    <div class="form-group">
                        <label>Portfolio</label>
                        <select name="portfolio_id" required>
                            <option value="">Select Portfolio</option>
                            <?php foreach ($portfolios as $p): ?>
                                <option value="<?php echo $p['id']; ?>"><?php echo htmlspecialchars($p['portfolio_name']); ?></option>
                            <?php endforeach; ?>
                        </select>
                    </div>
                    <div class="form-group">
                        <label>Photo</label>
                        <input type="file" name="photo" required accept="image/*">
                    </div>
                    <button type="submit" name="add_candidate" class="btn">Add Candidate</button>
                </form>
            </div>

            <div class="card">
                <h3>Existing Candidates</h3>
                <table>
                    <thead>
                        <tr>
                            <th>Photo</th>
                            <th>ID</th>
                            <th>Full Name</th>
                            <th>Gender</th>
                            <th>Portfolio</th>
                            <th>Action</th>
                        </tr>
                    </thead>
                    <tbody>
                        <?php foreach ($candidates as $candidate): ?>
                        <tr>
                            <td><img src="../<?php echo $candidate['photo']; ?>" class="candidate-img" alt="Photo"></td>
                            <td><?php echo $candidate['candidate_id']; ?></td>
                            <td><?php echo htmlspecialchars($candidate['fullname']); ?></td>
                            <td><?php echo $candidate['gender']; ?></td>
                            <td><?php echo htmlspecialchars($candidate['portfolio_name']); ?></td>
                            <td>
                                <a href="candidates.php?delete=<?php echo $candidate['id']; ?>" class="btn btn-danger" onclick="return confirm('Are you sure?')">Delete</a>
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
