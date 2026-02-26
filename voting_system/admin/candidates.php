<?php
session_start();
require_once '../db_connect.php';

if (!isset($_SESSION['admin_id'])) {
    header('Location: index.php');
    exit();
}

$edit_mode = false;
$edit_candidate = null;

// Handle Add Candidate
if (isset($_POST['add_candidate'])) {
    $fullname = trim($_POST['fullname']);
    $gender = $_POST['gender'];
    $portfolio_id = $_POST['portfolio_id'];

    // Photo Upload
    $photo_name = $_FILES['photo']['name'];
    $photo_tmp_name = $_FILES['photo']['tmp_name'];
    $photo_error = $_FILES['photo']['error'];

    // Absolute path to uploads directory
    $upload_dir = __DIR__ . '/../uploads/';

    // Create uploads directory if it doesn't exist
    if (!is_dir($upload_dir)) {
        mkdir($upload_dir, 0755, true);
    }

    // Basic Validation
    if (empty($fullname) || empty($gender) || empty($portfolio_id) || empty($photo_name)) {
        $_SESSION['error'] = "All fields are required";
    } elseif ($photo_error !== UPLOAD_ERR_OK) {
        $_SESSION['error'] = "Upload error code: " . $photo_error;
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

            // Rename file to prevent conflicts
            $file_ext = strtolower(pathinfo($photo_name, PATHINFO_EXTENSION));
            $new_filename = $candidate_id . '.' . $file_ext;
            $target_file = $upload_dir . $new_filename;

            // Check if image file is a actual image or fake image
            $check = getimagesize($photo_tmp_name);
            if($check === false) {
                throw new Exception("File is not an image.");
            }

            // Allow certain file formats
            if($file_ext != "jpg" && $file_ext != "png" && $file_ext != "jpeg" && $file_ext != "gif" ) {
                throw new Exception("Sorry, only JPG, JPEG, PNG & GIF files are allowed.");
            }

            // Upload Photo
            if (move_uploaded_file($photo_tmp_name, $target_file)) {
                $photo_path = 'uploads/' . $new_filename; // Relative path for DB

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
                $_SESSION['error'] = "Failed to upload photo to destination.";
            }

        } catch (Exception $e) {
            $_SESSION['error'] = "Error: " . $e->getMessage();
        }
    }
    header('Location: candidates.php');
    exit();
}

// Handle Update Candidate
if (isset($_POST['update_candidate'])) {
    $id = $_POST['candidate_id'];
    $fullname = trim($_POST['fullname']);
    $gender = $_POST['gender'];
    $portfolio_id = $_POST['portfolio_id'];

    // Check if new photo uploaded
    $new_photo = !empty($_FILES['photo']['name']);

    if (empty($fullname) || empty($gender) || empty($portfolio_id)) {
        $_SESSION['error'] = "All text fields are required";
    } else {
        try {
            // Get existing data to check if ID needs regeneration (if portfolio/gender changed)
            // But usually changing portfolio/gender shouldn't change ID to avoid confusion,
            // OR it should. Let's keep ID same for simplicity unless critical.
            // Prompt doesn't specify ID regeneration on edit. Let's keep it simple: just update details.

            if ($new_photo) {
                $photo_name = $_FILES['photo']['name'];
                $photo_tmp_name = $_FILES['photo']['tmp_name'];
                $upload_dir = __DIR__ . '/../uploads/';

                // Get current photo to overwrite or delete?
                // Better to use existing candidate_id for filename
                $stmt = $pdo->prepare("SELECT candidate_id, photo FROM candidates WHERE id = ?");
                $stmt->execute([$id]);
                $current = $stmt->fetch();

                $file_ext = strtolower(pathinfo($photo_name, PATHINFO_EXTENSION));
                $new_filename = $current['candidate_id'] . '.' . $file_ext; // Reuse ID
                $target_file = $upload_dir . $new_filename;

                // Upload
                if (move_uploaded_file($photo_tmp_name, $target_file)) {
                    $photo_path = 'uploads/' . $new_filename;

                    $stmt = $pdo->prepare("UPDATE candidates SET fullname=?, gender=?, portfolio_id=?, photo=? WHERE id=?");
                    $stmt->execute([$fullname, $gender, $portfolio_id, $photo_path, $id]);
                } else {
                     throw new Exception("Failed to upload new photo.");
                }
            } else {
                $stmt = $pdo->prepare("UPDATE candidates SET fullname=?, gender=?, portfolio_id=? WHERE id=?");
                $stmt->execute([$fullname, $gender, $portfolio_id, $id]);
            }

            $_SESSION['success'] = "Candidate updated successfully.";

        } catch (Exception $e) {
            $_SESSION['error'] = "Error updating candidate: " . $e->getMessage();
        }
    }
    header('Location: candidates.php');
    exit();
}

// Handle Edit Mode
if (isset($_GET['edit'])) {
    $id = $_GET['edit'];
    $stmt = $pdo->prepare("SELECT * FROM candidates WHERE id = ?");
    $stmt->execute([$id]);
    $edit_candidate = $stmt->fetch();
    if ($edit_candidate) {
        $edit_mode = true;
    }
}

// Handle Delete Candidate
if (isset($_GET['delete'])) {
    $id = $_GET['delete'];
    try {
        // Get photo path to delete file
        $stmt = $pdo->prepare("SELECT photo FROM candidates WHERE id = ?");
        $stmt->execute([$id]);
        $photo_path = $stmt->fetchColumn();

        if ($photo_path) {
            $file_path = __DIR__ . '/../' . $photo_path;
            if (file_exists($file_path)) {
                unlink($file_path);
            }
        }

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
        .btn-warning { background-color: #ffc107; color: #212529; }
        .btn-danger { background-color: #dc3545; }
        .btn-info { background-color: #17a2b8; color: white; }
        table { width: 100%; border-collapse: collapse; margin-top: 20px; }
        th, td { padding: 12px; text-align: left; border-bottom: 1px solid #ddd; }
        th { background-color: #f8f9fa; }
        .alert { padding: 15px; margin-bottom: 20px; border: 1px solid transparent; border-radius: 4px; }
        .alert-success { color: #155724; background-color: #d4edda; border-color: #c3e6cb; }
        .alert-danger { color: #721c24; background-color: #f8d7da; border-color: #f5c6cb; }
        .candidate-img { width: 50px; height: 50px; object-fit: cover; border-radius: 50%; }

        @media print {
            .sidebar, .form-group, .card form, .card h3:first-child, .alert, .btn { display: none; } /* Hide Sidebar, Forms, Top Card Title, Alerts, Buttons */
            .wrapper { display: block; }
            .main-content { margin: 0; padding: 0; }
            .header { box-shadow: none; border-bottom: 2px solid #333; justify-content: center; }
            .header h1 { font-size: 2rem; margin: 0; }
            .card { box-shadow: none; padding: 0; }
            table { width: 100%; border: 1px solid #ddd; }
            th, td { border: 1px solid #ddd; padding: 10px; }
            th:last-child, td:last-child { display: none; } /* Hide Action Column */
            body { background-color: white; }
        }
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
                <button onclick="window.print()" class="btn btn-info"><i class="fas fa-print"></i> Print Candidates</button>
            </header>

            <?php if (isset($_SESSION['success'])): ?>
                <div class="alert alert-success"><?php echo $_SESSION['success']; unset($_SESSION['success']); ?></div>
            <?php endif; ?>
            <?php if (isset($_SESSION['error'])): ?>
                <div class="alert alert-danger"><?php echo $_SESSION['error']; unset($_SESSION['error']); ?></div>
            <?php endif; ?>

            <div class="card">
                <h3><?php echo $edit_mode ? 'Edit Candidate' : 'Add New Candidate'; ?></h3>
                <form action="candidates.php" method="POST" enctype="multipart/form-data">
                    <?php if ($edit_mode): ?>
                        <input type="hidden" name="candidate_id" value="<?php echo $edit_candidate['id']; ?>">
                    <?php endif; ?>

                    <div class="form-group">
                        <label>Full Name</label>
                        <input type="text" name="fullname" required value="<?php echo $edit_mode ? htmlspecialchars($edit_candidate['fullname']) : ''; ?>">
                    </div>
                    <div class="form-group">
                        <label>Gender</label>
                        <select name="gender" required>
                            <option value="">Select Gender</option>
                            <option value="Boy" <?php echo ($edit_mode && $edit_candidate['gender'] == 'Boy') ? 'selected' : ''; ?>>Boy</option>
                            <option value="Girl" <?php echo ($edit_mode && $edit_candidate['gender'] == 'Girl') ? 'selected' : ''; ?>>Girl</option>
                        </select>
                    </div>
                    <div class="form-group">
                        <label>Portfolio</label>
                        <select name="portfolio_id" required>
                            <option value="">Select Portfolio</option>
                            <?php foreach ($portfolios as $p): ?>
                                <option value="<?php echo $p['id']; ?>" <?php echo ($edit_mode && $edit_candidate['portfolio_id'] == $p['id']) ? 'selected' : ''; ?>><?php echo htmlspecialchars($p['portfolio_name']); ?></option>
                            <?php endforeach; ?>
                        </select>
                    </div>
                    <div class="form-group">
                        <label>Photo <?php echo $edit_mode ? '(Leave empty to keep current)' : ''; ?></label>
                        <input type="file" name="photo" <?php echo $edit_mode ? '' : 'required'; ?> accept="image/*">
                        <?php if ($edit_mode && !empty($edit_candidate['photo'])): ?>
                            <br><img src="../<?php echo $edit_candidate['photo']; ?>" width="50" style="margin-top:10px;">
                        <?php endif; ?>
                    </div>

                    <?php if ($edit_mode): ?>
                        <button type="submit" name="update_candidate" class="btn btn-warning">Update Candidate</button>
                        <a href="candidates.php" class="btn" style="background:#6c757d; color:white;">Cancel</a>
                    <?php else: ?>
                        <button type="submit" name="add_candidate" class="btn">Add Candidate</button>
                    <?php endif; ?>
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
                                <a href="candidates.php?edit=<?php echo $candidate['id']; ?>" class="btn btn-warning" style="padding: 5px 10px; font-size: 0.9rem;">Edit</a>
                                <a href="candidates.php?delete=<?php echo $candidate['id']; ?>" class="btn btn-danger" style="padding: 5px 10px; font-size: 0.9rem;" onclick="return confirm('Are you sure?')">Delete</a>
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
