<?php
session_start();
require_once '../db_connect.php';

if (!isset($_SESSION['admin_id'])) {
    header('Location: index.php');
    exit();
}

// Handle Add Voter
if (isset($_POST['add_voter'])) {
    $fullname = trim($_POST['fullname']);
    $program = $_POST['program'];
    $class_id = $_POST['class_id'];

    if (!empty($fullname) && !empty($program) && !empty($class_id)) {
        try {
            // Get Class Name
            $stmt = $pdo->prepare("SELECT class_name FROM classes WHERE id = ?");
            $stmt->execute([$class_id]);
            $class_name = $stmt->fetchColumn();

            if (!$class_name) {
                throw new Exception("Invalid Class");
            }

            // Generate Voter ID
            // Find last ID for this class
            // Pattern: class_name + 3 digits
            $prefix = $class_name;
            $stmt = $pdo->prepare("SELECT voter_id FROM voters WHERE voter_id LIKE ? ORDER BY LENGTH(voter_id) DESC, voter_id DESC LIMIT 1");
            $stmt->execute([$prefix . '%']);
            $last_id = $stmt->fetchColumn();

            if ($last_id) {
                // Extract numeric part. Assuming format is ClassName + digits.
                // But ClassName length varies.
                // However, prompt says: "It should comprise class information and additional three digits (eg. 1A1001)"
                // So suffix is always last 3 chars?
                // Or I can subtract the prefix length.
                $suffix = substr($last_id, strlen($prefix));
                if (is_numeric($suffix)) {
                    $next_num = intval($suffix) + 1;
                } else {
                    $next_num = 1;
                }
            } else {
                $next_num = 1;
            }
            $voter_id = $prefix . str_pad($next_num, 3, '0', STR_PAD_LEFT);

            // Insert
            $stmt = $pdo->prepare("INSERT INTO voters (voter_id, fullname, program, class_id) VALUES (:voter_id, :fullname, :program, :class_id)");
            $stmt->execute(['voter_id' => $voter_id, 'fullname' => $fullname, 'program' => $program, 'class_id' => $class_id]);
            $_SESSION['success'] = "Voter added successfully. ID: " . $voter_id;

        } catch (Exception $e) {
            $_SESSION['error'] = "Error adding voter: " . $e->getMessage();
        }
    } else {
        $_SESSION['error'] = "All fields are required";
    }
    header('Location: voters.php');
    exit();
}

// Handle Delete Voter
if (isset($_GET['delete'])) {
    $id = $_GET['delete'];
    try {
        $stmt = $pdo->prepare("DELETE FROM voters WHERE id = :id");
        $stmt->execute(['id' => $id]);
        $_SESSION['success'] = "Voter deleted successfully";
    } catch (PDOException $e) {
        $_SESSION['error'] = "Error deleting voter: " . $e->getMessage();
    }
    header('Location: voters.php');
    exit();
}

// Fetch Voters
$sql = "SELECT v.*, c.class_name FROM voters v JOIN classes c ON v.class_id = c.id ORDER BY c.class_name, v.fullname";
$voters = $pdo->query($sql)->fetchAll();

// Fetch Classes
$classes = $pdo->query("SELECT * FROM classes ORDER BY class_name ASC")->fetchAll();

// Programs
$programs = ['Visual Arts', 'General Arts', 'Home Econs', 'Agric Science', 'General Science', 'Business'];
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Manage Voters - BOA AMPONSEM SHS</title>
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
        .btn-success { background-color: #28a745; }
        .btn-danger { background-color: #dc3545; }
        table { width: 100%; border-collapse: collapse; margin-top: 20px; }
        th, td { padding: 12px; text-align: left; border-bottom: 1px solid #ddd; }
        th { background-color: #f8f9fa; }
        .alert { padding: 15px; margin-bottom: 20px; border: 1px solid transparent; border-radius: 4px; }
        .alert-success { color: #155724; background-color: #d4edda; border-color: #c3e6cb; }
        .alert-danger { color: #721c24; background-color: #f8d7da; border-color: #f5c6cb; }
        .flex-row { display: flex; gap: 20px; }
        .flex-col { flex: 1; }
    </style>
</head>
<body>
    <div class="wrapper">
        <nav class="sidebar">
            <h2>Admin Panel</h2>
            <ul>
                <li><a href="dashboard.php"><i class="fas fa-tachometer-alt"></i> Dashboard</a></li>
                <li class="active"><a href="voters.php"><i class="fas fa-users"></i> Voters</a></li>
                <li><a href="candidates.php"><i class="fas fa-user-tie"></i> Candidates</a></li>
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
                <h1>Manage Voters</h1>
            </header>

            <?php if (isset($_SESSION['success'])): ?>
                <div class="alert alert-success"><?php echo $_SESSION['success']; unset($_SESSION['success']); ?></div>
            <?php endif; ?>
            <?php if (isset($_SESSION['error'])): ?>
                <div class="alert alert-danger"><?php echo $_SESSION['error']; unset($_SESSION['error']); ?></div>
            <?php endif; ?>

            <div class="flex-row">
                <div class="card flex-col">
                    <h3>Add New Voter</h3>
                    <form action="voters.php" method="POST">
                        <div class="form-group">
                            <label>Full Name</label>
                            <input type="text" name="fullname" required>
                        </div>
                        <div class="form-group">
                            <label>Program</label>
                            <select name="program" required>
                                <option value="">Select Program</option>
                                <?php foreach ($programs as $prog): ?>
                                    <option value="<?php echo $prog; ?>"><?php echo $prog; ?></option>
                                <?php endforeach; ?>
                            </select>
                        </div>
                        <div class="form-group">
                            <label>Class</label>
                            <select name="class_id" required>
                                <option value="">Select Class</option>
                                <?php foreach ($classes as $class): ?>
                                    <option value="<?php echo $class['id']; ?>"><?php echo $class['class_name']; ?></option>
                                <?php endforeach; ?>
                            </select>
                        </div>
                        <button type="submit" name="add_voter" class="btn">Add Voter</button>
                    </form>
                </div>

                <div class="card flex-col">
                    <h3>Import Voters (CSV)</h3>
                    <p>Upload a CSV file with columns: Full Name, Program, Class Name</p>
                    <a href="voters_template.php" class="btn btn-success" style="text-decoration:none; display:inline-block; margin-bottom:10px;">Download Template</a>
                    <form action="voters_import.php" method="POST" enctype="multipart/form-data">
                        <div class="form-group">
                            <label>CSV File</label>
                            <input type="file" name="file" required accept=".csv">
                        </div>
                        <button type="submit" name="import" class="btn">Import</button>
                    </form>
                </div>
            </div>

            <div class="card">
                <h3>Existing Voters</h3>
                <table>
                    <thead>
                        <tr>
                            <th>Voter ID</th>
                            <th>Full Name</th>
                            <th>Program</th>
                            <th>Class</th>
                            <th>Status</th>
                            <th>Action</th>
                        </tr>
                    </thead>
                    <tbody>
                        <?php foreach ($voters as $voter): ?>
                        <tr>
                            <td><?php echo $voter['voter_id']; ?></td>
                            <td><?php echo htmlspecialchars($voter['fullname']); ?></td>
                            <td><?php echo htmlspecialchars($voter['program']); ?></td>
                            <td><?php echo htmlspecialchars($voter['class_name']); ?></td>
                            <td>
                                <?php if ($voter['has_voted']): ?>
                                    <span style="color: green; font-weight: bold;">Voted</span>
                                <?php else: ?>
                                    <span style="color: red;">Not Voted</span>
                                <?php endif; ?>
                            </td>
                            <td>
                                <a href="voters.php?delete=<?php echo $voter['id']; ?>" class="btn btn-danger" onclick="return confirm('Are you sure?')">Delete</a>
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
