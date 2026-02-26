<?php
session_start();
require_once '../db_connect.php';

if (!isset($_SESSION['admin_id'])) {
    header('Location: index.php');
    exit();
}

if (isset($_POST['import'])) {
    $filename = $_FILES['file']['tmp_name'];

    if ($_FILES['file']['size'] > 0) {
        $file = fopen($filename, "r");

        // Skip header
        fgetcsv($file);

        // Pre-fetch classes
        $classes_stmt = $pdo->query("SELECT id, class_name FROM classes");
        $classes = [];
        while ($row = $classes_stmt->fetch()) {
            $classes[strtoupper($row['class_name'])] = $row['id'];
        }

        // Allowed programs
        $allowed_programs = ['Visual Arts', 'General Arts', 'Home Econs', 'Agric Science', 'General Science', 'Business'];
        $allowed_programs_upper = array_map('strtoupper', $allowed_programs);

        // Track last IDs per class to avoid DB hits in loop
        $last_ids = [];

        $success_count = 0;
        $error_count = 0;
        $errors = [];

        while (($column = fgetcsv($file, 10000, ",")) !== FALSE) {
            $fullname = trim($column[0]);
            $program = trim($column[1]);
            $class_name = trim($column[2]);

            if (empty($fullname) || empty($program) || empty($class_name)) {
                $error_count++;
                continue;
            }

            // Validate Class
            $class_key = strtoupper($class_name);
            if (!isset($classes[$class_key])) {
                $errors[] = "Class '$class_name' not found for voter '$fullname'.";
                $error_count++;
                continue;
            }
            $class_id = $classes[$class_key];

            // Validate Program
            // Case-insensitive check
            $program_key = array_search(strtoupper($program), $allowed_programs_upper);
            if ($program_key === false) {
                 $errors[] = "Invalid program '$program' for voter '$fullname'.";
                 $error_count++;
                 continue;
            }
            $program_correct = $allowed_programs[$program_key];

            try {
                // Generate Voter ID
                if (!isset($last_ids[$class_name])) {
                    // Fetch from DB
                    $stmt = $pdo->prepare("SELECT voter_id FROM voters WHERE voter_id LIKE ? ORDER BY LENGTH(voter_id) DESC, voter_id DESC LIMIT 1");
                    $stmt->execute([$class_name . '%']);
                    $last_db_id = $stmt->fetchColumn();

                    if ($last_db_id) {
                        $suffix = substr($last_db_id, strlen($class_name));
                        $last_ids[$class_name] = is_numeric($suffix) ? intval($suffix) : 0;
                    } else {
                        $last_ids[$class_name] = 0;
                    }
                }

                $last_ids[$class_name]++;
                $voter_id = $class_name . str_pad($last_ids[$class_name], 3, '0', STR_PAD_LEFT);

                // Insert
                $stmt = $pdo->prepare("INSERT INTO voters (voter_id, fullname, program, class_id) VALUES (:voter_id, :fullname, :program, :class_id)");
                $stmt->execute(['voter_id' => $voter_id, 'fullname' => $fullname, 'program' => $program_correct, 'class_id' => $class_id]);
                $success_count++;

            } catch (PDOException $e) {
                $errors[] = "Database error for '$fullname': " . $e->getMessage();
                $error_count++;
            }
        }
        fclose($file);

        if ($error_count == 0) {
            $_SESSION['success'] = "Imported $success_count voters successfully.";
        } else {
            $_SESSION['error'] = "Imported $success_count voters. $error_count errors occurred.";
            if (!empty($errors)) {
                $_SESSION['error'] .= " Details: " . implode(" ", array_slice($errors, 0, 3));
                if (count($errors) > 3) $_SESSION['error'] .= "...";
            }
        }
    }
}
header('Location: voters.php');
exit();
?>
