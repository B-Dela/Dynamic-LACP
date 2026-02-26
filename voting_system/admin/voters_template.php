<?php
header('Content-Type: text/csv; charset=utf-8');
header('Content-Disposition: attachment; filename=voters_template.csv');

$output = fopen('php://output', 'w');
fputcsv($output, array('Full Name', 'Program', 'Class Name'));
fputcsv($output, array('John Doe', 'General Science', '1A1'));
fputcsv($output, array('Jane Smith', 'Visual Arts', '2B2'));
fclose($output);
?>
