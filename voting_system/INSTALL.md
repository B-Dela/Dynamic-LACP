# BOA AMPONSEM SHS Voting System - Installation Guide

This document provides a comprehensive guide to installing and configuring the Voting System on your local server.

## Prerequisites

*   **Web Server**: XAMPP, WAMP, MAMP, or LAMP stack.
*   **PHP Version**: 7.4 or higher.
*   **Database**: MySQL or MariaDB.
*   **Web Browser**: Chrome, Firefox, Safari, or Edge.

## Installation Steps

### 1. Setup Environment
1.  Download and install XAMPP from [apachefriends.org](https://www.apachefriends.org/).
2.  Start **Apache** and **MySQL** modules from the XAMPP Control Panel.

### 2. Database Configuration
1.  Open your web browser and go to `http://localhost/phpmyadmin`.
2.  Click on **New** to create a new database.
3.  Name the database `voting_system` and select `utf8mb4_general_ci` as the collation. Click **Create**.
4.  Click on the `voting_system` database you just created.
5.  Click on the **Import** tab.
6.  Click **Choose File** and select the `database.sql` file located in the `voting_system/` directory of this project.
7.  Click **Go** at the bottom of the page to import the tables.

### 3. Project Setup
1.  Copy the entire `voting_system` folder to your web server's root directory:
    *   **Windows (XAMPP)**: `C:\xampp\htdocs\`
    *   **macOS (MAMP)**: `/Applications/MAMP/htdocs/`
    *   **Linux (LAMP)**: `/var/www/html/`
2.  Ensure the `uploads` directory exists and is writable:
    *   `voting_system/uploads/`
    *   If on Linux/Mac, run: `chmod -R 777 voting_system/uploads/`

### 4. Database Connection
1.  Open `voting_system/db_connect.php` in a text editor.
2.  Verify the database credentials match your setup:
    ```php
    $host = 'localhost';
    $dbname = 'voting_system';
    $username = 'root'; // Default XAMPP username
    $password = '';     // Default XAMPP password (empty)
    ```
    *   If you have a password for your root user, update the `$password` variable.

## Usage Guide

### 1. Admin Panel
*   **URL**: `http://localhost/voting_system/admin/`
*   **Default Credentials**:
    *   **Username**: `admin`
    *   **Password**: `password123`

#### Initial Configuration Steps:
1.  **Login** to the Admin Panel.
2.  **Create Classes**: Go to "Classes" and add classes (e.g., 1A1, 2B2).
3.  **Create Portfolios**: Go to "Portfolios" and add positions (e.g., School Prefect, Dining Hall Prefect).
    *   *Short Code*: Used for candidate ID generation (e.g., SP for School Prefect).
4.  **Register Candidates**: Go to "Candidates", fill in details, and upload a photo.
5.  **Register Voters**:
    *   **Manually**: Go to "Voters" and add individually.
    *   **Import**: Download the CSV template, fill it with student data, and upload it.
6.  **Create Polling Stations**: Go to "Polling Stations" and create accounts for your 5 stations.

### 2. Polling Station (Voting)
*   **URL**: `http://localhost/voting_system/`
*   **Login**: Use the credentials created by the Admin in the "Polling Stations" section.

#### Voting Process:
1.  Polling Agent logs in.
2.  Student arrives at the desk.
3.  Agent asks for Student ID or Name and enters their **Voter ID** into the system.
4.  System verifies eligibility.
    *   If eligible, the system redirects to the **Ballot Page**.
    *   If already voted, an error message is displayed.
5.  Student selects their preferred candidates.
6.  Student clicks **Submit Vote**.
7.  A "Success" message appears, and the system redirects back to the Agent Dashboard after 3 seconds for the next voter.

### 3. Results
*   **URL**: `http://localhost/voting_system/admin/results.php`
*   **Access**: Admin Only.
*   View real-time vote counts and percentages.
*   Print results using the "Print Results" button.

### 4. System Reset
*   **Reset Votes**: Clears all votes but keeps candidates and voters.
*   **Reset Everything**: Wipes all data (except admin/stations/structure). USE WITH CAUTION.

## Troubleshooting
*   **Database Error**: Check `db_connect.php` credentials.
*   **Upload Error**: Ensure `uploads/` folder has write permissions.
*   **Voter ID not found**: Ensure the Voter ID was generated correctly during registration (format: ClassName + 3 Digits, e.g., 1A1001).

## Security Note
*   Change the default Admin password immediately after installation.
*   Change the database password in production environments.
