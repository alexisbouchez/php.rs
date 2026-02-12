<?php
// MySQL/MySQLi Demo Script
// This demonstrates real MySQL connectivity in php.rs

echo "MySQL/MySQLi Demo\n";
echo "================\n\n";

// Connection parameters (adjust these for your MySQL server)
$host = getenv('MYSQL_HOST') ?: 'localhost';
$user = getenv('MYSQL_USER') ?: 'root';
$pass = getenv('MYSQL_PASS') ?: '';
$db = getenv('MYSQL_DB') ?: 'test';
$port = getenv('MYSQL_PORT') ?: 3306;

echo "Connecting to MySQL...\n";
echo "Host: $host:$port\n";
echo "User: $user\n";
echo "Database: $db\n\n";

// Attempt connection
$conn = mysqli_connect($host, $user, $pass, $db, $port);

if (!$conn) {
    die("Connection failed: " . mysqli_connect_error() . "\n");
}

echo "✓ Connected successfully!\n";
echo "Server version: " . mysqli_get_server_info($conn) . "\n\n";

// Create a test table
echo "Creating test table...\n";
$result = mysqli_query($conn, "CREATE TABLE IF NOT EXISTS users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(100),
    email VARCHAR(100),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
)");

if ($result) {
    echo "✓ Table created successfully\n";
} else {
    echo "✗ Error creating table: " . mysqli_error($conn) . "\n";
}

// Insert some test data
echo "\nInserting test data...\n";
$queries = [
    "INSERT INTO users (name, email) VALUES ('Alice', 'alice@example.com')",
    "INSERT INTO users (name, email) VALUES ('Bob', 'bob@example.com')",
    "INSERT INTO users (name, email) VALUES ('Charlie', 'charlie@example.com')",
];

foreach ($queries as $query) {
    if (mysqli_query($conn, $query)) {
        echo "✓ Inserted: " . mysqli_insert_id($conn) . "\n";
    } else {
        echo "✗ Error: " . mysqli_error($conn) . "\n";
    }
}

// Query and display results
echo "\nQuerying data...\n";
$result = mysqli_query($conn, "SELECT * FROM users ORDER BY id");

if ($result) {
    echo "Found " . mysqli_num_rows($result) . " rows:\n\n";

    while ($row = mysqli_fetch_assoc($result)) {
        echo "ID: " . $row['id'] . "\n";
        echo "Name: " . $row['name'] . "\n";
        echo "Email: " . $row['email'] . "\n";
        echo "Created: " . $row['created_at'] . "\n";
        echo "---\n";
    }
} else {
    echo "✗ Query error: " . mysqli_error($conn) . "\n";
}

// Clean up
echo "\nCleaning up...\n";
mysqli_query($conn, "DROP TABLE users");
echo "✓ Test table dropped\n";

// Close connection
mysqli_close($conn);
echo "\n✓ Connection closed\n";
echo "\nDemo completed!\n";
