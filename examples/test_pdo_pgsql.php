<?php
// Test PostgreSQL PDO integration

echo "=== PDO PostgreSQL Integration Test ===\n\n";

// Test 1: Create PDO object with invalid connection (should throw exception)
echo "Test 1: PDO Exception handling\n";
try {
    $pdo = new PDO("pgsql:host=nonexistent.invalid;dbname=test", "user", "pass");
    echo "FAIL: Should have thrown exception\n";
} catch (PDOException $e) {
    echo "PASS: Caught PDOException: " . substr($e->getMessage(), 0, 50) . "...\n";
}

echo "\n";

// Test 2: Create PDO with SQLite (should work)
echo "Test 2: SQLite PDO (built-in driver)\n";
try {
    $pdo = new PDO("sqlite::memory:");
    echo "PASS: Created SQLite PDO connection\n";

    // Create table
    $pdo->exec("CREATE TABLE users (id INTEGER PRIMARY KEY, name TEXT)");
    echo "PASS: Created table\n";

    // Insert data
    $affected = $pdo->exec("INSERT INTO users (name) VALUES ('Alice')");
    echo "PASS: Inserted $affected row(s)\n";

    // Query data
    $stmt = $pdo->query("SELECT * FROM users");
    echo "PASS: Executed query\n";

    // Fetch result
    $row = $stmt->fetch(PDO::FETCH_ASSOC);
    if ($row && $row['name'] === 'Alice') {
        echo "PASS: Fetched row: " . $row['name'] . "\n";
    } else {
        echo "FAIL: Could not fetch row\n";
    }

    // Test prepared statement
    $stmt = $pdo->prepare("INSERT INTO users (name) VALUES (?)");
    $stmt->execute(['Bob']);
    echo "PASS: Executed prepared statement\n";

    // Fetch all
    $stmt = $pdo->query("SELECT * FROM users");
    $rows = $stmt->fetchAll(PDO::FETCH_ASSOC);
    echo "PASS: Fetched " . count($rows) . " rows\n";

    // Test transactions
    $pdo->beginTransaction();
    $pdo->exec("INSERT INTO users (name) VALUES ('Charlie')");
    $pdo->commit();
    echo "PASS: Transaction committed\n";

} catch (PDOException $e) {
    echo "FAIL: " . $e->getMessage() . "\n";
}

echo "\n=== All Tests Complete ===\n";
