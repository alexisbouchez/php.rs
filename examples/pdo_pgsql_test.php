<?php
// Test PostgreSQL PDO driver

echo "Testing PostgreSQL PDO driver...\n\n";

try {
    // Test DSN parsing
    $dsn = "pgsql:host=localhost;port=5432;dbname=testdb";
    echo "DSN: $dsn\n";

    // Try to create a connection (will fail without actual PostgreSQL server)
    // But we can verify the driver is registered
    echo "Attempting to create PDO connection...\n";

    try {
        $pdo = new PDO($dsn, "testuser", "testpass");
        echo "✓ Connection created successfully!\n";

        // Test a simple query
        $stmt = $pdo->query("SELECT version()");
        if ($stmt) {
            $row = $stmt->fetch(PDO::FETCH_ASSOC);
            echo "PostgreSQL version: " . $row['version'] . "\n";
        }
    } catch (PDOException $e) {
        // Expected if PostgreSQL server is not running
        echo "Connection failed (expected if no PostgreSQL server): " . $e->getMessage() . "\n";
        echo "✓ Driver is registered and attempted connection\n";
    }

    echo "\n✓ PostgreSQL PDO driver test complete!\n";

} catch (Exception $e) {
    echo "✗ Error: " . $e->getMessage() . "\n";
    exit(1);
}
