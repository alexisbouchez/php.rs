#!/bin/bash
# Test Laravel routes via HTTP server

cd /Users/alex/php.rs/tests/laravel-app

# Start server
/Users/alex/php.rs/target/release/php-rs -S localhost:8888 -t public > /tmp/laravel-test-server.log 2>&1 &
SERVER_PID=$!

echo "Server started with PID: $SERVER_PID"
sleep 2

echo "=== Testing Laravel Routes via HTTP ==="
echo ""

echo "Test 1: GET /"
curl -s http://localhost:8888/index-simple.php
echo ""
echo ""

echo "Test 2: GET /test (JSON)"
curl -s "http://localhost:8888/index-simple.php" -H "X-REQUEST-URI: /test" || echo "Note: Need to pass URI via routing"
echo ""
echo ""

echo "Test 3: Route with parameter /user/123"
# For this we'd need proper routing via a router file
echo "Note: Would need clean URL routing configured"
echo ""

# Cleanup
kill $SERVER_PID 2>/dev/null
echo "Server stopped"
