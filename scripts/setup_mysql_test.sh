#!/bin/bash
# Setup MySQL test database for php.rs mysqli integration tests

set -e

echo "Setting up MySQL test environment..."
echo "===================================="
echo

# Check if Docker is available
if ! command -v docker &> /dev/null; then
    echo "Error: Docker is not installed or not in PATH"
    echo "Please install Docker to run MySQL tests"
    exit 1
fi

# Configuration
CONTAINER_NAME="php-rs-mysql-test"
MYSQL_ROOT_PASSWORD="test_password"
MYSQL_DATABASE="testdb"
MYSQL_PORT="3307"  # Use non-standard port to avoid conflicts

# Check if container already exists
if docker ps -a --format '{{.Names}}' | grep -q "^${CONTAINER_NAME}$"; then
    echo "Container '${CONTAINER_NAME}' already exists."
    read -p "Remove and recreate? (y/N): " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        echo "Stopping and removing existing container..."
        docker stop "${CONTAINER_NAME}" 2>/dev/null || true
        docker rm "${CONTAINER_NAME}" 2>/dev/null || true
    else
        echo "Starting existing container..."
        docker start "${CONTAINER_NAME}"
        exit 0
    fi
fi

# Start MySQL container
echo "Starting MySQL 8.0 container..."
docker run -d \
    --name "${CONTAINER_NAME}" \
    -e MYSQL_ROOT_PASSWORD="${MYSQL_ROOT_PASSWORD}" \
    -e MYSQL_DATABASE="${MYSQL_DATABASE}" \
    -p "${MYSQL_PORT}:3306" \
    mysql:8.0 \
    --default-authentication-plugin=mysql_native_password

echo "Waiting for MySQL to be ready..."
sleep 10

# Wait for MySQL to be ready
MAX_TRIES=30
TRIES=0
until docker exec "${CONTAINER_NAME}" mysqladmin ping -ptest_password --silent 2>/dev/null; do
    TRIES=$((TRIES+1))
    if [ $TRIES -ge $MAX_TRIES ]; then
        echo "Error: MySQL failed to start after ${MAX_TRIES} attempts"
        docker logs "${CONTAINER_NAME}"
        exit 1
    fi
    echo "Waiting... (attempt $TRIES/$MAX_TRIES)"
    sleep 2
done

echo
echo "✓ MySQL test database is ready!"
echo
echo "Connection details:"
echo "  Host: localhost"
echo "  Port: ${MYSQL_PORT}"
echo "  User: root"
echo "  Password: ${MYSQL_ROOT_PASSWORD}"
echo "  Database: ${MYSQL_DATABASE}"
echo
echo "Environment variables for testing:"
echo "  export MYSQL_HOST=localhost"
echo "  export MYSQL_PORT=${MYSQL_PORT}"
echo "  export MYSQL_USER=root"
echo "  export MYSQL_PASS=${MYSQL_ROOT_PASSWORD}"
echo "  export MYSQL_DB=${MYSQL_DATABASE}"
echo
echo "To run integration tests:"
echo "  cargo test -p php-rs-ext-mysqlnd -- --ignored"
echo "  cargo test -p php-rs-ext-mysqli -- --ignored"
echo
echo "To run the demo script:"
echo "  cargo run -p php-rs-sapi-cli -- examples/mysql_demo.php"
echo
echo "To stop the container:"
echo "  docker stop ${CONTAINER_NAME}"
echo
echo "To remove the container:"
echo "  docker rm ${CONTAINER_NAME}"
