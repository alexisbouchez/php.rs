# php-rs-ext-mysqli

MySQL Improved (mysqli) extension for php.rs.

## Overview

This extension provides real MySQL database connectivity for php.rs, implementing the full mysqli API with actual network connections to MySQL/MariaDB servers.

## Architecture

The mysqli extension is built on two layers:

1. **php-rs-ext-mysqlnd** — Low-level MySQL native driver (mysqlnd) that implements the MySQL wire protocol using the Rust `mysql` crate
2. **php-rs-ext-mysqli** — High-level mysqli API that wraps mysqlnd and provides PHP-compatible functions

This matches PHP's architecture where mysqli uses mysqlnd as its underlying driver.

## Features

### Implemented

- ✅ **Connection Management**
  - `mysqli_connect()` — Real TCP connections to MySQL servers
  - `mysqli_close()` — Proper connection cleanup
  - Connection pooling via mysqlnd

- ✅ **Query Execution**
  - `mysqli_query()` — Execute SQL queries
  - Full result set retrieval
  - Automatic type conversion (INT, STRING, FLOAT, BLOB, NULL)

- ✅ **Result Handling**
  - `mysqli_fetch_assoc()` — Fetch associative arrays
  - `mysqli_fetch_row()` — Fetch numeric arrays
  - `mysqli_fetch_array()` — Fetch with mode (MYSQLI_ASSOC, MYSQLI_NUM, MYSQLI_BOTH)
  - `mysqli_num_rows()` — Get row count
  - Column metadata extraction

- ✅ **Error Handling**
  - `mysqli_errno()` — Get error number
  - `mysqli_error()` — Get error message
  - `mysqli_connect_errno()` — Connection error number
  - `mysqli_connect_error()` — Connection error message

- ✅ **Connection Info**
  - `mysqli_get_server_info()` — Server version
  - `mysqli_affected_rows()` — Rows affected by last query
  - `mysqli_insert_id()` — Last auto-increment ID

- ✅ **Utility Functions**
  - `mysqli_real_escape_string()` — Escape special characters for SQL

### Partial Implementation

- ⚠️ **Prepared Statements**
  - `mysqli_prepare()` — Create prepared statement
  - `mysqli_stmt_bind_param()` — Bind parameters
  - `mysqli_stmt_execute()` — Execute statement
  - Currently use stub implementation; need integration with mysql crate's prepared statements

- ⚠️ **Transactions**
  - `mysqli_begin_transaction()` — Start transaction
  - `mysqli_commit()` — Commit transaction
  - `mysqli_rollback()` — Rollback transaction
  - Basic state tracking implemented; need actual SQL execution

### Not Yet Implemented

- ❌ **Advanced Features**
  - Asynchronous queries (`mysqli_poll`, `mysqli_reap_async_query`)
  - Multi-query execution (`mysqli_multi_query`, `mysqli_next_result`)
  - Character set management beyond basic support
  - SSL/TLS connection options
  - Compression

## Usage Example

```php
<?php
// Connect to MySQL
$conn = mysqli_connect('localhost', 'root', 'password', 'testdb');

if (!$conn) {
    die('Connection failed: ' . mysqli_connect_error());
}

// Query data
$result = mysqli_query($conn, 'SELECT * FROM users');

while ($row = mysqli_fetch_assoc($result)) {
    echo $row['name'] . "\n";
}

// Close connection
mysqli_close($conn);
```

## Configuration

MySQL connection parameters can be set via environment variables:

```bash
export MYSQL_HOST=localhost
export MYSQL_PORT=3306
export MYSQL_USER=root
export MYSQL_PASS=password
export MYSQL_DB=testdb
```

## Testing

### Unit Tests

```bash
# Run mysqli unit tests (use stub connections)
cargo test -p php-rs-ext-mysqli

# Run mysqlnd unit tests
cargo test -p php-rs-ext-mysqlnd
```

### Integration Tests

Integration tests require a running MySQL server:

```bash
# Start MySQL (using Docker)
docker run -d --name mysql-test \
  -e MYSQL_ROOT_PASSWORD=test \
  -e MYSQL_DATABASE=testdb \
  -p 3306:3306 \
  mysql:8.0

# Run integration tests
export MYSQL_HOST=localhost
export MYSQL_USER=root
export MYSQL_PASS=test
export MYSQL_DB=testdb

cargo run -p php-rs-sapi-cli -- examples/mysql_demo.php
```

## Dependencies

- `mysql` (v25+) — Rust MySQL client library
- `php-rs-ext-mysqlnd` — Internal mysqlnd driver

## Architecture Notes

### Type Mapping

| MySQL Type | Rust Type | PHP Value |
|-----------|-----------|-----------|
| TINYINT, SMALLINT, INT, BIGINT | `i64` | Long |
| FLOAT, DOUBLE | `f64` | Float |
| VARCHAR, TEXT, CHAR | `String` | String |
| BLOB, BINARY | `Vec<u8>` | Blob |
| NULL | `None` | Null |

### Connection Pooling

The mysqlnd layer uses connection pooling via the `mysql::Pool` type. Each mysqli connection maintains a reference to a pool, allowing efficient connection reuse.

### Error Handling

MySQL errors are mapped to mysqli error codes:
- 2002 — Connection failed
- 2006 — Server has gone away
- 1064 — SQL syntax error
- 1045 — Access denied

## Compatibility

Target: PHP 8.6 mysqli extension

Current status:
- ✅ Basic procedural API (mysqli_*)
- ❌ Object-oriented API (mysqli class)
- ✅ Most common functions (connect, query, fetch, close)
- ⚠️ Prepared statements (partial)
- ⚠️ Transactions (partial)

## Future Work

1. Implement OOP API (mysqli class, mysqli_result class, mysqli_stmt class)
2. Add full prepared statement support with parameter binding
3. Implement transaction SQL execution (BEGIN, COMMIT, ROLLBACK)
4. Add multi-query support
5. Implement async query capabilities
6. Add comprehensive PHPT tests from php-src
7. Performance benchmarking against PHP's mysqli
8. Add MariaDB-specific features where compatible

## References

- [PHP mysqli documentation](https://www.php.net/manual/en/book.mysqli.php)
- [MySQL Protocol Documentation](https://dev.mysql.com/doc/dev/mysql-server/latest/PAGE_PROTOCOL.html)
- [mysql crate documentation](https://docs.rs/mysql/latest/mysql/)
