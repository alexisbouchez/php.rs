# PostgreSQL PDO Driver Implementation

This document describes the PostgreSQL PDO driver implementation for php.rs.

## Overview

The PostgreSQL PDO driver (`php-rs-ext-pdo-pgsql`) provides PDO database access to PostgreSQL databases. It implements the standard PDO driver interface and integrates with the php.rs PDO abstraction layer.

## Architecture

### Crate Structure

```
php-rs-ext-pdo/          # PDO base layer
├── PdoDriver trait      # Driver interface
├── PdoDriverConnection  # Connection interface
├── PdoDriverStatement   # Statement interface
├── PdoValue, PdoRow     # Data types
└── Driver registry      # Dynamic driver registration

php-rs-ext-pdo-pgsql/    # PostgreSQL driver
├── PdoPgsqlDriver       # Driver implementation
├── PgsqlConnection      # Connection implementation
├── PgsqlStatement       # Statement implementation
└── DSN parsing          # PostgreSQL DSN parser
```

### Driver Registration

The PDO system uses a dynamic driver registry that allows drivers to be registered at runtime:

```rust
// In php-rs-sapi-cli/src/main.rs
php_rs_ext_pdo::register_pdo_driver("pgsql", || {
    Box::new(php_rs_ext_pdo_pgsql::PdoPgsqlDriver::new())
});
```

This avoids cyclic dependencies between the PDO base and driver crates.

## Implementation Details

### Dependencies

- **postgres**: Synchronous PostgreSQL client library (version 0.19)
- **php-rs-ext-pdo**: PDO base layer providing traits and types

### DSN Format

PostgreSQL PDO DSN format:
```
pgsql:host=localhost;port=5432;dbname=mydb;sslmode=require
```

Supported parameters:
- `host` - PostgreSQL server hostname (default: "localhost")
- `port` - PostgreSQL server port (default: 5432)
- `dbname` - Database name
- `user` - Username (can also be passed via PDO constructor)
- `password` - Password (can also be passed via PDO constructor)
- `sslmode` - SSL mode: disable, allow, prefer, require, verify-ca, verify-full

### Type Conversions

| PostgreSQL Type | PdoValue Type |
|----------------|---------------|
| INTEGER, BIGINT | PdoValue::Int(i64) |
| REAL, DOUBLE | PdoValue::Float(f64) |
| BOOLEAN | PdoValue::Bool(bool) |
| VARCHAR, TEXT | PdoValue::Str(String) |
| BYTEA | PdoValue::Blob(Vec\<u8\>) |
| NULL | PdoValue::Null |

### Connection Handling

- Uses `postgres::Client` for database connections
- NoTls mode by default (can be configured via sslmode)
- Connection string built from DSN parameters
- Interior mutability via `RefCell` for single-threaded access

### Statement Execution

- Supports both direct execution and prepared statements
- Parameter binding using positional parameters ($1, $2, etc.)
- Results fetched into memory before iteration
- Automatic detection of SELECT vs. non-SELECT queries

### Transaction Support

- `BEGIN`, `COMMIT`, `ROLLBACK` transaction commands
- Transaction state tracking via `in_transaction` flag
- Error handling for nested transaction attempts

## Features

### Implemented

- [x] Driver registration and connection
- [x] DSN parsing with all standard parameters
- [x] Prepared statement support with positional parameters
- [x] Type conversions between PostgreSQL and PDO types
- [x] Transaction management (BEGIN, COMMIT, ROLLBACK)
- [x] Query execution for SELECT and non-SELECT statements
- [x] Result fetching with column name preservation
- [x] String quoting for SQL literals

### Not Yet Implemented

- [ ] Named parameters (`:name` style)
- [ ] SSL/TLS certificate configuration
- [ ] Connection pooling
- [ ] RETURNING clause support for last_insert_id()
- [ ] Binary parameter binding
- [ ] Large object support
- [ ] COPY command support
- [ ] PostgreSQL-specific attributes (PDO::PGSQL_ATTR_*)

### VM Integration

The PDO driver is implemented at the library level but not yet integrated with the VM:

- [ ] PDO class registration with VM
- [ ] PDOStatement class registration
- [ ] PDOException class registration
- [ ] Builtin function wrappers (new PDO, etc.)

## Testing

### Unit Tests

The crate includes unit tests for:
- DSN parsing with various formats
- Configuration defaults
- Error handling for invalid DSN
- Space-separated vs. semicolon-separated parameters

Run tests:
```bash
cargo test -p php-rs-ext-pdo-pgsql
```

### Integration Testing

To test with an actual PostgreSQL server:

```php
<?php
// Requires PostgreSQL server running on localhost:5432
$dsn = "pgsql:host=localhost;port=5432;dbname=testdb";
$pdo = new PDO($dsn, "username", "password");

// Create table
$pdo->exec("CREATE TABLE users (id SERIAL PRIMARY KEY, name VARCHAR(100))");

// Insert data
$stmt = $pdo->prepare("INSERT INTO users (name) VALUES ($1)");
$stmt->execute(["Alice"]);

// Query data
$stmt = $pdo->query("SELECT * FROM users");
while ($row = $stmt->fetch(PDO::FETCH_ASSOC)) {
    echo $row['name'] . "\n";
}
```

## Comparison with PHP's PDO_pgsql

### Similarities

- DSN format matches PHP's pgsql: syntax
- Type conversions follow PHP's coercion rules
- Transaction API identical to PHP's PDO
- Error codes use PostgreSQL SQLSTATE codes

### Differences

- Uses Rust's `postgres` crate instead of libpq
- No async/await support (synchronous only)
- Named parameters not yet implemented
- Some advanced features pending (COPY, large objects)

## Performance Considerations

- **Memory**: Results are fetched entirely into memory before iteration
- **Connection pooling**: Not implemented - each PDO object creates a new connection
- **Parameter binding**: Parameters converted to Rust types, then to PostgreSQL wire format
- **Type detection**: Uses try_get with multiple type attempts (could be optimized)

## Future Enhancements

1. **Named parameter support**: Parse `:name` style parameters and map to positional
2. **Streaming results**: Implement cursor-based fetching for large result sets
3. **Connection pooling**: Reuse connections across PDO instances
4. **Async support**: Add async/await using tokio-postgres
5. **SSL configuration**: Support certificate files and verification modes
6. **RETURNING support**: Extract last_insert_id from RETURNING clauses
7. **Prepared statement cache**: Cache prepared statements for reuse

## Security

- **SQL Injection**: Use prepared statements with parameter binding
- **String quoting**: The `quote()` method escapes single quotes properly
- **SSL/TLS**: Configurable via `sslmode` parameter
- **Credential handling**: Passwords not logged or exposed in errors

## References

- [PostgreSQL Documentation](https://www.postgresql.org/docs/)
- [PHP PDO_pgsql Documentation](https://www.php.net/manual/en/ref.pdo-pgsql.php)
- [Rust postgres crate](https://docs.rs/postgres/)
- [PDO Driver Interface](../../crates/php-rs-ext-pdo/src/lib.rs)
