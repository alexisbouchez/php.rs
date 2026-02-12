# php-rs-ext-pdo-pgsql

PostgreSQL driver for the PDO (PHP Data Objects) extension in php.rs.

## Features

- Full PostgreSQL DSN parsing
- Connection management with transaction support
- Prepared statement execution with parameter binding
- Type conversions between PostgreSQL and PHP types
- SSL/TLS connection support via sslmode parameter

## Usage

### Driver Registration

The driver must be registered with the PDO system before use:

```rust
use php_rs_ext_pdo::register_pdo_driver;
use php_rs_ext_pdo_pgsql::PdoPgsqlDriver;

register_pdo_driver("pgsql", || {
    Box::new(PdoPgsqlDriver::new())
});
```

### DSN Format

```
pgsql:host=localhost;port=5432;dbname=mydb;sslmode=require
```

**Supported parameters:**
- `host` - Server hostname (default: "localhost")
- `port` - Server port (default: 5432)
- `dbname` - Database name
- `user` - Username (can also be passed to PDO constructor)
- `password` - Password (can also be passed to PDO constructor)
- `sslmode` - SSL mode: disable, allow, prefer, require, verify-ca, verify-full

### Example (when VM integration is complete)

```php
<?php
$dsn = "pgsql:host=localhost;port=5432;dbname=testdb";
$pdo = new PDO($dsn, "username", "password");

// Query with prepared statement
$stmt = $pdo->prepare("SELECT * FROM users WHERE id = $1");
$stmt->execute([42]);
$row = $stmt->fetch(PDO::FETCH_ASSOC);

// Transaction
$pdo->beginTransaction();
$pdo->exec("INSERT INTO users (name) VALUES ('Alice')");
$pdo->commit();
```

## Type Conversions

| PostgreSQL Type | PdoValue | PHP Type |
|----------------|----------|----------|
| INTEGER, BIGINT | Int(i64) | int |
| REAL, DOUBLE PRECISION | Float(f64) | float |
| BOOLEAN | Bool(bool) | bool |
| VARCHAR, TEXT | Str(String) | string |
| BYTEA | Blob(Vec\<u8\>) | string |
| NULL | Null | null |

## Dependencies

- **postgres** v0.19 - PostgreSQL client library
- **php-rs-ext-pdo** - PDO base layer

## Testing

```bash
# Run unit tests
cargo test -p php-rs-ext-pdo-pgsql

# Run with actual PostgreSQL server
# (requires PostgreSQL server on localhost:5432)
cargo test -p php-rs-ext-pdo-pgsql -- --ignored
```

## Implementation Status

### Completed
- [x] DSN parsing
- [x] Driver registration
- [x] Connection management
- [x] Prepared statements with positional parameters ($1, $2, ...)
- [x] Type conversions
- [x] Transaction support (BEGIN, COMMIT, ROLLBACK)
- [x] Query execution
- [x] Result fetching

### Pending
- [ ] Named parameters (`:name` style)
- [ ] VM class integration (PDO, PDOStatement classes)
- [ ] SSL certificate configuration
- [ ] RETURNING clause support
- [ ] Large object (LOB) support
- [ ] COPY command support

## License

Same as php.rs workspace.

## References

- [PostgreSQL Documentation](https://www.postgresql.org/docs/)
- [PHP PDO_pgsql Reference](https://www.php.net/manual/en/ref.pdo-pgsql.php)
- [rust-postgres Documentation](https://docs.rs/postgres/)
