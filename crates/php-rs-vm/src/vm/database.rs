//! Database methods (PDO, SQLite3) — extracted from vm.rs.

use php_rs_compiler::op::ZOp;

#[allow(unused_imports)]
use super::helpers::*;
use super::{Vm, VmError, VmResult};
use crate::value::{ArrayKey, PhpArray, PhpObject, Value};

impl Vm {
    /// Call a PDO method.
    #[cfg(feature = "native-io")]
    pub(crate) fn call_pdo_method(
        &mut self,
        method: &str,
        args: &[Value],
    ) -> VmResult<Option<Value>> {
        use php_rs_ext_pdo::{FetchMode, PdoRow, PdoValue};

        let pdo_obj = match args.first() {
            Some(Value::Object(o)) => o,
            _ => return Ok(None),
        };
        let obj_id = pdo_obj.object_id();

        match method {
            "prepare" => {
                // $pdo->prepare($sql)
                let sql = args.get(1).map(|v| v.to_php_string()).unwrap_or_default();
                self.record_event("sql", format!("PREPARE {}", sql));

                if let Some(conn) = self.pdo_connections.get_mut(&obj_id) {
                    match conn.prepare(&sql) {
                        Ok(stmt) => {
                            let stmt_obj = PhpObject::new("PDOStatement".to_string());
                            stmt_obj.set_object_id(self.next_object_id);
                            self.next_object_id += 1;
                            let stmt_obj_id = stmt_obj.object_id();
                            self.pdo_statements.insert(stmt_obj_id, stmt);
                            Ok(Some(Value::Object(stmt_obj)))
                        }
                        Err(e) => {
                            let ex_obj = PhpObject::new("PDOException".to_string());
                            ex_obj.set_property(
                                "message".to_string(),
                                Value::String(format!("SQLSTATE[{}]: {}", e.sqlstate, e.message)),
                            );
                            Err(VmError::Thrown(Value::Object(ex_obj)))
                        }
                    }
                } else {
                    Ok(Some(Value::Bool(false)))
                }
            }
            "query" => {
                // $pdo->query($sql)
                let sql = args.get(1).map(|v| v.to_php_string()).unwrap_or_default();
                self.record_event("sql", sql.clone());

                if let Some(conn) = self.pdo_connections.get_mut(&obj_id) {
                    match conn.query(&sql) {
                        Ok(stmt) => {
                            let stmt_obj = PhpObject::new("PDOStatement".to_string());
                            stmt_obj.set_object_id(self.next_object_id);
                            self.next_object_id += 1;
                            let stmt_obj_id = stmt_obj.object_id();
                            self.pdo_statements.insert(stmt_obj_id, stmt);
                            Ok(Some(Value::Object(stmt_obj)))
                        }
                        Err(e) => {
                            let ex_obj = PhpObject::new("PDOException".to_string());
                            ex_obj.set_property(
                                "message".to_string(),
                                Value::String(format!("SQLSTATE[{}]: {}", e.sqlstate, e.message)),
                            );
                            Err(VmError::Thrown(Value::Object(ex_obj)))
                        }
                    }
                } else {
                    Ok(Some(Value::Bool(false)))
                }
            }
            "exec" => {
                // $pdo->exec($sql)
                let sql = args.get(1).map(|v| v.to_php_string()).unwrap_or_default();
                self.record_event("sql", sql.clone());

                if let Some(conn) = self.pdo_connections.get_mut(&obj_id) {
                    match conn.exec(&sql) {
                        Ok(affected) => Ok(Some(Value::Long(affected as i64))),
                        Err(e) => {
                            let ex_obj = PhpObject::new("PDOException".to_string());
                            ex_obj.set_property(
                                "message".to_string(),
                                Value::String(format!("SQLSTATE[{}]: {}", e.sqlstate, e.message)),
                            );
                            Err(VmError::Thrown(Value::Object(ex_obj)))
                        }
                    }
                } else {
                    Ok(Some(Value::Bool(false)))
                }
            }
            "beginTransaction" => {
                if let Some(conn) = self.pdo_connections.get_mut(&obj_id) {
                    match conn.begin_transaction() {
                        Ok(_) => Ok(Some(Value::Bool(true))),
                        Err(_) => Ok(Some(Value::Bool(false))),
                    }
                } else {
                    Ok(Some(Value::Bool(false)))
                }
            }
            "commit" => {
                if let Some(conn) = self.pdo_connections.get_mut(&obj_id) {
                    match conn.commit() {
                        Ok(_) => Ok(Some(Value::Bool(true))),
                        Err(_) => Ok(Some(Value::Bool(false))),
                    }
                } else {
                    Ok(Some(Value::Bool(false)))
                }
            }
            "rollBack" => {
                if let Some(conn) = self.pdo_connections.get_mut(&obj_id) {
                    match conn.rollback() {
                        Ok(_) => Ok(Some(Value::Bool(true))),
                        Err(_) => Ok(Some(Value::Bool(false))),
                    }
                } else {
                    Ok(Some(Value::Bool(false)))
                }
            }
            "lastInsertId" => {
                let seq_name = args.get(1).and_then(|v| match v {
                    Value::Null => None,
                    _ => Some(v.to_php_string()),
                });
                if let Some(conn) = self.pdo_connections.get(&obj_id) {
                    let id = conn.last_insert_id();
                    Ok(Some(Value::String(id)))
                } else {
                    Ok(Some(Value::String(String::new())))
                }
            }
            "inTransaction" => {
                if let Some(conn) = self.pdo_connections.get(&obj_id) {
                    Ok(Some(Value::Bool(conn.in_transaction())))
                } else {
                    Ok(Some(Value::Bool(false)))
                }
            }
            "quote" => {
                let string = args.get(1).map(|v| v.to_php_string()).unwrap_or_default();
                if let Some(conn) = self.pdo_connections.get(&obj_id) {
                    Ok(Some(Value::String(conn.quote(&string))))
                } else {
                    Ok(Some(Value::Bool(false)))
                }
            }
            "setAttribute" => {
                let attr = args.get(1).map(|v| v.to_long()).unwrap_or(0);
                let value = args.get(2).map(|v| v.to_long()).unwrap_or(0);
                if let Some(conn) = self.pdo_connections.get_mut(&obj_id) {
                    let result = conn.set_attribute(attr, value);
                    Ok(Some(Value::Bool(result)))
                } else {
                    Ok(Some(Value::Bool(false)))
                }
            }
            "getAttribute" => {
                let attr = args.get(1).map(|v| v.to_long()).unwrap_or(0);
                if let Some(conn) = self.pdo_connections.get(&obj_id) {
                    match conn.get_attribute(attr) {
                        Some(val) => Ok(Some(pdo_value_to_value(&val))),
                        None => Ok(Some(Value::Null)),
                    }
                } else {
                    Ok(Some(Value::Null))
                }
            }
            "errorCode" => {
                if let Some(conn) = self.pdo_connections.get(&obj_id) {
                    Ok(Some(Value::String(conn.error_code())))
                } else {
                    Ok(Some(Value::Null))
                }
            }
            "errorInfo" => {
                if let Some(conn) = self.pdo_connections.get(&obj_id) {
                    let (state, code, msg) = conn.error_info();
                    let mut arr = PhpArray::new();
                    arr.push(Value::String(state));
                    arr.push(match code {
                        Some(c) => Value::String(c),
                        None => Value::Null,
                    });
                    arr.push(match msg {
                        Some(m) => Value::String(m),
                        None => Value::Null,
                    });
                    Ok(Some(Value::Array(arr)))
                } else {
                    Ok(Some(Value::Array(PhpArray::new())))
                }
            }
            _ => Ok(None),
        }
    }

    /// Call a PDOStatement method.
    #[cfg(feature = "native-io")]
    pub(crate) fn call_pdo_statement_method(
        &mut self,
        method: &str,
        args: &[Value],
    ) -> VmResult<Option<Value>> {
        use php_rs_ext_pdo::{FetchMode, PdoRow, PdoValue};

        let stmt_obj = match args.first() {
            Some(Value::Object(o)) => o,
            _ => return Ok(None),
        };
        let obj_id = stmt_obj.object_id();

        match method {
            "execute" => {
                // $stmt->execute([$params])
                self.record_event("sql", "EXECUTE prepared".into());
                let params_val = args.get(1).cloned().unwrap_or(Value::Null);
                let params = if let Value::Array(ref a) = params_val {
                    Some(
                        a.entries()
                            .iter()
                            .map(|(_, v)| value_to_pdo_value(v))
                            .collect::<Vec<_>>(),
                    )
                } else {
                    None
                };

                if let Some(stmt) = self.pdo_statements.get_mut(&obj_id) {
                    match stmt.execute(params.as_deref()) {
                        Ok(_) => Ok(Some(Value::Bool(true))),
                        Err(e) => {
                            let ex_obj = PhpObject::new("PDOException".to_string());
                            ex_obj.set_property(
                                "message".to_string(),
                                Value::String(format!("SQLSTATE[{}]: {}", e.sqlstate, e.message)),
                            );
                            Err(VmError::Thrown(Value::Object(ex_obj)))
                        }
                    }
                } else {
                    Ok(Some(Value::Bool(false)))
                }
            }
            "fetch" => {
                // $stmt->fetch($fetch_mode = PDO::FETCH_BOTH)
                let fetch_mode_val = args.get(1).map(|v| v.to_long()).unwrap_or(3); // FETCH_BOTH = 3
                let fetch_mode = match fetch_mode_val {
                    1 => FetchMode::Assoc,  // FETCH_ASSOC
                    2 => FetchMode::Num,    // FETCH_NUM
                    5 => FetchMode::Obj,    // FETCH_OBJ
                    7 => FetchMode::Column, // FETCH_COLUMN
                    _ => FetchMode::Both,   // FETCH_BOTH (default)
                };

                if let Some(stmt) = self.pdo_statements.get_mut(&obj_id) {
                    if let Some(row) = stmt.fetch(fetch_mode) {
                        Ok(Some(pdo_row_to_value(&row, fetch_mode, self)))
                    } else {
                        Ok(Some(Value::Bool(false)))
                    }
                } else {
                    Ok(Some(Value::Bool(false)))
                }
            }
            "fetchAll" => {
                // $stmt->fetchAll($fetch_mode = PDO::FETCH_BOTH)
                let fetch_mode_raw = args.get(1).map(|v| v.to_long()).unwrap_or(4);

                // Check for FETCH_GROUP (0x10000) or FETCH_UNIQUE (0x30000) flags
                let is_group = (fetch_mode_raw & 0x10000) != 0;
                let is_unique = (fetch_mode_raw & 0x30000) == 0x30000;
                let base_mode = fetch_mode_raw & 0xFFFF;

                let fetch_mode = match base_mode {
                    2 => FetchMode::Assoc,
                    3 => FetchMode::Num,
                    5 => FetchMode::Obj,
                    7 => FetchMode::Column,
                    12 => FetchMode::KeyPair,
                    _ => FetchMode::Both,
                };

                if let Some(stmt) = self.pdo_statements.get_mut(&obj_id) {
                    let rows = stmt.fetch_all(fetch_mode);

                    if fetch_mode == FetchMode::KeyPair {
                        // FETCH_KEY_PAIR: first col = key, second col = value
                        let mut result = PhpArray::new();
                        for row in &rows {
                            if row.values.len() >= 2 {
                                let key_str = row.values[0].to_string();
                                result.set_string(key_str, pdo_value_to_value(&row.values[1]));
                            }
                        }
                        Ok(Some(Value::Array(result)))
                    } else if is_group || is_unique {
                        // FETCH_GROUP or FETCH_UNIQUE: group by first column
                        let mut result = PhpArray::new();
                        for row in &rows {
                            if row.values.is_empty() {
                                continue;
                            }
                            let key = row.values[0].to_string();
                            // Create a row value without the grouping column
                            let sub_row = PdoRow {
                                columns: row.columns[1..].to_vec(),
                                values: row.values[1..].to_vec(),
                            };
                            let row_val = pdo_row_to_value(&sub_row, fetch_mode, self);

                            if is_unique {
                                // FETCH_UNIQUE: one value per key
                                result.set_string(key, row_val);
                            } else {
                                // FETCH_GROUP: array of values per key
                                let existing = result.get_string(&key);
                                let mut group = match existing {
                                    Some(Value::Array(a)) => a.clone(),
                                    _ => PhpArray::new(),
                                };
                                group.push(row_val);
                                result.set_string(key, Value::Array(group));
                            }
                        }
                        Ok(Some(Value::Array(result)))
                    } else {
                        let mut result = PhpArray::new();
                        for row in rows {
                            result.push(pdo_row_to_value(&row, fetch_mode, self));
                        }
                        Ok(Some(Value::Array(result)))
                    }
                } else {
                    Ok(Some(Value::Array(PhpArray::new())))
                }
            }
            "fetchColumn" => {
                // $stmt->fetchColumn($column_number = 0)
                let col_num = args.get(1).map(|v| v.to_long() as usize).unwrap_or(0);

                if let Some(stmt) = self.pdo_statements.get_mut(&obj_id) {
                    if let Some(val) = stmt.fetch_column(col_num) {
                        Ok(Some(pdo_value_to_value(&val)))
                    } else {
                        Ok(Some(Value::Bool(false)))
                    }
                } else {
                    Ok(Some(Value::Bool(false)))
                }
            }
            "rowCount" => {
                if let Some(stmt) = self.pdo_statements.get(&obj_id) {
                    Ok(Some(Value::Long(stmt.row_count() as i64)))
                } else {
                    Ok(Some(Value::Long(0)))
                }
            }
            "columnCount" => {
                if let Some(stmt) = self.pdo_statements.get(&obj_id) {
                    Ok(Some(Value::Long(stmt.column_count() as i64)))
                } else {
                    Ok(Some(Value::Long(0)))
                }
            }
            "getColumnMeta" => {
                let col_idx = args.get(1).map(|v| v.to_long() as usize).unwrap_or(0);
                if let Some(stmt) = self.pdo_statements.get(&obj_id) {
                    if let Some(meta) = stmt.get_column_meta(col_idx) {
                        let mut arr = PhpArray::new();
                        arr.set_string("name".to_string(), Value::String(meta.name));
                        arr.set_string("table".to_string(), Value::String(meta.table));
                        arr.set_string("native_type".to_string(), Value::String(meta.native_type));
                        arr.set_string("len".to_string(), Value::Long(meta.len));
                        arr.set_string("precision".to_string(), Value::Long(meta.precision));
                        arr.set_string("pdo_type".to_string(), Value::Long(meta.pdo_type as i64));
                        arr.set_string("flags".to_string(), Value::Array(PhpArray::new()));
                        Ok(Some(Value::Array(arr)))
                    } else {
                        Ok(Some(Value::Bool(false)))
                    }
                } else {
                    Ok(Some(Value::Bool(false)))
                }
            }
            "bindValue" => {
                use php_rs_ext_pdo::{PdoParam, PdoValue as PV};
                let param_val = args.get(1).cloned().unwrap_or(Value::Null);
                let value_val = args.get(2).cloned().unwrap_or(Value::Null);

                let param = match &param_val {
                    Value::Long(i) => PdoParam::Positional(*i as usize),
                    Value::String(s) => {
                        let name = if s.starts_with(':') {
                            s.clone()
                        } else {
                            format!(":{}", s)
                        };
                        PdoParam::Named(name)
                    }
                    _ => PdoParam::Positional(param_val.to_long() as usize),
                };

                let pdo_val = value_to_pdo_value(&value_val);

                if let Some(stmt) = self.pdo_statements.get_mut(&obj_id) {
                    match stmt.bind_value(param, pdo_val) {
                        Ok(_) => Ok(Some(Value::Bool(true))),
                        Err(_) => Ok(Some(Value::Bool(false))),
                    }
                } else {
                    Ok(Some(Value::Bool(false)))
                }
            }
            "bindParam" => {
                // bindParam is effectively the same as bindValue in our implementation
                // (PHP's pass-by-reference is handled at the VM level, not here)
                use php_rs_ext_pdo::{PdoParam, PdoValue as PV};
                let param_val = args.get(1).cloned().unwrap_or(Value::Null);
                let value_val = args.get(2).cloned().unwrap_or(Value::Null);

                let param = match &param_val {
                    Value::Long(i) => PdoParam::Positional(*i as usize),
                    Value::String(s) => {
                        let name = if s.starts_with(':') {
                            s.clone()
                        } else {
                            format!(":{}", s)
                        };
                        PdoParam::Named(name)
                    }
                    _ => PdoParam::Positional(param_val.to_long() as usize),
                };

                let pdo_val = value_to_pdo_value(&value_val);

                if let Some(stmt) = self.pdo_statements.get_mut(&obj_id) {
                    match stmt.bind_value(param, pdo_val) {
                        Ok(_) => Ok(Some(Value::Bool(true))),
                        Err(_) => Ok(Some(Value::Bool(false))),
                    }
                } else {
                    Ok(Some(Value::Bool(false)))
                }
            }
            "closeCursor" => {
                // No-op for our implementation (results are already buffered)
                Ok(Some(Value::Bool(true)))
            }
            "debugDumpParams" => {
                // No-op, just return null
                Ok(Some(Value::Null))
            }
            _ => Ok(None),
        }
    }

    // -----------------------------------------------------------------------
    // SQLite3 method handlers
    // -----------------------------------------------------------------------

    /// Call a method on a `SQLite3` instance (or a static SQLite3 method).
    #[cfg(feature = "native-io")]
    pub(crate) fn call_sqlite3_method(
        &mut self,
        method: &str,
        args: &[Value],
    ) -> VmResult<Option<Value>> {
        use crate::sqlite3::Sqlite3PreparedStmt;

        // Handle static methods first (no $this needed)
        match method {
            // escapeString($str) → string  (static or instance)
            "escapeString" => {
                // static call: args[0] is the string; instance call: args[0] is $this, args[1] is string
                let s = if matches!(args.first(), Some(Value::Object(_))) {
                    args.get(1).map(|v| v.to_php_string()).unwrap_or_default()
                } else {
                    args.first().map(|v| v.to_php_string()).unwrap_or_default()
                };
                return Ok(Some(Value::String(s.replace('\'', "''"))));
            }
            // version() → array  (static or instance)
            "version" => {
                let ver_str = rusqlite::version();
                let ver_num = rusqlite::version_number();
                let mut arr = PhpArray::new();
                arr.set_string(
                    "versionString".to_string(),
                    Value::String(ver_str.to_string()),
                );
                arr.set_string("versionNumber".to_string(), Value::Long(ver_num as i64));
                return Ok(Some(Value::Array(arr)));
            }
            _ => {}
        }

        // Instance methods: $this is args[0]
        let obj = match args.first() {
            Some(Value::Object(o)) => o.clone(),
            _ => return Ok(None),
        };
        let db_id = obj.object_id();

        match method {
            // exec($sql) → bool
            "exec" => {
                let sql = args.get(1).map(|v| v.to_php_string()).unwrap_or_default();
                if let Some(conn) = self.sqlite3_connections.get(&db_id) {
                    match conn.conn.execute_batch(&sql) {
                        Ok(_) => Ok(Some(Value::Bool(true))),
                        Err(e) => {
                            if let Some(c) = self.sqlite3_connections.get_mut(&db_id) {
                                c.last_error_code =
                                    e.sqlite_error_code().map(|c| c as i32).unwrap_or(1);
                                c.last_error_msg = e.to_string();
                            }
                            Ok(Some(Value::Bool(false)))
                        }
                    }
                } else {
                    Ok(Some(Value::Bool(false)))
                }
            }

            // query($sql) → SQLite3Result|false
            "query" => {
                let sql = args.get(1).map(|v| v.to_php_string()).unwrap_or_default();
                self.sqlite3_execute_query(db_id, &sql, &[], &[])
            }

            // prepare($sql) → SQLite3Stmt|false
            "prepare" => {
                let sql = args.get(1).map(|v| v.to_php_string()).unwrap_or_default();
                if self.sqlite3_connections.contains_key(&db_id) {
                    let stmt_obj = PhpObject::new("SQLite3Stmt".to_string());
                    stmt_obj.set_object_id(self.next_object_id);
                    self.next_object_id += 1;
                    let stmt_id = stmt_obj.object_id();
                    self.sqlite3_stmts
                        .insert(stmt_id, Sqlite3PreparedStmt::new(&sql, db_id));
                    Ok(Some(Value::Object(stmt_obj)))
                } else {
                    Ok(Some(Value::Bool(false)))
                }
            }

            // querySingle($sql, $entire_row = false) → mixed
            "querySingle" => {
                let sql = args.get(1).map(|v| v.to_php_string()).unwrap_or_default();
                let entire_row = args.get(2).map(|v| v.to_bool()).unwrap_or(false);
                match self.sqlite3_execute_query(db_id, &sql, &[], &[])? {
                    Some(Value::Object(result_obj)) => {
                        let result_id = result_obj.object_id();
                        if let Some(rs) = self.sqlite3_results.get_mut(&result_id) {
                            if let Some(row) = rs.rows.first() {
                                if entire_row {
                                    let mut arr = PhpArray::new();
                                    for (col, val) in rs.columns.iter().zip(row.iter()) {
                                        arr.set_string(
                                            col.clone(),
                                            sqlite3_rusql_to_vm_value(val.clone()),
                                        );
                                    }
                                    Ok(Some(Value::Array(arr)))
                                } else {
                                    Ok(Some(sqlite3_rusql_to_vm_value(row[0].clone())))
                                }
                            } else {
                                Ok(Some(Value::Bool(false)))
                            }
                        } else {
                            Ok(Some(Value::Bool(false)))
                        }
                    }
                    _ => Ok(Some(Value::Bool(false))),
                }
            }

            // lastInsertRowID() → int
            "lastInsertRowID" => {
                if let Some(conn) = self.sqlite3_connections.get(&db_id) {
                    Ok(Some(Value::Long(conn.conn.last_insert_rowid())))
                } else {
                    Ok(Some(Value::Long(0)))
                }
            }

            // changes() → int
            "changes" => {
                if let Some(conn) = self.sqlite3_connections.get(&db_id) {
                    Ok(Some(Value::Long(conn.conn.changes() as i64)))
                } else {
                    Ok(Some(Value::Long(0)))
                }
            }

            // lastErrorCode() → int
            "lastErrorCode" => {
                if let Some(conn) = self.sqlite3_connections.get(&db_id) {
                    Ok(Some(Value::Long(conn.last_error_code as i64)))
                } else {
                    Ok(Some(Value::Long(0)))
                }
            }

            // lastErrorMsg() → string
            "lastErrorMsg" => {
                if let Some(conn) = self.sqlite3_connections.get(&db_id) {
                    Ok(Some(Value::String(conn.last_error_msg.clone())))
                } else {
                    Ok(Some(Value::String(String::new())))
                }
            }

            // close() → bool
            "close" => {
                self.sqlite3_connections.remove(&db_id);
                Ok(Some(Value::Bool(true)))
            }

            // busyTimeout($ms) → bool
            "busyTimeout" => {
                let ms = args.get(1).map(|v| v.to_long()).unwrap_or(0);
                if let Some(conn) = self.sqlite3_connections.get(&db_id) {
                    let dur = std::time::Duration::from_millis(ms as u64);
                    let ok = conn.conn.busy_timeout(dur).is_ok();
                    Ok(Some(Value::Bool(ok)))
                } else {
                    Ok(Some(Value::Bool(false)))
                }
            }

            // enableExceptions — no-op (we always throw)
            "enableExceptions" => Ok(Some(Value::Bool(true))),

            _ => Ok(None),
        }
    }

    /// Execute a query on a connection and return a SQLite3Result object.
    #[cfg(feature = "native-io")]
    pub(crate) fn sqlite3_execute_query(
        &mut self,
        db_id: u64,
        sql: &str,
        named: &[(String, crate::sqlite3::Sqlite3ParamValue)],
        positional: &[(usize, crate::sqlite3::Sqlite3ParamValue)],
    ) -> VmResult<Option<Value>> {
        use crate::sqlite3::Sqlite3ResultSet;

        self.record_event("sql", sql.to_string());

        // Execute query inside a scope so the immutable borrow on sqlite3_connections
        // ends before we insert into sqlite3_results (which needs &mut self).
        let query_result: Result<(Vec<String>, Vec<Vec<rusqlite::types::Value>>), (i32, String)> = {
            let conn_wrapper = match self.sqlite3_connections.get(&db_id) {
                Some(c) => c,
                None => return Ok(Some(Value::Bool(false))),
            };

            match conn_wrapper.conn.prepare(sql) {
                Err(e) => Err((
                    e.sqlite_error_code().map(|c| c as i32).unwrap_or(1),
                    e.to_string(),
                )),
                Ok(mut rusql_stmt) => {
                    // Bind named params
                    for (name, val) in named {
                        if let Ok(Some(idx)) = rusql_stmt.parameter_index(name) {
                            let _ = rusql_stmt.raw_bind_parameter(idx, val);
                        }
                    }
                    // Bind positional params (1-indexed)
                    for (idx, val) in positional {
                        let _ = rusql_stmt.raw_bind_parameter(*idx, val);
                    }

                    let col_count = rusql_stmt.column_count();
                    let columns: Vec<String> = (0..col_count)
                        .map(|i| rusql_stmt.column_name(i).unwrap_or("").to_string())
                        .collect();

                    let mut rows: Vec<Vec<rusqlite::types::Value>> = Vec::new();
                    let mut iter = rusql_stmt.raw_query();
                    while let Ok(Some(row)) = iter.next() {
                        let rv: Vec<rusqlite::types::Value> = (0..col_count)
                            .map(|i| {
                                row.get::<_, rusqlite::types::Value>(i)
                                    .unwrap_or(rusqlite::types::Value::Null)
                            })
                            .collect();
                        rows.push(rv);
                    }
                    Ok((columns, rows))
                }
            }
        }; // immutable borrow on sqlite3_connections ends here

        match query_result {
            Err((code, msg)) => {
                if let Some(c) = self.sqlite3_connections.get_mut(&db_id) {
                    c.last_error_code = code;
                    c.last_error_msg = msg;
                }
                Ok(Some(Value::Bool(false)))
            }
            Ok((columns, rows)) => {
                let result_obj = PhpObject::new("SQLite3Result".to_string());
                result_obj.set_object_id(self.next_object_id);
                self.next_object_id += 1;
                let result_id = result_obj.object_id();
                self.sqlite3_results
                    .insert(result_id, Sqlite3ResultSet::new(columns, rows));
                Ok(Some(Value::Object(result_obj)))
            }
        }
    }

    /// Call a method on a `SQLite3Result` instance.
    #[cfg(feature = "native-io")]
    pub(crate) fn call_sqlite3_result_method(
        &mut self,
        method: &str,
        args: &[Value],
    ) -> VmResult<Option<Value>> {
        let obj = match args.first() {
            Some(Value::Object(o)) => o.clone(),
            _ => return Ok(None),
        };
        let result_id = obj.object_id();

        match method {
            // fetchArray($mode = SQLITE3_BOTH) → array|false
            "fetchArray" => {
                let mode = args.get(1).map(|v| v.to_long()).unwrap_or(3); // SQLITE3_BOTH = 3
                if let Some(rs) = self.sqlite3_results.get_mut(&result_id) {
                    if rs.current_row >= rs.rows.len() {
                        return Ok(Some(Value::Bool(false)));
                    }
                    let row = rs.rows[rs.current_row].clone();
                    let cols = rs.columns.clone();
                    rs.current_row += 1;

                    let mut arr = PhpArray::new();
                    for (i, val) in row.iter().enumerate() {
                        let php_val = sqlite3_rusql_to_vm_value(val.clone());
                        if mode == 1 || mode == 3 {
                            // SQLITE3_ASSOC or SQLITE3_BOTH
                            if let Some(col) = cols.get(i) {
                                arr.set_string(col.clone(), php_val.clone());
                            }
                        }
                        if mode == 2 || mode == 3 {
                            // SQLITE3_NUM or SQLITE3_BOTH
                            arr.push(php_val);
                        }
                    }
                    Ok(Some(Value::Array(arr)))
                } else {
                    Ok(Some(Value::Bool(false)))
                }
            }

            // numColumns() → int
            "numColumns" => {
                if let Some(rs) = self.sqlite3_results.get(&result_id) {
                    Ok(Some(Value::Long(rs.columns.len() as i64)))
                } else {
                    Ok(Some(Value::Long(0)))
                }
            }

            // columnName($n) → string
            "columnName" => {
                let n = args.get(1).map(|v| v.to_long()).unwrap_or(0) as usize;
                if let Some(rs) = self.sqlite3_results.get(&result_id) {
                    Ok(Some(Value::String(
                        rs.columns.get(n).cloned().unwrap_or_default(),
                    )))
                } else {
                    Ok(Some(Value::Bool(false)))
                }
            }

            // columnType($n) → int
            "columnType" => {
                let n = args.get(1).map(|v| v.to_long()).unwrap_or(0) as usize;
                if let Some(rs) = self.sqlite3_results.get(&result_id) {
                    // Use the type of the value in the current (or first) row
                    let type_id = rs
                        .rows
                        .get(rs.current_row.saturating_sub(1))
                        .and_then(|r| r.get(n))
                        .map(crate::sqlite3::Sqlite3ResultSet::sqlite3_type_of)
                        .unwrap_or(5); // SQLITE3_NULL
                    Ok(Some(Value::Long(type_id)))
                } else {
                    Ok(Some(Value::Long(5)))
                }
            }

            // reset() → bool
            "reset" => {
                if let Some(rs) = self.sqlite3_results.get_mut(&result_id) {
                    rs.current_row = 0;
                    Ok(Some(Value::Bool(true)))
                } else {
                    Ok(Some(Value::Bool(false)))
                }
            }

            // finalize() → bool
            "finalize" => {
                self.sqlite3_results.remove(&result_id);
                Ok(Some(Value::Bool(true)))
            }

            _ => Ok(None),
        }
    }

    /// Call a method on a `SQLite3Stmt` instance.
    #[cfg(feature = "native-io")]
    pub(crate) fn call_sqlite3_stmt_method(
        &mut self,
        method: &str,
        args: &[Value],
    ) -> VmResult<Option<Value>> {
        let obj = match args.first() {
            Some(Value::Object(o)) => o.clone(),
            _ => return Ok(None),
        };
        let stmt_id = obj.object_id();

        match method {
            // bindValue($param, $value, $type = SQLITE3_TEXT) → bool
            "bindValue" => {
                let param = args.get(1).map(|v| v.to_php_string()).unwrap_or_default();
                let value = args.get(2).cloned().unwrap_or(Value::Null);
                let type_hint = args.get(3).map(|v| v.to_long()).unwrap_or(3); // SQLITE3_TEXT

                let sv = vm_value_to_sqlite3_param(value, type_hint);
                if let Some(stmt) = self.sqlite3_stmts.get_mut(&stmt_id) {
                    // Positional if numeric string
                    if let Ok(idx) = param.parse::<usize>() {
                        stmt.positional_params.insert(idx, sv);
                    } else {
                        let key = if param.starts_with(':') {
                            param
                        } else {
                            format!(":{}", param)
                        };
                        stmt.named_params.insert(key, sv);
                    }
                    Ok(Some(Value::Bool(true)))
                } else {
                    Ok(Some(Value::Bool(false)))
                }
            }

            // bindParam — same as bindValue for our purposes (no pass-by-ref in builtins)
            "bindParam" => {
                let param = args.get(1).map(|v| v.to_php_string()).unwrap_or_default();
                let value = args.get(2).cloned().unwrap_or(Value::Null);
                let type_hint = args.get(3).map(|v| v.to_long()).unwrap_or(3);

                let sv = vm_value_to_sqlite3_param(value, type_hint);
                if let Some(stmt) = self.sqlite3_stmts.get_mut(&stmt_id) {
                    if let Ok(idx) = param.parse::<usize>() {
                        stmt.positional_params.insert(idx, sv);
                    } else {
                        let key = if param.starts_with(':') {
                            param
                        } else {
                            format!(":{}", param)
                        };
                        stmt.named_params.insert(key, sv);
                    }
                    Ok(Some(Value::Bool(true)))
                } else {
                    Ok(Some(Value::Bool(false)))
                }
            }

            // execute() → SQLite3Result|false
            "execute" => {
                // Clone what we need to avoid borrow conflicts
                let (sql, db_id, named, positional) = {
                    let stmt = match self.sqlite3_stmts.get(&stmt_id) {
                        Some(s) => s,
                        None => return Ok(Some(Value::Bool(false))),
                    };
                    let named: Vec<(String, crate::sqlite3::Sqlite3ParamValue)> = stmt
                        .named_params
                        .iter()
                        .map(|(k, v)| (k.clone(), v.clone()))
                        .collect();
                    let mut positional: Vec<(usize, crate::sqlite3::Sqlite3ParamValue)> = stmt
                        .positional_params
                        .iter()
                        .map(|(k, v)| (*k, v.clone()))
                        .collect();
                    positional.sort_by_key(|(k, _)| *k);
                    (stmt.sql.clone(), stmt.db_obj_id, named, positional)
                };
                self.sqlite3_execute_query(db_id, &sql, &named, &positional)
            }

            // reset() → bool  (clear params, keep sql)
            "reset" => {
                if let Some(stmt) = self.sqlite3_stmts.get_mut(&stmt_id) {
                    stmt.named_params.clear();
                    stmt.positional_params.clear();
                    Ok(Some(Value::Bool(true)))
                } else {
                    Ok(Some(Value::Bool(false)))
                }
            }

            // clear() → bool
            "clear" => {
                if let Some(stmt) = self.sqlite3_stmts.get_mut(&stmt_id) {
                    stmt.named_params.clear();
                    stmt.positional_params.clear();
                    Ok(Some(Value::Bool(true)))
                } else {
                    Ok(Some(Value::Bool(false)))
                }
            }

            // close() → bool
            "close" => {
                self.sqlite3_stmts.remove(&stmt_id);
                Ok(Some(Value::Bool(true)))
            }

            // paramCount() → int
            "paramCount" => {
                if let Some(stmt) = self.sqlite3_stmts.get(&stmt_id) {
                    // Count ?-style params in the SQL
                    let count = stmt.sql.chars().filter(|&c| c == '?').count();
                    Ok(Some(Value::Long(count as i64)))
                } else {
                    Ok(Some(Value::Long(0)))
                }
            }

            // readOnly() → bool
            "readOnly" => {
                if let Some(stmt) = self.sqlite3_stmts.get(&stmt_id) {
                    let upper = stmt.sql.trim_start().to_uppercase();
                    let ro = upper.starts_with("SELECT")
                        || upper.starts_with("WITH")
                        || upper.starts_with("EXPLAIN");
                    Ok(Some(Value::Bool(ro)))
                } else {
                    Ok(Some(Value::Bool(false)))
                }
            }

            _ => Ok(None),
        }
    }
}
