use crate::builtins::BuiltinRegistry;
use crate::value::{PhpArray, PhpObject, Value};
use crate::vm::{Vm, VmResult};
use php_rs_compiler::op::OperandType;

// ===========================================================================
// MySQLi prepared statement state
// ===========================================================================

/// Tracks a prepared statement's SQL, bound parameters, and execution results.
#[derive(Debug, Clone)]
pub struct MysqliStmt {
    /// The prepared SQL with ? placeholders.
    pub sql: String,
    /// Connection ID this statement belongs to.
    pub conn_id: i64,
    /// Bound parameter values (positional, 0-based).
    pub params: Vec<Value>,
    /// Bound parameter types (from bind_param type string).
    pub param_types: String,
    /// Number of affected rows after execute.
    pub affected_rows: u64,
    /// Last insert ID after execute.
    pub insert_id: u64,
    /// Error message (empty if no error).
    pub error: String,
    /// Error number (0 if no error).
    pub errno: u16,
    /// SQLSTATE string.
    pub sqlstate: String,
    /// Number of parameters (? placeholders).
    pub param_count: usize,
}

// ===========================================================================
// PDO helper functions (shared with vm.rs PDO handling)
// ===========================================================================

/// Convert a VM Value to a PdoValue for PDO parameter binding.
pub(crate) fn value_to_pdo_value(value: &Value) -> php_rs_ext_pdo::PdoValue {
    use php_rs_ext_pdo::PdoValue;

    match value {
        Value::Null => PdoValue::Null,
        Value::Bool(b) => PdoValue::Bool(*b),
        Value::Long(i) => PdoValue::Int(*i),
        Value::Double(f) => PdoValue::Float(*f),
        Value::String(s) => PdoValue::Str(s.clone()),
        Value::Reference(rc) => value_to_pdo_value(&rc.borrow()),
        _ => PdoValue::Str(value.to_php_string()),
    }
}

/// Convert a PdoValue to a VM Value.
pub(crate) fn pdo_value_to_value(pdo_val: &php_rs_ext_pdo::PdoValue) -> Value {
    use php_rs_ext_pdo::PdoValue;

    match pdo_val {
        PdoValue::Null => Value::Null,
        PdoValue::Bool(b) => Value::Bool(*b),
        PdoValue::Int(i) => Value::Long(*i),
        PdoValue::Float(f) => Value::Double(*f),
        PdoValue::Str(s) => Value::String(s.clone()),
        PdoValue::Blob(b) => Value::String(String::from_utf8_lossy(b).to_string()),
    }
}

/// Convert a PdoRow to a VM Value based on fetch mode.
pub(crate) fn pdo_row_to_value(
    row: &php_rs_ext_pdo::PdoRow,
    fetch_mode: php_rs_ext_pdo::FetchMode,
    vm: &mut Vm,
) -> Value {
    use php_rs_ext_pdo::FetchMode;

    match fetch_mode {
        FetchMode::Assoc => {
            let mut arr = PhpArray::new();
            for (i, col) in row.columns.iter().enumerate() {
                if let Some(val) = row.values.get(i) {
                    arr.set_string(col.clone(), pdo_value_to_value(val));
                }
            }
            Value::Array(arr)
        }
        FetchMode::Num => {
            let mut arr = PhpArray::new();
            for (i, val) in row.values.iter().enumerate() {
                arr.set_int(i as i64, pdo_value_to_value(val));
            }
            Value::Array(arr)
        }
        FetchMode::Both => {
            let mut arr = PhpArray::new();
            for (i, val) in row.values.iter().enumerate() {
                arr.set_int(i as i64, pdo_value_to_value(val));
                if let Some(col) = row.columns.get(i) {
                    arr.set_string(col.clone(), pdo_value_to_value(val));
                }
            }
            Value::Array(arr)
        }
        FetchMode::Obj => {
            let obj = PhpObject::new("stdClass".to_string());
            obj.set_object_id(vm.next_object_id);
            vm.next_object_id += 1;
            for (i, col) in row.columns.iter().enumerate() {
                if let Some(val) = row.values.get(i) {
                    obj.set_property(col.clone(), pdo_value_to_value(val));
                }
            }
            Value::Object(obj)
        }
        FetchMode::Column => {
            // Return first column value
            row.values
                .first()
                .map(pdo_value_to_value)
                .unwrap_or(Value::Null)
        }
        FetchMode::KeyPair | FetchMode::Group | FetchMode::Unique => {
            // These modes are handled at the fetchAll level, fall back to Assoc for individual rows
            let mut arr = PhpArray::new();
            for (i, col) in row.columns.iter().enumerate() {
                if let Some(val) = row.values.get(i) {
                    arr.set_string(col.clone(), pdo_value_to_value(val));
                }
            }
            Value::Array(arr)
        }
    }
}

// ===========================================================================
// MySQL value conversion helper
// ===========================================================================

/// Convert a MySQL value from a row to a PHP Value.
fn mysqli_value_to_php_value(row: &mysql::Row, index: usize) -> Value {
    use mysql::prelude::FromValue;

    let mysql_val = match row.as_ref(index) {
        Some(val) => val,
        None => return Value::Null,
    };

    // Try different types in order
    if let Ok(s) = String::from_value_opt(mysql_val.clone()) {
        return Value::String(s);
    }
    if let Ok(i) = i64::from_value_opt(mysql_val.clone()) {
        return Value::Long(i);
    }
    if let Ok(f) = f64::from_value_opt(mysql_val.clone()) {
        return Value::Double(f);
    }
    if let Ok(bytes) = Vec::<u8>::from_value_opt(mysql_val.clone()) {
        // Convert bytes to string
        return Value::String(String::from_utf8_lossy(&bytes).to_string());
    }

    Value::Null
}

// ===========================================================================
// Registration
// ===========================================================================

pub(crate) fn register(r: &mut BuiltinRegistry) {
    // mysqli connection
    r.insert("mysqli_connect", php_mysqli_connect);
    r.insert("mysqli_init", php_mysqli_init);
    r.insert("mysqli_real_connect", php_mysqli_real_connect);
    r.insert("mysqli_close", php_mysqli_close);

    // mysqli queries
    r.insert("mysqli_query", php_mysqli_query);
    r.insert("mysqli_real_query", php_mysqli_query);

    // multi/store/use stubs
    r.insert("mysqli_multi_query", php_mysqli_bool_false_stub);
    r.insert("mysqli_next_result", php_mysqli_bool_false_stub);
    r.insert("mysqli_more_results", php_mysqli_bool_false_stub);
    r.insert("mysqli_store_result", php_mysqli_bool_false_stub);
    r.insert("mysqli_use_result", php_mysqli_bool_false_stub);

    // prepared statements
    r.insert("mysqli_prepare", php_mysqli_prepare);
    r.insert("mysqli_stmt_init", php_mysqli_stmt_init);
    r.insert("mysqli_stmt_prepare", php_mysqli_stmt_prepare);
    r.insert("mysqli_stmt_bind_param", php_mysqli_stmt_bind_param);
    r.insert("mysqli_stmt_bind_result", php_mysqli_bool_true_stub); // no-op (results via get_result)
    r.insert("mysqli_stmt_execute", php_mysqli_stmt_execute);
    r.insert("mysqli_stmt_fetch", php_mysqli_bool_false_stub); // use get_result + fetch_assoc instead
    r.insert("mysqli_stmt_close", php_mysqli_stmt_close);
    r.insert("mysqli_stmt_reset", php_mysqli_stmt_reset);
    r.insert("mysqli_stmt_free_result", php_mysqli_stmt_free_result);
    r.insert("mysqli_stmt_send_long_data", php_mysqli_bool_false_stub);
    r.insert("mysqli_stmt_store_result", php_mysqli_bool_true_stub); // results always buffered
    r.insert("mysqli_stmt_get_result", php_mysqli_stmt_get_result);
    r.insert("mysqli_stmt_data_seek", php_mysqli_bool_false_stub);
    r.insert("mysqli_stmt_more_results", php_mysqli_bool_false_stub);
    r.insert("mysqli_stmt_next_result", php_mysqli_bool_false_stub);
    r.insert("mysqli_stmt_result_metadata", php_mysqli_bool_false_stub);
    r.insert("mysqli_stmt_attr_get", php_mysqli_bool_false_stub);
    r.insert("mysqli_stmt_attr_set", php_mysqli_bool_false_stub);
    r.insert("mysqli_stmt_error_list", php_mysqli_empty_array_stub);

    // stmt metadata
    r.insert("mysqli_stmt_affected_rows", php_mysqli_stmt_affected_rows);
    r.insert("mysqli_stmt_insert_id", php_mysqli_stmt_insert_id);
    r.insert("mysqli_stmt_num_rows", php_mysqli_stmt_num_rows);
    r.insert("mysqli_stmt_param_count", php_mysqli_stmt_param_count);
    r.insert("mysqli_stmt_field_count", php_mysqli_long_zero_stub);
    r.insert("mysqli_stmt_errno", php_mysqli_stmt_errno);

    // stmt error info
    r.insert("mysqli_stmt_error", php_mysqli_stmt_error);
    r.insert("mysqli_stmt_sqlstate", php_mysqli_stmt_sqlstate);

    // metadata / info
    r.insert("mysqli_affected_rows", php_mysqli_affected_rows);
    r.insert("mysqli_insert_id", php_mysqli_insert_id);
    r.insert("mysqli_num_rows", php_mysqli_num_rows);
    r.insert("mysqli_num_fields", php_mysqli_num_fields);
    r.insert("mysqli_field_count", php_mysqli_num_fields);
    r.insert("mysqli_errno", php_mysqli_errno);
    r.insert("mysqli_error", php_mysqli_error);
    r.insert("mysqli_thread_id", php_mysqli_long_zero_stub);

    // string info stubs
    r.insert("mysqli_sqlstate", php_mysqli_string_empty_stub);
    r.insert("mysqli_info", php_mysqli_string_empty_stub);
    r.insert("mysqli_stat", php_mysqli_string_empty_stub);
    r.insert("mysqli_get_host_info", php_mysqli_string_empty_stub);
    r.insert("mysqli_get_proto_info", php_mysqli_string_empty_stub);
    r.insert("mysqli_get_server_info", php_mysqli_string_empty_stub);
    r.insert("mysqli_character_set_name", php_mysqli_string_empty_stub);
    r.insert("mysqli_get_client_info", php_mysqli_string_empty_stub);

    // error info
    r.insert("mysqli_error_list", php_mysqli_empty_array_stub);
    r.insert("mysqli_connect_errno", php_mysqli_long_zero_stub);
    r.insert("mysqli_connect_error", php_mysqli_null_stub);

    // transactions (stubs)
    r.insert("mysqli_autocommit", php_mysqli_bool_false_stub);
    r.insert("mysqli_begin_transaction", php_mysqli_bool_false_stub);
    r.insert("mysqli_commit", php_mysqli_bool_false_stub);
    r.insert("mysqli_rollback", php_mysqli_bool_false_stub);
    r.insert("mysqli_savepoint", php_mysqli_bool_false_stub);
    r.insert("mysqli_release_savepoint", php_mysqli_bool_false_stub);

    // charset / db
    r.insert("mysqli_set_charset", php_mysqli_set_charset);
    r.insert("mysqli_select_db", php_mysqli_select_db);

    // options / misc stubs
    r.insert("mysqli_options", php_mysqli_bool_false_stub);
    r.insert("mysqli_ssl_set", php_mysqli_bool_false_stub);
    r.insert("mysqli_change_user", php_mysqli_bool_false_stub);
    r.insert("mysqli_dump_debug_info", php_mysqli_bool_false_stub);
    r.insert("mysqli_refresh", php_mysqli_bool_false_stub);
    r.insert("mysqli_kill", php_mysqli_bool_false_stub);
    r.insert("mysqli_ping", php_mysqli_bool_false_stub);

    // fetch functions
    r.insert("mysqli_fetch_assoc", php_mysqli_fetch_assoc);
    r.insert("mysqli_fetch_array", php_mysqli_fetch_array);
    r.insert("mysqli_fetch_row", php_mysqli_fetch_row);
    r.insert("mysqli_fetch_object", php_mysqli_bool_false_stub);
    r.insert("mysqli_fetch_column", php_mysqli_bool_false_stub);
    r.insert("mysqli_fetch_all", php_mysqli_empty_array_stub);
    r.insert("mysqli_fetch_field", php_mysqli_bool_false_stub);
    r.insert("mysqli_fetch_field_direct", php_mysqli_bool_false_stub);
    r.insert("mysqli_fetch_fields", php_mysqli_empty_array_stub);
    r.insert("mysqli_fetch_lengths", php_mysqli_empty_array_stub);

    // seek / field stubs
    r.insert("mysqli_data_seek", php_mysqli_bool_false_stub);
    r.insert("mysqli_field_seek", php_mysqli_bool_false_stub);

    // free result
    r.insert("mysqli_free_result", php_mysqli_free_result);

    // stats
    r.insert("mysqli_get_connection_stats", php_mysqli_empty_array_stub);
    r.insert("mysqli_get_client_stats", php_mysqli_empty_array_stub);
    r.insert("mysqli_get_charset", php_mysqli_bool_false_stub);
    r.insert("mysqli_get_client_version", php_mysqli_long_zero_stub);
    r.insert("mysqli_get_server_version", php_mysqli_long_zero_stub);
    r.insert("mysqli_warning_count", php_mysqli_long_zero_stub);
    r.insert("mysqli_field_tell", php_mysqli_long_zero_stub);
    r.insert("mysqli_get_links_stats", php_mysqli_empty_array_stub);

    // escape
    r.insert("mysqli_escape_string", php_mysqli_real_escape_string);
    r.insert("mysqli_real_escape_string", php_mysqli_real_escape_string);

    // misc
    r.insert("mysqli_debug", php_mysqli_bool_true_stub);
    r.insert("mysqli_execute", php_mysqli_bool_false_stub);
    r.insert("mysqli_execute_query", php_mysqli_bool_false_stub);
    r.insert("mysqli_thread_safe", php_mysqli_bool_true_stub);
    r.insert("mysqli_get_warnings", php_mysqli_bool_false_stub);
    r.insert("mysqli_stmt_get_warnings", php_mysqli_bool_false_stub);
    r.insert("mysqli_poll", php_mysqli_long_zero_stub);
    r.insert("mysqli_reap_async_query", php_mysqli_bool_false_stub);
    r.insert("mysqli_report", php_mysqli_bool_false_stub);
    r.insert("mysqli_set_opt", php_mysqli_bool_false_stub);

    // ===================================================================
    // pgsql (124 functions) — stubs
    // ===================================================================
    r.insert("pg_connect", php_pg_bool_false_stub);
    r.insert("pg_pconnect", php_pg_bool_false_stub);
    r.insert("pg_connect_poll", php_pg_bool_false_stub);
    r.insert("pg_close", php_pg_bool_true_stub);
    r.insert("pg_connection_status", php_pg_long_zero_stub);
    r.insert("pg_connection_busy", php_pg_long_zero_stub);
    r.insert("pg_connection_reset", php_pg_long_zero_stub);
    r.insert("pg_dbname", php_pg_string_empty_stub);
    r.insert("pg_host", php_pg_string_empty_stub);
    r.insert("pg_port", php_pg_string_empty_stub);
    r.insert("pg_options", php_pg_string_empty_stub);
    r.insert("pg_parameter_status", php_pg_string_empty_stub);
    r.insert("pg_version", php_pg_string_empty_stub);
    r.insert("pg_ping", php_pg_bool_false_stub);
    r.insert("pg_query", php_pg_bool_false_stub);
    r.insert("pg_query_params", php_pg_bool_false_stub);
    r.insert("pg_prepare", php_pg_bool_false_stub);
    r.insert("pg_execute", php_pg_bool_false_stub);
    r.insert("pg_send_query", php_pg_bool_false_stub);
    r.insert("pg_send_query_params", php_pg_bool_false_stub);
    r.insert("pg_send_prepare", php_pg_bool_false_stub);
    r.insert("pg_send_execute", php_pg_bool_false_stub);
    r.insert("pg_result_status", php_pg_long_zero_stub);
    r.insert("pg_result_error_field", php_pg_long_zero_stub);
    r.insert("pg_result_error", php_pg_string_empty_stub);
    r.insert("pg_last_error", php_pg_string_empty_stub);
    r.insert("pg_num_rows", php_pg_long_zero_stub);
    r.insert("pg_num_fields", php_pg_long_zero_stub);
    r.insert("pg_affected_rows", php_pg_long_zero_stub);
    r.insert("pg_last_oid", php_pg_long_zero_stub);
    r.insert("pg_field_num", php_pg_long_zero_stub);
    r.insert("pg_fetch_result", php_pg_bool_false_stub);
    r.insert("pg_fetch_row", php_pg_bool_false_stub);
    r.insert("pg_fetch_assoc", php_pg_bool_false_stub);
    r.insert("pg_fetch_array", php_pg_bool_false_stub);
    r.insert("pg_fetch_object", php_pg_bool_false_stub);
    r.insert("pg_fetch_all", php_pg_bool_false_stub);
    r.insert("pg_fetch_all_columns", php_pg_bool_false_stub);
    r.insert("pg_result_seek", php_pg_bool_false_stub);
    r.insert("pg_field_is_null", php_pg_bool_false_stub);
    r.insert("pg_field_name", php_pg_string_empty_stub);
    r.insert("pg_field_type", php_pg_string_empty_stub);
    r.insert("pg_field_type_oid", php_pg_string_empty_stub);
    r.insert("pg_field_size", php_pg_string_empty_stub);
    r.insert("pg_field_prtlen", php_pg_string_empty_stub);
    r.insert("pg_field_table", php_pg_string_empty_stub);
    r.insert("pg_free_result", php_pg_bool_true_stub);
    r.insert("pg_last_notice", php_pg_string_empty_stub);
    r.insert("pg_end_copy", php_pg_bool_false_stub);
    r.insert("pg_put_line", php_pg_bool_false_stub);
    r.insert("pg_copy_from", php_pg_bool_false_stub);
    r.insert("pg_copy_to", php_pg_bool_false_stub);
    r.insert("pg_cancel_query", php_pg_bool_false_stub);
    r.insert("pg_escape_string", php_pg_escape_passthrough);
    r.insert("pg_escape_literal", php_pg_escape_passthrough);
    r.insert("pg_escape_identifier", php_pg_escape_passthrough);
    r.insert("pg_escape_bytea", php_pg_escape_passthrough);
    r.insert("pg_unescape_bytea", php_pg_escape_passthrough);
    r.insert("pg_get_result", php_pg_bool_false_stub);
    r.insert("pg_result_memory_size", php_pg_bool_false_stub);
    r.insert("pg_change_password", php_pg_bool_false_stub);
    r.insert("pg_get_notify", php_pg_bool_false_stub);
    r.insert("pg_get_pid", php_pg_bool_false_stub);
    r.insert("pg_consume_input", php_pg_bool_false_stub);
    r.insert("pg_flush", php_pg_bool_false_stub);
    r.insert("pg_meta_data", php_pg_bool_false_stub);
    r.insert("pg_convert", php_pg_bool_false_stub);
    r.insert("pg_insert", php_pg_bool_false_stub);
    r.insert("pg_update", php_pg_bool_false_stub);
    r.insert("pg_delete", php_pg_bool_false_stub);
    r.insert("pg_select", php_pg_bool_false_stub);
    r.insert("pg_lo_create", php_pg_bool_false_stub);
    r.insert("pg_lo_open", php_pg_bool_false_stub);
    r.insert("pg_lo_close", php_pg_bool_false_stub);
    r.insert("pg_lo_read", php_pg_bool_false_stub);
    r.insert("pg_lo_write", php_pg_bool_false_stub);
    r.insert("pg_lo_read_all", php_pg_bool_false_stub);
    r.insert("pg_lo_import", php_pg_bool_false_stub);
    r.insert("pg_lo_export", php_pg_bool_false_stub);
    r.insert("pg_lo_seek", php_pg_bool_false_stub);
    r.insert("pg_lo_tell", php_pg_bool_false_stub);
    r.insert("pg_lo_truncate", php_pg_bool_false_stub);
    r.insert("pg_lo_unlink", php_pg_bool_false_stub);
    r.insert("pg_trace", php_pg_bool_false_stub);
    r.insert("pg_untrace", php_pg_bool_false_stub);
    r.insert("pg_client_encoding", php_pg_utf8_stub);
    r.insert("pg_set_client_encoding", php_pg_utf8_stub);
    r.insert("pg_set_error_verbosity", php_pg_long_zero_stub);
    r.insert("pg_set_error_context_visibility", php_pg_long_zero_stub);
    r.insert("pg_socket", php_pg_bool_false_stub);
    r.insert("pg_jit", php_pg_bool_false_stub);
    r.insert("pg_set_chunked_rows_size", php_pg_bool_false_stub);
    // pgsql aliases
    r.insert("pg_clientencoding", php_pg_utf8_stub);
    r.insert("pg_close_stmt", php_pg_bool_false_stub);
    r.insert("pg_cmdtuples", php_pg_long_zero_stub);
    r.insert("pg_errormessage", php_pg_string_empty_stub);
    r.insert("pg_exec", php_pg_bool_false_stub);
    r.insert("pg_fieldisnull", php_pg_bool_false_stub);
    r.insert("pg_fieldname", php_pg_string_empty_stub);
    r.insert("pg_fieldtype", php_pg_string_empty_stub);
    r.insert("pg_fieldnum", php_pg_long_zero_stub);
    r.insert("pg_fieldprtlen", php_pg_long_zero_stub);
    r.insert("pg_fieldsize", php_pg_long_zero_stub);
    r.insert("pg_freeresult", php_pg_bool_true_stub);
    r.insert("pg_getlastoid", php_pg_long_zero_stub);
    r.insert("pg_loclose", php_pg_bool_false_stub);
    r.insert("pg_locreate", php_pg_bool_false_stub);
    r.insert("pg_loexport", php_pg_bool_false_stub);
    r.insert("pg_loimport", php_pg_bool_false_stub);
    r.insert("pg_loopen", php_pg_bool_false_stub);
    r.insert("pg_loread", php_pg_bool_false_stub);
    r.insert("pg_loreadall", php_pg_bool_false_stub);
    r.insert("pg_lounlink", php_pg_bool_false_stub);
    r.insert("pg_lowrite", php_pg_bool_false_stub);
    r.insert("pg_numfields", php_pg_long_zero_stub);
    r.insert("pg_numrows", php_pg_long_zero_stub);
    r.insert("pg_put_copy_data", php_pg_bool_false_stub);
    r.insert("pg_put_copy_end", php_pg_bool_false_stub);
    r.insert("pg_result", php_pg_bool_false_stub);
    r.insert("pg_service", php_pg_bool_false_stub);
    r.insert("pg_setclientencoding", php_pg_long_zero_stub);
    r.insert("pg_socket_poll", php_pg_long_zero_stub);
    r.insert("pg_transaction_status", php_pg_long_zero_stub);
    r.insert("pg_tty", php_pg_string_empty_stub);

    // ODBC stubs removed — now handled by remaining.rs with real ext crate
}

// ===========================================================================
// Generic stub helpers
// ===========================================================================

fn php_mysqli_bool_false_stub(
    _vm: &mut Vm,
    _args: &[Value],
    _ref_args: &[(usize, OperandType, u32)],
    _ref_prop_args: &[(usize, Value, String)],
) -> VmResult<Value> {
    Ok(Value::Bool(false))
}

fn php_mysqli_bool_true_stub(
    _vm: &mut Vm,
    _args: &[Value],
    _ref_args: &[(usize, OperandType, u32)],
    _ref_prop_args: &[(usize, Value, String)],
) -> VmResult<Value> {
    Ok(Value::Bool(true))
}

fn php_mysqli_long_zero_stub(
    _vm: &mut Vm,
    _args: &[Value],
    _ref_args: &[(usize, OperandType, u32)],
    _ref_prop_args: &[(usize, Value, String)],
) -> VmResult<Value> {
    Ok(Value::Long(0))
}

fn php_mysqli_string_empty_stub(
    _vm: &mut Vm,
    _args: &[Value],
    _ref_args: &[(usize, OperandType, u32)],
    _ref_prop_args: &[(usize, Value, String)],
) -> VmResult<Value> {
    Ok(Value::String(String::new()))
}

fn php_mysqli_null_stub(
    _vm: &mut Vm,
    _args: &[Value],
    _ref_args: &[(usize, OperandType, u32)],
    _ref_prop_args: &[(usize, Value, String)],
) -> VmResult<Value> {
    Ok(Value::Null)
}

fn php_mysqli_empty_array_stub(
    _vm: &mut Vm,
    _args: &[Value],
    _ref_args: &[(usize, OperandType, u32)],
    _ref_prop_args: &[(usize, Value, String)],
) -> VmResult<Value> {
    Ok(Value::Array(PhpArray::new()))
}

// ===========================================================================
// mysqli_connect
// ===========================================================================

fn php_mysqli_connect(
    vm: &mut Vm,
    args: &[Value],
    _ref_args: &[(usize, OperandType, u32)],
    _ref_prop_args: &[(usize, Value, String)],
) -> VmResult<Value> {
    // mysqli_connect($host, $user, $pass, $db, $port = 3306)
    let host_val = args.first().cloned().unwrap_or(Value::Null);
    let host = if matches!(host_val, Value::Null) {
        "127.0.0.1".to_string()
    } else {
        let h = host_val.to_php_string();
        if h.is_empty() || h == "localhost" {
            "127.0.0.1".to_string()
        } else {
            h
        }
    };
    let user = args.get(1).cloned().unwrap_or(Value::Null).to_php_string();
    let pass = args.get(2).cloned().unwrap_or(Value::Null).to_php_string();
    let db = args.get(3).cloned().unwrap_or(Value::Null).to_php_string();
    let port = args.get(4).cloned().unwrap_or(Value::Long(3306)).to_long() as u16;

    let opts = mysql::OptsBuilder::new()
        .ip_or_hostname(Some(host))
        .user(Some(user))
        .pass(Some(pass))
        .db_name(Some(db))
        .tcp_port(port);

    match mysql::Conn::new(opts) {
        Ok(conn) => {
            let conn_id = vm.next_resource_id;
            vm.next_resource_id += 1;
            vm.mysqli_connections.insert(conn_id, conn);
            vm.mysqli_conn_meta
                .insert(conn_id, (0, 0, String::new(), 0));
            Ok(Value::Resource(conn_id, "mysqli".to_string()))
        }
        Err(e) => {
            eprintln!("MySQLi connection error: {}", e);
            Ok(Value::Bool(false))
        }
    }
}

// ===========================================================================
// mysqli_init
// ===========================================================================

fn php_mysqli_init(
    vm: &mut Vm,
    _args: &[Value],
    _ref_args: &[(usize, OperandType, u32)],
    _ref_prop_args: &[(usize, Value, String)],
) -> VmResult<Value> {
    // mysqli_init() — just return a new resource ID for OO-style usage
    let conn_id = vm.next_resource_id;
    vm.next_resource_id += 1;
    Ok(Value::Resource(conn_id, "mysqli_init".to_string()))
}

// ===========================================================================
// mysqli_real_connect
// ===========================================================================

fn php_mysqli_real_connect(
    vm: &mut Vm,
    args: &[Value],
    _ref_args: &[(usize, OperandType, u32)],
    _ref_prop_args: &[(usize, Value, String)],
) -> VmResult<Value> {
    // mysqli_real_connect($link, $host, $user, $pass, $db, $port, $socket, $flags)
    // Extract link resource ID from first argument
    let conn_id = match args.first().cloned().unwrap_or(Value::Null) {
        Value::Resource(id, _) => id,
        _ => {
            // If no valid link, create a new one
            let id = vm.next_resource_id;
            vm.next_resource_id += 1;
            id
        }
    };

    // Extract connection parameters, handling NULL values
    let host_val = args.get(1).cloned().unwrap_or(Value::Null);
    let host = if matches!(host_val, Value::Null) {
        "127.0.0.1".to_string()
    } else {
        let h = host_val.to_php_string();
        if h.is_empty() || h == "localhost" {
            // Force IPv4 since MySQL often only listens on 127.0.0.1
            "127.0.0.1".to_string()
        } else {
            h
        }
    };

    let user_val = args.get(2).cloned().unwrap_or(Value::Null);
    let user = if matches!(user_val, Value::Null) {
        "".to_string()
    } else {
        user_val.to_php_string()
    };

    let pass_val = args.get(3).cloned().unwrap_or(Value::Null);
    let pass = if matches!(pass_val, Value::Null) {
        "".to_string()
    } else {
        pass_val.to_php_string()
    };

    let db_val = args.get(4).cloned().unwrap_or(Value::Null);
    let db_opt = if matches!(db_val, Value::Null) {
        None
    } else {
        Some(db_val.to_php_string())
    };

    let port_val = args.get(5).cloned().unwrap_or(Value::Long(3306));
    let port = if matches!(port_val, Value::Null) {
        3306
    } else {
        let p = port_val.to_long() as u16;
        if p == 0 {
            3306
        } else {
            p
        }
    };

    let mut opts = mysql::OptsBuilder::new()
        .ip_or_hostname(Some(host))
        .user(Some(user))
        .pass(Some(pass))
        .tcp_port(port);

    if let Some(db) = db_opt {
        opts = opts.db_name(Some(db));
    }

    match mysql::Conn::new(opts) {
        Ok(conn) => {
            vm.mysqli_connections.insert(conn_id, conn);
            vm.mysqli_conn_meta
                .insert(conn_id, (0, 0, String::new(), 0));
            Ok(Value::Bool(true))
        }
        Err(e) => {
            eprintln!("MySQLi connection error: {}", e);
            Ok(Value::Bool(false))
        }
    }
}

// ===========================================================================
// mysqli_close
// ===========================================================================

fn php_mysqli_close(
    vm: &mut Vm,
    args: &[Value],
    _ref_args: &[(usize, OperandType, u32)],
    _ref_prop_args: &[(usize, Value, String)],
) -> VmResult<Value> {
    let conn_id = match args.first().cloned().unwrap_or(Value::Null) {
        Value::Resource(id, _) => id,
        _ => return Ok(Value::Bool(false)),
    };

    if vm.mysqli_connections.remove(&conn_id).is_some() {
        vm.mysqli_conn_meta.remove(&conn_id);
        Ok(Value::Bool(true))
    } else {
        Ok(Value::Bool(false))
    }
}

// ===========================================================================
// mysqli_query / mysqli_real_query
// ===========================================================================

fn php_mysqli_query(
    vm: &mut Vm,
    args: &[Value],
    _ref_args: &[(usize, OperandType, u32)],
    _ref_prop_args: &[(usize, Value, String)],
) -> VmResult<Value> {
    use mysql::prelude::Queryable;

    // mysqli_query($conn, $sql)
    let conn_id = match args.first().cloned().unwrap_or(Value::Null) {
        Value::Resource(id, _) => id,
        _ => return Ok(Value::Bool(false)),
    };
    let sql = args.get(1).cloned().unwrap_or(Value::Null).to_php_string();
    vm.record_event("sql", sql.clone());

    let conn = match vm.mysqli_connections.get_mut(&conn_id) {
        Some(c) => c,
        None => return Ok(Value::Bool(false)),
    };

    // For SELECT queries, use exec to get rows directly
    // For other queries (INSERT/UPDATE/DELETE), just execute
    let rows_result: Result<Vec<mysql::Row>, mysql::Error> = conn.query(sql.clone());

    match rows_result {
        Ok(rows) => {
            // Get connection metadata
            let affected = conn.affected_rows();
            let insert_id = conn.last_insert_id();

            // Update connection metadata
            if let Some(meta) = vm.mysqli_conn_meta.get_mut(&conn_id) {
                meta.0 = insert_id;
                meta.1 = affected;
                meta.2.clear();
                meta.3 = 0;
            }

            // If we have rows, we need to extract field names
            if !rows.is_empty() {
                // Get column names from the first row
                let field_names: Vec<String> = rows[0]
                    .columns_ref()
                    .iter()
                    .map(|c| c.name_str().to_string())
                    .collect();

                let result_id = vm.next_resource_id;
                vm.next_resource_id += 1;
                vm.mysqli_results.insert(result_id, (rows, 0, field_names));
                Ok(Value::Resource(result_id, "mysqli_result".to_string()))
            } else {
                // No rows returned - this was an INSERT/UPDATE/DELETE
                Ok(Value::Bool(true))
            }
        }
        Err(e) => {
            // Update error state
            if let Some(meta) = vm.mysqli_conn_meta.get_mut(&conn_id) {
                meta.2 = format!("{}", e);
                meta.3 = 1;
            }
            Ok(Value::Bool(false))
        }
    }
}

// ===========================================================================
// mysqli_affected_rows
// ===========================================================================

fn php_mysqli_affected_rows(
    vm: &mut Vm,
    args: &[Value],
    _ref_args: &[(usize, OperandType, u32)],
    _ref_prop_args: &[(usize, Value, String)],
) -> VmResult<Value> {
    let conn_id = match args.first().cloned().unwrap_or(Value::Null) {
        Value::Resource(id, _) => id,
        _ => return Ok(Value::Long(-1)),
    };

    if let Some(meta) = vm.mysqli_conn_meta.get(&conn_id) {
        Ok(Value::Long(meta.1 as i64))
    } else {
        Ok(Value::Long(-1))
    }
}

// ===========================================================================
// mysqli_insert_id
// ===========================================================================

fn php_mysqli_insert_id(
    vm: &mut Vm,
    args: &[Value],
    _ref_args: &[(usize, OperandType, u32)],
    _ref_prop_args: &[(usize, Value, String)],
) -> VmResult<Value> {
    let conn_id = match args.first().cloned().unwrap_or(Value::Null) {
        Value::Resource(id, _) => id,
        _ => return Ok(Value::Long(0)),
    };

    if let Some(meta) = vm.mysqli_conn_meta.get(&conn_id) {
        Ok(Value::Long(meta.0 as i64))
    } else {
        Ok(Value::Long(0))
    }
}

// ===========================================================================
// mysqli_num_rows
// ===========================================================================

fn php_mysqli_num_rows(
    vm: &mut Vm,
    args: &[Value],
    _ref_args: &[(usize, OperandType, u32)],
    _ref_prop_args: &[(usize, Value, String)],
) -> VmResult<Value> {
    let result_id = match args.first().cloned().unwrap_or(Value::Null) {
        Value::Resource(id, _) => id,
        _ => return Ok(Value::Long(0)),
    };

    if let Some((rows, _, _)) = vm.mysqli_results.get(&result_id) {
        Ok(Value::Long(rows.len() as i64))
    } else {
        Ok(Value::Long(0))
    }
}

// ===========================================================================
// mysqli_num_fields / mysqli_field_count
// ===========================================================================

fn php_mysqli_num_fields(
    vm: &mut Vm,
    args: &[Value],
    _ref_args: &[(usize, OperandType, u32)],
    _ref_prop_args: &[(usize, Value, String)],
) -> VmResult<Value> {
    let result_id = match args.first().cloned().unwrap_or(Value::Null) {
        Value::Resource(id, _) => id,
        _ => return Ok(Value::Long(0)),
    };

    if let Some((_, _, field_names)) = vm.mysqli_results.get(&result_id) {
        Ok(Value::Long(field_names.len() as i64))
    } else {
        Ok(Value::Long(0))
    }
}

// ===========================================================================
// mysqli_errno
// ===========================================================================

fn php_mysqli_errno(
    vm: &mut Vm,
    args: &[Value],
    _ref_args: &[(usize, OperandType, u32)],
    _ref_prop_args: &[(usize, Value, String)],
) -> VmResult<Value> {
    let conn_id = match args.first().cloned().unwrap_or(Value::Null) {
        Value::Resource(id, _) => id,
        _ => return Ok(Value::Long(0)),
    };

    if let Some(meta) = vm.mysqli_conn_meta.get(&conn_id) {
        Ok(Value::Long(meta.3 as i64))
    } else {
        Ok(Value::Long(0))
    }
}

// ===========================================================================
// mysqli_error
// ===========================================================================

fn php_mysqli_error(
    vm: &mut Vm,
    args: &[Value],
    _ref_args: &[(usize, OperandType, u32)],
    _ref_prop_args: &[(usize, Value, String)],
) -> VmResult<Value> {
    let conn_id = match args.first().cloned().unwrap_or(Value::Null) {
        Value::Resource(id, _) => id,
        _ => return Ok(Value::String(String::new())),
    };

    if let Some(meta) = vm.mysqli_conn_meta.get(&conn_id) {
        Ok(Value::String(meta.2.clone()))
    } else {
        Ok(Value::String(String::new()))
    }
}

// ===========================================================================
// mysqli_set_charset
// ===========================================================================

fn php_mysqli_set_charset(
    vm: &mut Vm,
    args: &[Value],
    _ref_args: &[(usize, OperandType, u32)],
    _ref_prop_args: &[(usize, Value, String)],
) -> VmResult<Value> {
    use mysql::prelude::Queryable;

    // mysqli_set_charset($conn, $charset)
    let conn_id = match args.first().cloned().unwrap_or(Value::Null) {
        Value::Resource(id, _) => id,
        _ => return Ok(Value::Bool(false)),
    };
    let charset = args.get(1).cloned().unwrap_or(Value::Null).to_php_string();

    let conn = match vm.mysqli_connections.get_mut(&conn_id) {
        Some(c) => c,
        None => return Ok(Value::Bool(false)),
    };

    // Execute SET NAMES query
    match conn.query_drop(format!("SET NAMES '{}'", charset)) {
        Ok(_) => Ok(Value::Bool(true)),
        Err(_) => Ok(Value::Bool(false)),
    }
}

// ===========================================================================
// mysqli_select_db
// ===========================================================================

fn php_mysqli_select_db(
    vm: &mut Vm,
    args: &[Value],
    _ref_args: &[(usize, OperandType, u32)],
    _ref_prop_args: &[(usize, Value, String)],
) -> VmResult<Value> {
    use mysql::prelude::Queryable;

    // mysqli_select_db($conn, $dbname)
    let conn_id = match args.first().cloned().unwrap_or(Value::Null) {
        Value::Resource(id, _) => id,
        _ => return Ok(Value::Bool(false)),
    };

    let dbname = args.get(1).cloned().unwrap_or(Value::Null).to_php_string();

    if let Some(conn) = vm.mysqli_connections.get_mut(&conn_id) {
        let query = format!("USE `{}`", dbname.replace('`', "``"));
        let result: Result<Vec<mysql::Row>, mysql::Error> = conn.query(query);
        match result {
            Ok(_) => Ok(Value::Bool(true)),
            Err(e) => {
                if let Some((_, _, err_msg, err_no)) = vm.mysqli_conn_meta.get_mut(&conn_id) {
                    *err_msg = format!("{:?}", e);
                    *err_no = 1;
                }
                Ok(Value::Bool(false))
            }
        }
    } else {
        Ok(Value::Bool(false))
    }
}

// ===========================================================================
// mysqli_fetch_assoc
// ===========================================================================

fn php_mysqli_fetch_assoc(
    vm: &mut Vm,
    args: &[Value],
    _ref_args: &[(usize, OperandType, u32)],
    _ref_prop_args: &[(usize, Value, String)],
) -> VmResult<Value> {
    // mysqli_fetch_assoc($result) -> array|null
    let result_id = match args.first().cloned().unwrap_or(Value::Null) {
        Value::Resource(id, _) => id,
        _ => return Ok(Value::Null),
    };

    let result_data = match vm.mysqli_results.get_mut(&result_id) {
        Some(data) => data,
        None => return Ok(Value::Null),
    };

    let (rows, position, field_names) = result_data;

    if *position >= rows.len() {
        return Ok(Value::Null);
    }

    let current_position = *position;
    *position += 1;
    let row = rows[current_position].clone();
    let field_names_clone = field_names.clone();

    // Build associative array
    let mut arr = PhpArray::new();
    for (i, field_name) in field_names_clone.iter().enumerate() {
        let value = mysqli_value_to_php_value(&row, i);
        arr.set_string(field_name.clone(), value);
    }

    Ok(Value::Array(arr))
}

// ===========================================================================
// mysqli_fetch_array
// ===========================================================================

fn php_mysqli_fetch_array(
    vm: &mut Vm,
    args: &[Value],
    _ref_args: &[(usize, OperandType, u32)],
    _ref_prop_args: &[(usize, Value, String)],
) -> VmResult<Value> {
    // mysqli_fetch_array($result, $mode = MYSQLI_BOTH) -> array|null
    let result_id = match args.first().cloned().unwrap_or(Value::Null) {
        Value::Resource(id, _) => id,
        _ => return Ok(Value::Null),
    };
    let mode = args.get(1).cloned().unwrap_or(Value::Long(3)).to_long(); // MYSQLI_BOTH = 3

    let result_data = match vm.mysqli_results.get_mut(&result_id) {
        Some(data) => data,
        None => return Ok(Value::Null),
    };

    let (rows, position, field_names) = result_data;

    if *position >= rows.len() {
        return Ok(Value::Null);
    }

    let current_position = *position;
    *position += 1;
    let row = rows[current_position].clone();
    let field_names_clone = field_names.clone();

    // Build array based on mode
    let mut arr = PhpArray::new();
    for (i, field_name) in field_names_clone.iter().enumerate() {
        let value = mysqli_value_to_php_value(&row, i);
        // MYSQLI_NUM = 2, MYSQLI_ASSOC = 1, MYSQLI_BOTH = 3
        if mode & 2 != 0 {
            // Include numeric keys
            arr.set_int(i as i64, value.clone());
        }
        if mode & 1 != 0 {
            // Include associative keys
            arr.set_string(field_name.clone(), value);
        }
    }

    Ok(Value::Array(arr))
}

// ===========================================================================
// mysqli_fetch_row
// ===========================================================================

fn php_mysqli_fetch_row(
    vm: &mut Vm,
    args: &[Value],
    _ref_args: &[(usize, OperandType, u32)],
    _ref_prop_args: &[(usize, Value, String)],
) -> VmResult<Value> {
    // mysqli_fetch_row($result) -> array|null
    let result_id = match args.first().cloned().unwrap_or(Value::Null) {
        Value::Resource(id, _) => id,
        _ => return Ok(Value::Null),
    };

    let result_data = match vm.mysqli_results.get_mut(&result_id) {
        Some(data) => data,
        None => return Ok(Value::Null),
    };

    let (rows, position, field_names) = result_data;

    if *position >= rows.len() {
        return Ok(Value::Null);
    }

    let current_position = *position;
    *position += 1;
    let row = rows[current_position].clone();
    let num_fields = field_names.len();

    // Build indexed array
    let mut arr = PhpArray::new();
    for i in 0..num_fields {
        let value = mysqli_value_to_php_value(&row, i);
        arr.set_int(i as i64, value);
    }

    Ok(Value::Array(arr))
}

// ===========================================================================
// mysqli_free_result
// ===========================================================================

fn php_mysqli_free_result(
    vm: &mut Vm,
    args: &[Value],
    _ref_args: &[(usize, OperandType, u32)],
    _ref_prop_args: &[(usize, Value, String)],
) -> VmResult<Value> {
    let result_id = match args.first().cloned().unwrap_or(Value::Null) {
        Value::Resource(id, _) => id,
        _ => return Ok(Value::Null),
    };

    vm.mysqli_results.remove(&result_id);
    Ok(Value::Null)
}

// ===========================================================================
// mysqli_escape_string / mysqli_real_escape_string
// ===========================================================================

fn php_mysqli_real_escape_string(
    _vm: &mut Vm,
    args: &[Value],
    _ref_args: &[(usize, OperandType, u32)],
    _ref_prop_args: &[(usize, Value, String)],
) -> VmResult<Value> {
    let s = args
        .get(1)
        .cloned()
        .unwrap_or(args.first().cloned().unwrap_or(Value::Null))
        .to_php_string();
    Ok(Value::String(
        s.replace('\\', "\\\\")
            .replace('\'', "\\'")
            .replace('"', "\\\"")
            .replace('\0', "\\0"),
    ))
}

// ===========================================================================
// mysqli_prepare
// ===========================================================================

fn php_mysqli_prepare(
    vm: &mut Vm,
    args: &[Value],
    _ref_args: &[(usize, OperandType, u32)],
    _ref_prop_args: &[(usize, Value, String)],
) -> VmResult<Value> {
    // mysqli_prepare($conn, $query) -> mysqli_stmt|false
    let conn_id = match args.first().cloned().unwrap_or(Value::Null) {
        Value::Resource(id, _) => id,
        _ => return Ok(Value::Bool(false)),
    };
    let sql = args.get(1).cloned().unwrap_or(Value::Null).to_php_string();

    // Verify connection exists.
    if !vm.mysqli_connections.contains_key(&conn_id) {
        return Ok(Value::Bool(false));
    }

    // Count ? placeholders (outside strings).
    let param_count = count_placeholders(&sql);

    let stmt_id = vm.next_resource_id;
    vm.next_resource_id += 1;
    vm.mysqli_stmts.insert(stmt_id, MysqliStmt {
        sql,
        conn_id,
        params: Vec::new(),
        param_types: String::new(),
        affected_rows: 0,
        insert_id: 0,
        error: String::new(),
        errno: 0,
        sqlstate: "00000".to_string(),
        param_count,
    });

    Ok(Value::Resource(stmt_id, "mysqli_stmt".to_string()))
}

// ===========================================================================
// mysqli_stmt_init
// ===========================================================================

fn php_mysqli_stmt_init(
    vm: &mut Vm,
    args: &[Value],
    _ref_args: &[(usize, OperandType, u32)],
    _ref_prop_args: &[(usize, Value, String)],
) -> VmResult<Value> {
    // mysqli_stmt_init($conn) -> mysqli_stmt
    let conn_id = match args.first().cloned().unwrap_or(Value::Null) {
        Value::Resource(id, _) => id,
        _ => return Ok(Value::Bool(false)),
    };

    let stmt_id = vm.next_resource_id;
    vm.next_resource_id += 1;
    vm.mysqli_stmts.insert(stmt_id, MysqliStmt {
        sql: String::new(),
        conn_id,
        params: Vec::new(),
        param_types: String::new(),
        affected_rows: 0,
        insert_id: 0,
        error: String::new(),
        errno: 0,
        sqlstate: "00000".to_string(),
        param_count: 0,
    });

    Ok(Value::Resource(stmt_id, "mysqli_stmt".to_string()))
}

// ===========================================================================
// mysqli_stmt_prepare
// ===========================================================================

fn php_mysqli_stmt_prepare(
    vm: &mut Vm,
    args: &[Value],
    _ref_args: &[(usize, OperandType, u32)],
    _ref_prop_args: &[(usize, Value, String)],
) -> VmResult<Value> {
    // mysqli_stmt_prepare($stmt, $query) -> bool
    let stmt_id = match args.first().cloned().unwrap_or(Value::Null) {
        Value::Resource(id, _) => id,
        _ => return Ok(Value::Bool(false)),
    };
    let sql = args.get(1).cloned().unwrap_or(Value::Null).to_php_string();

    if let Some(stmt) = vm.mysqli_stmts.get_mut(&stmt_id) {
        stmt.param_count = count_placeholders(&sql);
        stmt.sql = sql;
        stmt.params.clear();
        stmt.param_types.clear();
        Ok(Value::Bool(true))
    } else {
        Ok(Value::Bool(false))
    }
}

// ===========================================================================
// mysqli_stmt_bind_param
// ===========================================================================

fn php_mysqli_stmt_bind_param(
    vm: &mut Vm,
    args: &[Value],
    _ref_args: &[(usize, OperandType, u32)],
    _ref_prop_args: &[(usize, Value, String)],
) -> VmResult<Value> {
    // mysqli_stmt_bind_param($stmt, $types, ...$values) -> bool
    let stmt_id = match args.first().cloned().unwrap_or(Value::Null) {
        Value::Resource(id, _) => id,
        _ => return Ok(Value::Bool(false)),
    };
    let types = args.get(1).cloned().unwrap_or(Value::Null).to_php_string();

    let stmt = match vm.mysqli_stmts.get_mut(&stmt_id) {
        Some(s) => s,
        None => return Ok(Value::Bool(false)),
    };

    stmt.param_types = types.clone();
    stmt.params.clear();

    // Collect bound values starting from arg index 2.
    for i in 2..args.len() {
        stmt.params.push(args[i].clone());
    }

    Ok(Value::Bool(true))
}

// ===========================================================================
// mysqli_stmt_execute
// ===========================================================================

fn php_mysqli_stmt_execute(
    vm: &mut Vm,
    args: &[Value],
    _ref_args: &[(usize, OperandType, u32)],
    _ref_prop_args: &[(usize, Value, String)],
) -> VmResult<Value> {
    use mysql::prelude::Queryable;

    // mysqli_stmt_execute($stmt) -> bool
    let stmt_id = match args.first().cloned().unwrap_or(Value::Null) {
        Value::Resource(id, _) => id,
        _ => return Ok(Value::Bool(false)),
    };

    // Get stmt data (clone to release borrow).
    let stmt_data = match vm.mysqli_stmts.get(&stmt_id) {
        Some(s) => s.clone(),
        None => return Ok(Value::Bool(false)),
    };

    let conn = match vm.mysqli_connections.get_mut(&stmt_data.conn_id) {
        Some(c) => c,
        None => {
            if let Some(stmt) = vm.mysqli_stmts.get_mut(&stmt_id) {
                stmt.error = "Connection not found".to_string();
                stmt.errno = 2006;
                stmt.sqlstate = "HY000".to_string();
            }
            return Ok(Value::Bool(false));
        }
    };

    // Convert bound params to mysql::Value.
    let mysql_params: Vec<mysql::Value> = stmt_data
        .params
        .iter()
        .enumerate()
        .map(|(i, v)| {
            let type_char = stmt_data.param_types.chars().nth(i).unwrap_or('s');
            value_to_mysql_param(v, type_char)
        })
        .collect();

    // Execute using prepared statement.
    let result = if mysql_params.is_empty() {
        conn.query::<mysql::Row, &str>(&stmt_data.sql)
    } else {
        match conn.prep(&stmt_data.sql) {
            Ok(prep_stmt) => conn.exec::<mysql::Row, _, _>(&prep_stmt, &mysql_params),
            Err(e) => Err(e),
        }
    };

    match result {
        Ok(rows) => {
            let affected = conn.affected_rows();
            let insert_id = conn.last_insert_id();

            // Store result rows if any.
            if !rows.is_empty() {
                let field_names: Vec<String> = rows[0]
                    .columns_ref()
                    .iter()
                    .map(|c| c.name_str().to_string())
                    .collect();

                let result_id = vm.next_resource_id;
                vm.next_resource_id += 1;
                vm.mysqli_results.insert(result_id, (rows, 0, field_names));

                // Associate result with statement for get_result.
                if let Some(stmt) = vm.mysqli_stmts.get_mut(&stmt_id) {
                    stmt.affected_rows = affected;
                    stmt.insert_id = insert_id;
                    stmt.error.clear();
                    stmt.errno = 0;
                    stmt.sqlstate = "00000".to_string();
                }

                // Store result_id on the stmt resource so get_result can find it.
                // We use the conn_meta trick: store in a separate map keyed by stmt_id.
                vm.mysqli_conn_meta.entry(stmt_id).or_insert((0, 0, String::new(), 0));
                if let Some(meta) = vm.mysqli_conn_meta.get_mut(&stmt_id) {
                    // Repurpose insert_id field to hold result_id.
                    meta.0 = result_id as u64;
                }
            } else {
                if let Some(stmt) = vm.mysqli_stmts.get_mut(&stmt_id) {
                    stmt.affected_rows = affected;
                    stmt.insert_id = insert_id;
                    stmt.error.clear();
                    stmt.errno = 0;
                    stmt.sqlstate = "00000".to_string();
                }
            }

            // Update connection metadata too.
            if let Some(meta) = vm.mysqli_conn_meta.get_mut(&stmt_data.conn_id) {
                meta.0 = insert_id;
                meta.1 = affected;
                meta.2.clear();
                meta.3 = 0;
            }

            Ok(Value::Bool(true))
        }
        Err(e) => {
            let err_msg = format!("{}", e);
            let errno = match &e {
                mysql::Error::MySqlError(me) => me.code as u16,
                _ => 1,
            };
            let sqlstate = match &e {
                mysql::Error::MySqlError(me) => me.state.clone(),
                _ => "HY000".to_string(),
            };

            if let Some(stmt) = vm.mysqli_stmts.get_mut(&stmt_id) {
                stmt.error = err_msg.clone();
                stmt.errno = errno;
                stmt.sqlstate = sqlstate;
            }
            if let Some(meta) = vm.mysqli_conn_meta.get_mut(&stmt_data.conn_id) {
                meta.2 = err_msg;
                meta.3 = errno;
            }
            Ok(Value::Bool(false))
        }
    }
}

// ===========================================================================
// mysqli_stmt_get_result
// ===========================================================================

fn php_mysqli_stmt_get_result(
    vm: &mut Vm,
    args: &[Value],
    _ref_args: &[(usize, OperandType, u32)],
    _ref_prop_args: &[(usize, Value, String)],
) -> VmResult<Value> {
    // mysqli_stmt_get_result($stmt) -> mysqli_result|false
    let stmt_id = match args.first().cloned().unwrap_or(Value::Null) {
        Value::Resource(id, _) => id,
        _ => return Ok(Value::Bool(false)),
    };

    // Look up the result_id stored during execute.
    if let Some(meta) = vm.mysqli_conn_meta.get(&stmt_id) {
        let result_id = meta.0 as i64;
        if vm.mysqli_results.contains_key(&result_id) {
            return Ok(Value::Resource(result_id, "mysqli_result".to_string()));
        }
    }

    Ok(Value::Bool(false))
}

// ===========================================================================
// mysqli_stmt_close
// ===========================================================================

fn php_mysqli_stmt_close(
    vm: &mut Vm,
    args: &[Value],
    _ref_args: &[(usize, OperandType, u32)],
    _ref_prop_args: &[(usize, Value, String)],
) -> VmResult<Value> {
    let stmt_id = match args.first().cloned().unwrap_or(Value::Null) {
        Value::Resource(id, _) => id,
        _ => return Ok(Value::Bool(false)),
    };

    vm.mysqli_stmts.remove(&stmt_id);
    Ok(Value::Bool(true))
}

// ===========================================================================
// mysqli_stmt_reset
// ===========================================================================

fn php_mysqli_stmt_reset(
    vm: &mut Vm,
    args: &[Value],
    _ref_args: &[(usize, OperandType, u32)],
    _ref_prop_args: &[(usize, Value, String)],
) -> VmResult<Value> {
    let stmt_id = match args.first().cloned().unwrap_or(Value::Null) {
        Value::Resource(id, _) => id,
        _ => return Ok(Value::Bool(false)),
    };

    if let Some(stmt) = vm.mysqli_stmts.get_mut(&stmt_id) {
        stmt.params.clear();
        stmt.param_types.clear();
        stmt.affected_rows = 0;
        stmt.insert_id = 0;
        stmt.error.clear();
        stmt.errno = 0;
        stmt.sqlstate = "00000".to_string();
        Ok(Value::Bool(true))
    } else {
        Ok(Value::Bool(false))
    }
}

// ===========================================================================
// mysqli_stmt_free_result
// ===========================================================================

fn php_mysqli_stmt_free_result(
    vm: &mut Vm,
    args: &[Value],
    _ref_args: &[(usize, OperandType, u32)],
    _ref_prop_args: &[(usize, Value, String)],
) -> VmResult<Value> {
    let stmt_id = match args.first().cloned().unwrap_or(Value::Null) {
        Value::Resource(id, _) => id,
        _ => return Ok(Value::Null),
    };

    // Remove associated result.
    if let Some(meta) = vm.mysqli_conn_meta.get(&stmt_id) {
        let result_id = meta.0 as i64;
        vm.mysqli_results.remove(&result_id);
    }
    Ok(Value::Null)
}

// ===========================================================================
// mysqli_stmt_affected_rows
// ===========================================================================

fn php_mysqli_stmt_affected_rows(
    vm: &mut Vm,
    args: &[Value],
    _ref_args: &[(usize, OperandType, u32)],
    _ref_prop_args: &[(usize, Value, String)],
) -> VmResult<Value> {
    let stmt_id = match args.first().cloned().unwrap_or(Value::Null) {
        Value::Resource(id, _) => id,
        _ => return Ok(Value::Long(-1)),
    };

    if let Some(stmt) = vm.mysqli_stmts.get(&stmt_id) {
        Ok(Value::Long(stmt.affected_rows as i64))
    } else {
        Ok(Value::Long(-1))
    }
}

// ===========================================================================
// mysqli_stmt_insert_id
// ===========================================================================

fn php_mysqli_stmt_insert_id(
    vm: &mut Vm,
    args: &[Value],
    _ref_args: &[(usize, OperandType, u32)],
    _ref_prop_args: &[(usize, Value, String)],
) -> VmResult<Value> {
    let stmt_id = match args.first().cloned().unwrap_or(Value::Null) {
        Value::Resource(id, _) => id,
        _ => return Ok(Value::Long(0)),
    };

    if let Some(stmt) = vm.mysqli_stmts.get(&stmt_id) {
        Ok(Value::Long(stmt.insert_id as i64))
    } else {
        Ok(Value::Long(0))
    }
}

// ===========================================================================
// mysqli_stmt_num_rows
// ===========================================================================

fn php_mysqli_stmt_num_rows(
    vm: &mut Vm,
    args: &[Value],
    _ref_args: &[(usize, OperandType, u32)],
    _ref_prop_args: &[(usize, Value, String)],
) -> VmResult<Value> {
    let stmt_id = match args.first().cloned().unwrap_or(Value::Null) {
        Value::Resource(id, _) => id,
        _ => return Ok(Value::Long(0)),
    };

    // Get result from associated meta.
    if let Some(meta) = vm.mysqli_conn_meta.get(&stmt_id) {
        let result_id = meta.0 as i64;
        if let Some((rows, _, _)) = vm.mysqli_results.get(&result_id) {
            return Ok(Value::Long(rows.len() as i64));
        }
    }
    Ok(Value::Long(0))
}

// ===========================================================================
// mysqli_stmt_param_count
// ===========================================================================

fn php_mysqli_stmt_param_count(
    vm: &mut Vm,
    args: &[Value],
    _ref_args: &[(usize, OperandType, u32)],
    _ref_prop_args: &[(usize, Value, String)],
) -> VmResult<Value> {
    let stmt_id = match args.first().cloned().unwrap_or(Value::Null) {
        Value::Resource(id, _) => id,
        _ => return Ok(Value::Long(0)),
    };

    if let Some(stmt) = vm.mysqli_stmts.get(&stmt_id) {
        Ok(Value::Long(stmt.param_count as i64))
    } else {
        Ok(Value::Long(0))
    }
}

// ===========================================================================
// mysqli_stmt_errno
// ===========================================================================

fn php_mysqli_stmt_errno(
    vm: &mut Vm,
    args: &[Value],
    _ref_args: &[(usize, OperandType, u32)],
    _ref_prop_args: &[(usize, Value, String)],
) -> VmResult<Value> {
    let stmt_id = match args.first().cloned().unwrap_or(Value::Null) {
        Value::Resource(id, _) => id,
        _ => return Ok(Value::Long(0)),
    };

    if let Some(stmt) = vm.mysqli_stmts.get(&stmt_id) {
        Ok(Value::Long(stmt.errno as i64))
    } else {
        Ok(Value::Long(0))
    }
}

// ===========================================================================
// mysqli_stmt_error
// ===========================================================================

fn php_mysqli_stmt_error(
    vm: &mut Vm,
    args: &[Value],
    _ref_args: &[(usize, OperandType, u32)],
    _ref_prop_args: &[(usize, Value, String)],
) -> VmResult<Value> {
    let stmt_id = match args.first().cloned().unwrap_or(Value::Null) {
        Value::Resource(id, _) => id,
        _ => return Ok(Value::String(String::new())),
    };

    if let Some(stmt) = vm.mysqli_stmts.get(&stmt_id) {
        Ok(Value::String(stmt.error.clone()))
    } else {
        Ok(Value::String(String::new()))
    }
}

// ===========================================================================
// mysqli_stmt_sqlstate
// ===========================================================================

fn php_mysqli_stmt_sqlstate(
    vm: &mut Vm,
    args: &[Value],
    _ref_args: &[(usize, OperandType, u32)],
    _ref_prop_args: &[(usize, Value, String)],
) -> VmResult<Value> {
    let stmt_id = match args.first().cloned().unwrap_or(Value::Null) {
        Value::Resource(id, _) => id,
        _ => return Ok(Value::String("00000".to_string())),
    };

    if let Some(stmt) = vm.mysqli_stmts.get(&stmt_id) {
        Ok(Value::String(stmt.sqlstate.clone()))
    } else {
        Ok(Value::String("00000".to_string()))
    }
}

// ===========================================================================
// Helper: convert PHP Value to mysql::Value based on type char
// ===========================================================================

fn value_to_mysql_param(value: &Value, type_char: char) -> mysql::Value {
    match value {
        Value::Null => mysql::Value::NULL,
        _ => match type_char {
            'i' => mysql::Value::Int(value.to_long()),
            'd' => mysql::Value::Double(value.to_double()),
            'b' => mysql::Value::Bytes(value.to_php_string().into_bytes()),
            _ => mysql::Value::Bytes(value.to_php_string().into_bytes()), // 's' and default
        },
    }
}

/// Count ? placeholders in SQL (outside of string literals).
fn count_placeholders(sql: &str) -> usize {
    let mut count = 0;
    let mut in_single_quote = false;
    let mut in_double_quote = false;
    let mut prev = '\0';

    for ch in sql.chars() {
        match ch {
            '\'' if !in_double_quote && prev != '\\' => in_single_quote = !in_single_quote,
            '"' if !in_single_quote && prev != '\\' => in_double_quote = !in_double_quote,
            '?' if !in_single_quote && !in_double_quote => count += 1,
            _ => {}
        }
        prev = ch;
    }

    count
}

// ===========================================================================
// pgsql stub helpers
// ===========================================================================

fn php_pg_bool_false_stub(
    _vm: &mut Vm,
    _args: &[Value],
    _ref_args: &[(usize, OperandType, u32)],
    _ref_prop_args: &[(usize, Value, String)],
) -> VmResult<Value> {
    Ok(Value::Bool(false))
}

fn php_pg_bool_true_stub(
    _vm: &mut Vm,
    _args: &[Value],
    _ref_args: &[(usize, OperandType, u32)],
    _ref_prop_args: &[(usize, Value, String)],
) -> VmResult<Value> {
    Ok(Value::Bool(true))
}

fn php_pg_long_zero_stub(
    _vm: &mut Vm,
    _args: &[Value],
    _ref_args: &[(usize, OperandType, u32)],
    _ref_prop_args: &[(usize, Value, String)],
) -> VmResult<Value> {
    Ok(Value::Long(0))
}

fn php_pg_string_empty_stub(
    _vm: &mut Vm,
    _args: &[Value],
    _ref_args: &[(usize, OperandType, u32)],
    _ref_prop_args: &[(usize, Value, String)],
) -> VmResult<Value> {
    Ok(Value::String(String::new()))
}

fn php_pg_utf8_stub(
    _vm: &mut Vm,
    _args: &[Value],
    _ref_args: &[(usize, OperandType, u32)],
    _ref_prop_args: &[(usize, Value, String)],
) -> VmResult<Value> {
    Ok(Value::String("UTF8".into()))
}

fn php_pg_escape_passthrough(
    _vm: &mut Vm,
    args: &[Value],
    _ref_args: &[(usize, OperandType, u32)],
    _ref_prop_args: &[(usize, Value, String)],
) -> VmResult<Value> {
    let s = args.first().cloned().unwrap_or(Value::Null).to_php_string();
    Ok(Value::String(s))
}

// ===========================================================================
// ODBC stub helpers
// ===========================================================================

fn php_odbc_bool_false_stub(
    _vm: &mut Vm,
    _args: &[Value],
    _ref_args: &[(usize, OperandType, u32)],
    _ref_prop_args: &[(usize, Value, String)],
) -> VmResult<Value> {
    Ok(Value::Bool(false))
}

fn php_odbc_bool_true_stub(
    _vm: &mut Vm,
    _args: &[Value],
    _ref_args: &[(usize, OperandType, u32)],
    _ref_prop_args: &[(usize, Value, String)],
) -> VmResult<Value> {
    Ok(Value::Bool(true))
}

fn php_odbc_null_stub(
    _vm: &mut Vm,
    _args: &[Value],
    _ref_args: &[(usize, OperandType, u32)],
    _ref_prop_args: &[(usize, Value, String)],
) -> VmResult<Value> {
    Ok(Value::Null)
}

fn php_odbc_long_zero_stub(
    _vm: &mut Vm,
    _args: &[Value],
    _ref_args: &[(usize, OperandType, u32)],
    _ref_prop_args: &[(usize, Value, String)],
) -> VmResult<Value> {
    Ok(Value::Long(0))
}

fn php_odbc_string_empty_stub(
    _vm: &mut Vm,
    _args: &[Value],
    _ref_args: &[(usize, OperandType, u32)],
    _ref_prop_args: &[(usize, Value, String)],
) -> VmResult<Value> {
    Ok(Value::String(String::new()))
}

fn php_odbc_connection_string_quote(
    _vm: &mut Vm,
    args: &[Value],
    _ref_args: &[(usize, OperandType, u32)],
    _ref_prop_args: &[(usize, Value, String)],
) -> VmResult<Value> {
    let s = args.first().cloned().unwrap_or(Value::Null).to_php_string();
    Ok(Value::String(format!("{{{}}}", s)))
}
