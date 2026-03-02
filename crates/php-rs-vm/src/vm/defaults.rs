//! Default constants and classes — built-in PHP definitions pre-registered on VM startup.
//!
//! Extracted from `Vm::with_config()` for clarity and to enable future lazy initialization.
//! Constants and classes are built with pre-allocated HashMap capacity to avoid rehashing.

use std::collections::HashMap;

use crate::value::Value;
use super::ClassDef;

/// Build the default PHP constants HashMap.
/// Pre-allocates capacity for ~200 constants to avoid rehashing.
pub(crate) fn build_default_constants() -> HashMap<String, Value> {
    // Pre-allocate with known capacity — avoids ~7 rehash operations.
    let mut c = HashMap::with_capacity(256);

    // Core PHP constants
    c.insert("DIRECTORY_SEPARATOR".into(), Value::String("/".into()));
    c.insert("PATH_SEPARATOR".into(), Value::String(":".into()));
    c.insert("PHP_EOL".into(), Value::String("\n".into()));
    c.insert("PHP_INT_MAX".into(), Value::Long(i64::MAX));
    c.insert("PHP_INT_MIN".into(), Value::Long(i64::MIN));
    c.insert("PHP_INT_SIZE".into(), Value::Long(8));
    c.insert("PHP_FLOAT_MAX".into(), Value::Double(f64::MAX));
    c.insert("PHP_FLOAT_MIN".into(), Value::Double(f64::MIN_POSITIVE));
    c.insert("PHP_FLOAT_EPSILON".into(), Value::Double(f64::EPSILON));
    c.insert("INF".into(), Value::Double(f64::INFINITY));
    c.insert("NAN".into(), Value::Double(f64::NAN));
    c.insert("PHP_FLOAT_INF".into(), Value::Double(f64::INFINITY));
    c.insert("PHP_FLOAT_NAN".into(), Value::Double(f64::NAN));
    c.insert("PHP_MAJOR_VERSION".into(), Value::Long(8));
    c.insert("PHP_MINOR_VERSION".into(), Value::Long(6));
    c.insert("PHP_RELEASE_VERSION".into(), Value::Long(0));
    c.insert("PHP_VERSION".into(), Value::String("8.6.0".into()));
    c.insert("PHP_VERSION_ID".into(), Value::Long(80600));
    c.insert("PHP_MAXPATHLEN".into(), Value::Long(1024));
    c.insert(
        "PHP_OS".into(),
        Value::String(
            if cfg!(target_arch = "wasm32") {
                "WASM"
            } else if cfg!(target_os = "macos") {
                "Darwin"
            } else if cfg!(target_os = "windows") {
                "WINNT"
            } else {
                "Linux"
            }
            .into(),
        ),
    );
    c.insert(
        "PHP_OS_FAMILY".into(),
        Value::String(
            if cfg!(target_arch = "wasm32") {
                "WASM"
            } else if cfg!(target_os = "windows") {
                "Windows"
            } else {
                "Unix"
            }
            .into(),
        ),
    );
    c.insert(
        "PHP_SAPI".into(),
        Value::String(
            if cfg!(target_arch = "wasm32") {
                "wasm"
            } else {
                "cli"
            }
            .into(),
        ),
    );
    c.insert("PHP_PREFIX".into(), Value::String("/usr".into()));
    c.insert("PHP_BINDIR".into(), Value::String("/usr/bin".into()));

    // Built-in constants
    c.insert("TRUE".into(), Value::Bool(true));
    c.insert("FALSE".into(), Value::Bool(false));
    c.insert("NULL".into(), Value::Null);

    // Standard streams
    c.insert("STDIN".into(), Value::Resource(0, "stream".into()));
    c.insert("STDOUT".into(), Value::Resource(1, "stream".into()));
    c.insert("STDERR".into(), Value::Resource(2, "stream".into()));

    // Error level constants
    c.insert("E_ERROR".into(), Value::Long(1));
    c.insert("E_WARNING".into(), Value::Long(2));
    c.insert("E_PARSE".into(), Value::Long(4));
    c.insert("E_NOTICE".into(), Value::Long(8));
    c.insert("E_CORE_ERROR".into(), Value::Long(16));
    c.insert("E_CORE_WARNING".into(), Value::Long(32));
    c.insert("E_COMPILE_ERROR".into(), Value::Long(64));
    c.insert("E_COMPILE_WARNING".into(), Value::Long(128));
    c.insert("E_USER_ERROR".into(), Value::Long(256));
    c.insert("E_USER_WARNING".into(), Value::Long(512));
    c.insert("E_USER_NOTICE".into(), Value::Long(1024));
    c.insert("E_STRICT".into(), Value::Long(2048));
    c.insert("E_RECOVERABLE_ERROR".into(), Value::Long(4096));
    c.insert("E_DEPRECATED".into(), Value::Long(8192));
    c.insert("E_USER_DEPRECATED".into(), Value::Long(16384));
    c.insert("E_ALL".into(), Value::Long(32767));

    // String padding constants
    c.insert("STR_PAD_RIGHT".into(), Value::Long(1));
    c.insert("STR_PAD_LEFT".into(), Value::Long(0));
    c.insert("STR_PAD_BOTH".into(), Value::Long(2));

    // Sort constants
    c.insert("SORT_REGULAR".into(), Value::Long(0));
    c.insert("SORT_NUMERIC".into(), Value::Long(1));
    c.insert("SORT_STRING".into(), Value::Long(2));
    c.insert("SORT_ASC".into(), Value::Long(4));
    c.insert("SORT_DESC".into(), Value::Long(3));
    c.insert("SORT_NATURAL".into(), Value::Long(6));
    c.insert("SORT_FLAG_CASE".into(), Value::Long(8));

    // Array filter constants
    c.insert("ARRAY_FILTER_USE_BOTH".into(), Value::Long(1));
    c.insert("ARRAY_FILTER_USE_KEY".into(), Value::Long(2));
    c.insert("ARRAY_FILTER_USE_VALUE".into(), Value::Long(0));

    // PCRE constants
    c.insert("PREG_SPLIT_NO_EMPTY".into(), Value::Long(1));
    c.insert("PREG_SPLIT_DELIM_CAPTURE".into(), Value::Long(2));
    c.insert("PREG_SPLIT_OFFSET_CAPTURE".into(), Value::Long(4));
    c.insert("PREG_GREP_INVERT".into(), Value::Long(1));
    c.insert("PREG_NO_ERROR".into(), Value::Long(0));
    c.insert("PREG_INTERNAL_ERROR".into(), Value::Long(1));
    c.insert("PREG_BACKTRACK_LIMIT_ERROR".into(), Value::Long(2));
    c.insert("PREG_RECURSION_LIMIT_ERROR".into(), Value::Long(3));
    c.insert("PREG_BAD_UTF8_ERROR".into(), Value::Long(4));
    c.insert("PREG_BAD_UTF8_OFFSET_ERROR".into(), Value::Long(5));
    c.insert("PREG_JIT_STACKLIMIT_ERROR".into(), Value::Long(6));
    c.insert("PREG_OFFSET_CAPTURE".into(), Value::Long(256));
    c.insert("PREG_UNMATCHED_AS_NULL".into(), Value::Long(512));
    c.insert("PREG_SET_ORDER".into(), Value::Long(2));
    c.insert("PREG_PATTERN_ORDER".into(), Value::Long(1));

    // JSON constants
    c.insert("JSON_PRETTY_PRINT".into(), Value::Long(128));
    c.insert("JSON_UNESCAPED_SLASHES".into(), Value::Long(64));
    c.insert("JSON_UNESCAPED_UNICODE".into(), Value::Long(256));
    c.insert("JSON_THROW_ON_ERROR".into(), Value::Long(4194304));
    c.insert("JSON_FORCE_OBJECT".into(), Value::Long(16));
    c.insert("JSON_HEX_TAG".into(), Value::Long(1));
    c.insert("JSON_HEX_AMP".into(), Value::Long(2));
    c.insert("JSON_HEX_APOS".into(), Value::Long(4));
    c.insert("JSON_HEX_QUOT".into(), Value::Long(8));
    c.insert("JSON_NUMERIC_CHECK".into(), Value::Long(32));

    // Filter constants
    c.insert("FILTER_VALIDATE_INT".into(), Value::Long(257));
    c.insert("FILTER_VALIDATE_FLOAT".into(), Value::Long(259));
    c.insert("FILTER_VALIDATE_EMAIL".into(), Value::Long(274));
    c.insert("FILTER_VALIDATE_URL".into(), Value::Long(273));
    c.insert("FILTER_VALIDATE_IP".into(), Value::Long(275));
    c.insert("FILTER_VALIDATE_BOOLEAN".into(), Value::Long(258));
    c.insert("FILTER_VALIDATE_DOMAIN".into(), Value::Long(276));
    c.insert("FILTER_VALIDATE_MAC".into(), Value::Long(279));
    c.insert("FILTER_SANITIZE_STRING".into(), Value::Long(513));
    c.insert("FILTER_SANITIZE_ENCODED".into(), Value::Long(514));
    c.insert("FILTER_SANITIZE_SPECIAL_CHARS".into(), Value::Long(515));
    c.insert("FILTER_SANITIZE_NUMBER_INT".into(), Value::Long(517));
    c.insert("FILTER_SANITIZE_NUMBER_FLOAT".into(), Value::Long(520));
    c.insert("FILTER_SANITIZE_EMAIL".into(), Value::Long(522));
    c.insert("FILTER_SANITIZE_URL".into(), Value::Long(523));
    c.insert("FILTER_SANITIZE_ADD_SLASHES".into(), Value::Long(524));
    c.insert("FILTER_DEFAULT".into(), Value::Long(516));
    c.insert("FILTER_FLAG_NONE".into(), Value::Long(0));
    c.insert("FILTER_FLAG_STRIP_LOW".into(), Value::Long(4));
    c.insert("FILTER_FLAG_STRIP_HIGH".into(), Value::Long(8));
    c.insert("FILTER_FLAG_ALLOW_FRACTION".into(), Value::Long(4096));
    c.insert("FILTER_FLAG_ALLOW_THOUSAND".into(), Value::Long(8192));
    c.insert("FILTER_FLAG_ALLOW_SCIENTIFIC".into(), Value::Long(16384));
    c.insert("FILTER_FLAG_NO_ENCODE_QUOTES".into(), Value::Long(128));
    c.insert("FILTER_FLAG_ENCODE_LOW".into(), Value::Long(16));
    c.insert("FILTER_FLAG_ENCODE_HIGH".into(), Value::Long(32));
    c.insert("FILTER_FLAG_ENCODE_AMP".into(), Value::Long(64));
    c.insert("FILTER_FLAG_IPV4".into(), Value::Long(1048576));
    c.insert("FILTER_FLAG_IPV6".into(), Value::Long(2097152));
    c.insert("FILTER_FLAG_NO_RES_RANGE".into(), Value::Long(4194304));
    c.insert("FILTER_FLAG_NO_PRIV_RANGE".into(), Value::Long(8388608));
    c.insert("FILTER_FLAG_PATH_REQUIRED".into(), Value::Long(262144));
    c.insert("FILTER_FLAG_QUERY_REQUIRED".into(), Value::Long(524288));
    c.insert("FILTER_REQUIRE_SCALAR".into(), Value::Long(33554432));
    c.insert("FILTER_REQUIRE_ARRAY".into(), Value::Long(16777216));
    c.insert("FILTER_FORCE_ARRAY".into(), Value::Long(67108864));
    c.insert("FILTER_NULL_ON_FAILURE".into(), Value::Long(134217728));
    c.insert("FILTER_CALLBACK".into(), Value::Long(1024));

    // Input type constants for filter_input()
    c.insert("INPUT_GET".into(), Value::Long(1));
    c.insert("INPUT_POST".into(), Value::Long(2));
    c.insert("INPUT_COOKIE".into(), Value::Long(4));
    c.insert("INPUT_ENV".into(), Value::Long(16));
    c.insert("INPUT_SERVER".into(), Value::Long(32));
    c.insert("INPUT_SESSION".into(), Value::Long(64));
    c.insert("INPUT_REQUEST".into(), Value::Long(99));

    // URL component constants
    c.insert("PHP_URL_SCHEME".into(), Value::Long(0));
    c.insert("PHP_URL_HOST".into(), Value::Long(1));
    c.insert("PHP_URL_PORT".into(), Value::Long(2));
    c.insert("PHP_URL_USER".into(), Value::Long(3));
    c.insert("PHP_URL_PASS".into(), Value::Long(4));
    c.insert("PHP_URL_PATH".into(), Value::Long(5));
    c.insert("PHP_URL_QUERY".into(), Value::Long(6));
    c.insert("PHP_URL_FRAGMENT".into(), Value::Long(7));

    // Filesystem constants
    c.insert("FILE_APPEND".into(), Value::Long(8));
    c.insert("LOCK_EX".into(), Value::Long(2));

    // Connection status constants
    c.insert("CONNECTION_NORMAL".into(), Value::Long(0));
    c.insert("CONNECTION_ABORTED".into(), Value::Long(1));
    c.insert("CONNECTION_TIMEOUT".into(), Value::Long(2));

    // Extract constants
    c.insert("EXTR_OVERWRITE".into(), Value::Long(0));
    c.insert("EXTR_SKIP".into(), Value::Long(1));
    c.insert("EXTR_PREFIX_SAME".into(), Value::Long(2));
    c.insert("EXTR_PREFIX_ALL".into(), Value::Long(3));
    c.insert("EXTR_PREFIX_INVALID".into(), Value::Long(4));
    c.insert("EXTR_IF_EXISTS".into(), Value::Long(6));
    c.insert("EXTR_REFS".into(), Value::Long(256));

    // Calendar constants
    c.insert("CAL_GREGORIAN".into(), Value::Long(0));
    c.insert("CAL_JULIAN".into(), Value::Long(1));
    c.insert("CAL_JEWISH".into(), Value::Long(2));
    c.insert("CAL_FRENCH".into(), Value::Long(3));

    // SQLite3 constants
    c.insert("SQLITE3_ASSOC".into(), Value::Long(1));
    c.insert("SQLITE3_NUM".into(), Value::Long(2));
    c.insert("SQLITE3_BOTH".into(), Value::Long(3));
    c.insert("SQLITE3_INTEGER".into(), Value::Long(1));
    c.insert("SQLITE3_FLOAT".into(), Value::Long(2));
    c.insert("SQLITE3_TEXT".into(), Value::Long(3));
    c.insert("SQLITE3_BLOB".into(), Value::Long(4));
    c.insert("SQLITE3_NULL".into(), Value::Long(5));
    c.insert("SQLITE3_OPEN_READONLY".into(), Value::Long(1));
    c.insert("SQLITE3_OPEN_READWRITE".into(), Value::Long(2));
    c.insert("SQLITE3_OPEN_CREATE".into(), Value::Long(4));

    // Password hash constants
    c.insert("PASSWORD_DEFAULT".into(), Value::Long(1));
    c.insert("PASSWORD_BCRYPT".into(), Value::Long(1));
    c.insert("PASSWORD_ARGON2I".into(), Value::Long(2));
    c.insert("PASSWORD_ARGON2ID".into(), Value::Long(3));
    c.insert("PASSWORD_BCRYPT_DEFAULT_COST".into(), Value::Long(10));

    // Stream constants
    c.insert("STREAM_NOTIFY_RESOLVE".into(), Value::Long(1));
    c.insert("STREAM_NOTIFY_CONNECT".into(), Value::Long(2));
    c.insert("STREAM_NOTIFY_AUTH_REQUIRED".into(), Value::Long(3));
    c.insert("STREAM_NOTIFY_MIME_TYPE_IS".into(), Value::Long(4));
    c.insert("STREAM_NOTIFY_FILE_SIZE_IS".into(), Value::Long(5));
    c.insert("STREAM_NOTIFY_REDIRECTED".into(), Value::Long(6));
    c.insert("STREAM_NOTIFY_PROGRESS".into(), Value::Long(7));
    c.insert("STREAM_NOTIFY_COMPLETED".into(), Value::Long(8));
    c.insert("STREAM_NOTIFY_FAILURE".into(), Value::Long(9));
    c.insert("STREAM_NOTIFY_AUTH_RESULT".into(), Value::Long(10));
    c.insert("STREAM_NOTIFY_SEVERITY_INFO".into(), Value::Long(0));
    c.insert("STREAM_NOTIFY_SEVERITY_WARN".into(), Value::Long(1));
    c.insert("STREAM_NOTIFY_SEVERITY_ERR".into(), Value::Long(2));
    c.insert("STREAM_FILTER_READ".into(), Value::Long(1));
    c.insert("STREAM_FILTER_WRITE".into(), Value::Long(2));
    c.insert("STREAM_FILTER_ALL".into(), Value::Long(3));

    // cURL constants (native-io feature only)
    #[cfg(feature = "native-io")]
    {
        use php_rs_ext_curl::constants;
        c.insert("CURLOPT_URL".into(), Value::Long(constants::CURLOPT_URL as i64));
        c.insert("CURLOPT_RETURNTRANSFER".into(), Value::Long(constants::CURLOPT_RETURNTRANSFER as i64));
        c.insert("CURLOPT_POST".into(), Value::Long(constants::CURLOPT_POST as i64));
        c.insert("CURLOPT_POSTFIELDS".into(), Value::Long(constants::CURLOPT_POSTFIELDS as i64));
        c.insert("CURLOPT_HTTPHEADER".into(), Value::Long(constants::CURLOPT_HTTPHEADER as i64));
        c.insert("CURLOPT_TIMEOUT".into(), Value::Long(constants::CURLOPT_TIMEOUT as i64));
        c.insert("CURLOPT_FOLLOWLOCATION".into(), Value::Long(constants::CURLOPT_FOLLOWLOCATION as i64));
        c.insert("CURLOPT_SSL_VERIFYPEER".into(), Value::Long(constants::CURLOPT_SSL_VERIFYPEER as i64));
        c.insert("CURLOPT_USERAGENT".into(), Value::Long(constants::CURLOPT_USERAGENT as i64));
        c.insert("CURLOPT_CUSTOMREQUEST".into(), Value::Long(constants::CURLOPT_CUSTOMREQUEST as i64));
        c.insert("CURLOPT_CONNECTTIMEOUT".into(), Value::Long(constants::CURLOPT_CONNECTTIMEOUT as i64));
        c.insert("CURLOPT_HEADER".into(), Value::Long(constants::CURLOPT_HEADER as i64));
        c.insert("CURLOPT_NOBODY".into(), Value::Long(constants::CURLOPT_NOBODY as i64));
        c.insert("CURLOPT_VERBOSE".into(), Value::Long(41));
        c.insert("CURLOPT_REFERER".into(), Value::Long(10016));
        c.insert("CURLOPT_COOKIE".into(), Value::Long(10022));
        c.insert("CURLOPT_COOKIEFILE".into(), Value::Long(10031));
        c.insert("CURLOPT_COOKIEJAR".into(), Value::Long(10082));
        c.insert("CURLOPT_USERNAME".into(), Value::Long(10173));
        c.insert("CURLOPT_PASSWORD".into(), Value::Long(10174));
        c.insert("CURLOPT_USERPWD".into(), Value::Long(10005));
        c.insert("CURLOPT_MAXREDIRS".into(), Value::Long(68));
        c.insert("CURLOPT_SSL_VERIFYHOST".into(), Value::Long(81));
        c.insert("CURLOPT_CAINFO".into(), Value::Long(10065));
        c.insert("CURLOPT_SSLCERT".into(), Value::Long(10025));
        c.insert("CURLOPT_SSLKEY".into(), Value::Long(10087));
        c.insert("CURLOPT_ENCODING".into(), Value::Long(10102));
        c.insert("CURLOPT_HTTP_VERSION".into(), Value::Long(84));
        c.insert("CURLOPT_HTTPGET".into(), Value::Long(80));
        c.insert("CURLOPT_PUT".into(), Value::Long(54));
        c.insert("CURLOPT_INFILE".into(), Value::Long(10009));
        c.insert("CURLOPT_INFILESIZE".into(), Value::Long(14));
        c.insert("CURLOPT_WRITEHEADER".into(), Value::Long(10029));
        c.insert("CURLOPT_FILE".into(), Value::Long(10001));
        c.insert("CURLOPT_RANGE".into(), Value::Long(10007));
        c.insert("CURLOPT_RESUME_FROM".into(), Value::Long(21));
        c.insert("CURLOPT_AUTOREFERER".into(), Value::Long(58));
        c.insert("CURLOPT_PORT".into(), Value::Long(3));
        c.insert("CURLOPT_MAXFILESIZE".into(), Value::Long(114));
        c.insert("CURLOPT_PROTOCOLS".into(), Value::Long(181));
        c.insert("CURLOPT_REDIR_PROTOCOLS".into(), Value::Long(182));
        c.insert("CURLOPT_FRESH_CONNECT".into(), Value::Long(74));
        c.insert("CURLOPT_FORBID_REUSE".into(), Value::Long(75));
        c.insert("CURLOPT_INTERFACE".into(), Value::Long(10062));
        c.insert("CURLOPT_PROXY".into(), Value::Long(10004));
        c.insert("CURLOPT_PROXYPORT".into(), Value::Long(59));
        c.insert("CURLOPT_PROXYTYPE".into(), Value::Long(101));
        c.insert("CURLOPT_PROXYUSERPWD".into(), Value::Long(10006));
        c.insert("CURLOPT_IPRESOLVE".into(), Value::Long(113));
        c.insert("CURLOPT_TIMEOUT_MS".into(), Value::Long(155));
        c.insert("CURLOPT_CONNECTTIMEOUT_MS".into(), Value::Long(156));
        c.insert("CURLOPT_LOW_SPEED_LIMIT".into(), Value::Long(19));
        c.insert("CURLOPT_LOW_SPEED_TIME".into(), Value::Long(20));
        c.insert("CURLOPT_DNS_CACHE_TIMEOUT".into(), Value::Long(92));
        c.insert("CURLOPT_BUFFERSIZE".into(), Value::Long(98));
        c.insert("CURLOPT_TCP_NODELAY".into(), Value::Long(121));
        c.insert("CURLOPT_SAFE_UPLOAD".into(), Value::Long(-1));
        // CURLINFO constants
        c.insert("CURLINFO_HTTP_CODE".into(), Value::Long(constants::CURLINFO_HTTP_CODE as i64));
        c.insert("CURLINFO_TOTAL_TIME".into(), Value::Long(constants::CURLINFO_TOTAL_TIME as i64));
        c.insert("CURLINFO_CONTENT_TYPE".into(), Value::Long(constants::CURLINFO_CONTENT_TYPE as i64));
        c.insert("CURLINFO_EFFECTIVE_URL".into(), Value::Long(constants::CURLINFO_EFFECTIVE_URL as i64));
        c.insert("CURLINFO_HEADER_SIZE".into(), Value::Long(constants::CURLINFO_HEADER_SIZE as i64));
        c.insert("CURLINFO_RESPONSE_CODE".into(), Value::Long(2097154));
        c.insert("CURLINFO_NAMELOOKUP_TIME".into(), Value::Long(3145732));
        c.insert("CURLINFO_CONNECT_TIME".into(), Value::Long(3145733));
        c.insert("CURLINFO_PRETRANSFER_TIME".into(), Value::Long(3145734));
        c.insert("CURLINFO_STARTTRANSFER_TIME".into(), Value::Long(3145736));
        c.insert("CURLINFO_REDIRECT_COUNT".into(), Value::Long(2097172));
        c.insert("CURLINFO_REDIRECT_TIME".into(), Value::Long(3145737));
        c.insert("CURLINFO_REDIRECT_URL".into(), Value::Long(1048607));
        c.insert("CURLINFO_SIZE_DOWNLOAD".into(), Value::Long(3145738));
        c.insert("CURLINFO_SIZE_UPLOAD".into(), Value::Long(3145735));
        c.insert("CURLINFO_SPEED_DOWNLOAD".into(), Value::Long(3145733));
        c.insert("CURLINFO_SPEED_UPLOAD".into(), Value::Long(3145734));
        c.insert("CURLINFO_REQUEST_SIZE".into(), Value::Long(2097164));
        c.insert("CURLINFO_SSL_VERIFYRESULT".into(), Value::Long(2097165));
        c.insert("CURLINFO_CONTENT_LENGTH_DOWNLOAD".into(), Value::Long(3145743));
        c.insert("CURLINFO_CONTENT_LENGTH_UPLOAD".into(), Value::Long(3145744));
        c.insert("CURLINFO_PRIVATE".into(), Value::Long(1048597));
        c.insert("CURLINFO_HTTPAUTH_AVAIL".into(), Value::Long(2097175));
        c.insert("CURLINFO_PROXYAUTH_AVAIL".into(), Value::Long(2097176));
        // CURLE error constants
        c.insert("CURLE_OK".into(), Value::Long(constants::CURLE_OK as i64));
        c.insert("CURLE_UNSUPPORTED_PROTOCOL".into(), Value::Long(constants::CURLE_UNSUPPORTED_PROTOCOL as i64));
        c.insert("CURLE_URL_MALFORMAT".into(), Value::Long(constants::CURLE_URL_MALFORMAT as i64));
        c.insert("CURLE_COULDNT_RESOLVE_HOST".into(), Value::Long(constants::CURLE_COULDNT_RESOLVE_HOST as i64));
        c.insert("CURLE_COULDNT_CONNECT".into(), Value::Long(constants::CURLE_COULDNT_CONNECT as i64));
        c.insert("CURLE_OPERATION_TIMEDOUT".into(), Value::Long(constants::CURLE_OPERATION_TIMEDOUT as i64));
        c.insert("CURLE_SSL_CONNECT_ERROR".into(), Value::Long(constants::CURLE_SSL_CONNECT_ERROR as i64));
        c.insert("CURLE_FAILED_INIT".into(), Value::Long(2));
        c.insert("CURLE_NOT_BUILT_IN".into(), Value::Long(4));
        c.insert("CURLE_COULDNT_RESOLVE_PROXY".into(), Value::Long(5));
        c.insert("CURLE_PARTIAL_FILE".into(), Value::Long(18));
        c.insert("CURLE_HTTP_RETURNED_ERROR".into(), Value::Long(22));
        c.insert("CURLE_WRITE_ERROR".into(), Value::Long(23));
        c.insert("CURLE_READ_ERROR".into(), Value::Long(26));
        c.insert("CURLE_OUT_OF_MEMORY".into(), Value::Long(27));
        c.insert("CURLE_SEND_ERROR".into(), Value::Long(55));
        c.insert("CURLE_RECV_ERROR".into(), Value::Long(56));
        c.insert("CURLE_SSL_CERTPROBLEM".into(), Value::Long(58));
        c.insert("CURLE_SSL_CIPHER".into(), Value::Long(59));
        c.insert("CURLE_SSL_CACERT".into(), Value::Long(60));
        c.insert("CURLE_BAD_CONTENT_ENCODING".into(), Value::Long(61));
        c.insert("CURLE_TOO_MANY_REDIRECTS".into(), Value::Long(47));
        c.insert("CURLVERSION_NOW".into(), Value::Long(9));
        // HTTP version constants
        c.insert("CURL_HTTP_VERSION_NONE".into(), Value::Long(0));
        c.insert("CURL_HTTP_VERSION_1_0".into(), Value::Long(1));
        c.insert("CURL_HTTP_VERSION_1_1".into(), Value::Long(2));
        c.insert("CURL_HTTP_VERSION_2_0".into(), Value::Long(3));
        c.insert("CURL_HTTP_VERSION_2".into(), Value::Long(3));
        // cURL multi constants
        c.insert("CURLM_OK".into(), Value::Long(0));
        c.insert("CURLM_BAD_HANDLE".into(), Value::Long(1));
        c.insert("CURLM_BAD_EASY_HANDLE".into(), Value::Long(2));
        c.insert("CURLM_OUT_OF_MEMORY".into(), Value::Long(3));
        c.insert("CURLM_INTERNAL_ERROR".into(), Value::Long(4));
        // CURLPROTO constants
        c.insert("CURLPROTO_HTTP".into(), Value::Long(1));
        c.insert("CURLPROTO_HTTPS".into(), Value::Long(2));
        c.insert("CURLPROTO_FTP".into(), Value::Long(4));
        c.insert("CURLPROTO_ALL".into(), Value::Long(-1));
    }

    // INI permission constants
    c.insert("INI_USER".into(), Value::Long(4));
    c.insert("INI_PERDIR".into(), Value::Long(2));
    c.insert("INI_SYSTEM".into(), Value::Long(1));
    c.insert("INI_ALL".into(), Value::Long(7));
    c.insert("PHP_INI_USER".into(), Value::Long(4));
    c.insert("PHP_INI_PERDIR".into(), Value::Long(2));
    c.insert("PHP_INI_SYSTEM".into(), Value::Long(1));
    c.insert("PHP_INI_ALL".into(), Value::Long(7));

    // Session constants
    c.insert("PHP_SESSION_DISABLED".into(), Value::Long(0));
    c.insert("PHP_SESSION_NONE".into(), Value::Long(1));
    c.insert("PHP_SESSION_ACTIVE".into(), Value::Long(2));

    c
}

/// Build the default built-in classes HashMap (SPL, DateTime, SQLite3, etc.).
/// Pre-allocates capacity for ~40 classes.
pub(crate) fn build_default_classes() -> HashMap<String, ClassDef> {
    let mut cls = HashMap::with_capacity(48);

    let make_class = |name: &str, parent: Option<&str>, constants: Vec<(&str, i64)>| -> ClassDef {
        let mut cc = HashMap::new();
        for (k, v) in constants {
            cc.insert(k.to_string(), Value::Long(v));
        }
        ClassDef {
            _name: name.to_string(),
            parent: parent.map(|s| s.to_string()),
            interfaces: Vec::new(),
            traits: Vec::new(),
            is_abstract: false,
            is_final: false,
            is_interface: false,
            is_enum: false,
            is_readonly: false,
            methods: HashMap::new(),
            method_flags: HashMap::new(),
            property_flags: HashMap::new(),
            default_properties: HashMap::new(),
            class_constants: cc,
            class_constant_flags: HashMap::new(),
            static_properties: HashMap::new(),
            property_types: HashMap::new(),
            attributes: Vec::new(),
            property_get_hooks: HashMap::new(),
            property_set_hooks: HashMap::new(),
        }
    };

    // SPL file classes
    cls.insert("SplFileInfo".into(), make_class("SplFileInfo", None, vec![]));
    cls.insert("DirectoryIterator".into(), make_class("DirectoryIterator", Some("SplFileInfo"), vec![]));
    cls.insert(
        "FilesystemIterator".into(),
        make_class("FilesystemIterator", Some("DirectoryIterator"), vec![
            ("CURRENT_AS_PATHNAME", 32), ("CURRENT_AS_FILEINFO", 0),
            ("CURRENT_AS_SELF", 16), ("KEY_AS_PATHNAME", 0),
            ("KEY_AS_FILENAME", 256), ("FOLLOW_SYMLINKS", 512),
            ("NEW_CURRENT_AND_KEY", 256), ("SKIP_DOTS", 4096),
            ("UNIX_PATHS", 8192), ("OTHER_MODE_MASK", 0xF000),
        ]),
    );
    cls.insert("RecursiveDirectoryIterator".into(), make_class("RecursiveDirectoryIterator", Some("FilesystemIterator"), vec![]));

    // SPL iterator classes
    cls.insert(
        "RecursiveIteratorIterator".into(),
        make_class("RecursiveIteratorIterator", None, vec![
            ("LEAVES_ONLY", 0), ("SELF_FIRST", 1), ("CHILD_FIRST", 2),
            ("CATCH_GET_CHILD", 16),
        ]),
    );
    cls.insert("FilterIterator".into(), make_class("FilterIterator", None, vec![]));
    cls.insert("RecursiveFilterIterator".into(), make_class("RecursiveFilterIterator", Some("FilterIterator"), vec![]));
    cls.insert("IteratorIterator".into(), make_class("IteratorIterator", None, vec![]));
    cls.insert("AppendIterator".into(), make_class("AppendIterator", None, vec![]));
    cls.insert(
        "RegexIterator".into(),
        make_class("RegexIterator", Some("FilterIterator"), vec![
            ("MATCH", 0), ("GET_MATCH", 1), ("ALL_MATCHES", 2),
            ("SPLIT", 3), ("REPLACE", 4), ("USE_KEY", 1),
        ]),
    );
    cls.insert("RecursiveRegexIterator".into(), make_class("RecursiveRegexIterator", Some("RegexIterator"), vec![]));

    // SQLite3 classes
    cls.insert(
        "SQLite3".into(),
        make_class("SQLite3", None, vec![
            ("SQLITE3_ASSOC", 1), ("SQLITE3_NUM", 2), ("SQLITE3_BOTH", 3),
            ("SQLITE3_INTEGER", 1), ("SQLITE3_FLOAT", 2), ("SQLITE3_TEXT", 3),
            ("SQLITE3_BLOB", 4), ("SQLITE3_NULL", 5),
            ("SQLITE3_OPEN_READONLY", 1), ("SQLITE3_OPEN_READWRITE", 2), ("SQLITE3_OPEN_CREATE", 4),
        ]),
    );
    cls.insert("SQLite3Result".into(), make_class("SQLite3Result", None, vec![]));
    cls.insert("SQLite3Stmt".into(), make_class("SQLite3Stmt", None, vec![]));

    // DateTime classes
    let datetime_constants = vec![
        ("ATOM", 0), ("COOKIE", 0), ("ISO8601", 0),
        ("RFC822", 0), ("RFC850", 0), ("RFC1036", 0),
        ("RFC1123", 0), ("RFC7231", 0), ("RFC2822", 0),
        ("RFC3339", 0), ("RFC3339_EXTENDED", 0),
        ("RSS", 0), ("W3C", 0),
    ];
    cls.insert("DateTime".into(), make_class("DateTime", None, datetime_constants.clone()));
    cls.insert("DateTimeImmutable".into(), make_class("DateTimeImmutable", None, datetime_constants));
    cls.insert(
        "DateTimeZone".into(),
        make_class("DateTimeZone", None, vec![
            ("AFRICA", 1), ("AMERICA", 2), ("ANTARCTICA", 4), ("ARCTIC", 8),
            ("ASIA", 16), ("ATLANTIC", 32), ("AUSTRALIA", 64), ("EUROPE", 128),
            ("INDIAN", 256), ("PACIFIC", 512), ("UTC", 1024),
            ("ALL", 2047), ("ALL_WITH_BC", 4095), ("PER_COUNTRY", 4096),
        ]),
    );
    cls.insert("DateInterval".into(), make_class("DateInterval", None, vec![]));
    cls.insert(
        "DatePeriod".into(),
        make_class("DatePeriod", None, vec![("EXCLUDE_START_DATE", 1), ("INCLUDE_END_DATE", 2)]),
    );

    // SPL data structures
    cls.insert("SplFixedArray".into(), make_class("SplFixedArray", None, vec![]));
    cls.insert(
        "SplDoublyLinkedList".into(),
        make_class("SplDoublyLinkedList", None, vec![
            ("IT_MODE_LIFO", 2), ("IT_MODE_FIFO", 0),
            ("IT_MODE_DELETE", 1), ("IT_MODE_KEEP", 0),
        ]),
    );
    cls.insert("SplStack".into(), make_class("SplStack", Some("SplDoublyLinkedList"), vec![]));
    cls.insert("SplQueue".into(), make_class("SplQueue", Some("SplDoublyLinkedList"), vec![]));
    cls.insert("SplHeap".into(), make_class("SplHeap", None, vec![]));
    cls.insert("SplMinHeap".into(), make_class("SplMinHeap", Some("SplHeap"), vec![]));
    cls.insert("SplMaxHeap".into(), make_class("SplMaxHeap", Some("SplHeap"), vec![]));
    cls.insert(
        "SplPriorityQueue".into(),
        make_class("SplPriorityQueue", None, vec![
            ("EXTR_BOTH", 3), ("EXTR_PRIORITY", 1), ("EXTR_DATA", 2),
        ]),
    );
    cls.insert("SplObjectStorage".into(), make_class("SplObjectStorage", None, vec![]));
    cls.insert("WeakMap".into(), make_class("WeakMap", None, vec![]));
    cls.insert("WeakReference".into(), make_class("WeakReference", None, vec![]));

    // Built-in interfaces
    let make_interface = |name: &str| -> ClassDef {
        ClassDef {
            _name: name.to_string(),
            parent: None,
            interfaces: Vec::new(),
            traits: Vec::new(),
            is_abstract: true,
            is_final: false,
            is_interface: true,
            is_enum: false,
            is_readonly: false,
            methods: HashMap::new(),
            method_flags: HashMap::new(),
            property_flags: HashMap::new(),
            default_properties: HashMap::new(),
            class_constants: HashMap::new(),
            class_constant_flags: HashMap::new(),
            static_properties: HashMap::new(),
            property_types: HashMap::new(),
            attributes: Vec::new(),
            property_get_hooks: HashMap::new(),
            property_set_hooks: HashMap::new(),
        }
    };
    cls.insert("SessionHandlerInterface".into(), make_interface("SessionHandlerInterface"));
    cls.insert("SessionIdInterface".into(), make_interface("SessionIdInterface"));
    cls.insert("SessionUpdateTimestampHandlerInterface".into(), make_interface("SessionUpdateTimestampHandlerInterface"));

    // Add __construct sentinels for built-in classes with constructors
    for name in &[
        "DateTime", "DateTimeImmutable", "DateTimeZone", "DateInterval",
        "DatePeriod", "SplFixedArray", "SplDoublyLinkedList", "SplStack",
        "SplQueue", "SplHeap", "SplMinHeap", "SplMaxHeap",
        "SplPriorityQueue", "SplObjectStorage",
    ] {
        if let Some(class_def) = cls.get_mut(*name) {
            class_def.methods.insert("__construct".to_string(), usize::MAX);
        }
    }

    cls
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_constants_populated() {
        let constants = build_default_constants();
        assert!(constants.len() > 100, "Expected >100 constants, got {}", constants.len());
        assert_eq!(constants.get("PHP_INT_MAX"), Some(&Value::Long(i64::MAX)));
        assert_eq!(constants.get("TRUE"), Some(&Value::Bool(true)));
        assert_eq!(constants.get("NULL"), Some(&Value::Null));
        assert_eq!(constants.get("E_ALL"), Some(&Value::Long(32767)));
    }

    #[test]
    fn test_default_classes_populated() {
        let classes = build_default_classes();
        assert!(classes.len() > 20, "Expected >20 classes, got {}", classes.len());
        assert!(classes.contains_key("DateTime"));
        assert!(classes.contains_key("SplFileInfo"));
        assert!(classes.contains_key("SQLite3"));
    }

    #[test]
    fn test_default_classes_have_constructors() {
        let classes = build_default_classes();
        let dt = classes.get("DateTime").unwrap();
        assert!(dt.methods.contains_key("__construct"));
    }

    #[test]
    fn test_default_classes_inheritance() {
        let classes = build_default_classes();
        let di = classes.get("DirectoryIterator").unwrap();
        assert_eq!(di.parent.as_deref(), Some("SplFileInfo"));
    }
}
