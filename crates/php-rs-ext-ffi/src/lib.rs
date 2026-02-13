//! PHP ffi extension implementation for php.rs
//!
//! Provides Foreign Function Interface for calling C code from PHP.
//! Reference: php-src/ext/ffi/
//!
//! This is a pure Rust implementation that provides the full API surface.
//! Actual FFI calls are not performed; the extension manages types and memory layout.

use std::collections::HashMap;

/// Error type for FFI operations.
#[derive(Debug, Clone, PartialEq)]
pub enum FfiError {
    /// Type not found
    TypeNotFound(String),
    /// Parse error in C declaration
    ParseError(String),
    /// Invalid cast
    InvalidCast(String),
    /// Null pointer access
    NullPointer,
    /// Out of bounds access
    OutOfBounds,
    /// Invalid operation
    InvalidOperation(String),
}

impl std::fmt::Display for FfiError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FfiError::TypeNotFound(name) => write!(f, "FFI type not found: {}", name),
            FfiError::ParseError(msg) => write!(f, "FFI parse error: {}", msg),
            FfiError::InvalidCast(msg) => write!(f, "FFI invalid cast: {}", msg),
            FfiError::NullPointer => write!(f, "FFI null pointer dereference"),
            FfiError::OutOfBounds => write!(f, "FFI out of bounds access"),
            FfiError::InvalidOperation(msg) => write!(f, "FFI invalid operation: {}", msg),
        }
    }
}

/// Represents an FFI type.
#[derive(Debug, Clone, PartialEq)]
pub enum FfiType {
    /// void
    Void,
    /// int8_t / char
    Int8,
    /// uint8_t / unsigned char
    Uint8,
    /// int16_t / short
    Int16,
    /// uint16_t / unsigned short
    Uint16,
    /// int32_t / int
    Int32,
    /// uint32_t / unsigned int
    Uint32,
    /// int64_t / long long
    Int64,
    /// uint64_t / unsigned long long
    Uint64,
    /// float
    Float,
    /// double
    Double,
    /// bool
    Bool,
    /// char (as character type)
    Char,
    /// char* (null-terminated string)
    String,
    /// Pointer to another type
    Pointer(Box<FfiType>),
    /// Fixed-size array
    Array(Box<FfiType>, usize),
    /// Struct with named fields
    Struct(Vec<(std::string::String, FfiType)>),
}

impl FfiType {
    /// Get the size in bytes of this type.
    pub fn size(&self) -> usize {
        match self {
            FfiType::Void => 0,
            FfiType::Int8 | FfiType::Uint8 | FfiType::Bool | FfiType::Char => 1,
            FfiType::Int16 | FfiType::Uint16 => 2,
            FfiType::Int32 | FfiType::Uint32 | FfiType::Float => 4,
            FfiType::Int64 | FfiType::Uint64 | FfiType::Double => 8,
            FfiType::String | FfiType::Pointer(_) => 8,
            FfiType::Array(inner, count) => inner.size() * count,
            FfiType::Struct(fields) => {
                let mut total = 0usize;
                for (_, field_type) in fields {
                    let field_size = field_type.size();
                    let field_align = field_type.alignment();
                    // Align to field boundary
                    if field_align > 0 {
                        let padding = (field_align - (total % field_align)) % field_align;
                        total += padding;
                    }
                    total += field_size;
                }
                // Align struct size to largest alignment
                let struct_align = self.alignment();
                if struct_align > 0 {
                    let padding = (struct_align - (total % struct_align)) % struct_align;
                    total += padding;
                }
                total
            }
        }
    }

    /// Get the alignment requirement of this type.
    pub fn alignment(&self) -> usize {
        match self {
            FfiType::Void => 1,
            FfiType::Int8 | FfiType::Uint8 | FfiType::Bool | FfiType::Char => 1,
            FfiType::Int16 | FfiType::Uint16 => 2,
            FfiType::Int32 | FfiType::Uint32 | FfiType::Float => 4,
            FfiType::Int64 | FfiType::Uint64 | FfiType::Double => 8,
            FfiType::String | FfiType::Pointer(_) => 8,
            FfiType::Array(inner, _) => inner.alignment(),
            FfiType::Struct(fields) => fields.iter().map(|(_, t)| t.alignment()).max().unwrap_or(1),
        }
    }
}

/// Represents C data managed by FFI.
#[derive(Debug, Clone)]
pub struct FfiCData {
    /// Type information
    pub type_info: FfiType,
    /// Raw data bytes
    pub data: Vec<u8>,
    /// Whether this data has been freed
    pub freed: bool,
}

impl FfiCData {
    /// Create new zeroed CData of the given type.
    pub fn new(type_info: FfiType) -> Self {
        let size = type_info.size();
        FfiCData {
            type_info,
            data: vec![0u8; size],
            freed: false,
        }
    }
}

/// Parsed C function declaration.
#[derive(Debug, Clone)]
pub struct FfiFunction {
    /// Function name
    pub name: std::string::String,
    /// Return type
    pub return_type: FfiType,
    /// Parameter types
    pub params: Vec<(std::string::String, FfiType)>,
}

/// Parsed C declarations (from FFI::cdef()).
#[derive(Debug, Clone)]
pub struct FfiCDef {
    /// Declared functions
    pub functions: Vec<FfiFunction>,
    /// Declared types (typedefs, structs)
    pub types: HashMap<std::string::String, FfiType>,
}

/// FFI scope for preloaded definitions.
#[derive(Debug, Clone)]
pub struct FfiScope {
    /// Scope name
    pub name: std::string::String,
    /// C definitions in this scope
    pub cdef: FfiCDef,
}

/// Parse a C type name to an FfiType.
fn parse_c_type(type_name: &str) -> Result<FfiType, FfiError> {
    let trimmed = type_name.trim();
    // Handle pointer types
    if let Some(stripped) = trimmed.strip_suffix('*') {
        let inner = stripped.trim();
        let inner_type = parse_c_type(inner)?;
        return Ok(FfiType::Pointer(Box::new(inner_type)));
    }

    match trimmed {
        "void" => Ok(FfiType::Void),
        "int8_t" | "signed char" => Ok(FfiType::Int8),
        "uint8_t" | "unsigned char" => Ok(FfiType::Uint8),
        "int16_t" | "short" | "signed short" => Ok(FfiType::Int16),
        "uint16_t" | "unsigned short" => Ok(FfiType::Uint16),
        "int32_t" | "int" | "signed int" | "signed" => Ok(FfiType::Int32),
        "uint32_t" | "unsigned int" | "unsigned" => Ok(FfiType::Uint32),
        "int64_t" | "long long" | "signed long long" => Ok(FfiType::Int64),
        "uint64_t" | "unsigned long long" => Ok(FfiType::Uint64),
        "float" => Ok(FfiType::Float),
        "double" => Ok(FfiType::Double),
        "bool" | "_Bool" => Ok(FfiType::Bool),
        "char" => Ok(FfiType::Char),
        "long" | "signed long" => Ok(FfiType::Int64), // 64-bit platform
        "unsigned long" => Ok(FfiType::Uint64),
        "size_t" => Ok(FfiType::Uint64),
        "ssize_t" | "ptrdiff_t" => Ok(FfiType::Int64),
        _ => Err(FfiError::TypeNotFound(trimmed.to_string())),
    }
}

/// Parse C declarations into FfiCDef.
///
/// PHP signature: FFI::cdef(string $code = "", ?string $lib = null): FFI
pub fn ffi_cdef(code: &str) -> Result<FfiCDef, FfiError> {
    let mut functions = Vec::new();
    let mut types = HashMap::new();

    for line in code.lines() {
        let line = line.trim().trim_end_matches(';').trim();
        if line.is_empty() || line.starts_with("//") || line.starts_with('#') {
            continue;
        }

        // Try to parse typedef
        if line.starts_with("typedef") {
            let rest = line.strip_prefix("typedef").unwrap().trim();
            // Simple: typedef OLD_TYPE NEW_NAME;
            if let Some(last_space) = rest.rfind(|c: char| c.is_whitespace()) {
                let type_def = rest[..last_space].trim();
                let type_name = rest[last_space..].trim();
                if let Ok(t) = parse_c_type(type_def) {
                    types.insert(type_name.to_string(), t);
                }
            }
            continue;
        }

        // Try to parse function declaration: RETURN_TYPE NAME(PARAMS)
        if let Some(paren_start) = line.find('(') {
            if let Some(paren_end) = line.rfind(')') {
                let before_paren = &line[..paren_start];
                let params_str = &line[paren_start + 1..paren_end];

                // Split return type and function name
                let before_trimmed = before_paren.trim();
                if let Some(last_space) = before_trimmed.rfind(|c: char| c.is_whitespace()) {
                    let return_type_str = before_trimmed[..last_space].trim();
                    let func_name = before_trimmed[last_space..].trim().trim_start_matches('*');

                    let return_type = parse_c_type(return_type_str).unwrap_or(FfiType::Void);

                    // Parse parameters
                    let mut params = Vec::new();
                    if params_str.trim() != "void" && !params_str.trim().is_empty() {
                        for param in params_str.split(',') {
                            let param = param.trim();
                            if let Some(last_space) = param.rfind(|c: char| c.is_whitespace()) {
                                let param_type_str = param[..last_space].trim();
                                let param_name = param[last_space..].trim().trim_start_matches('*');
                                let param_type =
                                    parse_c_type(param_type_str).unwrap_or(FfiType::Int32);
                                params.push((param_name.to_string(), param_type));
                            }
                        }
                    }

                    functions.push(FfiFunction {
                        name: func_name.to_string(),
                        return_type,
                        params,
                    });
                }
            }
        }
    }

    Ok(FfiCDef { functions, types })
}

/// Create a new FFI CData instance of the given type.
///
/// PHP signature: FFI::new(string|FFI\CType $type, bool $owned = true, bool $persistent = false): FFI\CData
pub fn ffi_new(type_name: &str) -> Result<FfiCData, FfiError> {
    // Check for array syntax: type[N]
    if let Some(bracket_start) = type_name.find('[') {
        if let Some(bracket_end) = type_name.find(']') {
            let base_type_name = type_name[..bracket_start].trim();
            let size_str = &type_name[bracket_start + 1..bracket_end];
            let size: usize = size_str
                .parse()
                .map_err(|_| FfiError::ParseError(format!("Invalid array size: {}", size_str)))?;
            let base_type = parse_c_type(base_type_name)?;
            let array_type = FfiType::Array(Box::new(base_type), size);
            return Ok(FfiCData::new(array_type));
        }
    }

    let type_info = parse_c_type(type_name)?;
    Ok(FfiCData::new(type_info))
}

/// Free a CData instance.
///
/// PHP signature: FFI::free(FFI\CData &$ptr): void
pub fn ffi_free(data: &mut FfiCData) {
    data.data.clear();
    data.freed = true;
}

/// Cast CData to a different type.
///
/// PHP signature: FFI::cast(string|FFI\CType $type, FFI\CData|int|float|bool|null &$ptr): FFI\CData
pub fn ffi_cast(type_name: &str, data: &FfiCData) -> Result<FfiCData, FfiError> {
    if data.freed {
        return Err(FfiError::InvalidOperation(
            "Cannot cast freed data".to_string(),
        ));
    }

    let new_type = parse_c_type(type_name)?;
    let new_size = new_type.size();

    let mut new_data = vec![0u8; new_size];
    let copy_len = std::cmp::min(data.data.len(), new_size);
    new_data[..copy_len].copy_from_slice(&data.data[..copy_len]);

    Ok(FfiCData {
        type_info: new_type,
        data: new_data,
        freed: false,
    })
}

/// Get the type of CData.
///
/// PHP signature: FFI::typeof(FFI\CData &$ptr): FFI\CType
pub fn ffi_typeof(data: &FfiCData) -> FfiType {
    data.type_info.clone()
}

/// Get the size of CData or type.
///
/// PHP signature: FFI::sizeof(FFI\CData|FFI\CType &$ptr): int
pub fn ffi_sizeof(data: &FfiCData) -> usize {
    data.type_info.size()
}

/// Get the alignment of CData or type.
///
/// PHP signature: FFI::alignof(FFI\CData|FFI\CType &$ptr): int
pub fn ffi_alignof(data: &FfiCData) -> usize {
    data.type_info.alignment()
}

/// Copy memory between CData instances.
///
/// PHP signature: FFI::memcpy(FFI\CData &$to, mixed &$from, int $size): void
pub fn ffi_memcpy(dst: &mut FfiCData, src: &FfiCData, size: usize) {
    let copy_len = std::cmp::min(size, std::cmp::min(dst.data.len(), src.data.len()));
    dst.data[..copy_len].copy_from_slice(&src.data[..copy_len]);
}

/// Fill CData memory with a byte value.
///
/// PHP signature: FFI::memset(FFI\CData &$ptr, int $value, int $size): void
pub fn ffi_memset(dst: &mut FfiCData, value: u8, size: usize) {
    let fill_len = std::cmp::min(size, dst.data.len());
    for byte in dst.data[..fill_len].iter_mut() {
        *byte = value;
    }
}

/// Read a null-terminated string from CData.
///
/// PHP signature: FFI::string(FFI\CData &$ptr, ?int $size = null): string
pub fn ffi_string(data: &FfiCData, size: Option<usize>) -> String {
    match size {
        Some(n) => {
            let len = std::cmp::min(n, data.data.len());
            String::from_utf8_lossy(&data.data[..len]).to_string()
        }
        None => {
            // Find null terminator
            let end = data
                .data
                .iter()
                .position(|&b| b == 0)
                .unwrap_or(data.data.len());
            String::from_utf8_lossy(&data.data[..end]).to_string()
        }
    }
}

/// Check if a CData pointer is null.
///
/// PHP signature: FFI::isNull(FFI\CData &$ptr): bool
#[allow(non_snake_case)]
pub fn ffi_isNull(data: &FfiCData) -> bool {
    data.data.iter().all(|&b| b == 0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ffi_type_sizes() {
        assert_eq!(FfiType::Void.size(), 0);
        assert_eq!(FfiType::Int8.size(), 1);
        assert_eq!(FfiType::Uint8.size(), 1);
        assert_eq!(FfiType::Int16.size(), 2);
        assert_eq!(FfiType::Uint16.size(), 2);
        assert_eq!(FfiType::Int32.size(), 4);
        assert_eq!(FfiType::Uint32.size(), 4);
        assert_eq!(FfiType::Int64.size(), 8);
        assert_eq!(FfiType::Uint64.size(), 8);
        assert_eq!(FfiType::Float.size(), 4);
        assert_eq!(FfiType::Double.size(), 8);
        assert_eq!(FfiType::Pointer(Box::new(FfiType::Void)).size(), 8);
        assert_eq!(FfiType::Bool.size(), 1);
        assert_eq!(FfiType::Char.size(), 1);
    }

    #[test]
    fn test_ffi_type_alignment() {
        assert_eq!(FfiType::Int8.alignment(), 1);
        assert_eq!(FfiType::Int16.alignment(), 2);
        assert_eq!(FfiType::Int32.alignment(), 4);
        assert_eq!(FfiType::Int64.alignment(), 8);
        assert_eq!(FfiType::Double.alignment(), 8);
        assert_eq!(FfiType::Pointer(Box::new(FfiType::Int32)).alignment(), 8);
    }

    #[test]
    fn test_ffi_new() {
        let data = ffi_new("int32_t").unwrap();
        assert_eq!(data.type_info, FfiType::Int32);
        assert_eq!(data.data.len(), 4);
        assert!(data.data.iter().all(|&b| b == 0));
    }

    #[test]
    fn test_ffi_new_array() {
        let data = ffi_new("int32_t[10]").unwrap();
        assert_eq!(ffi_sizeof(&data), 40);
        assert_eq!(data.data.len(), 40);
    }

    #[test]
    fn test_ffi_new_unknown_type() {
        let result = ffi_new("nonexistent_type");
        assert!(result.is_err());
        assert!(matches!(result, Err(FfiError::TypeNotFound(_))));
    }

    #[test]
    fn test_ffi_free() {
        let mut data = ffi_new("int32_t").unwrap();
        assert!(!data.freed);
        ffi_free(&mut data);
        assert!(data.freed);
        assert!(data.data.is_empty());
    }

    #[test]
    fn test_ffi_cast() {
        let mut src = ffi_new("int32_t").unwrap();
        src.data = vec![0x42, 0x00, 0x00, 0x00]; // 66 in little-endian

        let dst = ffi_cast("int64_t", &src).unwrap();
        assert_eq!(dst.type_info, FfiType::Int64);
        assert_eq!(dst.data.len(), 8);
        assert_eq!(dst.data[0], 0x42);
    }

    #[test]
    fn test_ffi_cast_freed() {
        let mut data = ffi_new("int32_t").unwrap();
        ffi_free(&mut data);
        let result = ffi_cast("int64_t", &data);
        assert!(result.is_err());
    }

    #[test]
    fn test_ffi_typeof() {
        let data = ffi_new("double").unwrap();
        assert_eq!(ffi_typeof(&data), FfiType::Double);
    }

    #[test]
    fn test_ffi_sizeof() {
        let data = ffi_new("int64_t").unwrap();
        assert_eq!(ffi_sizeof(&data), 8);

        let data2 = ffi_new("int8_t").unwrap();
        assert_eq!(ffi_sizeof(&data2), 1);
    }

    #[test]
    fn test_ffi_alignof() {
        let data = ffi_new("int32_t").unwrap();
        assert_eq!(ffi_alignof(&data), 4);

        let data2 = ffi_new("double").unwrap();
        assert_eq!(ffi_alignof(&data2), 8);
    }

    #[test]
    fn test_ffi_memcpy() {
        let mut src = ffi_new("int32_t").unwrap();
        src.data = vec![1, 2, 3, 4];

        let mut dst = ffi_new("int32_t").unwrap();
        ffi_memcpy(&mut dst, &src, 4);
        assert_eq!(dst.data, vec![1, 2, 3, 4]);
    }

    #[test]
    fn test_ffi_memcpy_partial() {
        let mut src = ffi_new("int32_t").unwrap();
        src.data = vec![0xAA, 0xBB, 0xCC, 0xDD];

        let mut dst = ffi_new("int32_t").unwrap();
        ffi_memcpy(&mut dst, &src, 2);
        assert_eq!(dst.data, vec![0xAA, 0xBB, 0x00, 0x00]);
    }

    #[test]
    fn test_ffi_memset() {
        let mut data = ffi_new("int32_t").unwrap();
        ffi_memset(&mut data, 0xFF, 4);
        assert_eq!(data.data, vec![0xFF, 0xFF, 0xFF, 0xFF]);
    }

    #[test]
    fn test_ffi_memset_partial() {
        let mut data = ffi_new("int32_t").unwrap();
        ffi_memset(&mut data, 0xAB, 2);
        assert_eq!(data.data, vec![0xAB, 0xAB, 0x00, 0x00]);
    }

    #[test]
    fn test_ffi_string() {
        let mut data = ffi_new("char[12]").unwrap();
        let bytes = b"Hello World\0";
        data.data[..12].copy_from_slice(bytes);

        assert_eq!(ffi_string(&data, None), "Hello World");
        assert_eq!(ffi_string(&data, Some(5)), "Hello");
    }

    #[test]
    fn test_ffi_is_null() {
        let data = ffi_new("int32_t").unwrap();
        assert!(ffi_isNull(&data)); // zeroed = null

        let mut data2 = ffi_new("int32_t").unwrap();
        data2.data[0] = 1;
        assert!(!ffi_isNull(&data2));
    }

    #[test]
    fn test_ffi_cdef_function() {
        let cdef = ffi_cdef("int printf(char *format);").unwrap();
        assert_eq!(cdef.functions.len(), 1);
        assert_eq!(cdef.functions[0].name, "printf");
        assert_eq!(cdef.functions[0].return_type, FfiType::Int32);
    }

    #[test]
    fn test_ffi_cdef_multiple() {
        let code = r#"
            int add(int a, int b);
            void free(void *ptr);
            double sqrt(double x);
        "#;
        let cdef = ffi_cdef(code).unwrap();
        assert_eq!(cdef.functions.len(), 3);
        assert_eq!(cdef.functions[0].name, "add");
        assert_eq!(cdef.functions[1].name, "free");
        assert_eq!(cdef.functions[2].name, "sqrt");
    }

    #[test]
    fn test_ffi_cdef_typedef() {
        let code = "typedef unsigned int uint_t;";
        let cdef = ffi_cdef(code).unwrap();
        assert_eq!(cdef.types.get("uint_t"), Some(&FfiType::Uint32));
    }

    #[test]
    fn test_ffi_struct_type() {
        let fields = vec![
            ("x".to_string(), FfiType::Int32),
            ("y".to_string(), FfiType::Int32),
        ];
        let struct_type = FfiType::Struct(fields);
        assert_eq!(struct_type.size(), 8); // 4 + 4
        assert_eq!(struct_type.alignment(), 4);
    }

    #[test]
    fn test_ffi_struct_with_padding() {
        let fields = vec![
            ("a".to_string(), FfiType::Int8),  // 1 byte + 7 padding
            ("b".to_string(), FfiType::Int64), // 8 bytes
        ];
        let struct_type = FfiType::Struct(fields);
        assert_eq!(struct_type.size(), 16); // 1 + 7 pad + 8
        assert_eq!(struct_type.alignment(), 8);
    }

    #[test]
    fn test_ffi_pointer_type() {
        let ptr = FfiType::Pointer(Box::new(FfiType::Int32));
        assert_eq!(ptr.size(), 8);
        assert_eq!(ptr.alignment(), 8);

        // Pointer to pointer
        let pptr = FfiType::Pointer(Box::new(ptr));
        assert_eq!(pptr.size(), 8);
    }

    #[test]
    fn test_ffi_array_type() {
        let arr = FfiType::Array(Box::new(FfiType::Int32), 5);
        assert_eq!(arr.size(), 20);
        assert_eq!(arr.alignment(), 4);
    }

    #[test]
    fn test_parse_c_type() {
        assert_eq!(parse_c_type("int").unwrap(), FfiType::Int32);
        assert_eq!(parse_c_type("unsigned int").unwrap(), FfiType::Uint32);
        assert_eq!(parse_c_type("double").unwrap(), FfiType::Double);
        assert_eq!(parse_c_type("void").unwrap(), FfiType::Void);
        assert_eq!(
            parse_c_type("int *").unwrap(),
            FfiType::Pointer(Box::new(FfiType::Int32))
        );
        assert!(parse_c_type("unknown_type").is_err());
    }
}
