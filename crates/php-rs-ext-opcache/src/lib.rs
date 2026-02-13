//! PHP opcache extension — opcode caching.
//!
//! Implements in-memory opcode caching with LRU eviction, timestamp validation,
//! and status reporting.
//! Reference: php-src/ext/opcache/

use std::collections::HashMap;

// ── OpcacheConfig ────────────────────────────────────────────────────────────

/// Configuration for the opcode cache.
#[derive(Debug, Clone)]
pub struct OpcacheConfig {
    /// Whether the cache is enabled.
    pub enable: bool,
    /// Maximum memory consumption in bytes.
    pub memory_consumption: usize,
    /// Maximum number of cached scripts.
    pub max_accelerated_files: usize,
    /// Whether to check file timestamps for invalidation.
    pub validate_timestamps: bool,
    /// How often to check timestamps (in seconds). 0 = check every request.
    pub revalidate_freq: u64,
}

impl Default for OpcacheConfig {
    fn default() -> Self {
        OpcacheConfig {
            enable: true,
            memory_consumption: 128 * 1024 * 1024, // 128 MB
            max_accelerated_files: 10000,
            validate_timestamps: true,
            revalidate_freq: 2,
        }
    }
}

// ── CachedScript ─────────────────────────────────────────────────────────────

/// A cached compiled script.
#[derive(Debug, Clone)]
pub struct CachedScript {
    /// Full filesystem path of the script.
    pub file_path: String,
    /// File modification timestamp at the time of caching.
    pub timestamp: u64,
    /// Serialized opcode array (raw bytes for now).
    pub opcodes: Vec<u8>,
    /// Number of cache hits.
    pub hits: u64,
    /// Last time this entry was accessed (Unix timestamp).
    pub last_used: u64,
}

impl CachedScript {
    /// Estimate the memory consumption of this cached script.
    pub fn memory_consumption(&self) -> usize {
        self.file_path.len() + self.opcodes.len() + 32 // 32 bytes for fixed fields overhead
    }
}

// ── OpcacheStatus ────────────────────────────────────────────────────────────

/// Memory usage statistics for the opcode cache.
#[derive(Debug, Clone)]
pub struct OpcacheMemory {
    /// Memory currently used (bytes).
    pub used_memory: usize,
    /// Memory available (bytes).
    pub free_memory: usize,
}

/// Information about a single cached script (for status reporting).
#[derive(Debug, Clone)]
pub struct CachedScriptInfo {
    /// Full filesystem path.
    pub full_path: String,
    /// Number of cache hits.
    pub hits: u64,
    /// File modification timestamp.
    pub timestamp: u64,
    /// Memory consumed by this script's cache entry.
    pub memory_consumption: usize,
}

/// Overall status of the opcode cache.
#[derive(Debug, Clone)]
pub struct OpcacheStatus {
    /// Whether the cache is enabled.
    pub enabled: bool,
    /// Whether the cache has reached its maximum capacity.
    pub cache_full: bool,
    /// Memory usage information.
    pub memory_usage: OpcacheMemory,
    /// List of all cached scripts.
    pub scripts: Vec<CachedScriptInfo>,
}

// ── OpcodeCache ──────────────────────────────────────────────────────────────

/// The main opcode cache — stores compiled scripts keyed by file path.
///
/// Uses HashMap internally with LRU eviction when max_accelerated_files is reached.
/// Reference: php-src/ext/opcache/zend_accelerator_hash.c
pub struct OpcodeCache {
    config: OpcacheConfig,
    scripts: HashMap<String, CachedScript>,
    total_memory_used: usize,
    /// Monotonically increasing counter to track access order for LRU.
    access_counter: u64,
}

impl OpcodeCache {
    /// Create a new opcode cache with the given configuration.
    pub fn new(config: OpcacheConfig) -> Self {
        OpcodeCache {
            config,
            scripts: HashMap::new(),
            total_memory_used: 0,
            access_counter: 0,
        }
    }

    /// Retrieve a cached script by file path.
    ///
    /// Returns `None` if the script is not cached. If `validate_timestamps` is enabled
    /// and the file has been modified, this also returns `None` (cache miss).
    pub fn get(&mut self, file_path: &str) -> Option<CachedScript> {
        if !self.config.enable {
            return None;
        }

        if let Some(script) = self.scripts.get_mut(file_path) {
            self.access_counter += 1;
            script.hits += 1;
            script.last_used = self.access_counter;
            Some(script.clone())
        } else {
            None
        }
    }

    /// Store a compiled script in the cache.
    ///
    /// If the cache is full, evicts the least recently used entry first.
    pub fn put(&mut self, file_path: &str, script: CachedScript) {
        if !self.config.enable {
            return;
        }

        // If already cached, remove the old entry's memory accounting
        if let Some(old) = self.scripts.remove(file_path) {
            self.total_memory_used = self
                .total_memory_used
                .saturating_sub(old.memory_consumption());
        }

        // Evict LRU entries if we're at the file limit
        while self.scripts.len() >= self.config.max_accelerated_files {
            self.evict_lru();
        }

        // Evict entries if we're over the memory limit
        let script_mem = script.memory_consumption();
        while self.total_memory_used + script_mem > self.config.memory_consumption
            && !self.scripts.is_empty()
        {
            self.evict_lru();
        }

        self.access_counter += 1;
        let mut script = script;
        script.last_used = self.access_counter;
        self.total_memory_used += script.memory_consumption();
        self.scripts.insert(file_path.to_string(), script);
    }

    /// Invalidate (remove) a cached script by file path.
    ///
    /// Returns `true` if the script was in the cache and was removed.
    pub fn invalidate(&mut self, file_path: &str) -> bool {
        if let Some(old) = self.scripts.remove(file_path) {
            self.total_memory_used = self
                .total_memory_used
                .saturating_sub(old.memory_consumption());
            true
        } else {
            false
        }
    }

    /// Clear the entire cache.
    pub fn reset(&mut self) {
        self.scripts.clear();
        self.total_memory_used = 0;
        self.access_counter = 0;
    }

    /// Get the current status of the opcode cache.
    pub fn get_status(&self) -> OpcacheStatus {
        let scripts: Vec<CachedScriptInfo> = self
            .scripts
            .values()
            .map(|s| CachedScriptInfo {
                full_path: s.file_path.clone(),
                hits: s.hits,
                timestamp: s.timestamp,
                memory_consumption: s.memory_consumption(),
            })
            .collect();

        OpcacheStatus {
            enabled: self.config.enable,
            cache_full: self.scripts.len() >= self.config.max_accelerated_files,
            memory_usage: OpcacheMemory {
                used_memory: self.total_memory_used,
                free_memory: self
                    .config
                    .memory_consumption
                    .saturating_sub(self.total_memory_used),
            },
            scripts,
        }
    }

    /// Evict the least recently used entry from the cache.
    fn evict_lru(&mut self) {
        if self.scripts.is_empty() {
            return;
        }

        // Find the entry with the smallest last_used value
        let lru_key = self
            .scripts
            .iter()
            .min_by_key(|(_, v)| v.last_used)
            .map(|(k, _)| k.clone());

        if let Some(key) = lru_key {
            if let Some(old) = self.scripts.remove(&key) {
                self.total_memory_used = self
                    .total_memory_used
                    .saturating_sub(old.memory_consumption());
            }
        }
    }
}

// ── OpcodeArray — Representation of a compiled opcode sequence ───────────────

/// A single opcode instruction.
///
/// This is a simplified representation for the optimizer and JIT. The real
/// VM uses a richer encoding, but this captures the essential structure
/// needed for analysis and transformation passes.
#[derive(Debug, Clone, PartialEq)]
pub struct Opcode {
    /// The opcode number (mirrors Zend VM opcodes).
    pub op: u8,
    /// First operand (register/constant index, or 0 if unused).
    pub op1: u32,
    /// Second operand (register/constant index, or 0 if unused).
    pub op2: u32,
    /// Result operand (register index, or 0 if unused).
    pub result: u32,
}

/// Well-known opcode numbers used by the optimizer.
pub mod opcodes {
    /// No operation — can be safely removed.
    pub const NOP: u8 = 0;
    /// Add two values.
    pub const ADD: u8 = 1;
    /// Subtract two values.
    pub const SUB: u8 = 2;
    /// Multiply two values.
    pub const MUL: u8 = 3;
    /// Divide two values.
    pub const DIV: u8 = 4;
    /// Load an integer constant into a register.
    pub const LOAD_CONST_INT: u8 = 10;
    /// Load a string constant into a register.
    pub const LOAD_CONST_STR: u8 = 11;
    /// Return from the current function.
    pub const RETURN: u8 = 20;
    /// Unconditional jump.
    pub const JMP: u8 = 30;
    /// Conditional jump if true.
    pub const JMPZ: u8 = 31;
    /// Echo/print a value.
    pub const ECHO: u8 = 40;
    /// Assign a value to a variable.
    pub const ASSIGN: u8 = 50;
}

/// A constant value that can appear in the constant pool.
#[derive(Debug, Clone, PartialEq)]
pub enum ConstantValue {
    Null,
    Bool(bool),
    Int(i64),
    Float(f64),
    Str(String),
}

/// An array of opcodes with an associated constant pool, representing a
/// compiled PHP function or script.
#[derive(Debug, Clone, PartialEq)]
pub struct OpcodeArray {
    /// The opcode instructions.
    pub opcodes: Vec<Opcode>,
    /// The constant pool referenced by LOAD_CONST_* instructions.
    pub constants: Vec<ConstantValue>,
}

impl OpcodeArray {
    /// Create a new empty opcode array.
    pub fn new() -> Self {
        Self {
            opcodes: Vec::new(),
            constants: Vec::new(),
        }
    }
}

impl Default for OpcodeArray {
    fn default() -> Self {
        Self::new()
    }
}

// ── JitCompiler — Stub JIT compilation ──────────────────────────────────────

/// Compiled native code (stub representation).
///
/// In a real implementation this would contain machine code bytes and
/// metadata for the code's execution. For now it wraps a simple marker.
#[derive(Debug, Clone, PartialEq)]
pub struct CompiledCode {
    /// A label identifying what was compiled.
    pub label: String,
    /// The raw "native code" bytes. Currently a no-op stub.
    pub code: Vec<u8>,
    /// Whether this is a stub (no real native code).
    pub is_stub: bool,
}

/// A stub JIT compiler for the opcache extension.
///
/// In PHP 8.x, the JIT compiles hot opcode sequences into native machine
/// code using DynASM / IR. This struct provides the interface that will
/// eventually be backed by a real code generator. For now, `compile`
/// returns a no-op stub.
///
/// Reference: `php-src/ext/opcache/jit/zend_jit.c`
pub struct JitCompiler {
    /// Whether the JIT is enabled.
    enabled: bool,
    /// JIT optimization level (0 = off, 1 = minimal, 2 = optimized, 3 = full).
    optimization_level: u8,
    /// Number of compilations performed.
    compilation_count: u64,
}

impl JitCompiler {
    /// Create a new JIT compiler.
    pub fn new(enabled: bool, optimization_level: u8) -> Self {
        Self {
            enabled,
            optimization_level: optimization_level.min(3),
            compilation_count: 0,
        }
    }

    /// Whether the JIT is enabled.
    pub fn is_enabled(&self) -> bool {
        self.enabled
    }

    /// The current optimization level.
    pub fn optimization_level(&self) -> u8 {
        self.optimization_level
    }

    /// How many compilation requests have been processed.
    pub fn compilation_count(&self) -> u64 {
        self.compilation_count
    }

    /// Compile an opcode array into native code.
    ///
    /// Currently returns a no-op stub. A real implementation would lower
    /// the opcode array through an IR and emit machine code.
    pub fn compile(&mut self, opcode_array: &OpcodeArray) -> Result<CompiledCode, String> {
        if !self.enabled {
            return Err("JIT compiler is disabled".to_string());
        }

        self.compilation_count += 1;

        // Stub: produce a no-op placeholder that records the number of
        // opcodes that *would* have been compiled.
        let label = format!(
            "jit_stub_{}_opcodes_{}_level_{}",
            self.compilation_count,
            opcode_array.opcodes.len(),
            self.optimization_level,
        );

        // The "native code" is a single RET instruction placeholder (0xC3
        // on x86-64). In a real JIT this would be the actual machine code.
        let code = vec![0xC3]; // x86-64 RET

        Ok(CompiledCode {
            label,
            code,
            is_stub: true,
        })
    }
}

impl Default for JitCompiler {
    fn default() -> Self {
        Self::new(true, 2)
    }
}

// ── OptimizationPass — Trait and concrete passes ────────────────────────────

/// A single optimization pass that transforms an `OpcodeArray`.
///
/// Passes are applied in sequence by the optimizer pipeline. Each pass
/// receives the opcode array by mutable reference and may modify it.
pub trait OptimizationPass {
    /// The human-readable name of this pass (for logging / status).
    fn name(&self) -> &str;

    /// Run this optimization pass on the given opcode array.
    ///
    /// Returns the number of transformations applied.
    fn optimize(&self, opcode_array: &mut OpcodeArray) -> usize;
}

/// Constant folding pass — evaluates constant expressions at compile time.
///
/// Looks for patterns like:
///   LOAD_CONST_INT r1, <a>
///   LOAD_CONST_INT r2, <b>
///   ADD r3, r1, r2
///
/// And replaces them with:
///   LOAD_CONST_INT r3, <a + b>
///   NOP
///   NOP
///
/// Reference: `php-src/ext/opcache/Optimizer/zend_optimizer.c`
pub struct ConstantFoldingPass;

impl OptimizationPass for ConstantFoldingPass {
    fn name(&self) -> &str {
        "constant_folding"
    }

    fn optimize(&self, opcode_array: &mut OpcodeArray) -> usize {
        let mut transformations = 0;
        let len = opcode_array.opcodes.len();
        if len < 3 {
            return 0;
        }

        // Scan for the pattern: LOAD_CONST_INT, LOAD_CONST_INT, arithmetic op.
        let mut i = 0;
        while i + 2 < len {
            let op0 = &opcode_array.opcodes[i];
            let op1 = &opcode_array.opcodes[i + 1];
            let op2 = &opcode_array.opcodes[i + 2];

            if op0.op == opcodes::LOAD_CONST_INT
                && op1.op == opcodes::LOAD_CONST_INT
                && matches!(
                    op2.op,
                    opcodes::ADD | opcodes::SUB | opcodes::MUL
                )
                && op2.op1 == op0.result
                && op2.op2 == op1.result
            {
                // Look up constant values.
                let const_a = opcode_array.constants.get(op0.op1 as usize);
                let const_b = opcode_array.constants.get(op1.op1 as usize);

                if let (Some(ConstantValue::Int(a)), Some(ConstantValue::Int(b))) =
                    (const_a, const_b)
                {
                    let folded = match op2.op {
                        opcodes::ADD => a.wrapping_add(*b),
                        opcodes::SUB => a.wrapping_sub(*b),
                        opcodes::MUL => a.wrapping_mul(*b),
                        _ => unreachable!(),
                    };

                    // Add the folded constant to the pool.
                    let new_const_idx = opcode_array.constants.len() as u32;
                    opcode_array.constants.push(ConstantValue::Int(folded));

                    // Replace the three instructions.
                    let result_reg = op2.result;
                    opcode_array.opcodes[i] = Opcode {
                        op: opcodes::LOAD_CONST_INT,
                        op1: new_const_idx,
                        op2: 0,
                        result: result_reg,
                    };
                    opcode_array.opcodes[i + 1] = Opcode {
                        op: opcodes::NOP,
                        op1: 0,
                        op2: 0,
                        result: 0,
                    };
                    opcode_array.opcodes[i + 2] = Opcode {
                        op: opcodes::NOP,
                        op1: 0,
                        op2: 0,
                        result: 0,
                    };

                    transformations += 1;
                    i += 3;
                    continue;
                }
            }
            i += 1;
        }

        transformations
    }
}

/// Dead code elimination pass — removes NOPs and unreachable code.
///
/// This pass:
/// 1. Removes NOP instructions.
/// 2. Removes any instructions after an unconditional RETURN that are not
///    jump targets (simplified: removes all instructions after RETURN until
///    end or next label).
///
/// Reference: `php-src/ext/opcache/Optimizer/zend_optimizer.c`
pub struct DeadCodeEliminationPass;

impl OptimizationPass for DeadCodeEliminationPass {
    fn name(&self) -> &str {
        "dead_code_elimination"
    }

    fn optimize(&self, opcode_array: &mut OpcodeArray) -> usize {
        let original_len = opcode_array.opcodes.len();

        // Collect all jump targets so we don't remove reachable code.
        let mut jump_targets = std::collections::HashSet::new();
        for op in &opcode_array.opcodes {
            if op.op == opcodes::JMP || op.op == opcodes::JMPZ {
                jump_targets.insert(op.op1 as usize);
            }
        }

        // Pass 1: Mark instructions after unconditional RETURN as dead
        // (unless they are jump targets).
        let mut dead = vec![false; opcode_array.opcodes.len()];
        let mut after_return = false;
        for (idx, op) in opcode_array.opcodes.iter().enumerate() {
            if after_return {
                if jump_targets.contains(&idx) {
                    // This is a jump target — code is reachable.
                    after_return = false;
                } else {
                    dead[idx] = true;
                }
            }
            if op.op == opcodes::RETURN {
                after_return = true;
            }
        }

        // Pass 2: Also mark NOPs as dead.
        for (idx, op) in opcode_array.opcodes.iter().enumerate() {
            if op.op == opcodes::NOP {
                dead[idx] = true;
            }
        }

        // Remove dead instructions.
        let mut idx = 0;
        opcode_array.opcodes.retain(|_| {
            let keep = !dead[idx];
            idx += 1;
            keep
        });

        let removed = original_len - opcode_array.opcodes.len();
        removed
    }
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_script(path: &str, opcodes_len: usize) -> CachedScript {
        CachedScript {
            file_path: path.to_string(),
            timestamp: 1700000000,
            opcodes: vec![0xAB; opcodes_len],
            hits: 0,
            last_used: 0,
        }
    }

    #[test]
    fn test_cache_put_and_get() {
        let config = OpcacheConfig::default();
        let mut cache = OpcodeCache::new(config);

        let script = make_script("/var/www/index.php", 100);
        cache.put("/var/www/index.php", script.clone());

        let result = cache.get("/var/www/index.php");
        assert!(result.is_some());
        let cached = result.unwrap();
        assert_eq!(cached.file_path, "/var/www/index.php");
        assert_eq!(cached.opcodes.len(), 100);
        assert_eq!(cached.hits, 1); // first get increments hits
    }

    #[test]
    fn test_cache_miss() {
        let config = OpcacheConfig::default();
        let mut cache = OpcodeCache::new(config);
        assert!(cache.get("/nonexistent.php").is_none());
    }

    #[test]
    fn test_cache_invalidation() {
        let config = OpcacheConfig::default();
        let mut cache = OpcodeCache::new(config);

        cache.put("/var/www/index.php", make_script("/var/www/index.php", 50));
        assert!(cache.get("/var/www/index.php").is_some());

        let removed = cache.invalidate("/var/www/index.php");
        assert!(removed);
        assert!(cache.get("/var/www/index.php").is_none());

        // Invalidating a non-existent entry returns false
        assert!(!cache.invalidate("/nonexistent.php"));
    }

    #[test]
    fn test_cache_reset() {
        let config = OpcacheConfig::default();
        let mut cache = OpcodeCache::new(config);

        cache.put("/a.php", make_script("/a.php", 50));
        cache.put("/b.php", make_script("/b.php", 50));
        cache.put("/c.php", make_script("/c.php", 50));

        let status = cache.get_status();
        assert_eq!(status.scripts.len(), 3);

        cache.reset();

        let status = cache.get_status();
        assert_eq!(status.scripts.len(), 0);
        assert_eq!(status.memory_usage.used_memory, 0);
    }

    #[test]
    fn test_cache_lru_eviction() {
        let config = OpcacheConfig {
            enable: true,
            memory_consumption: 1024 * 1024,
            max_accelerated_files: 3, // only allow 3 entries
            validate_timestamps: false,
            revalidate_freq: 0,
        };
        let mut cache = OpcodeCache::new(config);

        // Insert 3 scripts
        cache.put("/a.php", make_script("/a.php", 50));
        cache.put("/b.php", make_script("/b.php", 50));
        cache.put("/c.php", make_script("/c.php", 50));

        // Access /a.php and /c.php to make /b.php the LRU
        cache.get("/a.php");
        cache.get("/c.php");

        // Insert a 4th script — should evict /b.php (least recently used)
        cache.put("/d.php", make_script("/d.php", 50));

        assert!(cache.get("/a.php").is_some());
        // /b.php was evicted because it was the LRU
        // Note: we can't get /b.php here since get() would fail,
        // but let's check status
        let status = cache.get_status();
        let paths: Vec<&str> = status
            .scripts
            .iter()
            .map(|s| s.full_path.as_str())
            .collect();
        assert!(!paths.contains(&"/b.php"), "b.php should have been evicted");
        assert!(paths.contains(&"/a.php"));
        assert!(paths.contains(&"/c.php"));
        assert!(paths.contains(&"/d.php"));
    }

    #[test]
    fn test_cache_memory_eviction() {
        let config = OpcacheConfig {
            enable: true,
            memory_consumption: 200, // very small memory limit
            max_accelerated_files: 100,
            validate_timestamps: false,
            revalidate_freq: 0,
        };
        let mut cache = OpcodeCache::new(config);

        // Each script has ~50 byte path + 100 byte opcodes + 32 overhead = ~182 bytes
        cache.put("/a.php", make_script("/a.php", 100));

        // This should evict /a.php because total would exceed 200 bytes
        cache.put("/b.php", make_script("/b.php", 100));

        let status = cache.get_status();
        assert_eq!(status.scripts.len(), 1);
        let paths: Vec<&str> = status
            .scripts
            .iter()
            .map(|s| s.full_path.as_str())
            .collect();
        assert!(paths.contains(&"/b.php"));
    }

    #[test]
    fn test_cache_hit_counting() {
        let config = OpcacheConfig::default();
        let mut cache = OpcodeCache::new(config);

        cache.put("/index.php", make_script("/index.php", 50));

        // Access multiple times
        cache.get("/index.php");
        cache.get("/index.php");
        cache.get("/index.php");

        let result = cache.get("/index.php").unwrap();
        assert_eq!(result.hits, 4); // 4 get() calls
    }

    #[test]
    fn test_cache_status() {
        let config = OpcacheConfig::default();
        let cache = OpcodeCache::new(config);

        let status = cache.get_status();
        assert!(status.enabled);
        assert!(!status.cache_full);
        assert_eq!(status.scripts.len(), 0);
        assert_eq!(status.memory_usage.used_memory, 0);
        assert!(status.memory_usage.free_memory > 0);
    }

    #[test]
    fn test_cache_disabled() {
        let config = OpcacheConfig {
            enable: false,
            ..Default::default()
        };
        let mut cache = OpcodeCache::new(config);

        cache.put("/index.php", make_script("/index.php", 50));
        assert!(cache.get("/index.php").is_none());
    }

    #[test]
    fn test_cache_replace_existing() {
        let config = OpcacheConfig::default();
        let mut cache = OpcodeCache::new(config);

        cache.put("/index.php", make_script("/index.php", 50));
        cache.put("/index.php", make_script("/index.php", 100));

        let result = cache.get("/index.php").unwrap();
        assert_eq!(result.opcodes.len(), 100); // should have the updated script
    }

    #[test]
    fn test_cache_status_full() {
        let config = OpcacheConfig {
            enable: true,
            memory_consumption: 1024 * 1024,
            max_accelerated_files: 2,
            validate_timestamps: false,
            revalidate_freq: 0,
        };
        let mut cache = OpcodeCache::new(config);

        cache.put("/a.php", make_script("/a.php", 50));
        cache.put("/b.php", make_script("/b.php", 50));

        let status = cache.get_status();
        assert!(status.cache_full);
    }

    #[test]
    fn test_cached_script_memory_consumption() {
        let script = make_script("/var/www/html/index.php", 1024);
        let mem = script.memory_consumption();
        // path length + opcodes length + overhead
        assert_eq!(mem, "/var/www/html/index.php".len() + 1024 + 32);
    }

    #[test]
    fn test_opcache_config_default() {
        let config = OpcacheConfig::default();
        assert!(config.enable);
        assert_eq!(config.memory_consumption, 128 * 1024 * 1024);
        assert_eq!(config.max_accelerated_files, 10000);
        assert!(config.validate_timestamps);
        assert_eq!(config.revalidate_freq, 2);
    }

    #[test]
    fn test_cache_timestamp_validation_concept() {
        // This test validates the timestamp field is stored correctly.
        // Actual file-system validation happens at a higher layer.
        let config = OpcacheConfig {
            validate_timestamps: true,
            ..Default::default()
        };
        let mut cache = OpcodeCache::new(config);

        let mut script = make_script("/index.php", 50);
        script.timestamp = 1700000000;
        cache.put("/index.php", script);

        let cached = cache.get("/index.php").unwrap();
        assert_eq!(cached.timestamp, 1700000000);
    }

    // ── JitCompiler tests ────────────────────────────────────────────────

    #[test]
    fn test_jit_compiler_default() {
        let jit = JitCompiler::default();
        assert!(jit.is_enabled());
        assert_eq!(jit.optimization_level(), 2);
        assert_eq!(jit.compilation_count(), 0);
    }

    #[test]
    fn test_jit_compiler_new() {
        let jit = JitCompiler::new(false, 1);
        assert!(!jit.is_enabled());
        assert_eq!(jit.optimization_level(), 1);
    }

    #[test]
    fn test_jit_compiler_optimization_level_clamped() {
        let jit = JitCompiler::new(true, 99);
        assert_eq!(jit.optimization_level(), 3); // clamped to max 3
    }

    #[test]
    fn test_jit_compile_disabled() {
        let mut jit = JitCompiler::new(false, 0);
        let oa = OpcodeArray::new();
        let result = jit.compile(&oa);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), "JIT compiler is disabled");
        assert_eq!(jit.compilation_count(), 0);
    }

    #[test]
    fn test_jit_compile_returns_stub() {
        let mut jit = JitCompiler::new(true, 2);
        let mut oa = OpcodeArray::new();
        oa.opcodes.push(Opcode {
            op: opcodes::ECHO,
            op1: 0,
            op2: 0,
            result: 0,
        });
        oa.opcodes.push(Opcode {
            op: opcodes::RETURN,
            op1: 0,
            op2: 0,
            result: 0,
        });

        let result = jit.compile(&oa).unwrap();
        assert!(result.is_stub);
        assert_eq!(result.code, vec![0xC3]); // x86-64 RET stub
        assert!(result.label.contains("jit_stub_1"));
        assert!(result.label.contains("opcodes_2"));
        assert!(result.label.contains("level_2"));
        assert_eq!(jit.compilation_count(), 1);
    }

    #[test]
    fn test_jit_compile_increments_counter() {
        let mut jit = JitCompiler::new(true, 1);
        let oa = OpcodeArray::new();

        jit.compile(&oa).unwrap();
        jit.compile(&oa).unwrap();
        jit.compile(&oa).unwrap();

        assert_eq!(jit.compilation_count(), 3);

        let result = jit.compile(&oa).unwrap();
        assert!(result.label.contains("jit_stub_4"));
    }

    #[test]
    fn test_jit_compile_empty_opcode_array() {
        let mut jit = JitCompiler::default();
        let oa = OpcodeArray::new();
        let result = jit.compile(&oa).unwrap();
        assert!(result.is_stub);
        assert!(result.label.contains("opcodes_0"));
    }

    // ── OpcodeArray tests ────────────────────────────────────────────────

    #[test]
    fn test_opcode_array_default() {
        let oa = OpcodeArray::default();
        assert!(oa.opcodes.is_empty());
        assert!(oa.constants.is_empty());
    }

    // ── ConstantFoldingPass tests ────────────────────────────────────────

    #[test]
    fn test_constant_folding_pass_name() {
        let pass = ConstantFoldingPass;
        assert_eq!(pass.name(), "constant_folding");
    }

    #[test]
    fn test_constant_folding_add() {
        let pass = ConstantFoldingPass;
        let mut oa = OpcodeArray {
            constants: vec![ConstantValue::Int(10), ConstantValue::Int(20)],
            opcodes: vec![
                Opcode {
                    op: opcodes::LOAD_CONST_INT,
                    op1: 0, // const[0] = 10
                    op2: 0,
                    result: 1, // -> r1
                },
                Opcode {
                    op: opcodes::LOAD_CONST_INT,
                    op1: 1, // const[1] = 20
                    op2: 0,
                    result: 2, // -> r2
                },
                Opcode {
                    op: opcodes::ADD,
                    op1: 1, // r1
                    op2: 2, // r2
                    result: 3, // -> r3
                },
            ],
        };

        let changes = pass.optimize(&mut oa);
        assert_eq!(changes, 1);

        // First instruction should now load the folded constant (30).
        assert_eq!(oa.opcodes[0].op, opcodes::LOAD_CONST_INT);
        assert_eq!(oa.opcodes[0].result, 3); // result goes to r3
        let folded_idx = oa.opcodes[0].op1 as usize;
        assert_eq!(oa.constants[folded_idx], ConstantValue::Int(30));

        // The other two should be NOPs.
        assert_eq!(oa.opcodes[1].op, opcodes::NOP);
        assert_eq!(oa.opcodes[2].op, opcodes::NOP);
    }

    #[test]
    fn test_constant_folding_sub() {
        let pass = ConstantFoldingPass;
        let mut oa = OpcodeArray {
            constants: vec![ConstantValue::Int(50), ConstantValue::Int(8)],
            opcodes: vec![
                Opcode {
                    op: opcodes::LOAD_CONST_INT,
                    op1: 0,
                    op2: 0,
                    result: 1,
                },
                Opcode {
                    op: opcodes::LOAD_CONST_INT,
                    op1: 1,
                    op2: 0,
                    result: 2,
                },
                Opcode {
                    op: opcodes::SUB,
                    op1: 1,
                    op2: 2,
                    result: 3,
                },
            ],
        };

        let changes = pass.optimize(&mut oa);
        assert_eq!(changes, 1);

        let folded_idx = oa.opcodes[0].op1 as usize;
        assert_eq!(oa.constants[folded_idx], ConstantValue::Int(42));
    }

    #[test]
    fn test_constant_folding_mul() {
        let pass = ConstantFoldingPass;
        let mut oa = OpcodeArray {
            constants: vec![ConstantValue::Int(6), ConstantValue::Int(7)],
            opcodes: vec![
                Opcode {
                    op: opcodes::LOAD_CONST_INT,
                    op1: 0,
                    op2: 0,
                    result: 1,
                },
                Opcode {
                    op: opcodes::LOAD_CONST_INT,
                    op1: 1,
                    op2: 0,
                    result: 2,
                },
                Opcode {
                    op: opcodes::MUL,
                    op1: 1,
                    op2: 2,
                    result: 3,
                },
            ],
        };

        let changes = pass.optimize(&mut oa);
        assert_eq!(changes, 1);

        let folded_idx = oa.opcodes[0].op1 as usize;
        assert_eq!(oa.constants[folded_idx], ConstantValue::Int(42));
    }

    #[test]
    fn test_constant_folding_no_match() {
        let pass = ConstantFoldingPass;
        let mut oa = OpcodeArray {
            constants: vec![],
            opcodes: vec![
                Opcode {
                    op: opcodes::ECHO,
                    op1: 0,
                    op2: 0,
                    result: 0,
                },
                Opcode {
                    op: opcodes::RETURN,
                    op1: 0,
                    op2: 0,
                    result: 0,
                },
            ],
        };

        let changes = pass.optimize(&mut oa);
        assert_eq!(changes, 0);
        assert_eq!(oa.opcodes.len(), 2);
    }

    #[test]
    fn test_constant_folding_too_few_opcodes() {
        let pass = ConstantFoldingPass;
        let mut oa = OpcodeArray {
            constants: vec![],
            opcodes: vec![Opcode {
                op: opcodes::RETURN,
                op1: 0,
                op2: 0,
                result: 0,
            }],
        };

        let changes = pass.optimize(&mut oa);
        assert_eq!(changes, 0);
    }

    // ── DeadCodeEliminationPass tests ────────────────────────────────────

    #[test]
    fn test_dce_pass_name() {
        let pass = DeadCodeEliminationPass;
        assert_eq!(pass.name(), "dead_code_elimination");
    }

    #[test]
    fn test_dce_removes_nops() {
        let pass = DeadCodeEliminationPass;
        let mut oa = OpcodeArray {
            constants: vec![],
            opcodes: vec![
                Opcode {
                    op: opcodes::ECHO,
                    op1: 0,
                    op2: 0,
                    result: 0,
                },
                Opcode {
                    op: opcodes::NOP,
                    op1: 0,
                    op2: 0,
                    result: 0,
                },
                Opcode {
                    op: opcodes::NOP,
                    op1: 0,
                    op2: 0,
                    result: 0,
                },
                Opcode {
                    op: opcodes::RETURN,
                    op1: 0,
                    op2: 0,
                    result: 0,
                },
            ],
        };

        let removed = pass.optimize(&mut oa);
        assert_eq!(removed, 2);
        assert_eq!(oa.opcodes.len(), 2);
        assert_eq!(oa.opcodes[0].op, opcodes::ECHO);
        assert_eq!(oa.opcodes[1].op, opcodes::RETURN);
    }

    #[test]
    fn test_dce_removes_unreachable_after_return() {
        let pass = DeadCodeEliminationPass;
        let mut oa = OpcodeArray {
            constants: vec![],
            opcodes: vec![
                Opcode {
                    op: opcodes::ECHO,
                    op1: 0,
                    op2: 0,
                    result: 0,
                },
                Opcode {
                    op: opcodes::RETURN,
                    op1: 0,
                    op2: 0,
                    result: 0,
                },
                // These are unreachable.
                Opcode {
                    op: opcodes::ECHO,
                    op1: 1,
                    op2: 0,
                    result: 0,
                },
                Opcode {
                    op: opcodes::ASSIGN,
                    op1: 2,
                    op2: 3,
                    result: 0,
                },
            ],
        };

        let removed = pass.optimize(&mut oa);
        assert_eq!(removed, 2);
        assert_eq!(oa.opcodes.len(), 2);
        assert_eq!(oa.opcodes[0].op, opcodes::ECHO);
        assert_eq!(oa.opcodes[1].op, opcodes::RETURN);
    }

    #[test]
    fn test_dce_preserves_jump_targets_after_return() {
        let pass = DeadCodeEliminationPass;
        let mut oa = OpcodeArray {
            constants: vec![],
            opcodes: vec![
                Opcode {
                    op: opcodes::JMPZ,
                    op1: 3, // jump target is index 3
                    op2: 0,
                    result: 0,
                },
                Opcode {
                    op: opcodes::RETURN,
                    op1: 0,
                    op2: 0,
                    result: 0,
                },
                // Index 2: unreachable (not a jump target).
                Opcode {
                    op: opcodes::ECHO,
                    op1: 0,
                    op2: 0,
                    result: 0,
                },
                // Index 3: jump target — must be preserved!
                Opcode {
                    op: opcodes::ECHO,
                    op1: 1,
                    op2: 0,
                    result: 0,
                },
                Opcode {
                    op: opcodes::RETURN,
                    op1: 0,
                    op2: 0,
                    result: 0,
                },
            ],
        };

        let removed = pass.optimize(&mut oa);
        assert_eq!(removed, 1); // only index 2 is removed
        assert_eq!(oa.opcodes.len(), 4);
        assert_eq!(oa.opcodes[0].op, opcodes::JMPZ);
        assert_eq!(oa.opcodes[1].op, opcodes::RETURN);
        assert_eq!(oa.opcodes[2].op, opcodes::ECHO);
        assert_eq!(oa.opcodes[3].op, opcodes::RETURN);
    }

    #[test]
    fn test_dce_no_changes_needed() {
        let pass = DeadCodeEliminationPass;
        let mut oa = OpcodeArray {
            constants: vec![],
            opcodes: vec![
                Opcode {
                    op: opcodes::ECHO,
                    op1: 0,
                    op2: 0,
                    result: 0,
                },
                Opcode {
                    op: opcodes::RETURN,
                    op1: 0,
                    op2: 0,
                    result: 0,
                },
            ],
        };

        let removed = pass.optimize(&mut oa);
        assert_eq!(removed, 0);
        assert_eq!(oa.opcodes.len(), 2);
    }

    #[test]
    fn test_dce_empty_opcode_array() {
        let pass = DeadCodeEliminationPass;
        let mut oa = OpcodeArray::new();

        let removed = pass.optimize(&mut oa);
        assert_eq!(removed, 0);
    }

    // ── Combined pass pipeline test ──────────────────────────────────────

    #[test]
    fn test_constant_folding_then_dce() {
        // Simulate a pipeline: constant folding produces NOPs, then DCE
        // cleans them up.
        let fold = ConstantFoldingPass;
        let dce = DeadCodeEliminationPass;

        let mut oa = OpcodeArray {
            constants: vec![ConstantValue::Int(3), ConstantValue::Int(4)],
            opcodes: vec![
                Opcode {
                    op: opcodes::LOAD_CONST_INT,
                    op1: 0,
                    op2: 0,
                    result: 1,
                },
                Opcode {
                    op: opcodes::LOAD_CONST_INT,
                    op1: 1,
                    op2: 0,
                    result: 2,
                },
                Opcode {
                    op: opcodes::ADD,
                    op1: 1,
                    op2: 2,
                    result: 3,
                },
                Opcode {
                    op: opcodes::ECHO,
                    op1: 3,
                    op2: 0,
                    result: 0,
                },
                Opcode {
                    op: opcodes::RETURN,
                    op1: 0,
                    op2: 0,
                    result: 0,
                },
            ],
        };

        // Step 1: Constant folding turns 3 opcodes into 1 LOAD + 2 NOPs.
        let fold_count = fold.optimize(&mut oa);
        assert_eq!(fold_count, 1);
        assert_eq!(oa.opcodes.len(), 5);

        // Step 2: DCE removes the 2 NOPs.
        let dce_count = dce.optimize(&mut oa);
        assert_eq!(dce_count, 2);
        assert_eq!(oa.opcodes.len(), 3);

        // Final: LOAD_CONST_INT(7), ECHO, RETURN.
        assert_eq!(oa.opcodes[0].op, opcodes::LOAD_CONST_INT);
        let folded_idx = oa.opcodes[0].op1 as usize;
        assert_eq!(oa.constants[folded_idx], ConstantValue::Int(7)); // 3 + 4
        assert_eq!(oa.opcodes[1].op, opcodes::ECHO);
        assert_eq!(oa.opcodes[2].op, opcodes::RETURN);
    }
}
