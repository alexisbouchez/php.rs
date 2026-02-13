//! PHP array functions.
//!
//! Reference: php-src/ext/standard/array.c
//!
//! Note: These functions operate on Vec<(Key, Value)> ordered maps.
//! When integrated with the VM, they'll work with ZArray from php-rs-types.
//! For now we use a simplified representation for testing.

/// Simplified key type for standalone testing.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum ArrayKey {
    Int(i64),
    Str(String),
}

/// Simplified value type for standalone testing.
#[derive(Debug, Clone, PartialEq)]
pub enum ArrayValue {
    Null,
    Bool(bool),
    Int(i64),
    Float(f64),
    Str(String),
    Array(PhpArray),
}

impl ArrayValue {
    pub fn as_str(&self) -> String {
        match self {
            ArrayValue::Null => String::new(),
            ArrayValue::Bool(true) => "1".to_string(),
            ArrayValue::Bool(false) => String::new(),
            ArrayValue::Int(n) => n.to_string(),
            ArrayValue::Float(f) => format!("{}", f),
            ArrayValue::Str(s) => s.clone(),
            ArrayValue::Array(_) => "Array".to_string(),
        }
    }

    pub fn is_truthy(&self) -> bool {
        match self {
            ArrayValue::Null => false,
            ArrayValue::Bool(b) => *b,
            ArrayValue::Int(n) => *n != 0,
            ArrayValue::Float(f) => *f != 0.0,
            ArrayValue::Str(s) => !s.is_empty() && s != "0",
            ArrayValue::Array(a) => !a.entries.is_empty(),
        }
    }
}

/// Simplified ordered map for testing array functions.
#[derive(Debug, Clone, PartialEq)]
pub struct PhpArray {
    pub entries: Vec<(ArrayKey, ArrayValue)>,
    next_int_key: i64,
}

impl PhpArray {
    pub fn new() -> Self {
        Self {
            entries: Vec::new(),
            next_int_key: 0,
        }
    }

    pub fn from_values(values: Vec<ArrayValue>) -> Self {
        let mut arr = Self::new();
        for v in values {
            arr.push(v);
        }
        arr
    }

    pub fn push(&mut self, value: ArrayValue) {
        let key = ArrayKey::Int(self.next_int_key);
        self.next_int_key += 1;
        self.entries.push((key, value));
    }

    pub fn set(&mut self, key: ArrayKey, value: ArrayValue) {
        // Update next_int_key if needed
        if let ArrayKey::Int(n) = &key {
            if *n >= self.next_int_key {
                self.next_int_key = n + 1;
            }
        }

        // Check if key exists
        for entry in &mut self.entries {
            if entry.0 == key {
                entry.1 = value;
                return;
            }
        }
        self.entries.push((key, value));
    }

    pub fn get(&self, key: &ArrayKey) -> Option<&ArrayValue> {
        self.entries.iter().find(|(k, _)| k == key).map(|(_, v)| v)
    }

    pub fn remove(&mut self, key: &ArrayKey) -> Option<ArrayValue> {
        let pos = self.entries.iter().position(|(k, _)| k == key)?;
        Some(self.entries.remove(pos).1)
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn keys(&self) -> Vec<ArrayKey> {
        self.entries.iter().map(|(k, _)| k.clone()).collect()
    }

    pub fn values(&self) -> Vec<ArrayValue> {
        self.entries.iter().map(|(_, v)| v.clone()).collect()
    }
}

impl Default for PhpArray {
    fn default() -> Self {
        Self::new()
    }
}

// ── 8.2.1: count ─────────────────────────────────────────────────────────────

/// count() / sizeof() — Count elements in an array.
pub fn php_count(arr: &PhpArray) -> i64 {
    arr.len() as i64
}

// ── 8.2.2: Stack operations ──────────────────────────────────────────────────

/// array_push() — Push one or more elements onto the end.
pub fn php_array_push(arr: &mut PhpArray, values: Vec<ArrayValue>) -> i64 {
    for v in values {
        arr.push(v);
    }
    arr.len() as i64
}

/// array_pop() — Pop the element off the end.
pub fn php_array_pop(arr: &mut PhpArray) -> Option<ArrayValue> {
    arr.entries.pop().map(|(_, v)| v)
}

/// array_shift() — Shift an element off the beginning.
pub fn php_array_shift(arr: &mut PhpArray) -> Option<ArrayValue> {
    if arr.entries.is_empty() {
        return None;
    }
    let (_, v) = arr.entries.remove(0);
    // Re-index integer keys
    let mut next = 0i64;
    for entry in &mut arr.entries {
        if let ArrayKey::Int(_) = entry.0 {
            entry.0 = ArrayKey::Int(next);
            next += 1;
        }
    }
    arr.next_int_key = next;
    Some(v)
}

/// array_unshift() — Prepend one or more elements.
pub fn php_array_unshift(arr: &mut PhpArray, values: Vec<ArrayValue>) -> i64 {
    let mut new_entries: Vec<(ArrayKey, ArrayValue)> = values
        .into_iter()
        .enumerate()
        .map(|(i, v)| (ArrayKey::Int(i as i64), v))
        .collect();

    let offset = new_entries.len() as i64;
    for entry in &mut arr.entries {
        if let ArrayKey::Int(n) = &mut entry.0 {
            *n += offset;
        }
    }
    new_entries.append(&mut arr.entries);
    arr.entries = new_entries;
    arr.next_int_key = arr
        .entries
        .iter()
        .filter_map(|(k, _)| match k {
            ArrayKey::Int(n) => Some(*n + 1),
            _ => None,
        })
        .max()
        .unwrap_or(0);
    arr.len() as i64
}

// ── 8.2.3: Merge ─────────────────────────────────────────────────────────────

/// array_merge() — Merge one or more arrays.
pub fn php_array_merge(arrays: &[&PhpArray]) -> PhpArray {
    let mut result = PhpArray::new();
    for arr in arrays {
        for (key, value) in &arr.entries {
            match key {
                ArrayKey::Int(_) => result.push(value.clone()),
                ArrayKey::Str(s) => {
                    result.set(ArrayKey::Str(s.clone()), value.clone());
                }
            }
        }
    }
    result
}

// ── 8.2.4: Keys / values / combine ──────────────────────────────────────────

/// array_keys() — Return all the keys.
pub fn php_array_keys(arr: &PhpArray) -> PhpArray {
    let mut result = PhpArray::new();
    for (key, _) in &arr.entries {
        match key {
            ArrayKey::Int(n) => result.push(ArrayValue::Int(*n)),
            ArrayKey::Str(s) => result.push(ArrayValue::Str(s.clone())),
        }
    }
    result
}

/// array_values() — Return all the values, re-indexed.
pub fn php_array_values(arr: &PhpArray) -> PhpArray {
    PhpArray::from_values(arr.values())
}

/// array_combine() — Creates an array by using one array for keys and another for values.
pub fn php_array_combine(keys: &PhpArray, values: &PhpArray) -> Option<PhpArray> {
    if keys.len() != values.len() {
        return None;
    }
    let mut result = PhpArray::new();
    for (k, v) in keys.values().iter().zip(values.values().iter()) {
        let key = match k {
            ArrayValue::Int(n) => ArrayKey::Int(*n),
            ArrayValue::Str(s) => ArrayKey::Str(s.clone()),
            other => ArrayKey::Str(other.as_str()),
        };
        result.set(key, v.clone());
    }
    Some(result)
}

// ── 8.2.5: Search ────────────────────────────────────────────────────────────

/// in_array() — Check if a value exists in an array.
pub fn php_in_array(needle: &ArrayValue, arr: &PhpArray, strict: bool) -> bool {
    arr.entries.iter().any(|(_, v)| {
        if strict {
            v == needle
        } else {
            v.as_str() == needle.as_str()
        }
    })
}

/// array_search() — Search for a value and return its key.
pub fn php_array_search(needle: &ArrayValue, arr: &PhpArray, strict: bool) -> Option<ArrayKey> {
    arr.entries
        .iter()
        .find(|(_, v)| {
            if strict {
                v == needle
            } else {
                v.as_str() == needle.as_str()
            }
        })
        .map(|(k, _)| k.clone())
}

/// array_key_exists() — Check if a key exists.
pub fn php_array_key_exists(key: &ArrayKey, arr: &PhpArray) -> bool {
    arr.entries.iter().any(|(k, _)| k == key)
}

// ── 8.2.6: Map / filter / walk ───────────────────────────────────────────────

/// array_map() — Apply a callback to each element.
pub fn php_array_map(arr: &PhpArray, callback: impl Fn(&ArrayValue) -> ArrayValue) -> PhpArray {
    let mut result = PhpArray::new();
    for (key, value) in &arr.entries {
        result.set(key.clone(), callback(value));
    }
    result
}

/// array_filter() — Filter elements using a callback.
pub fn php_array_filter(
    arr: &PhpArray,
    callback: Option<&dyn Fn(&ArrayValue) -> bool>,
) -> PhpArray {
    let mut result = PhpArray {
        entries: Vec::new(),
        next_int_key: 0,
    };
    for (key, value) in &arr.entries {
        let keep = match callback {
            Some(f) => f(value),
            None => value.is_truthy(),
        };
        if keep {
            result.entries.push((key.clone(), value.clone()));
            if let ArrayKey::Int(n) = key {
                if *n >= result.next_int_key {
                    result.next_int_key = n + 1;
                }
            }
        }
    }
    result
}

// ── 8.2.7: Reduce / column ──────────────────────────────────────────────────

/// array_reduce() — Iteratively reduce the array to a single value.
pub fn php_array_reduce(
    arr: &PhpArray,
    callback: impl Fn(&ArrayValue, &ArrayValue) -> ArrayValue,
    initial: ArrayValue,
) -> ArrayValue {
    let mut carry = initial;
    for (_, value) in &arr.entries {
        carry = callback(&carry, value);
    }
    carry
}

// ── 8.2.8: Slice / splice / chunk ────────────────────────────────────────────

/// array_slice() — Extract a slice of the array.
pub fn php_array_slice(
    arr: &PhpArray,
    offset: i64,
    length: Option<i64>,
    preserve_keys: bool,
) -> PhpArray {
    let len = arr.len() as i64;
    let start = if offset < 0 {
        (len + offset).max(0) as usize
    } else {
        (offset as usize).min(arr.len())
    };
    let end = match length {
        Some(l) if l < 0 => ((len + l) as usize).max(start),
        Some(l) => (start + l as usize).min(arr.len()),
        None => arr.len(),
    };

    let mut result = PhpArray::new();
    for (key, value) in &arr.entries[start..end] {
        if preserve_keys {
            result.set(key.clone(), value.clone());
        } else {
            match key {
                ArrayKey::Int(_) => result.push(value.clone()),
                ArrayKey::Str(_) => result.set(key.clone(), value.clone()),
            }
        }
    }
    result
}

/// array_chunk() — Split an array into chunks.
pub fn php_array_chunk(arr: &PhpArray, size: usize, preserve_keys: bool) -> Vec<PhpArray> {
    if size == 0 {
        return vec![];
    }

    arr.entries
        .chunks(size)
        .map(|chunk| {
            let mut result = PhpArray::new();
            for (key, value) in chunk {
                if preserve_keys {
                    result.set(key.clone(), value.clone());
                } else {
                    result.push(value.clone());
                }
            }
            result
        })
        .collect()
}

// ── 8.2.9: Manipulation ─────────────────────────────────────────────────────

/// array_unique() — Remove duplicate values.
pub fn php_array_unique(arr: &PhpArray) -> PhpArray {
    let mut seen = Vec::new();
    let mut result = PhpArray {
        entries: Vec::new(),
        next_int_key: 0,
    };
    for (key, value) in &arr.entries {
        let s = value.as_str();
        if !seen.contains(&s) {
            seen.push(s);
            result.entries.push((key.clone(), value.clone()));
            if let ArrayKey::Int(n) = key {
                if *n >= result.next_int_key {
                    result.next_int_key = n + 1;
                }
            }
        }
    }
    result
}

/// array_flip() — Exchange all keys with their values.
pub fn php_array_flip(arr: &PhpArray) -> PhpArray {
    let mut result = PhpArray::new();
    for (key, value) in &arr.entries {
        let new_key = match value {
            ArrayValue::Int(n) => ArrayKey::Int(*n),
            ArrayValue::Str(s) => ArrayKey::Str(s.clone()),
            _ => continue,
        };
        let new_value = match key {
            ArrayKey::Int(n) => ArrayValue::Int(*n),
            ArrayKey::Str(s) => ArrayValue::Str(s.clone()),
        };
        result.set(new_key, new_value);
    }
    result
}

/// array_reverse() — Return an array with elements in reverse order.
pub fn php_array_reverse(arr: &PhpArray, preserve_keys: bool) -> PhpArray {
    let mut result = PhpArray::new();
    for (key, value) in arr.entries.iter().rev() {
        if preserve_keys {
            result.set(key.clone(), value.clone());
        } else {
            match key {
                ArrayKey::Int(_) => result.push(value.clone()),
                ArrayKey::Str(_) => result.set(key.clone(), value.clone()),
            }
        }
    }
    result
}

// ── 8.2.10: Sorting ──────────────────────────────────────────────────────────

/// sort() — Sort an array in ascending order (reindex).
pub fn php_sort(arr: &mut PhpArray) {
    arr.entries.sort_by(|(_, a), (_, b)| {
        a.as_str()
            .partial_cmp(&b.as_str())
            .unwrap_or(std::cmp::Ordering::Equal)
    });
    // Reindex
    for (i, entry) in arr.entries.iter_mut().enumerate() {
        entry.0 = ArrayKey::Int(i as i64);
    }
    arr.next_int_key = arr.len() as i64;
}

/// rsort() — Sort an array in descending order (reindex).
pub fn php_rsort(arr: &mut PhpArray) {
    arr.entries.sort_by(|(_, a), (_, b)| {
        b.as_str()
            .partial_cmp(&a.as_str())
            .unwrap_or(std::cmp::Ordering::Equal)
    });
    for (i, entry) in arr.entries.iter_mut().enumerate() {
        entry.0 = ArrayKey::Int(i as i64);
    }
    arr.next_int_key = arr.len() as i64;
}

/// asort() — Sort an array in ascending order, maintaining key association.
pub fn php_asort(arr: &mut PhpArray) {
    arr.entries.sort_by(|(_, a), (_, b)| {
        a.as_str()
            .partial_cmp(&b.as_str())
            .unwrap_or(std::cmp::Ordering::Equal)
    });
}

/// ksort() — Sort an array by key in ascending order.
pub fn php_ksort(arr: &mut PhpArray) {
    arr.entries.sort_by(|(a, _), (b, _)| match (a, b) {
        (ArrayKey::Int(a), ArrayKey::Int(b)) => a.cmp(b),
        (ArrayKey::Str(a), ArrayKey::Str(b)) => a.cmp(b),
        (ArrayKey::Int(_), ArrayKey::Str(_)) => std::cmp::Ordering::Less,
        (ArrayKey::Str(_), ArrayKey::Int(_)) => std::cmp::Ordering::Greater,
    });
}

// ── 8.2.12: Diff / intersect ─────────────────────────────────────────────────

/// array_diff() — Compute the difference of arrays.
pub fn php_array_diff(arr: &PhpArray, others: &[&PhpArray]) -> PhpArray {
    let mut result = PhpArray {
        entries: Vec::new(),
        next_int_key: 0,
    };
    for (key, value) in &arr.entries {
        let val_str = value.as_str();
        let in_other = others
            .iter()
            .any(|other| other.entries.iter().any(|(_, v)| v.as_str() == val_str));
        if !in_other {
            result.entries.push((key.clone(), value.clone()));
            if let ArrayKey::Int(n) = key {
                if *n >= result.next_int_key {
                    result.next_int_key = n + 1;
                }
            }
        }
    }
    result
}

/// array_intersect() — Compute the intersection of arrays.
pub fn php_array_intersect(arr: &PhpArray, others: &[&PhpArray]) -> PhpArray {
    let mut result = PhpArray {
        entries: Vec::new(),
        next_int_key: 0,
    };
    for (key, value) in &arr.entries {
        let val_str = value.as_str();
        let in_all = others
            .iter()
            .all(|other| other.entries.iter().any(|(_, v)| v.as_str() == val_str));
        if in_all {
            result.entries.push((key.clone(), value.clone()));
            if let ArrayKey::Int(n) = key {
                if *n >= result.next_int_key {
                    result.next_int_key = n + 1;
                }
            }
        }
    }
    result
}

// ── 8.2.13: Fill / range ─────────────────────────────────────────────────────

/// array_fill() — Fill an array with values.
pub fn php_array_fill(start_index: i64, num: usize, value: ArrayValue) -> PhpArray {
    let mut arr = PhpArray::new();
    for i in 0..num {
        arr.set(ArrayKey::Int(start_index + i as i64), value.clone());
    }
    arr
}

/// range() — Create an array containing a range of elements.
pub fn php_range(start: i64, end: i64, step: i64) -> PhpArray {
    let step = if step == 0 { 1 } else { step.abs() };
    let mut arr = PhpArray::new();

    if start <= end {
        let mut i = start;
        while i <= end {
            arr.push(ArrayValue::Int(i));
            i += step;
        }
    } else {
        let mut i = start;
        while i >= end {
            arr.push(ArrayValue::Int(i));
            i -= step;
        }
    }

    arr
}

#[cfg(test)]
mod tests {
    use super::*;

    fn int(n: i64) -> ArrayValue {
        ArrayValue::Int(n)
    }
    fn str(s: &str) -> ArrayValue {
        ArrayValue::Str(s.to_string())
    }

    #[test]
    fn test_count() {
        let arr = PhpArray::from_values(vec![int(1), int(2), int(3)]);
        assert_eq!(php_count(&arr), 3);
        assert_eq!(php_count(&PhpArray::new()), 0);
    }

    #[test]
    fn test_push_pop() {
        let mut arr = PhpArray::from_values(vec![int(1), int(2)]);
        php_array_push(&mut arr, vec![int(3), int(4)]);
        assert_eq!(arr.len(), 4);

        assert_eq!(php_array_pop(&mut arr), Some(int(4)));
        assert_eq!(arr.len(), 3);
    }

    #[test]
    fn test_shift_unshift() {
        let mut arr = PhpArray::from_values(vec![int(1), int(2), int(3)]);
        assert_eq!(php_array_shift(&mut arr), Some(int(1)));
        assert_eq!(arr.len(), 2);
        assert_eq!(arr.entries[0].0, ArrayKey::Int(0)); // Re-indexed

        php_array_unshift(&mut arr, vec![int(0)]);
        assert_eq!(arr.len(), 3);
        assert_eq!(arr.get(&ArrayKey::Int(0)), Some(&int(0)));
    }

    #[test]
    fn test_merge() {
        let a = PhpArray::from_values(vec![int(1), int(2)]);
        let mut b = PhpArray::new();
        b.set(ArrayKey::Str("key".to_string()), str("val"));
        b.push(int(3));

        let merged = php_array_merge(&[&a, &b]);
        assert_eq!(merged.len(), 4);
        assert_eq!(
            merged.get(&ArrayKey::Str("key".to_string())),
            Some(&str("val"))
        );
    }

    #[test]
    fn test_keys_values() {
        let mut arr = PhpArray::new();
        arr.set(ArrayKey::Str("a".to_string()), int(1));
        arr.set(ArrayKey::Str("b".to_string()), int(2));

        let keys = php_array_keys(&arr);
        assert_eq!(keys.len(), 2);

        let values = php_array_values(&arr);
        assert_eq!(values.len(), 2);
    }

    #[test]
    fn test_combine() {
        let keys = PhpArray::from_values(vec![str("a"), str("b")]);
        let values = PhpArray::from_values(vec![int(1), int(2)]);
        let combined = php_array_combine(&keys, &values).unwrap();
        assert_eq!(combined.get(&ArrayKey::Str("a".to_string())), Some(&int(1)));
        assert_eq!(combined.get(&ArrayKey::Str("b".to_string())), Some(&int(2)));
    }

    #[test]
    fn test_in_array() {
        let arr = PhpArray::from_values(vec![int(1), str("2"), int(3)]);
        assert!(php_in_array(&int(1), &arr, true));
        assert!(!php_in_array(&int(2), &arr, true)); // Strict: "2" != 2
        assert!(php_in_array(&int(2), &arr, false)); // Loose: "2" == "2"
    }

    #[test]
    fn test_array_search() {
        let arr = PhpArray::from_values(vec![str("a"), str("b"), str("c")]);
        assert_eq!(
            php_array_search(&str("b"), &arr, false),
            Some(ArrayKey::Int(1))
        );
        assert_eq!(php_array_search(&str("z"), &arr, false), None);
    }

    #[test]
    fn test_array_key_exists() {
        let mut arr = PhpArray::new();
        arr.set(ArrayKey::Str("name".to_string()), str("PHP"));
        assert!(php_array_key_exists(
            &ArrayKey::Str("name".to_string()),
            &arr
        ));
        assert!(!php_array_key_exists(
            &ArrayKey::Str("nope".to_string()),
            &arr
        ));
    }

    #[test]
    fn test_array_map() {
        let arr = PhpArray::from_values(vec![int(1), int(2), int(3)]);
        let result = php_array_map(&arr, |v| match v {
            ArrayValue::Int(n) => ArrayValue::Int(n * 2),
            _ => v.clone(),
        });
        assert_eq!(result.get(&ArrayKey::Int(0)), Some(&int(2)));
        assert_eq!(result.get(&ArrayKey::Int(2)), Some(&int(6)));
    }

    #[test]
    fn test_array_filter() {
        let arr = PhpArray::from_values(vec![
            int(0),
            int(1),
            str(""),
            str("hello"),
            ArrayValue::Null,
        ]);
        let result = php_array_filter(&arr, None);
        assert_eq!(result.len(), 2); // 1 and "hello"
    }

    #[test]
    fn test_array_reduce() {
        let arr = PhpArray::from_values(vec![int(1), int(2), int(3)]);
        let sum = php_array_reduce(
            &arr,
            |carry, item| match (carry, item) {
                (ArrayValue::Int(a), ArrayValue::Int(b)) => ArrayValue::Int(a + b),
                _ => carry.clone(),
            },
            int(0),
        );
        assert_eq!(sum, int(6));
    }

    #[test]
    fn test_array_slice() {
        let arr = PhpArray::from_values(vec![int(1), int(2), int(3), int(4), int(5)]);
        let slice = php_array_slice(&arr, 1, Some(3), false);
        assert_eq!(slice.len(), 3);
        assert_eq!(slice.get(&ArrayKey::Int(0)), Some(&int(2)));

        // Negative offset
        let slice = php_array_slice(&arr, -2, None, false);
        assert_eq!(slice.len(), 2);
        assert_eq!(slice.get(&ArrayKey::Int(0)), Some(&int(4)));
    }

    #[test]
    fn test_array_chunk() {
        let arr = PhpArray::from_values(vec![int(1), int(2), int(3), int(4), int(5)]);
        let chunks = php_array_chunk(&arr, 2, false);
        assert_eq!(chunks.len(), 3);
        assert_eq!(chunks[0].len(), 2);
        assert_eq!(chunks[2].len(), 1);
    }

    #[test]
    fn test_array_unique() {
        let arr = PhpArray::from_values(vec![int(1), int(2), int(1), int(3), int(2)]);
        let result = php_array_unique(&arr);
        assert_eq!(result.len(), 3);
    }

    #[test]
    fn test_array_flip() {
        let mut arr = PhpArray::new();
        arr.set(ArrayKey::Str("a".to_string()), int(1));
        arr.set(ArrayKey::Str("b".to_string()), int(2));

        let flipped = php_array_flip(&arr);
        assert_eq!(
            flipped.get(&ArrayKey::Int(1)),
            Some(&ArrayValue::Str("a".to_string()))
        );
    }

    #[test]
    fn test_array_reverse() {
        let arr = PhpArray::from_values(vec![int(1), int(2), int(3)]);
        let rev = php_array_reverse(&arr, false);
        assert_eq!(rev.get(&ArrayKey::Int(0)), Some(&int(3)));
        assert_eq!(rev.get(&ArrayKey::Int(2)), Some(&int(1)));
    }

    #[test]
    fn test_sort() {
        let mut arr = PhpArray::from_values(vec![int(3), int(1), int(2)]);
        php_sort(&mut arr);
        assert_eq!(arr.get(&ArrayKey::Int(0)), Some(&int(1)));
        assert_eq!(arr.get(&ArrayKey::Int(2)), Some(&int(3)));
    }

    #[test]
    fn test_ksort() {
        let mut arr = PhpArray::new();
        arr.set(ArrayKey::Str("c".to_string()), int(3));
        arr.set(ArrayKey::Str("a".to_string()), int(1));
        arr.set(ArrayKey::Str("b".to_string()), int(2));
        php_ksort(&mut arr);
        assert_eq!(arr.entries[0].0, ArrayKey::Str("a".to_string()));
        assert_eq!(arr.entries[2].0, ArrayKey::Str("c".to_string()));
    }

    #[test]
    fn test_array_diff() {
        let a = PhpArray::from_values(vec![int(1), int(2), int(3), int(4)]);
        let b = PhpArray::from_values(vec![int(2), int(4)]);
        let diff = php_array_diff(&a, &[&b]);
        assert_eq!(diff.len(), 2); // 1 and 3
    }

    #[test]
    fn test_array_intersect() {
        let a = PhpArray::from_values(vec![int(1), int(2), int(3), int(4)]);
        let b = PhpArray::from_values(vec![int(2), int(4), int(5)]);
        let inter = php_array_intersect(&a, &[&b]);
        assert_eq!(inter.len(), 2); // 2 and 4
    }

    #[test]
    fn test_array_fill() {
        let arr = php_array_fill(5, 3, str("x"));
        assert_eq!(arr.len(), 3);
        assert_eq!(arr.get(&ArrayKey::Int(5)), Some(&str("x")));
        assert_eq!(arr.get(&ArrayKey::Int(7)), Some(&str("x")));
    }

    #[test]
    fn test_range() {
        let arr = php_range(1, 5, 1);
        assert_eq!(arr.len(), 5);

        let arr = php_range(0, 10, 3);
        assert_eq!(arr.len(), 4); // 0, 3, 6, 9

        let arr = php_range(5, 1, 1);
        assert_eq!(arr.len(), 5); // 5, 4, 3, 2, 1
    }
}
