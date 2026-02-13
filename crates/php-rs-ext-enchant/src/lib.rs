//! PHP enchant extension implementation for php.rs
//!
//! Provides spell checking functionality via enchant library interface.
//! Reference: php-src/ext/enchant/
//!
//! This is a pure Rust stub implementation that provides the full API surface.
//! Dictionary checks always return true; suggestions return empty lists.
//! Personal word lists are functional.

use std::collections::{HashMap, HashSet};

/// Error type for enchant operations.
#[derive(Debug, Clone, PartialEq)]
pub enum EnchantError {
    /// Dictionary not available
    DictNotAvailable(String),
    /// Broker error
    BrokerError(String),
    /// Generic error
    GenericError(String),
}

impl std::fmt::Display for EnchantError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            EnchantError::DictNotAvailable(tag) => {
                write!(f, "Dictionary not available for tag: {}", tag)
            }
            EnchantError::BrokerError(msg) => write!(f, "Enchant broker error: {}", msg),
            EnchantError::GenericError(msg) => write!(f, "Enchant error: {}", msg),
        }
    }
}

/// Provider information returned by enchant_broker_describe.
#[derive(Debug, Clone, PartialEq)]
pub struct BrokerProvider {
    /// Provider name
    pub name: String,
    /// Provider description
    pub desc: String,
    /// Path to the provider DLL/SO
    pub dll_path: String,
}

/// Enchant dictionary for spell checking.
#[derive(Debug, Clone)]
pub struct EnchantDict {
    /// Language tag (e.g., "en_US", "fr_FR")
    pub tag: String,
    /// Personal word list (user-added words)
    pub personal_words: HashSet<String>,
    /// Known word list (built-in dictionary words)
    pub word_list: HashSet<String>,
}

impl EnchantDict {
    /// Create a new dictionary for the given language tag.
    fn new(tag: &str) -> Self {
        let mut word_list = HashSet::new();
        // Add some common English words for the stub
        if tag.starts_with("en") {
            for word in &[
                "the",
                "be",
                "to",
                "of",
                "and",
                "a",
                "in",
                "that",
                "have",
                "it",
                "for",
                "not",
                "on",
                "with",
                "he",
                "as",
                "you",
                "do",
                "at",
                "this",
                "but",
                "his",
                "by",
                "from",
                "they",
                "we",
                "say",
                "her",
                "she",
                "or",
                "an",
                "will",
                "my",
                "one",
                "all",
                "would",
                "there",
                "their",
                "what",
                "so",
                "up",
                "out",
                "if",
                "about",
                "who",
                "get",
                "which",
                "go",
                "me",
                "when",
                "make",
                "can",
                "like",
                "time",
                "no",
                "just",
                "him",
                "know",
                "take",
                "people",
                "into",
                "year",
                "your",
                "good",
                "some",
                "could",
                "them",
                "see",
                "other",
                "than",
                "then",
                "now",
                "look",
                "only",
                "come",
                "its",
                "over",
                "think",
                "also",
                "back",
                "after",
                "use",
                "two",
                "how",
                "our",
                "work",
                "first",
                "well",
                "way",
                "even",
                "new",
                "want",
                "because",
                "any",
                "these",
                "give",
                "day",
                "most",
                "us",
                "hello",
                "world",
                "test",
                "word",
                "spell",
                "check",
                "correct",
                "dictionary",
            ] {
                word_list.insert(word.to_string());
            }
        }

        EnchantDict {
            tag: tag.to_string(),
            personal_words: HashSet::new(),
            word_list,
        }
    }
}

/// Enchant broker that manages dictionaries.
#[derive(Debug, Clone)]
pub struct EnchantBroker {
    /// Available dictionaries keyed by language tag
    pub dictionaries: HashMap<String, EnchantDict>,
    /// Supported language tags
    supported_tags: Vec<String>,
}

/// Initialize an enchant broker.
///
/// PHP signature: enchant_broker_init(): EnchantBroker|false
pub fn enchant_broker_init() -> EnchantBroker {
    let supported_tags = vec![
        "en_US".to_string(),
        "en_GB".to_string(),
        "fr_FR".to_string(),
        "de_DE".to_string(),
        "es_ES".to_string(),
    ];

    EnchantBroker {
        dictionaries: HashMap::new(),
        supported_tags,
    }
}

/// Free an enchant broker.
///
/// PHP signature: enchant_broker_free(EnchantBroker $broker): bool
pub fn enchant_broker_free(broker: &mut EnchantBroker) {
    broker.dictionaries.clear();
    broker.supported_tags.clear();
}

/// Request a dictionary for the given language tag.
///
/// PHP signature: enchant_broker_request_dict(EnchantBroker $broker, string $tag): EnchantDict|false
pub fn enchant_broker_request_dict<'a>(
    broker: &'a mut EnchantBroker,
    tag: &str,
) -> Result<&'a mut EnchantDict, EnchantError> {
    if !broker.supported_tags.iter().any(|t| t == tag) {
        return Err(EnchantError::DictNotAvailable(tag.to_string()));
    }

    if !broker.dictionaries.contains_key(tag) {
        broker
            .dictionaries
            .insert(tag.to_string(), EnchantDict::new(tag));
    }

    Ok(broker.dictionaries.get_mut(tag).unwrap())
}

/// Free a dictionary from the broker.
///
/// PHP signature: enchant_broker_free_dict(EnchantBroker $broker, EnchantDict $dict): bool
pub fn enchant_broker_free_dict(broker: &mut EnchantBroker, tag: &str) {
    broker.dictionaries.remove(tag);
}

/// Check if a dictionary exists for the given tag.
///
/// PHP signature: enchant_broker_dict_exists(EnchantBroker $broker, string $tag): bool
pub fn enchant_broker_dict_exists(broker: &EnchantBroker, tag: &str) -> bool {
    broker.supported_tags.iter().any(|t| t == tag)
}

/// List available dictionaries.
///
/// PHP signature: enchant_broker_list_dicts(EnchantBroker $broker): array
pub fn enchant_broker_list_dicts(broker: &EnchantBroker) -> Vec<String> {
    broker.supported_tags.clone()
}

/// Check if a word is correctly spelled.
///
/// PHP signature: enchant_dict_check(EnchantDict $dict, string $word): bool
pub fn enchant_dict_check(dict: &EnchantDict, word: &str) -> bool {
    if word.is_empty() {
        return true;
    }

    let lower = word.to_lowercase();

    // Check personal words first
    if dict.personal_words.contains(&lower) {
        return true;
    }

    // Check built-in word list
    if dict.word_list.contains(&lower) {
        return true;
    }

    // Stub: for non-English or unknown words, return true
    if !dict.tag.starts_with("en") {
        return true;
    }

    // If we have a word list and the word is not in it, return false
    if !dict.word_list.is_empty() {
        return false;
    }

    // Default: return true (stub behavior)
    true
}

/// Suggest corrections for a misspelled word.
///
/// PHP signature: enchant_dict_suggest(EnchantDict $dict, string $word): array
pub fn enchant_dict_suggest(dict: &EnchantDict, word: &str) -> Vec<String> {
    if word.is_empty() {
        return Vec::new();
    }

    let lower = word.to_lowercase();
    let mut suggestions = Vec::new();

    // Simple suggestion: find words in the dictionary that are close
    // (differ by one character, or have one character added/removed)
    for dict_word in &dict.word_list {
        let distance = levenshtein_distance(&lower, dict_word);
        if distance > 0 && distance <= 2 {
            suggestions.push(dict_word.clone());
        }
    }

    // Also check personal words
    for personal_word in &dict.personal_words {
        let distance = levenshtein_distance(&lower, personal_word);
        if distance > 0 && distance <= 2 {
            suggestions.push(personal_word.clone());
        }
    }

    suggestions.sort();
    suggestions
}

/// Simple Levenshtein distance calculation.
fn levenshtein_distance(a: &str, b: &str) -> usize {
    let a_chars: Vec<char> = a.chars().collect();
    let b_chars: Vec<char> = b.chars().collect();
    let a_len = a_chars.len();
    let b_len = b_chars.len();

    if a_len == 0 {
        return b_len;
    }
    if b_len == 0 {
        return a_len;
    }

    let mut matrix = vec![vec![0usize; b_len + 1]; a_len + 1];

    for (i, row) in matrix.iter_mut().enumerate().take(a_len + 1) {
        row[0] = i;
    }
    for (j, val) in matrix[0].iter_mut().enumerate().take(b_len + 1) {
        *val = j;
    }

    for i in 1..=a_len {
        for j in 1..=b_len {
            let cost = if a_chars[i - 1] == b_chars[j - 1] {
                0
            } else {
                1
            };
            matrix[i][j] = (matrix[i - 1][j] + 1)
                .min(matrix[i][j - 1] + 1)
                .min(matrix[i - 1][j - 1] + cost);
        }
    }

    matrix[a_len][b_len]
}

/// Add a word to the personal dictionary.
///
/// PHP signature: enchant_dict_add(EnchantDict $dict, string $word): void
pub fn enchant_dict_add(dict: &mut EnchantDict, word: &str) {
    dict.personal_words.insert(word.to_lowercase());
}

/// Check if a word was added to the personal dictionary.
///
/// PHP signature: enchant_dict_is_added(EnchantDict $dict, string $word): bool
pub fn enchant_dict_is_added(dict: &EnchantDict, word: &str) -> bool {
    dict.personal_words.contains(&word.to_lowercase())
}

/// Describe the providers available to the broker.
///
/// PHP signature: enchant_broker_describe(EnchantBroker $broker): array
pub fn enchant_broker_describe(_broker: &EnchantBroker) -> Vec<BrokerProvider> {
    vec![BrokerProvider {
        name: "php-rs-enchant".to_string(),
        desc: "PHP-RS built-in spell checker stub".to_string(),
        dll_path: String::new(),
    }]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_broker_init() {
        let broker = enchant_broker_init();
        assert!(broker.dictionaries.is_empty());
        assert!(!broker.supported_tags.is_empty());
    }

    #[test]
    fn test_broker_free() {
        let mut broker = enchant_broker_init();
        enchant_broker_request_dict(&mut broker, "en_US").unwrap();
        assert!(!broker.dictionaries.is_empty());

        enchant_broker_free(&mut broker);
        assert!(broker.dictionaries.is_empty());
    }

    #[test]
    fn test_broker_dict_exists() {
        let broker = enchant_broker_init();
        assert!(enchant_broker_dict_exists(&broker, "en_US"));
        assert!(enchant_broker_dict_exists(&broker, "fr_FR"));
        assert!(!enchant_broker_dict_exists(&broker, "zz_ZZ"));
    }

    #[test]
    fn test_broker_request_dict() {
        let mut broker = enchant_broker_init();
        let result = enchant_broker_request_dict(&mut broker, "en_US");
        assert!(result.is_ok());
        let dict = result.unwrap();
        assert_eq!(dict.tag, "en_US");
    }

    #[test]
    fn test_broker_request_dict_unavailable() {
        let mut broker = enchant_broker_init();
        let result = enchant_broker_request_dict(&mut broker, "xx_XX");
        assert!(result.is_err());
        assert!(matches!(result, Err(EnchantError::DictNotAvailable(_))));
    }

    #[test]
    fn test_broker_list_dicts() {
        let broker = enchant_broker_init();
        let dicts = enchant_broker_list_dicts(&broker);
        assert!(dicts.contains(&"en_US".to_string()));
        assert!(dicts.contains(&"fr_FR".to_string()));
    }

    #[test]
    fn test_dict_check_known_words() {
        let mut broker = enchant_broker_init();
        let dict = enchant_broker_request_dict(&mut broker, "en_US").unwrap();

        assert!(enchant_dict_check(dict, "hello"));
        assert!(enchant_dict_check(dict, "world"));
        assert!(enchant_dict_check(dict, "the"));
        assert!(!enchant_dict_check(dict, "xyzzy"));
        assert!(!enchant_dict_check(dict, "asdfgh"));
    }

    #[test]
    fn test_dict_check_empty() {
        let mut broker = enchant_broker_init();
        let dict = enchant_broker_request_dict(&mut broker, "en_US").unwrap();
        assert!(enchant_dict_check(dict, ""));
    }

    #[test]
    fn test_dict_add_and_check() {
        let mut broker = enchant_broker_init();
        let dict = enchant_broker_request_dict(&mut broker, "en_US").unwrap();

        assert!(!enchant_dict_check(dict, "foobar"));
        assert!(!enchant_dict_is_added(dict, "foobar"));

        enchant_dict_add(dict, "foobar");
        assert!(enchant_dict_check(dict, "foobar"));
        assert!(enchant_dict_is_added(dict, "foobar"));
    }

    #[test]
    fn test_dict_suggest() {
        let mut broker = enchant_broker_init();
        let dict = enchant_broker_request_dict(&mut broker, "en_US").unwrap();

        // "helo" is close to "hello"
        let suggestions = enchant_dict_suggest(dict, "helo");
        assert!(suggestions.contains(&"hello".to_string()));
    }

    #[test]
    fn test_dict_suggest_empty() {
        let mut broker = enchant_broker_init();
        let dict = enchant_broker_request_dict(&mut broker, "en_US").unwrap();
        let suggestions = enchant_dict_suggest(dict, "");
        assert!(suggestions.is_empty());
    }

    #[test]
    fn test_broker_free_dict() {
        let mut broker = enchant_broker_init();
        enchant_broker_request_dict(&mut broker, "en_US").unwrap();
        assert!(broker.dictionaries.contains_key("en_US"));

        enchant_broker_free_dict(&mut broker, "en_US");
        assert!(!broker.dictionaries.contains_key("en_US"));
    }

    #[test]
    fn test_broker_describe() {
        let broker = enchant_broker_init();
        let providers = enchant_broker_describe(&broker);
        assert_eq!(providers.len(), 1);
        assert_eq!(providers[0].name, "php-rs-enchant");
    }

    #[test]
    fn test_dict_case_insensitive() {
        let mut broker = enchant_broker_init();
        let dict = enchant_broker_request_dict(&mut broker, "en_US").unwrap();

        // Word list is lowercase, but check should be case-insensitive
        assert!(enchant_dict_check(dict, "Hello"));
        assert!(enchant_dict_check(dict, "THE"));

        enchant_dict_add(dict, "MyWord");
        assert!(enchant_dict_check(dict, "myword"));
        assert!(enchant_dict_is_added(dict, "MYWORD"));
    }

    #[test]
    fn test_levenshtein_distance() {
        assert_eq!(levenshtein_distance("kitten", "sitting"), 3);
        assert_eq!(levenshtein_distance("", "abc"), 3);
        assert_eq!(levenshtein_distance("abc", ""), 3);
        assert_eq!(levenshtein_distance("hello", "hello"), 0);
        assert_eq!(levenshtein_distance("hello", "helo"), 1);
    }
}
