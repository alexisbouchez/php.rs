use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

/// A Composer package with all metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Package {
    pub name: String,
    #[serde(default)]
    pub version: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub version_normalized: String,
    #[serde(rename = "type", default = "default_package_type")]
    pub package_type: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub require: BTreeMap<String, String>,
    #[serde(
        default,
        rename = "require-dev",
        skip_serializing_if = "BTreeMap::is_empty"
    )]
    pub require_dev: BTreeMap<String, String>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub conflict: BTreeMap<String, String>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub replace: BTreeMap<String, String>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub provide: BTreeMap<String, String>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub suggest: BTreeMap<String, String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub autoload: Option<Autoload>,
    #[serde(
        default,
        rename = "autoload-dev",
        skip_serializing_if = "Option::is_none"
    )]
    pub autoload_dev: Option<Autoload>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<SourceInfo>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dist: Option<DistInfo>,
    #[serde(
        default,
        skip_serializing_if = "Vec::is_empty",
        deserialize_with = "string_or_vec"
    )]
    pub license: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub homepage: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub keywords: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub authors: Vec<Author>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub extra: Option<serde_json::Value>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub bin: Vec<String>,
    #[serde(
        default,
        rename = "minimum-stability",
        skip_serializing_if = "Option::is_none"
    )]
    pub minimum_stability: Option<String>,
    #[serde(
        default,
        rename = "prefer-stable",
        skip_serializing_if = "Option::is_none"
    )]
    pub prefer_stable: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub repositories: Option<serde_json::Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub config: Option<serde_json::Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scripts: Option<serde_json::Value>,
    #[serde(
        default,
        rename = "default-branch",
        skip_serializing_if = "Option::is_none"
    )]
    pub default_branch: Option<bool>,
    /// Notification URL for Packagist stats
    #[serde(
        default,
        rename = "notification-url",
        skip_serializing_if = "Option::is_none"
    )]
    pub notification_url: Option<String>,
}

fn default_package_type() -> String {
    "library".to_string()
}

/// Deserialize a field that can be either a string or an array of strings.
fn string_or_vec<'de, D>(deserializer: D) -> Result<Vec<String>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    use serde::de;

    struct StringOrVec;

    impl<'de> de::Visitor<'de> for StringOrVec {
        type Value = Vec<String>;

        fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
            f.write_str("string or array of strings")
        }

        fn visit_str<E: de::Error>(self, v: &str) -> Result<Vec<String>, E> {
            Ok(vec![v.to_string()])
        }

        fn visit_seq<A: de::SeqAccess<'de>>(self, mut seq: A) -> Result<Vec<String>, A::Error> {
            let mut v = Vec::new();
            while let Some(s) = seq.next_element()? {
                v.push(s);
            }
            Ok(v)
        }
    }

    deserializer.deserialize_any(StringOrVec)
}

impl Package {
    pub fn new(name: &str, version: &str) -> Self {
        Package {
            name: name.to_string(),
            version: version.to_string(),
            version_normalized: String::new(),
            package_type: "library".to_string(),
            description: None,
            require: BTreeMap::new(),
            require_dev: BTreeMap::new(),
            conflict: BTreeMap::new(),
            replace: BTreeMap::new(),
            provide: BTreeMap::new(),
            suggest: BTreeMap::new(),
            autoload: None,
            autoload_dev: None,
            source: None,
            dist: None,
            license: Vec::new(),
            homepage: None,
            keywords: Vec::new(),
            authors: Vec::new(),
            extra: None,
            bin: Vec::new(),
            minimum_stability: None,
            prefer_stable: None,
            repositories: None,
            config: None,
            scripts: None,
            default_branch: None,
            notification_url: None,
        }
    }

    /// Return the vendor/package name parts.
    pub fn vendor(&self) -> Option<&str> {
        self.name.split('/').next()
    }

    pub fn short_name(&self) -> Option<&str> {
        self.name.split('/').nth(1)
    }
}

/// Autoload configuration.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Autoload {
    #[serde(default, rename = "psr-4", skip_serializing_if = "BTreeMap::is_empty")]
    pub psr4: BTreeMap<String, AutoloadPath>,
    #[serde(default, rename = "psr-0", skip_serializing_if = "BTreeMap::is_empty")]
    pub psr0: BTreeMap<String, AutoloadPath>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub classmap: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub files: Vec<String>,
    #[serde(
        default,
        rename = "exclude-from-classmap",
        skip_serializing_if = "Vec::is_empty"
    )]
    pub exclude_from_classmap: Vec<String>,
}

/// An autoload path can be a single string or an array of strings.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum AutoloadPath {
    Single(String),
    Multiple(Vec<String>),
}

impl AutoloadPath {
    pub fn paths(&self) -> Vec<&str> {
        match self {
            AutoloadPath::Single(s) => vec![s.as_str()],
            AutoloadPath::Multiple(v) => v.iter().map(|s| s.as_str()).collect(),
        }
    }
}

/// Source (VCS) info for a package.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SourceInfo {
    #[serde(rename = "type")]
    pub source_type: String,
    pub url: String,
    pub reference: String,
}

/// Distribution (archive) info for a package.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DistInfo {
    #[serde(rename = "type")]
    pub dist_type: String,
    pub url: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reference: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub shasum: Option<String>,
}

/// Package author info.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Author {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub homepage: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub role: Option<String>,
}
