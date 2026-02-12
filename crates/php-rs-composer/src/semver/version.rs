use std::cmp::Ordering;
use std::fmt;

/// Stability levels, ordered from most stable to least stable.
/// Lower numeric value = more stable.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Stability {
    Stable = 0,
    RC = 5,
    Beta = 10,
    Alpha = 15,
    Dev = 20,
}

impl Stability {
    pub fn from_str(s: &str) -> Option<Stability> {
        match s.to_lowercase().as_str() {
            "stable" => Some(Stability::Stable),
            "rc" | "c" => Some(Stability::RC),
            "beta" | "b" => Some(Stability::Beta),
            "alpha" | "a" => Some(Stability::Alpha),
            "dev" => Some(Stability::Dev),
            "patch" | "pl" | "p" => Some(Stability::Stable),
            _ => None,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Stability::Stable => "stable",
            Stability::RC => "RC",
            Stability::Beta => "beta",
            Stability::Alpha => "alpha",
            Stability::Dev => "dev",
        }
    }
}

impl PartialOrd for Stability {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Stability {
    fn cmp(&self, other: &Self) -> Ordering {
        // Lower value = more stable = "greater" in version ordering
        // stable(0) > RC(5) > beta(10) > alpha(15) > dev(20)
        (*other as u8).cmp(&(*self as u8))
    }
}

impl fmt::Display for Stability {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// A parsed and normalized PHP Composer version.
///
/// Versions are normalized to 4-component form: MAJOR.MINOR.PATCH.BUILD
/// with optional stability suffix (e.g., -alpha1, -beta2, -RC3).
///
/// Dev branches are represented as `dev-{name}` with `is_dev_branch = true`.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Version {
    /// The 4 numeric components: [major, minor, patch, build]
    pub components: [u64; 4],
    /// Stability level
    pub stability: Stability,
    /// Stability version number (e.g., 3 for alpha3)
    pub stability_version: u64,
    /// Whether this is a dev branch version (e.g., dev-master)
    pub is_dev_branch: bool,
    /// Original branch name for dev branches
    pub branch_name: Option<String>,
    /// The original pretty-printed version string
    pub pretty: String,
    /// Normalized version string
    pub normalized: String,
}

impl Version {
    /// Create a new version from components.
    pub fn new(major: u64, minor: u64, patch: u64, build: u64) -> Self {
        let normalized = format!("{}.{}.{}.{}", major, minor, patch, build);
        Version {
            components: [major, minor, patch, build],
            stability: Stability::Stable,
            stability_version: 0,
            is_dev_branch: false,
            branch_name: None,
            pretty: normalized.clone(),
            normalized,
        }
    }

    /// Create a dev branch version.
    pub fn dev_branch(name: &str) -> Self {
        let normalized = format!("dev-{}", name);
        Version {
            components: [0, 0, 0, 0],
            stability: Stability::Dev,
            stability_version: 0,
            is_dev_branch: true,
            branch_name: Some(name.to_string()),
            pretty: normalized.clone(),
            normalized,
        }
    }

    pub fn major(&self) -> u64 {
        self.components[0]
    }

    pub fn minor(&self) -> u64 {
        self.components[1]
    }

    pub fn patch(&self) -> u64 {
        self.components[2]
    }

    pub fn build(&self) -> u64 {
        self.components[3]
    }
}

impl PartialOrd for Version {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Version {
    fn cmp(&self, other: &Self) -> Ordering {
        // Dev branches compare by name
        if self.is_dev_branch && other.is_dev_branch {
            return self.branch_name.cmp(&other.branch_name);
        }

        // Dev branches without numeric components are always less than numeric versions
        if self.is_dev_branch && self.components == [0, 0, 0, 0] {
            return Ordering::Less;
        }
        if other.is_dev_branch && other.components == [0, 0, 0, 0] {
            return Ordering::Greater;
        }

        // Compare numeric components
        for i in 0..4 {
            match self.components[i].cmp(&other.components[i]) {
                Ordering::Equal => continue,
                other => return other,
            }
        }

        // Same numeric components: compare stability
        match self.stability.cmp(&other.stability) {
            Ordering::Equal => {}
            other => return other,
        }

        // Same stability: compare stability version
        self.stability_version.cmp(&other.stability_version)
    }
}

impl fmt::Display for Version {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.normalized)
    }
}
