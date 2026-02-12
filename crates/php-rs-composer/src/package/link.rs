use crate::semver::MultiConstraint;

/// The type of dependency link.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum LinkType {
    Require,
    RequireDev,
    Conflict,
    Replace,
    Provide,
}

impl LinkType {
    pub fn as_str(&self) -> &'static str {
        match self {
            LinkType::Require => "require",
            LinkType::RequireDev => "require-dev",
            LinkType::Conflict => "conflict",
            LinkType::Replace => "replace",
            LinkType::Provide => "provide",
        }
    }
}

/// A dependency link between packages.
///
/// Represents a relationship like "package A requires package B ^1.0".
#[derive(Debug, Clone)]
pub struct Link {
    /// Source package name (the one declaring the dependency).
    pub source: String,
    /// Target package name (the one being depended on).
    pub target: String,
    /// Version constraint for the target.
    pub constraint: MultiConstraint,
    /// Original constraint string (for display).
    pub pretty_constraint: String,
    /// Type of link.
    pub link_type: LinkType,
}

impl Link {
    pub fn new(
        source: &str,
        target: &str,
        constraint: MultiConstraint,
        pretty_constraint: &str,
        link_type: LinkType,
    ) -> Self {
        Link {
            source: source.to_string(),
            target: target.to_string(),
            constraint,
            pretty_constraint: pretty_constraint.to_string(),
            link_type,
        }
    }
}
