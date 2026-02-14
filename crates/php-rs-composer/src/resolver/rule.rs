/// Type of solver rule.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuleType {
    /// Root package requires this package.
    RootRequire,
    /// Package dependency (A requires B).
    Package,
    /// Same-name conflict (only one version of a package can be installed).
    SameName,
    /// Explicit conflict between packages.
    Conflict,
    /// Learned conflict clause from CDCL.
    Learned,
}

/// A SAT solver clause.
///
/// Literals are signed integers: +id = install package, -id = skip package.
/// A clause is satisfied if at least one literal is true.
#[derive(Debug, Clone)]
pub struct Rule {
    /// Literals in this clause.
    pub literals: Vec<i32>,
    /// Type of rule (for error reporting).
    pub rule_type: RuleType,
    /// Human-readable reason for this rule.
    pub reason: String,
    /// Whether this rule is enabled (disabled rules are ignored).
    pub enabled: bool,
}

impl Rule {
    pub fn new(literals: Vec<i32>, rule_type: RuleType, reason: &str) -> Self {
        Rule {
            literals,
            rule_type,
            reason: reason.to_string(),
            enabled: true,
        }
    }

    /// A unit clause has exactly one literal.
    pub fn is_unit(&self) -> bool {
        self.literals.len() == 1
    }
}
