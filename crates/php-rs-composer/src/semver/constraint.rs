use std::fmt;

use super::version::Version;

/// Comparison operator for a version constraint.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ConstraintOp {
    Eq,
    Ne,
    Lt,
    Le,
    Gt,
    Ge,
}

impl ConstraintOp {
    pub fn as_str(&self) -> &'static str {
        match self {
            ConstraintOp::Eq => "==",
            ConstraintOp::Ne => "!=",
            ConstraintOp::Lt => "<",
            ConstraintOp::Le => "<=",
            ConstraintOp::Gt => ">",
            ConstraintOp::Ge => ">=",
        }
    }
}

impl fmt::Display for ConstraintOp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// A single version constraint: operator + version.
/// Examples: ">=1.0.0.0", "<2.0.0.0", "==1.5.0.0"
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Constraint {
    pub op: ConstraintOp,
    pub version: Version,
}

impl Constraint {
    pub fn new(op: ConstraintOp, version: Version) -> Self {
        Constraint { op, version }
    }

    /// Check if a candidate version satisfies this constraint.
    pub fn matches_version(&self, candidate: &Version) -> bool {
        let cmp = candidate.cmp(&self.version);
        match self.op {
            ConstraintOp::Eq => cmp == std::cmp::Ordering::Equal,
            ConstraintOp::Ne => cmp != std::cmp::Ordering::Equal,
            ConstraintOp::Lt => cmp == std::cmp::Ordering::Less,
            ConstraintOp::Le => cmp != std::cmp::Ordering::Greater,
            ConstraintOp::Gt => cmp == std::cmp::Ordering::Greater,
            ConstraintOp::Ge => cmp != std::cmp::Ordering::Less,
        }
    }
}

impl fmt::Display for Constraint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.op == ConstraintOp::Eq {
            write!(f, "{}", self.version)
        } else {
            write!(f, "{} {}", self.op, self.version)
        }
    }
}

/// How sub-constraints in a MultiConstraint are combined.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MultiConstraintMode {
    /// All sub-constraints must match (AND / conjunctive).
    And,
    /// At least one sub-constraint must match (OR / disjunctive).
    Or,
}

/// A composite constraint combining multiple sub-constraints.
///
/// AND: `>=1.0 <2.0` (conjunctive, all must match)
/// OR: `^1.0 || ^2.0` (disjunctive, any must match)
///
/// Can be nested: `(>=1.0 <2.0) || (>=3.0 <4.0)` is an OR of two ANDs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MultiConstraint {
    /// A single constraint (leaf node).
    Single(Constraint),
    /// A composite of multiple constraints.
    Multi {
        constraints: Vec<MultiConstraint>,
        mode: MultiConstraintMode,
    },
    /// Matches all versions (wildcard / no constraint).
    MatchAll,
}

impl MultiConstraint {
    /// Create an AND (conjunctive) multi-constraint.
    pub fn and(constraints: Vec<MultiConstraint>) -> Self {
        if constraints.len() == 1 {
            return constraints.into_iter().next().unwrap();
        }
        MultiConstraint::Multi {
            constraints,
            mode: MultiConstraintMode::And,
        }
    }

    /// Create an OR (disjunctive) multi-constraint.
    pub fn or(constraints: Vec<MultiConstraint>) -> Self {
        if constraints.len() == 1 {
            return constraints.into_iter().next().unwrap();
        }
        MultiConstraint::Multi {
            constraints,
            mode: MultiConstraintMode::Or,
        }
    }

    /// Create a single constraint wrapper.
    pub fn single(op: ConstraintOp, version: Version) -> Self {
        MultiConstraint::Single(Constraint::new(op, version))
    }

    /// Check if a candidate version satisfies this constraint tree.
    pub fn matches_version(&self, candidate: &Version) -> bool {
        match self {
            MultiConstraint::Single(c) => c.matches_version(candidate),
            MultiConstraint::Multi { constraints, mode } => match mode {
                MultiConstraintMode::And => {
                    constraints.iter().all(|c| c.matches_version(candidate))
                }
                MultiConstraintMode::Or => constraints.iter().any(|c| c.matches_version(candidate)),
            },
            MultiConstraint::MatchAll => true,
        }
    }
}

impl fmt::Display for MultiConstraint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            MultiConstraint::Single(c) => write!(f, "{}", c),
            MultiConstraint::Multi { constraints, mode } => {
                let sep = match mode {
                    MultiConstraintMode::And => " ",
                    MultiConstraintMode::Or => " || ",
                };
                let parts: Vec<String> = constraints.iter().map(|c| c.to_string()).collect();
                write!(f, "{}", parts.join(sep))
            }
            MultiConstraint::MatchAll => write!(f, "*"),
        }
    }
}
