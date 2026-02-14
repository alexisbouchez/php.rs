use super::rule::Rule;

/// A dependency resolution problem (unsatisfiable constraint set).
#[derive(Debug)]
pub struct Problem {
    pub reasons: Vec<ProblemReason>,
}

/// A single reason contributing to a resolution problem.
#[derive(Debug)]
pub struct ProblemReason {
    pub rule: Rule,
    pub message: String,
}

impl Problem {
    pub fn new() -> Self {
        Problem {
            reasons: Vec::new(),
        }
    }

    pub fn add_reason(&mut self, rule: Rule, message: String) {
        self.reasons.push(ProblemReason { rule, message });
    }

    /// Generate a human-readable problem description.
    pub fn to_string_pretty(&self) -> String {
        let mut lines = Vec::new();
        lines.push("Problem:".to_string());
        for (i, reason) in self.reasons.iter().enumerate() {
            lines.push(format!("  {}. {}", i + 1, reason.message));
        }
        lines.join("\n")
    }
}

impl Default for Problem {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Display for Problem {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.to_string_pretty())
    }
}
