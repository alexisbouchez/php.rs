/// 2-literal watching for efficient unit propagation.
///
/// Each clause watches two of its literals. When a watched literal becomes
/// false, we search for another non-false literal to watch. If we can't
/// find one, the remaining watched literal must be true (unit propagation).
#[derive(Debug)]
pub struct RuleWatchGraph {
    /// For each literal (mapped to index), the list of rule IDs watching it.
    /// Literal `l` maps to index: if l > 0, index = 2*l; if l < 0, index = 2*(-l)+1
    watches: Vec<Vec<usize>>,
}

impl RuleWatchGraph {
    pub fn new(max_id: usize) -> Self {
        // Need indices for both positive and negative literals
        let size = (max_id + 1) * 2 + 2;
        RuleWatchGraph {
            watches: vec![Vec::new(); size],
        }
    }

    fn literal_index(literal: i32) -> usize {
        if literal > 0 {
            (literal as usize) * 2
        } else {
            ((-literal) as usize) * 2 + 1
        }
    }

    /// Add a watch for a literal on a rule.
    pub fn watch(&mut self, literal: i32, rule_id: usize) {
        let idx = Self::literal_index(literal);
        if idx < self.watches.len() {
            self.watches[idx].push(rule_id);
        }
    }

    /// Get all rule IDs watching a literal.
    pub fn watchers(&self, literal: i32) -> &[usize] {
        let idx = Self::literal_index(literal);
        if idx < self.watches.len() {
            &self.watches[idx]
        } else {
            &[]
        }
    }

    /// Remove a rule from a literal's watch list.
    pub fn unwatch(&mut self, literal: i32, rule_id: usize) {
        let idx = Self::literal_index(literal);
        if idx < self.watches.len() {
            self.watches[idx].retain(|&id| id != rule_id);
        }
    }
}
