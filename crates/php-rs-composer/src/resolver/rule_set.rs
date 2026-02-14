use super::rule::{Rule, RuleType};

/// Collection of solver rules grouped by type.
#[derive(Debug, Default)]
pub struct RuleSet {
    pub rules: Vec<Rule>,
}

impl RuleSet {
    pub fn new() -> Self {
        RuleSet { rules: Vec::new() }
    }

    pub fn add(&mut self, rule: Rule) -> usize {
        let id = self.rules.len();
        self.rules.push(rule);
        id
    }

    pub fn get(&self, id: usize) -> Option<&Rule> {
        self.rules.get(id)
    }

    pub fn len(&self) -> usize {
        self.rules.len()
    }

    pub fn is_empty(&self) -> bool {
        self.rules.is_empty()
    }

    /// Get all rules of a specific type.
    pub fn by_type(&self, rule_type: RuleType) -> impl Iterator<Item = (usize, &Rule)> {
        self.rules
            .iter()
            .enumerate()
            .filter(move |(_, r)| r.rule_type == rule_type && r.enabled)
    }
}
