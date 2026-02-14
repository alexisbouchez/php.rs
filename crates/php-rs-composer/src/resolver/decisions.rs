use std::collections::HashMap;

/// Decision stack for SAT solver.
///
/// Tracks which packages are decided as installed (+) or skipped (-),
/// along with the decision level for backtracking.
#[derive(Debug)]
pub struct Decisions {
    /// Package ID → decision level (positive = install, negative = skip)
    decision_map: HashMap<usize, i32>,
    /// Ordered decision queue: (literal, level, rule_id)
    queue: Vec<(i32, usize, Option<usize>)>,
    /// Current decision level
    level: usize,
}

impl Decisions {
    pub fn new() -> Self {
        Decisions {
            decision_map: HashMap::new(),
            queue: Vec::new(),
            level: 0,
        }
    }

    /// Make a decision: positive literal = install, negative = skip.
    pub fn decide(&mut self, literal: i32, rule_id: Option<usize>) {
        let pkg_id = literal.unsigned_abs() as usize;
        // Store sign to indicate install (+) or skip (-).
        // Use level+1 so that level 0 still produces a nonzero value.
        let value = if literal > 0 { 1 } else { -1 } * (self.level as i32 + 1);
        self.decision_map.insert(pkg_id, value);
        self.queue.push((literal, self.level, rule_id));
    }

    /// Check if a package has been decided.
    pub fn is_decided(&self, pkg_id: usize) -> bool {
        self.decision_map.contains_key(&pkg_id)
    }

    /// Get the decision for a package: Some(true) = install, Some(false) = skip, None = undecided.
    pub fn get(&self, pkg_id: usize) -> Option<bool> {
        self.decision_map.get(&pkg_id).map(|&v| v > 0)
    }

    /// Check if a literal is satisfied by current decisions.
    pub fn is_satisfied(&self, literal: i32) -> bool {
        let pkg_id = literal.unsigned_abs() as usize;
        match self.decision_map.get(&pkg_id) {
            Some(&v) if literal > 0 => v > 0,
            Some(&v) if literal < 0 => v < 0,
            _ => false,
        }
    }

    /// Check if a literal conflicts with current decisions.
    pub fn is_conflict(&self, literal: i32) -> bool {
        let pkg_id = literal.unsigned_abs() as usize;
        match self.decision_map.get(&pkg_id) {
            Some(&v) if literal > 0 => v < 0,
            Some(&v) if literal < 0 => v > 0,
            _ => false,
        }
    }

    /// Increment decision level (start a new branch).
    pub fn increment_level(&mut self) {
        self.level += 1;
    }

    /// Get current decision level.
    pub fn level(&self) -> usize {
        self.level
    }

    /// Revert all decisions at levels > target_level.
    pub fn revert_to_level(&mut self, target_level: usize) {
        while let Some(&(literal, level, _)) = self.queue.last() {
            if level <= target_level {
                break;
            }
            let pkg_id = literal.unsigned_abs() as usize;
            self.decision_map.remove(&pkg_id);
            self.queue.pop();
        }
        self.level = target_level;
    }

    /// Get all positive decisions (installed packages).
    pub fn installed(&self) -> Vec<usize> {
        self.decision_map
            .iter()
            .filter(|(_, &v)| v > 0)
            .map(|(&id, _)| id)
            .collect()
    }

    /// Get the decision queue.
    pub fn queue(&self) -> &[(i32, usize, Option<usize>)] {
        &self.queue
    }

    /// Get the decision level for a package.
    pub fn decision_level(&self, pkg_id: usize) -> Option<usize> {
        // Find the queue entry for this package
        for &(literal, level, _) in &self.queue {
            if literal.unsigned_abs() as usize == pkg_id {
                return Some(level);
            }
        }
        None
    }
}

impl Default for Decisions {
    fn default() -> Self {
        Self::new()
    }
}
