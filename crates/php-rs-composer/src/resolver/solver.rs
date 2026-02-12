use std::collections::HashSet;

use super::decisions::Decisions;
use super::policy::DefaultPolicy;
use super::pool::Pool;
use super::problem::Problem;
use super::rule::{Rule, RuleType};
use super::rule_set::RuleSet;
use super::rule_watch_graph::RuleWatchGraph;
use super::transaction::{Operation, Transaction};
use crate::package::Package;
use crate::semver::VersionParser;

/// DPLL/CDCL SAT solver for dependency resolution.
pub struct Solver {
    pool: Pool,
    rules: RuleSet,
    watch_graph: RuleWatchGraph,
    decisions: Decisions,
    policy: DefaultPolicy,
    problems: Vec<Problem>,
    /// Previously locked package versions (from composer.lock).
    locked: Vec<(String, String)>,
    /// Track which packages already have dependency rules generated.
    rules_generated_for: HashSet<usize>,
    /// Track which same-name rule pairs have been generated.
    same_name_generated: HashSet<String>,
    /// Index in the decision queue up to which propagation has been done.
    propagate_index: usize,
}

impl Solver {
    pub fn new(pool: Pool, policy: DefaultPolicy) -> Self {
        let max_id = pool.len();
        Solver {
            pool,
            rules: RuleSet::new(),
            watch_graph: RuleWatchGraph::new(max_id),
            decisions: Decisions::new(),
            policy,
            problems: Vec::new(),
            locked: Vec::new(),
            rules_generated_for: HashSet::new(),
            same_name_generated: HashSet::new(),
            propagate_index: 0,
        }
    }

    /// Set previously locked package versions.
    /// The solver will prefer these versions when resolving.
    pub fn set_locked_packages(&mut self, locked: Vec<(String, String)>) {
        self.locked = locked;
    }

    /// Add root requirements and generate rules.
    pub fn add_root_requirements(&mut self, requires: &[(String, String)]) {
        for (name, constraint_str) in requires {
            let constraint = VersionParser::parse_constraints(constraint_str).ok();
            let mut matching = self.pool.what_provides(name, constraint.as_ref());

            if matching.is_empty() {
                let mut problem = Problem::new();
                problem.add_reason(
                    Rule::new(
                        vec![],
                        RuleType::RootRequire,
                        &format!("Root requires {} {}", name, constraint_str),
                    ),
                    format!(
                        "Root composer.json requires {} {}, but no matching package was found.",
                        name, constraint_str
                    ),
                );
                self.problems.push(problem);
                continue;
            }

            // Sort by policy preference (prefer locked, then stable, then latest)
            self.sort_by_preference(name, &mut matching);

            // Root require rule: at least one of the matching versions must be installed
            let literals: Vec<i32> = matching.iter().map(|&id| id as i32).collect();
            let rule = Rule::new(
                literals.clone(),
                RuleType::RootRequire,
                &format!("Root requires {} {}", name, constraint_str),
            );
            let rule_id = self.rules.add(rule);

            // Set up watches
            if literals.len() >= 2 {
                self.watch_graph.watch(literals[0], rule_id);
                self.watch_graph.watch(literals[1], rule_id);
            } else if literals.len() == 1 {
                self.watch_graph.watch(literals[0], rule_id);
            }

            // Generate same-name conflict rules (only one version per package)
            self.add_same_name_rules(name, &matching);

            // Generate dependency rules for each candidate (recursively)
            for &pkg_id in &matching {
                self.add_dependency_rules(pkg_id);
            }
        }
    }

    /// Sort package IDs by preference: locked version first, then policy order.
    fn sort_by_preference(&self, name: &str, ids: &mut [usize]) {
        let locked_version = self
            .locked
            .iter()
            .find(|(n, _)| n == name)
            .map(|(_, v)| v.clone());

        // Sort: locked version first, then by policy
        self.policy.sort_by_preference(&self.pool, ids);

        if let Some(locked_ver) = locked_version {
            ids.sort_by(|&a, &b| {
                let a_locked = self
                    .pool
                    .package(a)
                    .map_or(false, |p| p.version == locked_ver);
                let b_locked = self
                    .pool
                    .package(b)
                    .map_or(false, |p| p.version == locked_ver);
                b_locked.cmp(&a_locked) // true (locked) sorts first
            });
        }
    }

    /// Add rules ensuring only one version of a package is installed.
    fn add_same_name_rules(&mut self, name: &str, ids: &[usize]) {
        for i in 0..ids.len() {
            for j in (i + 1)..ids.len() {
                // Deduplicate same-name rules
                let key = format!("{}:{}", ids[i], ids[j]);
                if self.same_name_generated.contains(&key) {
                    continue;
                }
                self.same_name_generated.insert(key);

                let rule = Rule::new(
                    vec![-(ids[i] as i32), -(ids[j] as i32)],
                    RuleType::SameName,
                    &format!("Only one version of {} can be installed", name),
                );
                let rule_id = self.rules.add(rule);
                self.watch_graph.watch(-(ids[i] as i32), rule_id);
                self.watch_graph.watch(-(ids[j] as i32), rule_id);
            }
        }
    }

    /// Add dependency rules for a package, recursively for all transitive deps.
    fn add_dependency_rules(&mut self, pkg_id: usize) {
        if self.rules_generated_for.contains(&pkg_id) {
            return;
        }
        self.rules_generated_for.insert(pkg_id);

        let pkg = match self.pool.package(pkg_id) {
            Some(p) => p.clone(),
            None => return,
        };

        // Collect transitive dependency package IDs to recurse into
        let mut recurse_into: Vec<usize> = Vec::new();

        for (dep_name, dep_constraint_str) in &pkg.require {
            // Skip platform requirements (php, ext-*)
            if dep_name.starts_with("ext-")
                || dep_name == "php"
                || dep_name == "php-64bit"
                || dep_name == "composer-plugin-api"
                || dep_name == "composer-runtime-api"
            {
                continue;
            }

            let constraint = VersionParser::parse_constraints(dep_constraint_str).ok();
            let providers = self.pool.what_provides(dep_name, constraint.as_ref());

            if providers.is_empty() {
                continue;
            }

            // If pkg_id is installed, at least one provider must be installed
            // Rule: -pkg_id OR provider1 OR provider2 OR ...
            let mut literals: Vec<i32> = vec![-(pkg_id as i32)];
            literals.extend(providers.iter().map(|&id| id as i32));

            let rule = Rule::new(
                literals.clone(),
                RuleType::Package,
                &format!(
                    "{} {} requires {} {}",
                    pkg.name, pkg.version, dep_name, dep_constraint_str
                ),
            );
            let rule_id = self.rules.add(rule);

            if literals.len() >= 2 {
                self.watch_graph.watch(literals[0], rule_id);
                self.watch_graph.watch(literals[1], rule_id);
            }

            // Same-name rules for the dependency
            self.add_same_name_rules(dep_name, &providers);

            // Schedule recursive rule generation for providers
            recurse_into.extend_from_slice(&providers);
        }

        // Add conflict rules
        for (conflict_name, conflict_constraint_str) in &pkg.conflict {
            let constraint = VersionParser::parse_constraints(conflict_constraint_str).ok();
            let conflicting = self.pool.what_provides(conflict_name, constraint.as_ref());

            for &conflict_id in &conflicting {
                let rule = Rule::new(
                    vec![-(pkg_id as i32), -(conflict_id as i32)],
                    RuleType::Conflict,
                    &format!(
                        "{} {} conflicts with {} {}",
                        pkg.name, pkg.version, conflict_name, conflict_constraint_str
                    ),
                );
                let rule_id = self.rules.add(rule);
                self.watch_graph.watch(-(pkg_id as i32), rule_id);
                self.watch_graph.watch(-(conflict_id as i32), rule_id);
            }
        }

        // Recurse into transitive dependencies
        for dep_id in recurse_into {
            self.add_dependency_rules(dep_id);
        }
    }

    /// Run the solver. Returns Ok(Transaction) or Err with problems.
    pub fn solve(&mut self) -> Result<Transaction, Vec<Problem>> {
        self.solve_with_locked(None)
    }

    /// Run the solver with optional previously-installed packages for update detection.
    pub fn solve_with_locked(
        &mut self,
        previously_installed: Option<&[Package]>,
    ) -> Result<Transaction, Vec<Problem>> {
        if !self.problems.is_empty() {
            return Err(std::mem::take(&mut self.problems));
        }

        // Unit propagation for initial assertions
        if let Err(conflict_rule_id) = self.propagate() {
            let mut problem = Problem::new();
            if let Some(rule) = self.rules.get(conflict_rule_id) {
                problem.add_reason(rule.clone(), rule.reason.clone());
            }
            return Err(vec![problem]);
        }

        // Main DPLL loop with CDCL
        let mut iteration_limit = self.pool.len() * self.pool.len() + 100;
        loop {
            iteration_limit -= 1;
            if iteration_limit == 0 {
                let mut problem = Problem::new();
                problem.add_reason(
                    Rule::new(vec![], RuleType::Learned, "Solver iteration limit reached"),
                    "Could not resolve dependencies: solver iteration limit reached.".to_string(),
                );
                return Err(vec![problem]);
            }

            match self.find_undecided() {
                Some(pkg_id) => {
                    self.decisions.increment_level();
                    self.decisions.decide(pkg_id as i32, None);

                    if let Err(conflict_rule_id) = self.propagate() {
                        // Try to resolve by negating the decision
                        if !self.resolve_conflict(pkg_id, conflict_rule_id)? {
                            return Err(self.build_conflict_problems(conflict_rule_id));
                        }
                    }
                }
                None => break,
            }
        }

        // Build transaction from decisions
        let installed = self.decisions.installed();
        let mut operations = Vec::new();

        for id in installed {
            if let Some(pkg) = self.pool.package(id) {
                // Check if this is an update from a previously installed version
                if let Some(prev) = previously_installed {
                    if let Some(old) = prev.iter().find(|p| p.name == pkg.name) {
                        if old.version != pkg.version {
                            operations.push(Operation::Update {
                                from: old.clone(),
                                to: pkg.clone(),
                            });
                            continue;
                        }
                    }
                }
                operations.push(Operation::Install(pkg.clone()));
            }
        }

        // Sort by name for deterministic output
        operations.sort_by(|a, b| a.package().name.cmp(&b.package().name));

        Ok(Transaction::new(operations))
    }

    /// Resolve a conflict by backtracking. Returns Ok(true) if resolved, Ok(false) if unresolvable.
    fn resolve_conflict(
        &mut self,
        pkg_id: usize,
        _conflict_rule_id: usize,
    ) -> Result<bool, Vec<Problem>> {
        let current_level = self.decisions.level();

        if current_level == 0 {
            return Ok(false);
        }

        // Revert the decision that caused the conflict
        self.decisions.revert_to_level(current_level - 1);
        self.propagate_index = self.decisions.queue().len();

        // Try the opposite: skip this package instead of installing it
        self.decisions.decide(-(pkg_id as i32), None);

        match self.propagate() {
            Ok(()) => Ok(true),
            Err(_new_conflict) => {
                // The negation also fails. Backtrack further if possible.
                if current_level <= 1 {
                    return Ok(false);
                }
                self.decisions.revert_to_level(current_level - 2);
                self.propagate_index = self.decisions.queue().len();

                match self.propagate() {
                    Ok(()) => Ok(true),
                    Err(_) => Ok(false),
                }
            }
        }
    }

    /// Build problem descriptions from a conflict.
    fn build_conflict_problems(&self, conflict_rule_id: usize) -> Vec<Problem> {
        let mut problem = Problem::new();
        if let Some(rule) = self.rules.get(conflict_rule_id) {
            problem.add_reason(rule.clone(), rule.reason.clone());
        }
        // Add context from related rules
        for (_, rule) in self.rules.by_type(RuleType::RootRequire) {
            let all_false = rule
                .literals
                .iter()
                .all(|&lit| self.decisions.is_conflict(lit));
            if all_false {
                problem.add_reason(rule.clone(), rule.reason.clone());
            }
        }
        vec![problem]
    }

    /// Unit propagation using the watch graph.
    /// Only processes decisions added since last propagation call.
    fn propagate(&mut self) -> Result<(), usize> {
        loop {
            let queue_len = self.decisions.queue().len();
            if self.propagate_index >= queue_len {
                break;
            }

            let decided_literal = self.decisions.queue()[self.propagate_index].0;
            self.propagate_index += 1;

            // When a literal is decided, check rules watching its negation
            let neg = -decided_literal;
            let watchers: Vec<usize> = self.watch_graph.watchers(neg).to_vec();

            for rule_id in watchers {
                let rule = match self.rules.get(rule_id) {
                    Some(r) if r.enabled => r.clone(),
                    _ => continue,
                };

                let mut undecided_literal = None;
                let mut satisfied = false;
                let mut num_false = 0;

                for &lit in &rule.literals {
                    if self.decisions.is_satisfied(lit) {
                        satisfied = true;
                        break;
                    }
                    if self.decisions.is_conflict(lit) {
                        num_false += 1;
                    } else if !self.decisions.is_decided(lit.unsigned_abs() as usize) {
                        undecided_literal = Some(lit);
                    }
                }

                if satisfied {
                    continue;
                }

                if num_false == rule.literals.len() {
                    return Err(rule_id);
                }

                if let Some(unit_lit) = undecided_literal {
                    if num_false == rule.literals.len() - 1 {
                        self.decisions.decide(unit_lit, Some(rule_id));
                    }
                }
            }
        }

        Ok(())
    }

    /// Find an undecided package to branch on.
    fn find_undecided(&self) -> Option<usize> {
        for (_, rule) in self.rules.by_type(RuleType::RootRequire) {
            for &lit in &rule.literals {
                let pkg_id = lit.unsigned_abs() as usize;
                if !self.decisions.is_decided(pkg_id) {
                    return Some(pkg_id);
                }
            }
        }

        for (_, rule) in self.rules.by_type(RuleType::Package) {
            for &lit in &rule.literals {
                let pkg_id = lit.unsigned_abs() as usize;
                if !self.decisions.is_decided(pkg_id) {
                    return Some(pkg_id);
                }
            }
        }

        None
    }

    /// Get the problems (if any).
    pub fn problems(&self) -> &[Problem] {
        &self.problems
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::resolver::PoolBuilder;

    fn make_package(name: &str, version: &str, requires: &[(&str, &str)]) -> Package {
        let mut pkg = Package::new(name, version);
        for (dep_name, dep_constraint) in requires {
            pkg.require
                .insert(dep_name.to_string(), dep_constraint.to_string());
        }
        pkg
    }

    fn make_conflicting_package(
        name: &str,
        version: &str,
        requires: &[(&str, &str)],
        conflicts: &[(&str, &str)],
    ) -> Package {
        let mut pkg = make_package(name, version, requires);
        for (c_name, c_constraint) in conflicts {
            pkg.conflict
                .insert(c_name.to_string(), c_constraint.to_string());
        }
        pkg
    }

    #[test]
    fn test_simple_install() {
        let packages = vec![make_package("vendor/a", "1.0.0", &[])];
        let pool = PoolBuilder::build_from_packages(packages);
        let mut solver = Solver::new(pool, DefaultPolicy::default());
        solver.add_root_requirements(&[("vendor/a".to_string(), "^1.0".to_string())]);

        let result = solver.solve();
        assert!(result.is_ok(), "Solver should succeed");
        let tx = result.unwrap();
        assert_eq!(tx.operations.len(), 1);
        assert_eq!(tx.operations[0].package().name, "vendor/a");
    }

    #[test]
    fn test_transitive_dependency() {
        let packages = vec![
            make_package("vendor/a", "1.0.0", &[("vendor/b", "^2.0")]),
            make_package("vendor/b", "2.1.0", &[]),
        ];
        let pool = PoolBuilder::build_from_packages(packages);
        let mut solver = Solver::new(pool, DefaultPolicy::default());
        solver.add_root_requirements(&[("vendor/a".to_string(), "^1.0".to_string())]);

        let result = solver.solve();
        assert!(result.is_ok(), "Solver should succeed");
        let tx = result.unwrap();
        assert_eq!(tx.operations.len(), 2);
        let names: Vec<&str> = tx
            .operations
            .iter()
            .map(|op| op.package().name.as_str())
            .collect();
        assert!(names.contains(&"vendor/a"));
        assert!(names.contains(&"vendor/b"));
    }

    #[test]
    fn test_version_selection() {
        let packages = vec![
            make_package("vendor/a", "1.0.0", &[]),
            make_package("vendor/a", "1.1.0", &[]),
            make_package("vendor/a", "1.2.0", &[]),
        ];
        let pool = PoolBuilder::build_from_packages(packages);
        let mut solver = Solver::new(pool, DefaultPolicy::default());
        solver.add_root_requirements(&[("vendor/a".to_string(), "^1.0".to_string())]);

        let result = solver.solve();
        assert!(result.is_ok());
        let tx = result.unwrap();
        assert_eq!(tx.operations.len(), 1);
    }

    #[test]
    fn test_no_matching_package() {
        let packages = vec![make_package("vendor/a", "2.0.0", &[])];
        let pool = PoolBuilder::build_from_packages(packages);
        let mut solver = Solver::new(pool, DefaultPolicy::default());
        solver.add_root_requirements(&[("vendor/b".to_string(), "^1.0".to_string())]);

        let result = solver.solve();
        assert!(result.is_err(), "Should fail for missing package");
    }

    #[test]
    fn test_conflict_detection() {
        let packages = vec![
            make_conflicting_package("vendor/a", "1.0.0", &[], &[("vendor/b", ">=1.0")]),
            make_package("vendor/b", "1.0.0", &[]),
        ];
        let pool = PoolBuilder::build_from_packages(packages);
        let mut solver = Solver::new(pool, DefaultPolicy::default());
        solver.add_root_requirements(&[
            ("vendor/a".to_string(), "^1.0".to_string()),
            ("vendor/b".to_string(), "^1.0".to_string()),
        ]);

        let result = solver.solve();
        assert!(result.is_err(), "Should detect conflict");
    }

    #[test]
    fn test_diamond_dependency() {
        // A→B^1.0, A→C^1.0, B→D^1.0, C→D^1.0
        let packages = vec![
            make_package(
                "vendor/a",
                "1.0.0",
                &[("vendor/b", "^1.0"), ("vendor/c", "^1.0")],
            ),
            make_package("vendor/b", "1.0.0", &[("vendor/d", "^1.0")]),
            make_package("vendor/c", "1.0.0", &[("vendor/d", "^1.0")]),
            make_package("vendor/d", "1.0.0", &[]),
            make_package("vendor/d", "1.1.0", &[]),
        ];
        let pool = PoolBuilder::build_from_packages(packages);
        let mut solver = Solver::new(pool, DefaultPolicy::default());
        solver.add_root_requirements(&[("vendor/a".to_string(), "^1.0".to_string())]);

        let result = solver.solve();
        assert!(result.is_ok(), "Diamond deps should resolve");
        let tx = result.unwrap();
        let names: Vec<&str> = tx
            .operations
            .iter()
            .map(|op| op.package().name.as_str())
            .collect();
        assert!(names.contains(&"vendor/a"));
        assert!(names.contains(&"vendor/b"));
        assert!(names.contains(&"vendor/c"));
        assert!(names.contains(&"vendor/d"));
        // Should only have one version of D
        assert_eq!(names.iter().filter(|&&n| n == "vendor/d").count(), 1);
    }

    #[test]
    fn test_locked_package_preference() {
        let packages = vec![
            make_package("vendor/a", "1.0.0", &[]),
            make_package("vendor/a", "1.1.0", &[]),
            make_package("vendor/a", "1.2.0", &[]),
        ];
        let pool = PoolBuilder::build_from_packages(packages);
        let mut solver = Solver::new(pool, DefaultPolicy::default());
        solver.set_locked_packages(vec![("vendor/a".to_string(), "1.1.0".to_string())]);
        solver.add_root_requirements(&[("vendor/a".to_string(), "^1.0".to_string())]);

        let result = solver.solve();
        assert!(result.is_ok());
        let tx = result.unwrap();
        assert_eq!(tx.operations.len(), 1);
        assert_eq!(tx.operations[0].package().version, "1.1.0");
    }

    #[test]
    fn test_update_detection() {
        let packages = vec![make_package("vendor/a", "1.1.0", &[])];
        let pool = PoolBuilder::build_from_packages(packages);
        let mut solver = Solver::new(pool, DefaultPolicy::default());
        solver.add_root_requirements(&[("vendor/a".to_string(), "^1.0".to_string())]);

        let old = Package::new("vendor/a", "1.0.0");
        let result = solver.solve_with_locked(Some(&[old]));
        assert!(result.is_ok());
        let tx = result.unwrap();
        assert_eq!(tx.operations.len(), 1);
        match &tx.operations[0] {
            Operation::Update { from, to } => {
                assert_eq!(from.version, "1.0.0");
                assert_eq!(to.version, "1.1.0");
            }
            _ => panic!("Expected Update operation"),
        }
    }
}
