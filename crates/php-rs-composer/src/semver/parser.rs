use regex::Regex;

use super::constraint::{ConstraintOp, MultiConstraint};
use super::version::{Stability, Version};

/// Parser for Composer-compatible version strings and constraints.
pub struct VersionParser;

impl VersionParser {
    /// Normalize a version string to canonical form.
    ///
    /// Examples:
    /// - "v1.2.3" → "1.2.3.0"
    /// - "1.2" → "1.2.0.0"
    /// - "1.2.3.4" → "1.2.3.4"
    /// - "1.0-alpha1" → "1.0.0.0-alpha1"
    /// - "dev-master" → "dev-master"
    /// - "1.0.x-dev" → "1.0.9999999.9999999-dev"
    pub fn normalize(version: &str) -> Result<Version, String> {
        let version = version.trim();

        // Strip leading 'v' or 'V'
        let version = if version.starts_with('v') || version.starts_with('V') {
            &version[1..]
        } else {
            version
        };

        // Handle dev-{branch} format
        if let Some(branch) = version.strip_prefix("dev-") {
            return Ok(Version::dev_branch(branch));
        }

        // Handle {branch}-dev format (e.g., "master-dev")
        if let Some(branch) = version.strip_suffix("-dev") {
            if !branch.contains('.') || Self::is_x_range(branch) {
                // If it looks like "1.0.x-dev", handle as x-range dev
                if Self::is_x_range(branch) {
                    return Self::parse_x_range_dev(branch);
                }
                return Ok(Version::dev_branch(branch));
            }
        }

        // Handle "x-dev" suffix for numeric ranges like "1.2.x-dev"
        if version.ends_with("-dev") {
            let base = &version[..version.len() - 4];
            if Self::is_x_range(base) {
                return Self::parse_x_range_dev(base);
            }
        }

        Self::parse_numeric_version(version)
    }

    /// Check if a string looks like an x-range (e.g., "1.0.x", "2.*")
    fn is_x_range(s: &str) -> bool {
        let parts: Vec<&str> = s.split('.').collect();
        parts
            .last()
            .map_or(false, |p| *p == "x" || *p == "*" || *p == "X")
    }

    /// Parse an x-range dev version like "1.0.x" into a dev version with 9999999 padding.
    fn parse_x_range_dev(s: &str) -> Result<Version, String> {
        let parts: Vec<&str> = s.split('.').collect();
        let mut components = [0u64; 4];

        for (i, part) in parts.iter().enumerate() {
            if i >= 4 {
                break;
            }
            if *part == "x" || *part == "*" || *part == "X" {
                components[i] = 9999999;
                // Fill remaining with 9999999
                for j in (i + 1)..4 {
                    components[j] = 9999999;
                }
                break;
            }
            components[i] = part
                .parse::<u64>()
                .map_err(|_| format!("Invalid version component: {}", part))?;
        }

        let normalized = format!(
            "{}.{}.{}.{}-dev",
            components[0], components[1], components[2], components[3]
        );

        Ok(Version {
            components,
            stability: Stability::Dev,
            stability_version: 0,
            is_dev_branch: false,
            branch_name: None,
            pretty: format!("{}-dev", s),
            normalized,
        })
    }

    /// Parse a numeric version string like "1.2.3-alpha1" into a Version.
    fn parse_numeric_version(version: &str) -> Result<Version, String> {
        // Split off stability suffix
        let (numeric_part, stability, stability_ver) = Self::extract_stability(version);

        // Parse numeric components
        let parts: Vec<&str> = numeric_part.split('.').collect();
        if parts.is_empty() || parts.len() > 4 {
            return Err(format!("Invalid version format: {}", version));
        }

        let mut components = [0u64; 4];
        for (i, part) in parts.iter().enumerate() {
            if i >= 4 {
                break;
            }
            components[i] = part
                .parse::<u64>()
                .map_err(|_| format!("Invalid version component '{}' in '{}'", part, version))?;
        }

        let normalized = if stability != Stability::Stable {
            let stab_str = match stability {
                Stability::RC => "RC".to_string(),
                other => other.as_str().to_lowercase(),
            };
            format!(
                "{}.{}.{}.{}-{}{}",
                components[0],
                components[1],
                components[2],
                components[3],
                stab_str,
                if stability_ver > 0 {
                    stability_ver.to_string()
                } else {
                    String::new()
                }
            )
        } else {
            format!(
                "{}.{}.{}.{}",
                components[0], components[1], components[2], components[3]
            )
        };

        Ok(Version {
            components,
            stability,
            stability_version: stability_ver,
            is_dev_branch: false,
            branch_name: None,
            pretty: version.to_string(),
            normalized,
        })
    }

    /// Extract stability info from a version string.
    /// Returns (numeric_part, stability, stability_version).
    fn extract_stability(version: &str) -> (&str, Stability, u64) {
        // Match patterns like "-alpha1", "-beta2", "-RC3", "-dev", "-patch1", "-p1"
        let re =
            Regex::new(r"(?i)[._-]?(dev|alpha|a|beta|b|rc|c|stable|patch|pl|p)\.?(\d*)$").unwrap();

        if let Some(caps) = re.captures(version) {
            let full_match = caps.get(0).unwrap();
            let numeric_part = &version[..full_match.start()];
            let stability_str = caps.get(1).unwrap().as_str();
            let stability_ver_str = caps.get(2).map_or("", |m| m.as_str());

            let stability = Stability::from_str(stability_str).unwrap_or(Stability::Stable);
            let stability_ver = stability_ver_str.parse::<u64>().unwrap_or(0);

            // If numeric_part is empty, something is wrong
            if numeric_part.is_empty() {
                return (version, Stability::Stable, 0);
            }

            (numeric_part, stability, stability_ver)
        } else {
            (version, Stability::Stable, 0)
        }
    }

    /// Parse a stability string like "stable", "dev", "alpha" etc.
    pub fn parse_stability(version: &str) -> Stability {
        let version = version.to_lowercase();
        if version.starts_with("dev-") || version.ends_with("-dev") {
            return Stability::Dev;
        }
        let (_, stability, _) = Self::extract_stability(&version);
        stability
    }

    /// Parse a version constraint string into a MultiConstraint.
    ///
    /// Supports:
    /// - Exact: "1.2.3"
    /// - Comparisons: ">=1.0", "<2.0", "!=1.5"
    /// - Tilde: "~1.2.3", "~1.2"
    /// - Caret: "^1.2.3", "^0.3"
    /// - Wildcard: "1.2.*"
    /// - Hyphen range: "1.0 - 2.0"
    /// - AND (space/comma): ">=1.0 <2.0", ">=1.0, <2.0"
    /// - OR: "^1.0 || ^2.0"
    /// - Stability: "@dev", "@beta" suffixes
    pub fn parse_constraints(constraint: &str) -> Result<MultiConstraint, String> {
        let constraint = constraint.trim();

        if constraint.is_empty() || constraint == "*" {
            return Ok(MultiConstraint::MatchAll);
        }

        // Strip stability flag suffix (e.g., "@dev", "@beta")
        let (constraint, _stability_flag) = Self::strip_stability_flag(constraint);

        // Split on "||" for OR
        let or_parts: Vec<&str> = constraint.split("||").collect();
        if or_parts.len() > 1 {
            let mut or_constraints = Vec::new();
            for part in &or_parts {
                let part = part.trim();
                if part.is_empty() {
                    continue;
                }
                or_constraints.push(Self::parse_and_constraints(part)?);
            }
            return Ok(MultiConstraint::or(or_constraints));
        }

        Self::parse_and_constraints(&constraint)
    }

    /// Strip a stability flag like "@dev" from the end of a constraint string.
    fn strip_stability_flag(constraint: &str) -> (String, Option<Stability>) {
        let re = Regex::new(r"@(dev|alpha|beta|rc|stable)\s*$").unwrap();
        if let Some(caps) = re.captures(constraint) {
            let stability = Stability::from_str(caps.get(1).unwrap().as_str());
            let clean = constraint[..caps.get(0).unwrap().start()]
                .trim()
                .to_string();
            (clean, stability)
        } else {
            (constraint.to_string(), None)
        }
    }

    /// Parse an AND constraint group (space or comma separated).
    fn parse_and_constraints(constraint: &str) -> Result<MultiConstraint, String> {
        let constraint = constraint.trim();

        // Check for hyphen range first: "1.0 - 2.0"
        if let Some(result) = Self::try_parse_hyphen_range(constraint)? {
            return Ok(result);
        }

        // Split on comma or whitespace (but not within operators)
        let parts = Self::split_and_parts(constraint);

        if parts.len() == 1 {
            return Self::parse_single_constraint(parts[0].trim());
        }

        let mut and_constraints = Vec::new();
        for part in &parts {
            let part = part.trim();
            if part.is_empty() {
                continue;
            }
            and_constraints.push(Self::parse_single_constraint(part)?);
        }

        Ok(MultiConstraint::and(and_constraints))
    }

    /// Split a constraint string on comma/whitespace boundaries, respecting operators.
    fn split_and_parts(constraint: &str) -> Vec<&str> {
        // Split on commas first
        let comma_parts: Vec<&str> = constraint.split(',').collect();
        if comma_parts.len() > 1 {
            return comma_parts;
        }

        // Split on whitespace, but group operator + version together
        let mut parts = Vec::new();
        let mut chars = constraint.char_indices().peekable();
        let mut start = 0;
        let mut in_token = false;

        while let Some(&(i, c)) = chars.peek() {
            if c.is_whitespace() {
                if in_token {
                    // Check if the next non-whitespace is an operator continuation
                    let rest = &constraint[i..].trim_start();
                    if !rest.starts_with(">=")
                        && !rest.starts_with("<=")
                        && !rest.starts_with("!=")
                        && !rest.starts_with('>')
                        && !rest.starts_with('<')
                        && !rest.starts_with('=')
                        && !rest.starts_with('~')
                        && !rest.starts_with('^')
                    {
                        // This whitespace separates two constraints
                        let token = constraint[start..i].trim();
                        if !token.is_empty() {
                            parts.push(token);
                        }
                        // Find start of next token
                        let next_start = i + constraint[i..]
                            .find(|c: char| !c.is_whitespace())
                            .unwrap_or(constraint.len() - i);
                        start = next_start;
                        in_token = false;
                        // Skip whitespace
                        while chars.peek().map_or(false, |&(_, c)| c.is_whitespace()) {
                            chars.next();
                        }
                        continue;
                    } else {
                        // The whitespace is followed by an operator for a new constraint
                        let token = constraint[start..i].trim();
                        if !token.is_empty() {
                            parts.push(token);
                        }
                        let next_start = i + constraint[i..]
                            .find(|c: char| !c.is_whitespace())
                            .unwrap_or(constraint.len() - i);
                        start = next_start;
                        in_token = false;
                        while chars.peek().map_or(false, |&(_, c)| c.is_whitespace()) {
                            chars.next();
                        }
                        continue;
                    }
                }
                chars.next();
            } else {
                in_token = true;
                chars.next();
            }
        }

        let remaining = constraint[start..].trim();
        if !remaining.is_empty() {
            parts.push(remaining);
        }

        if parts.is_empty() {
            vec![constraint]
        } else {
            parts
        }
    }

    /// Try to parse a hyphen range like "1.0 - 2.0".
    fn try_parse_hyphen_range(constraint: &str) -> Result<Option<MultiConstraint>, String> {
        let re = Regex::new(r"^(\S+)\s+-\s+(\S+)$").unwrap();
        if let Some(caps) = re.captures(constraint) {
            let low_str = caps.get(1).unwrap().as_str();
            let high_str = caps.get(2).unwrap().as_str();

            let low = Self::normalize(low_str)?;
            let high = Self::normalize(high_str)?;

            // Lower bound is always >=
            let lower = MultiConstraint::single(ConstraintOp::Ge, low);

            // Upper bound: if the high version was given with fewer components,
            // the next major/minor is excluded. E.g., "1.0 - 2.0" → <2.1.0.0
            // If exact (like "2.1.0"), then <=2.1.0.0
            let high_parts: Vec<&str> = high_str.split('.').collect();
            let upper = if high_parts.len() < 3 {
                // Incomplete version: bump the last specified component
                let mut bumped = high.clone();
                let idx = high_parts.len() - 1;
                bumped.components[idx] += 1;
                for j in (idx + 1)..4 {
                    bumped.components[j] = 0;
                }
                bumped.normalized = format!(
                    "{}.{}.{}.{}",
                    bumped.components[0],
                    bumped.components[1],
                    bumped.components[2],
                    bumped.components[3]
                );
                MultiConstraint::single(ConstraintOp::Lt, bumped)
            } else {
                MultiConstraint::single(ConstraintOp::Le, high)
            };

            return Ok(Some(MultiConstraint::and(vec![lower, upper])));
        }
        Ok(None)
    }

    /// Parse a single constraint token (no AND/OR).
    fn parse_single_constraint(constraint: &str) -> Result<MultiConstraint, String> {
        let constraint = constraint.trim();

        // Tilde range: ~1.2.3
        if let Some(rest) = constraint.strip_prefix('~') {
            return Self::parse_tilde_constraint(rest);
        }

        // Caret range: ^1.2.3
        if let Some(rest) = constraint.strip_prefix('^') {
            return Self::parse_caret_constraint(rest);
        }

        // Wildcard: 1.2.*
        if constraint.ends_with(".*") || constraint.ends_with(".x") || constraint == "*" {
            return Self::parse_wildcard_constraint(constraint);
        }

        // Comparison operator
        if constraint.starts_with(">=") {
            let ver = Self::normalize(constraint[2..].trim())?;
            return Ok(MultiConstraint::single(ConstraintOp::Ge, ver));
        }
        if constraint.starts_with("<=") {
            let ver = Self::normalize(constraint[2..].trim())?;
            return Ok(MultiConstraint::single(ConstraintOp::Le, ver));
        }
        if constraint.starts_with("!=") || constraint.starts_with("<>") {
            let ver = Self::normalize(constraint[2..].trim())?;
            return Ok(MultiConstraint::single(ConstraintOp::Ne, ver));
        }
        if constraint.starts_with('>') {
            let ver = Self::normalize(constraint[1..].trim())?;
            return Ok(MultiConstraint::single(ConstraintOp::Gt, ver));
        }
        if constraint.starts_with('<') {
            let ver = Self::normalize(constraint[1..].trim())?;
            return Ok(MultiConstraint::single(ConstraintOp::Lt, ver));
        }
        if constraint.starts_with("==") {
            let ver = Self::normalize(constraint[2..].trim())?;
            return Ok(MultiConstraint::single(ConstraintOp::Eq, ver));
        }
        if constraint.starts_with('=') {
            let ver = Self::normalize(constraint[1..].trim())?;
            return Ok(MultiConstraint::single(ConstraintOp::Eq, ver));
        }

        // Exact version
        let ver = Self::normalize(constraint)?;
        Ok(MultiConstraint::single(ConstraintOp::Eq, ver))
    }

    /// Parse a tilde constraint: ~1.2.3 → >=1.2.3 <1.3.0
    ///
    /// Rules:
    /// - ~1.2.3 → >=1.2.3.0 <1.3.0.0 (bumps second-to-last specified component)
    /// - ~1.2   → >=1.2.0.0 <2.0.0.0 (bumps second-to-last specified = major)
    /// - ~1     → >=1.0.0.0 <2.0.0.0
    fn parse_tilde_constraint(version_str: &str) -> Result<MultiConstraint, String> {
        let version_str = version_str.trim();
        let lower = Self::normalize(version_str)?;

        let parts: Vec<&str> = version_str.split('.').collect();
        let parts_len = parts.len();

        let mut upper = lower.clone();

        // Bump the second-to-last specified component
        let bump_idx = if parts_len >= 2 { parts_len - 2 } else { 0 };
        upper.components[bump_idx] += 1;
        for j in (bump_idx + 1)..4 {
            upper.components[j] = 0;
        }
        upper.stability = Stability::Dev;
        upper.stability_version = 0;
        upper.normalized = format!(
            "{}.{}.{}.{}-dev",
            upper.components[0], upper.components[1], upper.components[2], upper.components[3]
        );

        Ok(MultiConstraint::and(vec![
            MultiConstraint::single(ConstraintOp::Ge, lower),
            MultiConstraint::single(ConstraintOp::Lt, upper),
        ]))
    }

    /// Parse a caret constraint: ^1.2.3 → >=1.2.3 <2.0.0
    ///
    /// Rules:
    /// - ^1.2.3 → >=1.2.3.0 <2.0.0.0 (locks leftmost non-zero)
    /// - ^0.3.2 → >=0.3.2.0 <0.4.0.0 (0.x: locks 0.3)
    /// - ^0.0.4 → >=0.0.4.0 <0.0.5.0 (0.0.x: locks 0.0.4)
    /// - ^0.0   → >=0.0.0.0 <0.1.0.0
    fn parse_caret_constraint(version_str: &str) -> Result<MultiConstraint, String> {
        let version_str = version_str.trim();
        let lower = Self::normalize(version_str)?;

        let mut upper = lower.clone();

        // Find the leftmost non-zero component, or use the last specified component
        let parts: Vec<&str> = version_str.split('.').collect();
        let parts_len = parts.len();

        let bump_idx = if lower.components[0] != 0 {
            0
        } else if parts_len > 1 && lower.components[1] != 0 {
            1
        } else if parts_len > 2 && lower.components[2] != 0 {
            2
        } else if parts_len > 1 {
            // All zeros with multiple parts: bump the second-to-last specified
            // ^0.0 → >=0.0.0.0 <0.1.0.0
            parts_len - 1
        } else {
            0
        };

        upper.components[bump_idx] += 1;
        for j in (bump_idx + 1)..4 {
            upper.components[j] = 0;
        }
        upper.stability = Stability::Dev;
        upper.stability_version = 0;
        upper.normalized = format!(
            "{}.{}.{}.{}-dev",
            upper.components[0], upper.components[1], upper.components[2], upper.components[3]
        );

        Ok(MultiConstraint::and(vec![
            MultiConstraint::single(ConstraintOp::Ge, lower),
            MultiConstraint::single(ConstraintOp::Lt, upper),
        ]))
    }

    /// Parse a wildcard constraint: 1.2.* → >=1.2.0.0 <1.3.0.0
    fn parse_wildcard_constraint(constraint: &str) -> Result<MultiConstraint, String> {
        if constraint == "*" {
            return Ok(MultiConstraint::MatchAll);
        }

        // Strip trailing .* or .x
        let base = constraint
            .strip_suffix(".*")
            .or_else(|| constraint.strip_suffix(".x"))
            .unwrap_or(constraint);

        let parts: Vec<&str> = base.split('.').collect();
        let mut lower_components = [0u64; 4];
        let mut upper_components = [0u64; 4];

        for (i, part) in parts.iter().enumerate() {
            if i >= 4 {
                break;
            }
            let val = part
                .parse::<u64>()
                .map_err(|_| format!("Invalid wildcard version: {}", constraint))?;
            lower_components[i] = val;
            upper_components[i] = val;
        }

        // Bump the last specified component for upper bound
        let bump_idx = parts.len() - 1;
        upper_components[bump_idx] += 1;

        let lower = Version {
            components: lower_components,
            stability: Stability::Dev,
            stability_version: 0,
            is_dev_branch: false,
            branch_name: None,
            pretty: format!("{}.0", base),
            normalized: format!(
                "{}.{}.{}.{}-dev",
                lower_components[0], lower_components[1], lower_components[2], lower_components[3]
            ),
        };

        let upper = Version {
            components: upper_components,
            stability: Stability::Dev,
            stability_version: 0,
            is_dev_branch: false,
            branch_name: None,
            pretty: String::new(),
            normalized: format!(
                "{}.{}.{}.{}-dev",
                upper_components[0], upper_components[1], upper_components[2], upper_components[3]
            ),
        };

        Ok(MultiConstraint::and(vec![
            MultiConstraint::single(ConstraintOp::Ge, lower),
            MultiConstraint::single(ConstraintOp::Lt, upper),
        ]))
    }

    /// Parse the numeric alias prefix from a branch name.
    /// E.g., "dev-1.1" → Some("1.1"), "dev-master" → None
    pub fn parse_numeric_alias_prefix(branch: &str) -> Option<String> {
        let name = branch.strip_prefix("dev-").unwrap_or(branch);
        let re = Regex::new(r"^(\d+(?:\.\d+)*)").unwrap();
        re.captures(name)
            .map(|c| c.get(1).unwrap().as_str().to_string())
    }

    /// Normalize a branch name.
    /// "master" → "dev-master"
    /// "1.x" → "1.9999999.9999999.9999999-dev"
    pub fn normalize_branch(name: &str) -> Result<Version, String> {
        let name = name.trim();

        // Already has dev- prefix
        if name.starts_with("dev-") {
            return Self::normalize(name);
        }

        // Check if it's a numeric branch like "1.x"
        if Self::is_x_range(name) {
            return Self::parse_x_range_dev(name);
        }

        // Otherwise, it's a named branch
        Self::normalize(&format!("dev-{}", name))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ===== Version Normalization Tests =====

    #[test]
    fn test_normalize_simple_versions() {
        let v = VersionParser::normalize("1.2.3").unwrap();
        assert_eq!(v.normalized, "1.2.3.0");
        assert_eq!(v.components, [1, 2, 3, 0]);
        assert_eq!(v.stability, Stability::Stable);

        let v = VersionParser::normalize("1.0").unwrap();
        assert_eq!(v.normalized, "1.0.0.0");
        assert_eq!(v.components, [1, 0, 0, 0]);

        let v = VersionParser::normalize("1.2.3.4").unwrap();
        assert_eq!(v.normalized, "1.2.3.4");
        assert_eq!(v.components, [1, 2, 3, 4]);
    }

    #[test]
    fn test_normalize_strip_v_prefix() {
        let v = VersionParser::normalize("v1.2.3").unwrap();
        assert_eq!(v.normalized, "1.2.3.0");

        let v = VersionParser::normalize("V2.0.0").unwrap();
        assert_eq!(v.normalized, "2.0.0.0");
    }

    #[test]
    fn test_normalize_dev_branch() {
        let v = VersionParser::normalize("dev-master").unwrap();
        assert!(v.is_dev_branch);
        assert_eq!(v.branch_name, Some("master".to_string()));
        assert_eq!(v.stability, Stability::Dev);
        assert_eq!(v.normalized, "dev-master");

        let v = VersionParser::normalize("dev-feature/my-branch").unwrap();
        assert!(v.is_dev_branch);
        assert_eq!(v.branch_name, Some("feature/my-branch".to_string()));
    }

    #[test]
    fn test_normalize_stability_suffixes() {
        let v = VersionParser::normalize("1.0.0-alpha1").unwrap();
        assert_eq!(v.stability, Stability::Alpha);
        assert_eq!(v.stability_version, 1);
        assert_eq!(v.normalized, "1.0.0.0-alpha1");

        let v = VersionParser::normalize("2.0-beta2").unwrap();
        assert_eq!(v.stability, Stability::Beta);
        assert_eq!(v.stability_version, 2);
        assert_eq!(v.normalized, "2.0.0.0-beta2");

        let v = VersionParser::normalize("1.5-RC3").unwrap();
        assert_eq!(v.stability, Stability::RC);
        assert_eq!(v.stability_version, 3);
        assert_eq!(v.normalized, "1.5.0.0-RC3");

        let v = VersionParser::normalize("3.0.0-dev").unwrap();
        assert_eq!(v.stability, Stability::Dev);
        assert_eq!(v.normalized, "3.0.0.0-dev");
    }

    #[test]
    fn test_normalize_x_range_dev() {
        let v = VersionParser::normalize("1.0.x-dev").unwrap();
        assert_eq!(v.stability, Stability::Dev);
        assert_eq!(v.components, [1, 0, 9999999, 9999999]);
        assert_eq!(v.normalized, "1.0.9999999.9999999-dev");

        let v = VersionParser::normalize("2.x-dev").unwrap();
        assert_eq!(v.components, [2, 9999999, 9999999, 9999999]);
    }

    // ===== Version Comparison Tests =====

    #[test]
    fn test_version_ordering() {
        let v1 = VersionParser::normalize("1.0.0").unwrap();
        let v2 = VersionParser::normalize("2.0.0").unwrap();
        assert!(v1 < v2);

        let v1 = VersionParser::normalize("1.2.3").unwrap();
        let v2 = VersionParser::normalize("1.2.4").unwrap();
        assert!(v1 < v2);

        let v1 = VersionParser::normalize("1.0.0").unwrap();
        let v2 = VersionParser::normalize("1.0.0").unwrap();
        assert!(v1 == v2);
    }

    #[test]
    fn test_stability_ordering() {
        let stable = VersionParser::normalize("1.0.0").unwrap();
        let rc = VersionParser::normalize("1.0.0-RC1").unwrap();
        let beta = VersionParser::normalize("1.0.0-beta1").unwrap();
        let alpha = VersionParser::normalize("1.0.0-alpha1").unwrap();
        let dev = VersionParser::normalize("1.0.0-dev").unwrap();

        assert!(stable > rc);
        assert!(rc > beta);
        assert!(beta > alpha);
        assert!(alpha > dev);
    }

    #[test]
    fn test_stability_version_ordering() {
        let a1 = VersionParser::normalize("1.0.0-alpha1").unwrap();
        let a2 = VersionParser::normalize("1.0.0-alpha2").unwrap();
        assert!(a2 > a1);

        let b1 = VersionParser::normalize("1.0.0-beta1").unwrap();
        assert!(b1 > a2);
    }

    // ===== Constraint Parsing Tests =====

    #[test]
    fn test_exact_constraint() {
        let c = VersionParser::parse_constraints("1.2.3").unwrap();
        let v = VersionParser::normalize("1.2.3").unwrap();
        assert!(c.matches_version(&v));

        let v2 = VersionParser::normalize("1.2.4").unwrap();
        assert!(!c.matches_version(&v2));
    }

    #[test]
    fn test_comparison_constraints() {
        let c = VersionParser::parse_constraints(">=1.0.0").unwrap();
        assert!(c.matches_version(&VersionParser::normalize("1.0.0").unwrap()));
        assert!(c.matches_version(&VersionParser::normalize("2.0.0").unwrap()));
        assert!(!c.matches_version(&VersionParser::normalize("0.9.0").unwrap()));

        let c = VersionParser::parse_constraints("<2.0.0").unwrap();
        assert!(c.matches_version(&VersionParser::normalize("1.9.9").unwrap()));
        assert!(!c.matches_version(&VersionParser::normalize("2.0.0").unwrap()));
        assert!(!c.matches_version(&VersionParser::normalize("2.0.1").unwrap()));

        let c = VersionParser::parse_constraints("!=1.5.0").unwrap();
        assert!(c.matches_version(&VersionParser::normalize("1.4.0").unwrap()));
        assert!(!c.matches_version(&VersionParser::normalize("1.5.0").unwrap()));
        assert!(c.matches_version(&VersionParser::normalize("1.6.0").unwrap()));
    }

    #[test]
    fn test_wildcard_constraint() {
        let c = VersionParser::parse_constraints("1.2.*").unwrap();
        assert!(c.matches_version(&VersionParser::normalize("1.2.0").unwrap()));
        assert!(c.matches_version(&VersionParser::normalize("1.2.9").unwrap()));
        assert!(!c.matches_version(&VersionParser::normalize("1.3.0").unwrap()));
        assert!(!c.matches_version(&VersionParser::normalize("1.1.9").unwrap()));

        let c = VersionParser::parse_constraints("2.*").unwrap();
        assert!(c.matches_version(&VersionParser::normalize("2.0.0").unwrap()));
        assert!(c.matches_version(&VersionParser::normalize("2.99.99").unwrap()));
        assert!(!c.matches_version(&VersionParser::normalize("3.0.0").unwrap()));
        assert!(!c.matches_version(&VersionParser::normalize("1.9.9").unwrap()));
    }

    #[test]
    fn test_tilde_constraint() {
        // ~1.2.3 → >=1.2.3 <1.3.0
        let c = VersionParser::parse_constraints("~1.2.3").unwrap();
        assert!(c.matches_version(&VersionParser::normalize("1.2.3").unwrap()));
        assert!(c.matches_version(&VersionParser::normalize("1.2.9").unwrap()));
        assert!(!c.matches_version(&VersionParser::normalize("1.3.0").unwrap()));
        assert!(!c.matches_version(&VersionParser::normalize("1.2.2").unwrap()));

        // ~1.2 → >=1.2.0 <2.0.0
        let c = VersionParser::parse_constraints("~1.2").unwrap();
        assert!(c.matches_version(&VersionParser::normalize("1.2.0").unwrap()));
        assert!(c.matches_version(&VersionParser::normalize("1.9.9").unwrap()));
        assert!(!c.matches_version(&VersionParser::normalize("2.0.0").unwrap()));
        assert!(!c.matches_version(&VersionParser::normalize("1.1.9").unwrap()));
    }

    #[test]
    fn test_caret_constraint() {
        // ^1.2.3 → >=1.2.3 <2.0.0
        let c = VersionParser::parse_constraints("^1.2.3").unwrap();
        assert!(c.matches_version(&VersionParser::normalize("1.2.3").unwrap()));
        assert!(c.matches_version(&VersionParser::normalize("1.9.9").unwrap()));
        assert!(!c.matches_version(&VersionParser::normalize("2.0.0").unwrap()));
        assert!(!c.matches_version(&VersionParser::normalize("1.2.2").unwrap()));

        // ^0.3.2 → >=0.3.2 <0.4.0
        let c = VersionParser::parse_constraints("^0.3.2").unwrap();
        assert!(c.matches_version(&VersionParser::normalize("0.3.2").unwrap()));
        assert!(c.matches_version(&VersionParser::normalize("0.3.9").unwrap()));
        assert!(!c.matches_version(&VersionParser::normalize("0.4.0").unwrap()));

        // ^0.0.4 → >=0.0.4 <0.0.5
        let c = VersionParser::parse_constraints("^0.0.4").unwrap();
        assert!(c.matches_version(&VersionParser::normalize("0.0.4").unwrap()));
        assert!(!c.matches_version(&VersionParser::normalize("0.0.5").unwrap()));
        assert!(!c.matches_version(&VersionParser::normalize("0.0.3").unwrap()));
    }

    #[test]
    fn test_and_constraints() {
        // >=1.0 <2.0
        let c = VersionParser::parse_constraints(">=1.0 <2.0").unwrap();
        assert!(c.matches_version(&VersionParser::normalize("1.0.0").unwrap()));
        assert!(c.matches_version(&VersionParser::normalize("1.5.0").unwrap()));
        assert!(!c.matches_version(&VersionParser::normalize("2.0.0").unwrap()));
        assert!(!c.matches_version(&VersionParser::normalize("0.9.0").unwrap()));

        // Comma-separated
        let c = VersionParser::parse_constraints(">=1.0, <2.0").unwrap();
        assert!(c.matches_version(&VersionParser::normalize("1.5.0").unwrap()));
        assert!(!c.matches_version(&VersionParser::normalize("2.0.0").unwrap()));
    }

    #[test]
    fn test_or_constraints() {
        // ^1.0 || ^2.0
        let c = VersionParser::parse_constraints("^1.0 || ^2.0").unwrap();
        assert!(c.matches_version(&VersionParser::normalize("1.5.0").unwrap()));
        assert!(c.matches_version(&VersionParser::normalize("2.5.0").unwrap()));
        assert!(!c.matches_version(&VersionParser::normalize("3.0.0").unwrap()));
        assert!(!c.matches_version(&VersionParser::normalize("0.9.0").unwrap()));
    }

    #[test]
    fn test_hyphen_range() {
        // 1.0 - 2.0 → >=1.0.0.0 <2.1.0.0
        let c = VersionParser::parse_constraints("1.0 - 2.0").unwrap();
        assert!(c.matches_version(&VersionParser::normalize("1.0.0").unwrap()));
        assert!(c.matches_version(&VersionParser::normalize("2.0.0").unwrap()));
        assert!(c.matches_version(&VersionParser::normalize("2.0.5").unwrap()));
        assert!(!c.matches_version(&VersionParser::normalize("2.1.0").unwrap()));
        assert!(!c.matches_version(&VersionParser::normalize("0.9.0").unwrap()));

        // 1.0.0 - 2.1.0 → >=1.0.0.0 <=2.1.0.0
        let c = VersionParser::parse_constraints("1.0.0 - 2.1.0").unwrap();
        assert!(c.matches_version(&VersionParser::normalize("1.0.0").unwrap()));
        assert!(c.matches_version(&VersionParser::normalize("2.1.0").unwrap()));
        assert!(!c.matches_version(&VersionParser::normalize("2.1.1").unwrap()));
    }

    #[test]
    fn test_stability_flag() {
        let c = VersionParser::parse_constraints(">=1.0 @dev").unwrap();
        assert!(c.matches_version(&VersionParser::normalize("1.0.0").unwrap()));
        assert!(c.matches_version(&VersionParser::normalize("2.0.0").unwrap()));
    }

    #[test]
    fn test_wildcard_star() {
        let c = VersionParser::parse_constraints("*").unwrap();
        assert!(c.matches_version(&VersionParser::normalize("1.0.0").unwrap()));
        assert!(c.matches_version(&VersionParser::normalize("99.99.99").unwrap()));
    }

    #[test]
    fn test_parse_stability() {
        assert_eq!(VersionParser::parse_stability("1.0.0"), Stability::Stable);
        assert_eq!(
            VersionParser::parse_stability("1.0.0-alpha1"),
            Stability::Alpha
        );
        assert_eq!(
            VersionParser::parse_stability("1.0.0-beta2"),
            Stability::Beta
        );
        assert_eq!(VersionParser::parse_stability("1.0.0-RC3"), Stability::RC);
        assert_eq!(VersionParser::parse_stability("dev-master"), Stability::Dev);
        assert_eq!(VersionParser::parse_stability("1.0.x-dev"), Stability::Dev);
    }

    #[test]
    fn test_branch_alias_prefix() {
        assert_eq!(
            VersionParser::parse_numeric_alias_prefix("dev-1.1"),
            Some("1.1".to_string())
        );
        assert_eq!(
            VersionParser::parse_numeric_alias_prefix("dev-master"),
            None
        );
        assert_eq!(
            VersionParser::parse_numeric_alias_prefix("dev-1.2.3"),
            Some("1.2.3".to_string())
        );
    }

    #[test]
    fn test_normalize_branch() {
        let v = VersionParser::normalize_branch("master").unwrap();
        assert!(v.is_dev_branch);
        assert_eq!(v.branch_name, Some("master".to_string()));

        let v = VersionParser::normalize_branch("1.x").unwrap();
        assert_eq!(v.stability, Stability::Dev);
        assert_eq!(v.components[0], 1);
        assert_eq!(v.components[1], 9999999);
    }

    #[test]
    fn test_complex_or_and() {
        // ~1.0 !=1.0.1
        let c = VersionParser::parse_constraints("~1.0, !=1.0.1").unwrap();
        assert!(c.matches_version(&VersionParser::normalize("1.0.0").unwrap()));
        assert!(!c.matches_version(&VersionParser::normalize("1.0.1").unwrap()));
        assert!(c.matches_version(&VersionParser::normalize("1.0.2").unwrap()));
        assert!(!c.matches_version(&VersionParser::normalize("2.0.0").unwrap()));
    }

    #[test]
    fn test_caret_zero_zero() {
        // ^0.0 → >=0.0.0.0 <0.1.0.0
        let c = VersionParser::parse_constraints("^0.0").unwrap();
        assert!(c.matches_version(&VersionParser::normalize("0.0.0").unwrap()));
        assert!(c.matches_version(&VersionParser::normalize("0.0.9").unwrap()));
        assert!(!c.matches_version(&VersionParser::normalize("0.1.0").unwrap()));
    }

    #[test]
    fn test_display_constraints() {
        let c = VersionParser::parse_constraints("^1.2.3").unwrap();
        let s = c.to_string();
        assert!(s.contains(">="));
        assert!(s.contains("<"));
    }
}
