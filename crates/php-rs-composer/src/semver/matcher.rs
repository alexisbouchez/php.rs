use super::constraint::MultiConstraint;
use super::version::Version;

/// Check if a version matches a constraint.
///
/// This is a convenience function wrapping `MultiConstraint::matches_version`.
pub fn matches(constraint: &MultiConstraint, version: &Version) -> bool {
    constraint.matches_version(version)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::semver::parser::VersionParser;

    #[test]
    fn test_matches_convenience() {
        let c = VersionParser::parse_constraints("^1.0").unwrap();
        let v = VersionParser::normalize("1.5.0").unwrap();
        assert!(matches(&c, &v));

        let v2 = VersionParser::normalize("2.0.0").unwrap();
        assert!(!matches(&c, &v2));
    }

    #[test]
    fn test_matches_dev_branch_with_exact() {
        let c = VersionParser::parse_constraints("dev-master").unwrap();
        let v = VersionParser::normalize("dev-master").unwrap();
        assert!(matches(&c, &v));

        let v2 = VersionParser::normalize("dev-develop").unwrap();
        assert!(!matches(&c, &v2));
    }

    #[test]
    fn test_matches_complex_real_world() {
        // Laravel-style constraint
        let c = VersionParser::parse_constraints("^8.0 || ^9.0 || ^10.0 || ^11.0").unwrap();
        assert!(matches(&c, &VersionParser::normalize("8.5.0").unwrap()));
        assert!(matches(&c, &VersionParser::normalize("9.0.0").unwrap()));
        assert!(matches(&c, &VersionParser::normalize("11.99.0").unwrap()));
        assert!(!matches(&c, &VersionParser::normalize("7.0.0").unwrap()));
        assert!(!matches(&c, &VersionParser::normalize("12.0.0").unwrap()));
    }

    #[test]
    fn test_matches_with_prerelease() {
        let c = VersionParser::parse_constraints(">=1.0.0").unwrap();
        // Alpha is less stable but still >= 1.0.0 in version number
        let v = VersionParser::normalize("1.0.0-alpha1").unwrap();
        // 1.0.0-alpha1 < 1.0.0 (stable), so it should NOT match >=1.0.0 (stable)
        assert!(!matches(&c, &v));

        let v2 = VersionParser::normalize("1.0.1-alpha1").unwrap();
        // 1.0.1-alpha1 > 1.0.0 (different numeric component)
        assert!(matches(&c, &v2));
    }
}
