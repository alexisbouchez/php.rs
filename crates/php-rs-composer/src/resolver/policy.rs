use super::pool::Pool;
use crate::semver::VersionParser;

/// Policy for selecting which package version to try first.
pub struct DefaultPolicy {
    pub prefer_stable: bool,
    pub prefer_lowest: bool,
}

impl DefaultPolicy {
    pub fn new(prefer_stable: bool, prefer_lowest: bool) -> Self {
        DefaultPolicy {
            prefer_stable,
            prefer_lowest,
        }
    }

    /// Sort package IDs by preference (most preferred first).
    pub fn sort_by_preference(&self, pool: &Pool, ids: &mut [usize]) {
        ids.sort_by(|&a, &b| {
            let pkg_a = pool.package(a);
            let pkg_b = pool.package(b);

            match (pkg_a, pkg_b) {
                (Some(pa), Some(pb)) => {
                    let ver_a = VersionParser::normalize(&pa.version);
                    let ver_b = VersionParser::normalize(&pb.version);

                    match (ver_a, ver_b) {
                        (Ok(va), Ok(vb)) => {
                            if self.prefer_stable {
                                // Prefer stable over dev/alpha/beta/rc
                                let stab_cmp = va.stability.cmp(&vb.stability);
                                if stab_cmp != std::cmp::Ordering::Equal {
                                    return stab_cmp.reverse();
                                }
                            }

                            if self.prefer_lowest {
                                va.cmp(&vb)
                            } else {
                                vb.cmp(&va)
                            }
                        }
                        _ => std::cmp::Ordering::Equal,
                    }
                }
                _ => std::cmp::Ordering::Equal,
            }
        });
    }
}

impl Default for DefaultPolicy {
    fn default() -> Self {
        Self::new(true, false)
    }
}
