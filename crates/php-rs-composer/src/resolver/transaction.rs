use crate::package::Package;

/// An installation operation.
#[derive(Debug, Clone)]
pub enum Operation {
    Install(Package),
    Update { from: Package, to: Package },
    Uninstall(Package),
}

impl Operation {
    pub fn package(&self) -> &Package {
        match self {
            Operation::Install(p) => p,
            Operation::Update { to, .. } => to,
            Operation::Uninstall(p) => p,
        }
    }
}

impl std::fmt::Display for Operation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Operation::Install(p) => write!(f, "Installing {} ({})", p.name, p.version),
            Operation::Update { from, to } => {
                write!(
                    f,
                    "Updating {} ({} => {})",
                    to.name, from.version, to.version
                )
            }
            Operation::Uninstall(p) => write!(f, "Removing {} ({})", p.name, p.version),
        }
    }
}

/// Result of dependency resolution: a list of operations to perform.
#[derive(Debug)]
pub struct Transaction {
    pub operations: Vec<Operation>,
}

impl Transaction {
    pub fn new(operations: Vec<Operation>) -> Self {
        Transaction { operations }
    }

    pub fn is_empty(&self) -> bool {
        self.operations.is_empty()
    }
}
