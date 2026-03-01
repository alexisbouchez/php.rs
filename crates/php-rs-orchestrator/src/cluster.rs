//! Multi-node clustering — scale beyond a single machine.
//!
//! Manages a cluster of compute nodes, places apps on nodes with available
//! capacity, distributes routing tables, and provides high availability.
//!
//! Architecture:
//!   - One control plane node (runs the API, scheduler, router)
//!   - N compute nodes (run app processes)
//!   - Nodes communicate via HTTP API
//!   - State stored in shared JSON (upgradeable to etcd/Consul)

use std::collections::HashMap;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

// ── Node Registration & Discovery (Phase 10.1) ────────────────────────────

/// A compute node in the cluster.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClusterNode {
    /// Unique node identifier.
    pub id: String,
    /// Hostname or IP address.
    pub host: String,
    /// API port for inter-node communication.
    pub api_port: u16,
    /// Node status.
    pub status: NodeStatus,
    /// Node capacity.
    pub capacity: NodeCapacity,
    /// Current resource usage.
    pub usage: NodeUsage,
    /// Apps currently running on this node.
    pub apps: Vec<String>,
    /// Last heartbeat timestamp (ISO 8601).
    pub last_heartbeat: String,
    /// Labels for affinity/anti-affinity rules.
    #[serde(default)]
    pub labels: HashMap<String, String>,
    /// When the node was registered.
    pub registered_at: String,
}

/// Node status in the cluster.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum NodeStatus {
    /// Node is healthy and accepting work.
    Ready,
    /// Node is unhealthy (missed heartbeats).
    NotReady,
    /// Node is being drained (no new work, finishing existing).
    Draining,
    /// Node is cordoned (no new work, but not draining).
    Cordoned,
}

/// Node resource capacity.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeCapacity {
    /// Total CPU cores available.
    pub cpu_cores: u32,
    /// Total memory in MB.
    pub memory_mb: u64,
    /// Total disk space in MB.
    pub disk_mb: u64,
    /// Maximum number of app instances.
    pub max_apps: u32,
}

impl Default for NodeCapacity {
    fn default() -> Self {
        Self {
            cpu_cores: 4,
            memory_mb: 8192,
            disk_mb: 50000,
            max_apps: 100,
        }
    }
}

/// Current resource usage on a node.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct NodeUsage {
    /// CPU usage as percentage (0-100).
    pub cpu_percent: f32,
    /// Memory used in MB.
    pub memory_used_mb: u64,
    /// Disk used in MB.
    pub disk_used_mb: u64,
    /// Number of running app instances.
    pub running_apps: u32,
}

/// Cluster state — the central view of all nodes.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClusterState {
    /// All registered nodes.
    pub nodes: HashMap<String, ClusterNode>,
    /// Heartbeat timeout in seconds.
    pub heartbeat_timeout_secs: u64,
    /// App placement decisions: app_name -> node_id.
    pub placements: HashMap<String, Vec<String>>,
}

impl Default for ClusterState {
    fn default() -> Self {
        Self {
            nodes: HashMap::new(),
            heartbeat_timeout_secs: 30,
            placements: HashMap::new(),
        }
    }
}

impl ClusterState {
    /// Register a new node or update an existing one.
    pub fn register_node(&mut self, node: ClusterNode) {
        self.nodes.insert(node.id.clone(), node);
    }

    /// Remove a node from the cluster.
    pub fn deregister_node(&mut self, node_id: &str) -> Option<ClusterNode> {
        self.nodes.remove(node_id)
    }

    /// Update a node's heartbeat timestamp.
    pub fn heartbeat(&mut self, node_id: &str) -> bool {
        if let Some(node) = self.nodes.get_mut(node_id) {
            node.last_heartbeat = now_iso8601();
            if node.status == NodeStatus::NotReady {
                node.status = NodeStatus::Ready;
            }
            true
        } else {
            false
        }
    }

    /// Update a node's resource usage.
    pub fn update_usage(&mut self, node_id: &str, usage: NodeUsage) {
        if let Some(node) = self.nodes.get_mut(node_id) {
            node.usage = usage;
        }
    }

    /// Check for nodes that have missed heartbeats and mark them NotReady.
    pub fn check_heartbeats(&mut self) -> Vec<String> {
        let now = current_timestamp_secs();
        let timeout = self.heartbeat_timeout_secs;
        let mut failed = Vec::new();

        for (id, node) in &mut self.nodes {
            if node.status == NodeStatus::Ready {
                let last = parse_timestamp_secs(&node.last_heartbeat).unwrap_or(0);
                if now.saturating_sub(last) > timeout {
                    node.status = NodeStatus::NotReady;
                    failed.push(id.clone());
                }
            }
        }

        failed
    }

    /// Get all ready nodes.
    pub fn ready_nodes(&self) -> Vec<&ClusterNode> {
        self.nodes.values()
            .filter(|n| n.status == NodeStatus::Ready)
            .collect()
    }

    /// Get nodes that can accept new apps.
    pub fn schedulable_nodes(&self) -> Vec<&ClusterNode> {
        self.nodes.values()
            .filter(|n| n.status == NodeStatus::Ready && n.usage.running_apps < n.capacity.max_apps)
            .collect()
    }

    /// Drain a node — mark as draining, no new apps placed on it.
    pub fn drain_node(&mut self, node_id: &str) -> bool {
        if let Some(node) = self.nodes.get_mut(node_id) {
            node.status = NodeStatus::Draining;
            true
        } else {
            false
        }
    }

    /// Cordon a node — prevent new placements but keep running apps.
    pub fn cordon_node(&mut self, node_id: &str) -> bool {
        if let Some(node) = self.nodes.get_mut(node_id) {
            node.status = NodeStatus::Cordoned;
            true
        } else {
            false
        }
    }

    /// Uncordon a node — allow new placements again.
    pub fn uncordon_node(&mut self, node_id: &str) -> bool {
        if let Some(node) = self.nodes.get_mut(node_id) {
            if node.status == NodeStatus::Cordoned {
                node.status = NodeStatus::Ready;
                return true;
            }
        }
        false
    }
}

// ── App Placement / Scheduling (Phase 10.2) ───────────────────────────────

/// Placement strategy for app scheduling.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum PlacementStrategy {
    /// Pack apps onto fewest nodes (maximize density).
    BinPack,
    /// Spread apps across nodes (maximize availability).
    Spread,
    /// Place on the node with most available resources.
    MostAvailable,
}

impl Default for PlacementStrategy {
    fn default() -> Self {
        PlacementStrategy::BinPack
    }
}

/// Affinity/anti-affinity rules for placement.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AffinityRule {
    /// Label key to match.
    pub key: String,
    /// Label value to match.
    pub value: String,
    /// Whether this is required (hard) or preferred (soft).
    pub required: bool,
}

/// Result of a placement decision.
#[derive(Debug, Clone)]
pub struct PlacementDecision {
    /// Chosen node ID.
    pub node_id: String,
    /// Score (higher = better fit).
    pub score: f64,
    /// Reason for the decision.
    pub reason: String,
}

/// Schedule an app onto a node.
pub fn schedule_app(
    cluster: &ClusterState,
    app_name: &str,
    strategy: &PlacementStrategy,
    affinity: &[AffinityRule],
    replicas: usize,
) -> Result<Vec<PlacementDecision>, String> {
    let schedulable = cluster.schedulable_nodes();
    if schedulable.is_empty() {
        return Err("No schedulable nodes available".into());
    }

    // Filter by affinity rules.
    let candidates: Vec<&ClusterNode> = schedulable.into_iter()
        .filter(|node| {
            affinity.iter()
                .filter(|r| r.required)
                .all(|rule| {
                    node.labels.get(&rule.key).map(|v| v == &rule.value).unwrap_or(false)
                })
        })
        .collect();

    if candidates.is_empty() {
        return Err("No nodes match required affinity rules".into());
    }

    // Score candidates based on strategy.
    let mut scored: Vec<(&ClusterNode, f64)> = candidates.iter()
        .map(|node| {
            let base_score = match strategy {
                PlacementStrategy::BinPack => {
                    // Prefer nodes with more apps (pack tightly).
                    node.usage.running_apps as f64 / node.capacity.max_apps.max(1) as f64
                }
                PlacementStrategy::Spread => {
                    // Prefer nodes with fewer apps (spread out).
                    1.0 - (node.usage.running_apps as f64 / node.capacity.max_apps.max(1) as f64)
                }
                PlacementStrategy::MostAvailable => {
                    // Prefer nodes with most available memory.
                    let avail = node.capacity.memory_mb.saturating_sub(node.usage.memory_used_mb);
                    avail as f64 / node.capacity.memory_mb.max(1) as f64
                }
            };

            // Soft affinity bonus.
            let affinity_bonus: f64 = affinity.iter()
                .filter(|r| !r.required)
                .map(|rule| {
                    if node.labels.get(&rule.key).map(|v| v == &rule.value).unwrap_or(false) {
                        0.1
                    } else {
                        0.0
                    }
                })
                .sum();

            (*node, base_score + affinity_bonus)
        })
        .collect();

    // Sort by score (highest first).
    scored.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));

    // Check we don't place multiple replicas on same node (for Spread).
    let mut decisions = Vec::new();
    let mut used_nodes: Vec<String> = Vec::new();

    for _ in 0..replicas {
        let chosen = if *strategy == PlacementStrategy::Spread {
            scored.iter()
                .find(|(node, _)| !used_nodes.contains(&node.id))
                .or_else(|| scored.first())
        } else {
            scored.first()
        };

        match chosen {
            Some((node, score)) => {
                used_nodes.push(node.id.clone());
                decisions.push(PlacementDecision {
                    node_id: node.id.clone(),
                    score: *score,
                    reason: format!("Placed '{}' on node '{}' ({:?})", app_name, node.id, strategy),
                });
            }
            None => {
                return Err(format!("Cannot place replica {} — no available nodes", decisions.len() + 1));
            }
        }
    }

    Ok(decisions)
}

/// Migrate an app from one node to another.
pub fn plan_migration(
    _cluster: &ClusterState,
    app_name: &str,
    from_node: &str,
    to_node: &str,
) -> MigrationPlan {
    MigrationPlan {
        app_name: app_name.into(),
        source_node: from_node.into(),
        target_node: to_node.into(),
        steps: vec![
            MigrationStep::StartOnTarget,
            MigrationStep::WaitReady,
            MigrationStep::UpdateRouting,
            MigrationStep::DrainSource,
            MigrationStep::StopOnSource,
        ],
    }
}

/// Plan for migrating an app between nodes.
#[derive(Debug, Clone)]
pub struct MigrationPlan {
    pub app_name: String,
    pub source_node: String,
    pub target_node: String,
    pub steps: Vec<MigrationStep>,
}

#[derive(Debug, Clone)]
pub enum MigrationStep {
    StartOnTarget,
    WaitReady,
    UpdateRouting,
    DrainSource,
    StopOnSource,
}

// ── Distributed Routing (Phase 10.3) ──────────────────────────────────────

/// Distributed routing table — maps domains/apps to nodes.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct DistributedRoutingTable {
    /// App -> list of (node_id, port) backends.
    pub routes: HashMap<String, Vec<RouteBackend>>,
    /// Version number for consistency.
    pub version: u64,
    /// Last updated timestamp.
    pub updated_at: String,
}

/// A backend endpoint for routing.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RouteBackend {
    /// Node ID where the app runs.
    pub node_id: String,
    /// Node host address.
    pub host: String,
    /// Port on the node.
    pub port: u16,
    /// Weight for weighted round-robin (default 100).
    #[serde(default = "default_weight")]
    pub weight: u16,
    /// Whether this backend is healthy.
    pub healthy: bool,
}

fn default_weight() -> u16 { 100 }

impl DistributedRoutingTable {
    /// Build the routing table from cluster state and app placements.
    pub fn build_from_cluster(cluster: &ClusterState) -> Self {
        let mut routes: HashMap<String, Vec<RouteBackend>> = HashMap::new();

        for (app_name, node_ids) in &cluster.placements {
            let mut backends = Vec::new();
            for node_id in node_ids {
                if let Some(node) = cluster.nodes.get(node_id) {
                    backends.push(RouteBackend {
                        node_id: node_id.clone(),
                        host: node.host.clone(),
                        port: node.api_port, // Would be the app's port on this node.
                        weight: 100,
                        healthy: node.status == NodeStatus::Ready,
                    });
                }
            }
            if !backends.is_empty() {
                routes.insert(app_name.clone(), backends);
            }
        }

        Self {
            routes,
            version: current_timestamp_secs(),
            updated_at: now_iso8601(),
        }
    }

    /// Get healthy backends for an app.
    pub fn get_backends(&self, app_name: &str) -> Vec<&RouteBackend> {
        self.routes.get(app_name)
            .map(|backends| backends.iter().filter(|b| b.healthy).collect())
            .unwrap_or_default()
    }

    /// Select the next backend using round-robin.
    pub fn select_backend(&self, app_name: &str, counter: u64) -> Option<&RouteBackend> {
        let healthy = self.get_backends(app_name);
        if healthy.is_empty() {
            return None;
        }
        Some(healthy[(counter as usize) % healthy.len()])
    }

    /// Mark a backend as unhealthy.
    pub fn mark_unhealthy(&mut self, app_name: &str, node_id: &str) {
        if let Some(backends) = self.routes.get_mut(app_name) {
            for backend in backends {
                if backend.node_id == node_id {
                    backend.healthy = false;
                }
            }
        }
    }

    /// Mark a backend as healthy.
    pub fn mark_healthy(&mut self, app_name: &str, node_id: &str) {
        if let Some(backends) = self.routes.get_mut(app_name) {
            for backend in backends {
                if backend.node_id == node_id {
                    backend.healthy = true;
                }
            }
        }
    }
}

// ── Shared Storage (Phase 10.4) ───────────────────────────────────────────

/// Slug storage configuration — where app slugs are stored for distribution.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SlugStorage {
    /// Storage backend type.
    pub backend: SlugStorageBackend,
    /// S3 bucket name (for S3 backend).
    #[serde(default)]
    pub s3_bucket: String,
    /// S3 endpoint (for S3 backend).
    #[serde(default)]
    pub s3_endpoint: String,
    /// Local directory path (for filesystem backend).
    #[serde(default)]
    pub local_path: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum SlugStorageBackend {
    /// Local filesystem (single-node or shared NFS).
    Filesystem,
    /// S3-compatible object storage (MinIO, AWS S3).
    S3,
}

impl Default for SlugStorage {
    fn default() -> Self {
        Self {
            backend: SlugStorageBackend::Filesystem,
            s3_bucket: String::new(),
            s3_endpoint: String::new(),
            local_path: "/var/lib/php-rs/slugs".into(),
        }
    }
}

impl SlugStorage {
    /// Store a slug for an app version.
    pub fn store_slug(&self, app_name: &str, version: &str, slug_path: &str) -> Result<String, String> {
        match self.backend {
            SlugStorageBackend::Filesystem => {
                let dest_dir = format!("{}/{}", self.local_path, app_name);
                std::fs::create_dir_all(&dest_dir)
                    .map_err(|e| format!("Cannot create slug directory: {}", e))?;
                let dest = format!("{}/{}.tar.gz", dest_dir, version);
                std::fs::copy(slug_path, &dest)
                    .map_err(|e| format!("Cannot copy slug: {}", e))?;
                Ok(dest)
            }
            SlugStorageBackend::S3 => {
                // Upload via aws CLI.
                let s3_key = format!("{}/{}.tar.gz", app_name, version);
                let status = std::process::Command::new("aws")
                    .args([
                        "s3", "cp",
                        slug_path,
                        &format!("s3://{}/{}", self.s3_bucket, s3_key),
                        "--endpoint-url", &self.s3_endpoint,
                    ])
                    .stdout(std::process::Stdio::null())
                    .stderr(std::process::Stdio::null())
                    .status()
                    .map_err(|e| format!("aws s3 cp failed: {}", e))?;

                if !status.success() {
                    return Err("Failed to upload slug to S3".into());
                }
                Ok(format!("s3://{}/{}", self.s3_bucket, s3_key))
            }
        }
    }

    /// Pull a slug to a local path on a compute node.
    pub fn pull_slug(&self, app_name: &str, version: &str, dest_path: &str) -> Result<(), String> {
        match self.backend {
            SlugStorageBackend::Filesystem => {
                let source = format!("{}/{}/{}.tar.gz", self.local_path, app_name, version);
                std::fs::copy(&source, dest_path)
                    .map_err(|e| format!("Cannot copy slug from {}: {}", source, e))?;
                Ok(())
            }
            SlugStorageBackend::S3 => {
                let s3_key = format!("{}/{}.tar.gz", app_name, version);
                let status = std::process::Command::new("aws")
                    .args([
                        "s3", "cp",
                        &format!("s3://{}/{}", self.s3_bucket, s3_key),
                        dest_path,
                        "--endpoint-url", &self.s3_endpoint,
                    ])
                    .stdout(std::process::Stdio::null())
                    .stderr(std::process::Stdio::null())
                    .status()
                    .map_err(|e| format!("aws s3 cp failed: {}", e))?;

                if !status.success() {
                    return Err("Failed to download slug from S3".into());
                }
                Ok(())
            }
        }
    }
}

// ── High Availability (Phase 10.5) ────────────────────────────────────────

/// HA configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HAConfig {
    /// Minimum number of replicas per app.
    pub min_replicas: u32,
    /// Spread replicas across different nodes.
    pub spread_replicas: bool,
    /// Auto-failover on node failure.
    pub auto_failover: bool,
    /// Failover timeout in seconds (how long to wait before migrating).
    pub failover_timeout_secs: u64,
}

impl Default for HAConfig {
    fn default() -> Self {
        Self {
            min_replicas: 1,
            spread_replicas: true,
            auto_failover: true,
            failover_timeout_secs: 60,
        }
    }
}

/// Check for apps that need failover due to node failures.
pub fn check_failover(
    cluster: &ClusterState,
    ha_config: &HAConfig,
) -> Vec<FailoverAction> {
    if !ha_config.auto_failover {
        return Vec::new();
    }

    let mut actions = Vec::new();

    for (app_name, node_ids) in &cluster.placements {
        // Count healthy nodes running this app.
        let healthy_count = node_ids.iter()
            .filter(|nid| {
                cluster.nodes.get(*nid)
                    .map(|n| n.status == NodeStatus::Ready)
                    .unwrap_or(false)
            })
            .count();

        let unhealthy_nodes: Vec<String> = node_ids.iter()
            .filter(|nid| {
                cluster.nodes.get(*nid)
                    .map(|n| n.status != NodeStatus::Ready)
                    .unwrap_or(true)
            })
            .cloned()
            .collect();

        if (healthy_count as u32) < ha_config.min_replicas && !unhealthy_nodes.is_empty() {
            let deficit = ha_config.min_replicas as usize - healthy_count;
            for i in 0..deficit.min(unhealthy_nodes.len()) {
                actions.push(FailoverAction {
                    app_name: app_name.clone(),
                    failed_node: unhealthy_nodes[i].clone(),
                    action: FailoverType::Reschedule,
                    reason: format!(
                        "Node '{}' unhealthy, app '{}' has {}/{} healthy replicas",
                        unhealthy_nodes[i], app_name, healthy_count, ha_config.min_replicas
                    ),
                });
            }
        }
    }

    actions
}

/// An action to take for failover.
#[derive(Debug, Clone)]
pub struct FailoverAction {
    pub app_name: String,
    pub failed_node: String,
    pub action: FailoverType,
    pub reason: String,
}

#[derive(Debug, Clone, PartialEq)]
pub enum FailoverType {
    /// Reschedule the app on a new node.
    Reschedule,
    /// Alert but don't take action.
    Alert,
}

// ── Utilities ─────────────────────────────────────────────────────────────

fn now_iso8601() -> String {
    let d = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    let secs = d.as_secs();
    let (year, month, day, hour, min, sec) = secs_to_datetime(secs);
    format!("{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z", year, month, day, hour, min, sec)
}

fn current_timestamp_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn parse_timestamp_secs(iso: &str) -> Option<u64> {
    // Simple ISO 8601 parser: YYYY-MM-DDTHH:MM:SSZ
    if iso.len() < 19 { return None; }
    let year: u64 = iso[0..4].parse().ok()?;
    let month: u64 = iso[5..7].parse().ok()?;
    let day: u64 = iso[8..10].parse().ok()?;
    let hour: u64 = iso[11..13].parse().ok()?;
    let min: u64 = iso[14..16].parse().ok()?;
    let sec: u64 = iso[17..19].parse().ok()?;

    // Rough conversion (not accounting for leap years precisely).
    let days = (year - 1970) * 365 + (year - 1969) / 4
        + month_days(month, year) + day - 1;
    Some(days * 86400 + hour * 3600 + min * 60 + sec)
}

fn month_days(month: u64, year: u64) -> u64 {
    let days_in_months = [0, 31, 59, 90, 120, 151, 181, 212, 243, 273, 304, 334];
    let base = if month > 1 && month <= 12 { days_in_months[month as usize - 1] } else { 0 };
    // Leap year adjustment.
    if month > 2 && (year % 4 == 0 && (year % 100 != 0 || year % 400 == 0)) {
        base + 1
    } else {
        base
    }
}

fn secs_to_datetime(total_secs: u64) -> (u64, u64, u64, u64, u64, u64) {
    let sec = total_secs % 60;
    let min = (total_secs / 60) % 60;
    let hour = (total_secs / 3600) % 24;
    let mut days = total_secs / 86400;

    let mut year = 1970;
    loop {
        let days_in_year = if year % 4 == 0 && (year % 100 != 0 || year % 400 == 0) { 366 } else { 365 };
        if days < days_in_year { break; }
        days -= days_in_year;
        year += 1;
    }

    let leap = year % 4 == 0 && (year % 100 != 0 || year % 400 == 0);
    let month_lengths = [31, if leap { 29 } else { 28 }, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
    let mut month = 1;
    for &ml in &month_lengths {
        if days < ml { break; }
        days -= ml;
        month += 1;
    }

    (year, month, days + 1, hour, min, sec)
}

// ── Generate a unique node ID ─────────────────────────────────────────────

/// Generate a node ID from hostname + random suffix.
pub fn generate_node_id() -> String {
    let hostname = std::env::var("HOSTNAME")
        .or_else(|_| {
            std::process::Command::new("hostname")
                .output()
                .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
                .map_err(|_| std::env::VarError::NotPresent)
        })
        .unwrap_or_else(|_| "node".into());

    let ts = current_timestamp_secs();
    let pid = std::process::id();
    format!("{}-{:x}{:x}", hostname, ts, pid)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_node(id: &str, apps: u32, max_apps: u32) -> ClusterNode {
        ClusterNode {
            id: id.into(),
            host: format!("{}.local", id),
            api_port: 8080,
            status: NodeStatus::Ready,
            capacity: NodeCapacity {
                cpu_cores: 4,
                memory_mb: 8192,
                disk_mb: 50000,
                max_apps,
            },
            usage: NodeUsage {
                cpu_percent: 0.0,
                memory_used_mb: 0,
                disk_used_mb: 0,
                running_apps: apps,
            },
            apps: Vec::new(),
            last_heartbeat: now_iso8601(),
            labels: HashMap::new(),
            registered_at: now_iso8601(),
        }
    }

    #[test]
    fn test_register_and_deregister_node() {
        let mut cluster = ClusterState::default();
        let node = make_node("node1", 0, 10);
        cluster.register_node(node);
        assert_eq!(cluster.nodes.len(), 1);
        assert!(cluster.nodes.contains_key("node1"));

        cluster.deregister_node("node1");
        assert!(cluster.nodes.is_empty());
    }

    #[test]
    fn test_heartbeat() {
        let mut cluster = ClusterState::default();
        let mut node = make_node("node1", 0, 10);
        node.status = NodeStatus::NotReady;
        cluster.register_node(node);

        assert!(cluster.heartbeat("node1"));
        assert_eq!(cluster.nodes["node1"].status, NodeStatus::Ready);

        assert!(!cluster.heartbeat("nonexistent"));
    }

    #[test]
    fn test_check_heartbeats_timeout() {
        let mut cluster = ClusterState::default();
        cluster.heartbeat_timeout_secs = 1;

        let mut node = make_node("node1", 0, 10);
        // Set heartbeat to 5 seconds ago.
        node.last_heartbeat = "2020-01-01T00:00:00Z".into();
        cluster.register_node(node);

        let failed = cluster.check_heartbeats();
        assert_eq!(failed, vec!["node1"]);
        assert_eq!(cluster.nodes["node1"].status, NodeStatus::NotReady);
    }

    #[test]
    fn test_ready_nodes() {
        let mut cluster = ClusterState::default();
        cluster.register_node(make_node("node1", 0, 10));

        let mut n2 = make_node("node2", 0, 10);
        n2.status = NodeStatus::NotReady;
        cluster.register_node(n2);

        let mut n3 = make_node("node3", 0, 10);
        n3.status = NodeStatus::Draining;
        cluster.register_node(n3);

        let ready = cluster.ready_nodes();
        assert_eq!(ready.len(), 1);
        assert_eq!(ready[0].id, "node1");
    }

    #[test]
    fn test_schedulable_nodes() {
        let mut cluster = ClusterState::default();
        cluster.register_node(make_node("node1", 5, 10)); // Has room.
        cluster.register_node(make_node("node2", 10, 10)); // Full.
        cluster.register_node(make_node("node3", 0, 10)); // Empty.

        let schedulable = cluster.schedulable_nodes();
        assert_eq!(schedulable.len(), 2);
        let ids: Vec<&str> = schedulable.iter().map(|n| n.id.as_str()).collect();
        assert!(ids.contains(&"node1"));
        assert!(ids.contains(&"node3"));
    }

    #[test]
    fn test_drain_and_uncordon() {
        let mut cluster = ClusterState::default();
        cluster.register_node(make_node("node1", 0, 10));

        assert!(cluster.drain_node("node1"));
        assert_eq!(cluster.nodes["node1"].status, NodeStatus::Draining);
        assert!(cluster.ready_nodes().is_empty());

        // Can't uncordon a draining node (only cordoned).
        assert!(!cluster.uncordon_node("node1"));
    }

    #[test]
    fn test_cordon_and_uncordon() {
        let mut cluster = ClusterState::default();
        cluster.register_node(make_node("node1", 0, 10));

        assert!(cluster.cordon_node("node1"));
        assert_eq!(cluster.nodes["node1"].status, NodeStatus::Cordoned);

        assert!(cluster.uncordon_node("node1"));
        assert_eq!(cluster.nodes["node1"].status, NodeStatus::Ready);
    }

    // ── Scheduling Tests ──────────────────────────────────────────────────

    #[test]
    fn test_schedule_bin_pack() {
        let mut cluster = ClusterState::default();
        cluster.register_node(make_node("node1", 8, 10)); // 80% full.
        cluster.register_node(make_node("node2", 2, 10)); // 20% full.

        let decisions = schedule_app(
            &cluster, "myapp",
            &PlacementStrategy::BinPack,
            &[], 1,
        ).unwrap();

        assert_eq!(decisions.len(), 1);
        // BinPack prefers the fuller node.
        assert_eq!(decisions[0].node_id, "node1");
    }

    #[test]
    fn test_schedule_spread() {
        let mut cluster = ClusterState::default();
        cluster.register_node(make_node("node1", 8, 10)); // 80% full.
        cluster.register_node(make_node("node2", 2, 10)); // 20% full.

        let decisions = schedule_app(
            &cluster, "myapp",
            &PlacementStrategy::Spread,
            &[], 1,
        ).unwrap();

        assert_eq!(decisions.len(), 1);
        // Spread prefers the emptier node.
        assert_eq!(decisions[0].node_id, "node2");
    }

    #[test]
    fn test_schedule_multiple_replicas() {
        let mut cluster = ClusterState::default();
        cluster.register_node(make_node("node1", 0, 10));
        cluster.register_node(make_node("node2", 0, 10));
        cluster.register_node(make_node("node3", 0, 10));

        let decisions = schedule_app(
            &cluster, "myapp",
            &PlacementStrategy::Spread,
            &[], 3,
        ).unwrap();

        assert_eq!(decisions.len(), 3);
        // All should be on different nodes.
        let nodes: Vec<&str> = decisions.iter().map(|d| d.node_id.as_str()).collect();
        let mut unique = nodes.clone();
        unique.sort();
        unique.dedup();
        assert_eq!(unique.len(), 3);
    }

    #[test]
    fn test_schedule_no_nodes() {
        let cluster = ClusterState::default();
        let result = schedule_app(&cluster, "myapp", &PlacementStrategy::Spread, &[], 1);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("No schedulable"));
    }

    #[test]
    fn test_schedule_with_affinity() {
        let mut cluster = ClusterState::default();

        let mut n1 = make_node("node1", 0, 10);
        n1.labels.insert("zone".into(), "us-east".into());
        cluster.register_node(n1);

        let mut n2 = make_node("node2", 0, 10);
        n2.labels.insert("zone".into(), "us-west".into());
        cluster.register_node(n2);

        // Require us-east zone.
        let affinity = vec![AffinityRule {
            key: "zone".into(),
            value: "us-east".into(),
            required: true,
        }];

        let decisions = schedule_app(
            &cluster, "myapp",
            &PlacementStrategy::Spread,
            &affinity, 1,
        ).unwrap();

        assert_eq!(decisions[0].node_id, "node1");
    }

    // ── Routing Tests ─────────────────────────────────────────────────────

    #[test]
    fn test_build_routing_table() {
        let mut cluster = ClusterState::default();
        cluster.register_node(make_node("node1", 1, 10));
        cluster.register_node(make_node("node2", 1, 10));
        cluster.placements.insert("myapp".into(), vec!["node1".into(), "node2".into()]);

        let table = DistributedRoutingTable::build_from_cluster(&cluster);
        let backends = table.get_backends("myapp");
        assert_eq!(backends.len(), 2);
    }

    #[test]
    fn test_routing_round_robin() {
        let mut cluster = ClusterState::default();
        cluster.register_node(make_node("node1", 1, 10));
        cluster.register_node(make_node("node2", 1, 10));
        cluster.placements.insert("myapp".into(), vec!["node1".into(), "node2".into()]);

        let table = DistributedRoutingTable::build_from_cluster(&cluster);

        let b1 = table.select_backend("myapp", 0).unwrap();
        let b2 = table.select_backend("myapp", 1).unwrap();
        // Should alternate between node1 and node2.
        assert_ne!(b1.node_id, b2.node_id);
    }

    #[test]
    fn test_routing_mark_unhealthy() {
        let mut cluster = ClusterState::default();
        cluster.register_node(make_node("node1", 1, 10));
        cluster.register_node(make_node("node2", 1, 10));
        cluster.placements.insert("myapp".into(), vec!["node1".into(), "node2".into()]);

        let mut table = DistributedRoutingTable::build_from_cluster(&cluster);
        assert_eq!(table.get_backends("myapp").len(), 2);

        table.mark_unhealthy("myapp", "node1");
        let healthy = table.get_backends("myapp");
        assert_eq!(healthy.len(), 1);
        assert_eq!(healthy[0].node_id, "node2");

        table.mark_healthy("myapp", "node1");
        assert_eq!(table.get_backends("myapp").len(), 2);
    }

    #[test]
    fn test_routing_no_app() {
        let table = DistributedRoutingTable::default();
        assert!(table.get_backends("nonexistent").is_empty());
        assert!(table.select_backend("nonexistent", 0).is_none());
    }

    // ── Slug Storage Tests ────────────────────────────────────────────────

    #[test]
    fn test_slug_storage_filesystem() {
        let dir = std::env::temp_dir().join(format!("phprs-test-slug-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);

        let storage = SlugStorage {
            backend: SlugStorageBackend::Filesystem,
            local_path: dir.to_string_lossy().to_string(),
            ..Default::default()
        };

        // Create a test slug.
        let slug_src = dir.join("source.tar.gz");
        std::fs::create_dir_all(dir.clone()).unwrap();
        std::fs::write(&slug_src, b"fake slug data").unwrap();

        let result = storage.store_slug("myapp", "v1", slug_src.to_str().unwrap());
        assert!(result.is_ok());
        let stored_path = result.unwrap();
        assert!(std::path::Path::new(&stored_path).exists());

        // Pull slug.
        let pull_dest = dir.join("pulled.tar.gz");
        let result = storage.pull_slug("myapp", "v1", pull_dest.to_str().unwrap());
        assert!(result.is_ok());
        assert!(pull_dest.exists());

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_slug_storage_default() {
        let storage = SlugStorage::default();
        assert_eq!(storage.backend, SlugStorageBackend::Filesystem);
        assert_eq!(storage.local_path, "/var/lib/php-rs/slugs");
    }

    // ── Failover Tests ────────────────────────────────────────────────────

    #[test]
    fn test_failover_healthy_cluster() {
        let mut cluster = ClusterState::default();
        cluster.register_node(make_node("node1", 1, 10));
        cluster.register_node(make_node("node2", 1, 10));
        cluster.placements.insert("myapp".into(), vec!["node1".into(), "node2".into()]);

        let ha = HAConfig { min_replicas: 2, ..Default::default() };
        let actions = check_failover(&cluster, &ha);
        assert!(actions.is_empty());
    }

    #[test]
    fn test_failover_node_down() {
        let mut cluster = ClusterState::default();
        cluster.register_node(make_node("node1", 1, 10));
        let mut n2 = make_node("node2", 1, 10);
        n2.status = NodeStatus::NotReady;
        cluster.register_node(n2);
        cluster.placements.insert("myapp".into(), vec!["node1".into(), "node2".into()]);

        let ha = HAConfig { min_replicas: 2, ..Default::default() };
        let actions = check_failover(&cluster, &ha);
        assert_eq!(actions.len(), 1);
        assert_eq!(actions[0].app_name, "myapp");
        assert_eq!(actions[0].failed_node, "node2");
        assert_eq!(actions[0].action, FailoverType::Reschedule);
    }

    #[test]
    fn test_failover_disabled() {
        let mut cluster = ClusterState::default();
        let mut n1 = make_node("node1", 1, 10);
        n1.status = NodeStatus::NotReady;
        cluster.register_node(n1);
        cluster.placements.insert("myapp".into(), vec!["node1".into()]);

        let ha = HAConfig { auto_failover: false, ..Default::default() };
        let actions = check_failover(&cluster, &ha);
        assert!(actions.is_empty());
    }

    #[test]
    fn test_failover_sufficient_replicas() {
        let mut cluster = ClusterState::default();
        cluster.register_node(make_node("node1", 1, 10));
        cluster.register_node(make_node("node2", 1, 10));
        let mut n3 = make_node("node3", 1, 10);
        n3.status = NodeStatus::NotReady;
        cluster.register_node(n3);
        cluster.placements.insert("myapp".into(), vec!["node1".into(), "node2".into(), "node3".into()]);

        // Need 2 replicas, have 2 healthy — no failover needed.
        let ha = HAConfig { min_replicas: 2, ..Default::default() };
        let actions = check_failover(&cluster, &ha);
        assert!(actions.is_empty());
    }

    #[test]
    fn test_migration_plan() {
        let cluster = ClusterState::default();
        let plan = plan_migration(&cluster, "myapp", "node1", "node2");
        assert_eq!(plan.app_name, "myapp");
        assert_eq!(plan.source_node, "node1");
        assert_eq!(plan.target_node, "node2");
        assert_eq!(plan.steps.len(), 5);
    }

    #[test]
    fn test_generate_node_id() {
        let id = generate_node_id();
        assert!(!id.is_empty());
        // Should contain a hex suffix.
        assert!(id.contains('-'));
    }

    #[test]
    fn test_ha_config_default() {
        let ha = HAConfig::default();
        assert_eq!(ha.min_replicas, 1);
        assert!(ha.spread_replicas);
        assert!(ha.auto_failover);
        assert_eq!(ha.failover_timeout_secs, 60);
    }

    #[test]
    fn test_node_status_serialization() {
        let json = serde_json::to_string(&NodeStatus::Ready).unwrap();
        let parsed: NodeStatus = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, NodeStatus::Ready);
    }
}
