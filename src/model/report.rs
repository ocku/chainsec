use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use super::{AnalysisPoint, SerializableLimits};
use crate::model::REPORT_SCHEMA_VERSION;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PackageReport {
    pub package_id: String,
    pub source: PathBuf,
    pub source_url: Option<String>,
    pub resolved_version: Option<String>,
    pub digest: Option<String>,
    pub depth: usize,
    pub dependencies: Vec<String>,
    pub scanned_files: u64,
    pub scanned_bytes: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OperationalIssue {
    pub code: String,
    pub message: String,
    pub package: Option<String>,
    pub operation: String,
    pub fatal: bool,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ScanStatistics {
    pub packages: u64,
    pub source_files: u64,
    pub source_bytes: u64,
    pub findings: u64,
    pub cache_hits: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Report {
    pub schema_version: String,
    pub tool_version: String,
    pub root: PathBuf,
    pub policy: PolicySummary,
    pub packages: Vec<PackageReport>,
    pub findings: Vec<AnalysisPoint>,
    pub issues: Vec<OperationalIssue>,
    pub statistics: ScanStatistics,
}

impl Report {
    pub fn new(root: PathBuf, policy: PolicySummary) -> Self {
        Self {
            schema_version: REPORT_SCHEMA_VERSION.to_owned(),
            tool_version: env!("CARGO_PKG_VERSION").to_owned(),
            root,
            policy,
            packages: Vec::new(),
            findings: Vec::new(),
            issues: Vec::new(),
            statistics: ScanStatistics::default(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicySummary {
    pub require_lockfile: bool,
    pub offline: bool,
    pub trust_local_input: bool,
    pub allowed_hosts: Vec<String>,
    pub limits: SerializableLimits,
}
