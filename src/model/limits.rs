use std::time::Duration;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SerializableLimits {
    pub max_depth: usize,
    pub max_packages: usize,
    pub max_archive_bytes: u64,
    pub max_extracted_bytes: u64,
    pub max_extracted_files: u64,
    pub max_source_file_bytes: u64,
    pub max_source_files: u64,
    pub max_scan_seconds: u64,
}

#[derive(Debug, Clone)]
pub struct EngineLimits {
    pub max_depth: usize,
    pub max_packages: usize,
    pub max_archive_bytes: u64,
    pub max_extracted_bytes: u64,
    pub max_extracted_files: u64,
    pub max_source_file_bytes: u64,
    pub max_source_files: u64,
    pub max_scan_duration: Duration,
}

impl Default for EngineLimits {
    fn default() -> Self {
        Self {
            max_depth: 3,
            max_packages: 500,
            max_archive_bytes: 100 * 1024 * 1024,
            max_extracted_bytes: 500 * 1024 * 1024,
            max_extracted_files: 50_000,
            max_source_file_bytes: 2 * 1024 * 1024,
            max_source_files: 100_000,
            max_scan_duration: Duration::from_secs(300),
        }
    }
}

impl From<&EngineLimits> for SerializableLimits {
    fn from(value: &EngineLimits) -> Self {
        Self {
            max_depth: value.max_depth,
            max_packages: value.max_packages,
            max_archive_bytes: value.max_archive_bytes,
            max_extracted_bytes: value.max_extracted_bytes,
            max_extracted_files: value.max_extracted_files,
            max_source_file_bytes: value.max_source_file_bytes,
            max_source_files: value.max_source_files,
            max_scan_seconds: value.max_scan_duration.as_secs(),
        }
    }
}
