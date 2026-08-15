use std::time::Duration;

use serde::{Deserialize, Serialize};

pub const DEFAULT_MAX_PACKAGE_DEPTH: usize = 3;
pub const DEFAULT_MAX_PACKAGES: usize = 4096;
pub const DEFAULT_MAX_NETWORK_REQUESTS: usize = 1_000;
pub const DEFAULT_MAX_REDIRECT_HOPS: usize = 5;
pub const DEFAULT_REQUEST_TIMEOUT_SECONDS: u64 = 30;
pub const DEFAULT_MAX_ACQUISITION_SECONDS: u64 = 300;
pub const DEFAULT_MAX_ARCHIVE_SIZE: u64 = 100 * 1024 * 1024;
pub const DEFAULT_MAX_EXTRACTED_SIZE: u64 = 500 * 1024 * 1024;
pub const DEFAULT_MAX_EXTRACTED_FILES: u64 = 50_000;
pub const DEFAULT_MAX_FILE_DEPTH: usize = 128;
pub const DEFAULT_MAX_MANIFEST_FILE_SIZE: u64 = 2 * 1024 * 1024;
pub const DEFAULT_MAX_SOURCE_FILE_SIZE: u64 = 2 * 1024 * 1024;
pub const DEFAULT_MAX_SOURCE_FILES: u64 = 100_000;
pub const DEFAULT_MAX_FINDINGS: u64 = 100_000;
pub const DEFAULT_MAX_SCAN_SECONDS: u64 = 300;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SerializableLimits {
    pub max_package_depth: usize,
    pub max_packages: usize,
    pub max_network_requests: usize,
    #[serde(default = "default_max_redirect_hops")]
    pub max_redirect_hops: usize,
    #[serde(default = "default_request_timeout_seconds")]
    pub request_timeout_seconds: u64,
    pub max_acquisition_seconds: u64,
    pub max_archive_size: u64,
    pub max_extracted_size: u64,
    pub max_extracted_files: u64,
    #[serde(default = "default_max_file_depth")]
    pub max_file_depth: usize,
    #[serde(default = "default_max_manifest_file_size")]
    pub max_manifest_file_size: u64,
    pub max_source_file_size: u64,
    pub max_source_files: u64,
    pub max_findings: u64,
    pub max_scan_seconds: u64,
    #[serde(default)]
    pub fail_on_parse_error: bool,
}

#[derive(Debug, Clone)]
pub struct EngineLimits {
    pub max_package_depth: usize,
    pub max_packages: usize,
    pub max_network_requests: usize,
    pub max_redirect_hops: usize,
    pub request_timeout: Duration,
    pub max_acquisition_duration: Duration,
    pub max_archive_size: u64,
    pub max_extracted_size: u64,
    pub max_extracted_files: u64,
    pub max_file_depth: usize,
    pub max_manifest_file_size: u64,
    pub max_source_file_size: u64,
    pub max_source_files: u64,
    pub max_findings: u64,
    pub max_scan_duration: Duration,
    pub fail_on_parse_error: bool,
}

const fn default_max_redirect_hops() -> usize {
    DEFAULT_MAX_REDIRECT_HOPS
}

const fn default_request_timeout_seconds() -> u64 {
    DEFAULT_REQUEST_TIMEOUT_SECONDS
}

const fn default_max_file_depth() -> usize {
    DEFAULT_MAX_FILE_DEPTH
}

const fn default_max_manifest_file_size() -> u64 {
    DEFAULT_MAX_MANIFEST_FILE_SIZE
}

impl Default for EngineLimits {
    fn default() -> Self {
        Self {
            max_package_depth: DEFAULT_MAX_PACKAGE_DEPTH,
            max_packages: DEFAULT_MAX_PACKAGES,
            max_network_requests: DEFAULT_MAX_NETWORK_REQUESTS,
            max_redirect_hops: DEFAULT_MAX_REDIRECT_HOPS,
            request_timeout: Duration::from_secs(DEFAULT_REQUEST_TIMEOUT_SECONDS),
            max_acquisition_duration: Duration::from_secs(DEFAULT_MAX_ACQUISITION_SECONDS),
            max_archive_size: DEFAULT_MAX_ARCHIVE_SIZE,
            max_extracted_size: DEFAULT_MAX_EXTRACTED_SIZE,
            max_extracted_files: DEFAULT_MAX_EXTRACTED_FILES,
            max_file_depth: DEFAULT_MAX_FILE_DEPTH,
            max_manifest_file_size: DEFAULT_MAX_MANIFEST_FILE_SIZE,
            max_source_file_size: DEFAULT_MAX_SOURCE_FILE_SIZE,
            max_source_files: DEFAULT_MAX_SOURCE_FILES,
            max_findings: DEFAULT_MAX_FINDINGS,
            max_scan_duration: Duration::from_secs(DEFAULT_MAX_SCAN_SECONDS),
            fail_on_parse_error: false,
        }
    }
}

impl From<&EngineLimits> for SerializableLimits {
    fn from(value: &EngineLimits) -> Self {
        Self {
            max_package_depth: value.max_package_depth,
            max_packages: value.max_packages,
            max_network_requests: value.max_network_requests,
            max_redirect_hops: value.max_redirect_hops,
            request_timeout_seconds: value.request_timeout.as_secs(),
            max_acquisition_seconds: value.max_acquisition_duration.as_secs(),
            max_archive_size: value.max_archive_size,
            max_extracted_size: value.max_extracted_size,
            max_extracted_files: value.max_extracted_files,
            max_file_depth: value.max_file_depth,
            max_manifest_file_size: value.max_manifest_file_size,
            max_source_file_size: value.max_source_file_size,
            max_source_files: value.max_source_files,
            max_findings: value.max_findings,
            max_scan_seconds: value.max_scan_duration.as_secs(),
            fail_on_parse_error: value.fail_on_parse_error,
        }
    }
}

#[cfg(test)]
mod tests;
