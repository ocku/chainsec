mod dependency;
mod finding;
mod limits;
mod remote;
mod report;

pub(crate) use dependency::{DenoLockfileSnapshot, canonical_http_url};
pub use dependency::{Dependency, Ecosystem, FetchMetadata};
pub use finding::{
    AnalysisPoint, Capability, Confidence, EntropyMatcher, FindingType, Language, Location, Risk,
    Rule, RuleGroup, Suppression,
};
pub use limits::{
    DEFAULT_MAX_ACQUISITION_SECONDS, DEFAULT_MAX_ARCHIVE_SIZE, DEFAULT_MAX_EXTRACTED_FILES,
    DEFAULT_MAX_EXTRACTED_SIZE, DEFAULT_MAX_FILE_DEPTH, DEFAULT_MAX_FINDINGS,
    DEFAULT_MAX_MANIFEST_FILE_SIZE, DEFAULT_MAX_NETWORK_REQUESTS, DEFAULT_MAX_PACKAGE_DEPTH,
    DEFAULT_MAX_PACKAGES, DEFAULT_MAX_REDIRECT_HOPS, DEFAULT_MAX_SCAN_SECONDS,
    DEFAULT_MAX_SOURCE_FILE_SIZE, DEFAULT_MAX_SOURCE_FILES, DEFAULT_REQUEST_TIMEOUT_SECONDS,
    EngineLimits, SerializableLimits,
};
pub use remote::parse_remote_package;
pub use report::{
    CapabilityEvidence, CapabilityReport, OperationalIssue, PackageReport, PolicySummary, Report,
    ScanStatistics,
};

pub const REPORT_SCHEMA_VERSION: &str = "1.2.0";
