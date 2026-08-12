mod dependency;
mod finding;
mod limits;
mod report;

pub(crate) use dependency::{DenoLockfileSnapshot, canonical_deno_remote_url};
pub use dependency::{Dependency, Ecosystem, FetchMetadata};
pub use finding::{
    AnalysisPoint, Capability, Confidence, EntropyMatcher, FindingType, Language, Location, Risk,
    Rule, RuleGroup, Suppression,
};
pub use limits::{EngineLimits, SerializableLimits};
pub use report::{
    CapabilityEvidence, CapabilityReport, OperationalIssue, PackageReport, PolicySummary, Report,
    ScanStatistics,
};

pub const REPORT_SCHEMA_VERSION: &str = "1.2.0";
