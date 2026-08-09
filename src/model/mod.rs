mod dependency;
mod finding;
mod limits;
mod report;

pub use dependency::{Dependency, Ecosystem, FetchMetadata};
pub use finding::{
    AnalysisPoint, Capability, Confidence, EntropyMatcher, FindingType, Language, Location,
    Matcher, Risk, Rule, RuleGroup, SemanticRule, Suppression,
};
pub use limits::{EngineLimits, SerializableLimits};
pub use report::{
    CapabilityEvidence, CapabilityReport, OperationalIssue, PackageReport, PolicySummary, Report,
    ScanStatistics,
};

pub const REPORT_SCHEMA_VERSION: &str = "1.1.0";
