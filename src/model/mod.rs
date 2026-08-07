mod dependency;
mod finding;
mod limits;
mod report;

pub use dependency::{Dependency, Ecosystem, FetchMetadata};
pub use finding::{
    AnalysisPoint, Confidence, EntropyMatcher, FindingType, Language, Location, Risk, Rule,
    RuleGroup,
};
pub use limits::{EngineLimits, SerializableLimits};
pub use report::{OperationalIssue, PackageReport, PolicySummary, Report, ScanStatistics};

pub const REPORT_SCHEMA_VERSION: &str = "1.0.0";
