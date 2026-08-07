use std::path::PathBuf;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Risk {
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Confidence {
    Low,
    Medium,
    High,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FindingType {
    ArbitraryCodeExecution,
    CodeObfuscation,
    ProcessExecution,
    NetworkAccess,
    FilesystemAccess,
    SecretAccess,
    DynamicLoading,
    Deserialization,
    InstallScript,
    FileAnalysis,
}

/// A stable category used to target related rules with an ignore selector.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RuleGroup {
    Execution,
    Obfuscation,
    Process,
    Network,
    Filesystem,
    Secret,
    Loading,
    Deserialization,
    Install,
    File,
}

impl FindingType {
    pub const fn rule_group(self) -> RuleGroup {
        match self {
            Self::ArbitraryCodeExecution => RuleGroup::Execution,
            Self::CodeObfuscation => RuleGroup::Obfuscation,
            Self::ProcessExecution => RuleGroup::Process,
            Self::NetworkAccess => RuleGroup::Network,
            Self::FilesystemAccess => RuleGroup::Filesystem,
            Self::SecretAccess => RuleGroup::Secret,
            Self::DynamicLoading => RuleGroup::Loading,
            Self::Deserialization => RuleGroup::Deserialization,
            Self::InstallScript => RuleGroup::Install,
            Self::FileAnalysis => RuleGroup::File,
        }
    }
}

impl RuleGroup {
    pub const fn name(self) -> &'static str {
        match self {
            Self::Execution => "execution",
            Self::Obfuscation => "obfuscation",
            Self::Process => "process",
            Self::Network => "network",
            Self::Filesystem => "filesystem",
            Self::Secret => "secret",
            Self::Loading => "loading",
            Self::Deserialization => "deserialization",
            Self::Install => "install",
            Self::File => "file",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "execution" => Some(Self::Execution),
            "obfuscation" => Some(Self::Obfuscation),
            "process" => Some(Self::Process),
            "network" | "network-access" => Some(Self::Network),
            "filesystem" | "filesystem-access" | "fs" => Some(Self::Filesystem),
            "secret" => Some(Self::Secret),
            "loading" => Some(Self::Loading),
            "deserialization" => Some(Self::Deserialization),
            "install" => Some(Self::Install),
            "file" => Some(Self::File),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Language {
    Python,
    JavaScript,
    TypeScript,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EntropyMatcher {
    pub minimum_length: usize,
    pub minimum_entropy: f64,
    #[serde(default = "default_maximum_whitespace_ratio")]
    pub maximum_whitespace_ratio: f64,
}

fn default_maximum_whitespace_ratio() -> f64 {
    0.05
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Rule {
    pub id: String,
    pub version: u32,
    pub language: Language,
    pub finding_type: FindingType,
    pub risk: Risk,
    pub confidence: Confidence,
    pub rationale: String,
    pub remediation: String,
    pub query: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub entropy: Option<EntropyMatcher>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Location {
    pub start_line: usize,
    pub start_column: usize,
    pub end_line: usize,
    pub end_column: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnalysisPoint {
    pub id: String,
    pub rule_id: String,
    pub rule_version: u32,
    pub finding_type: FindingType,
    pub risk: Risk,
    pub confidence: Confidence,
    pub rationale: String,
    pub remediation: String,
    pub package: String,
    pub file: PathBuf,
    pub location: Location,
    pub matched_code: String,
    pub suppressed: bool,
}

impl AnalysisPoint {
    pub fn stable_id(
        rule_id: &str,
        rule_version: u32,
        package: &str,
        file: &str,
        location: &Location,
        matched_code: &str,
    ) -> String {
        let input = format!(
            "{rule_id}\0{rule_version}\0{package}\0{file}\0{}:{}-{}:{}\0{matched_code}",
            location.start_line, location.start_column, location.end_line, location.end_column
        );
        format!("sha256:{}", hex::encode(Sha256::digest(input.as_bytes())))
    }
}
