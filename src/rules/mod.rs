use std::{collections::HashSet, fs, path::Path};

use regex::bytes::Regex;
use serde::Deserialize;

use crate::{
    error::{Error, Result},
    model::{
        AnalysisPoint, CapabilityEvidence, Confidence, FindingType, Language, Risk, Rule, RuleGroup,
    },
};

macro_rules! rule {
    ($id:expr, $language:expr, $kind:expr, $risk:expr, $confidence:expr, $rationale:expr, $remediation:expr, $query:expr) => {
        $crate::rules::standard_rule(
            $id,
            $language,
            $crate::rules::RuleDefinition {
                finding_type: $kind,
                risk: $risk,
                confidence: $confidence,
                rationale: $rationale,
                remediation: $remediation,
                query: $query,
            },
        )
    };
}

pub(super) struct RuleDefinition<'a> {
    pub(super) finding_type: FindingType,
    pub(super) risk: Risk,
    pub(super) confidence: Confidence,
    pub(super) rationale: &'a str,
    pub(super) remediation: &'a str,
    pub(super) query: &'a str,
}

pub(super) fn standard_rule(id: &str, language: Language, definition: RuleDefinition<'_>) -> Rule {
    Rule {
        id: canonical_rule_id(id.to_owned(), language),
        version: 1,
        language,
        finding_type: definition.finding_type,
        risk: definition.risk,
        confidence: definition.confidence,
        rationale: definition.rationale.to_owned(),
        remediation: definition.remediation.to_owned(),
        capability: None,
        query: definition.query.to_owned(),
        entropy: None,
    }
}

fn canonical_rule_id(id: String, language: Language) -> String {
    let suffix = match language {
        Language::Python => ".py",
        Language::JavaScript => ".js",
        Language::TypeScript => ".ts",
    };
    let Some(name) = id.strip_suffix(suffix) else {
        return id;
    };
    let Some(name) = name.strip_prefix("chainsec.") else {
        return id;
    };
    let language = match language {
        Language::Python => "py",
        Language::JavaScript => "js",
        Language::TypeScript => "ts",
    };
    format!("chainsec.{language}.{name}")
}

mod built_in;
mod capabilities;

pub use built_in::built_in_rules;
pub use capabilities::capability_rules;

/// Returns the complete default catalog used by the CLI.
///
/// Detection rules (including GuardDog-derived rules) are kept separate from
/// informational-only capability rules.
pub fn default_rules() -> Vec<Rule> {
    let mut rules = built_in_rules();
    rules.extend(capability_rules());
    rules
}

#[derive(Debug, Clone)]
pub struct RuleSelector {
    group: Option<RuleGroup>,
    rule_id_glob: String,
    matcher: Regex,
}

impl PartialEq for RuleSelector {
    fn eq(&self, other: &Self) -> bool {
        self.group == other.group && self.rule_id_glob == other.rule_id_glob
    }
}

impl Eq for RuleSelector {}

impl RuleSelector {
    pub fn matches_rule(&self, rule: &Rule) -> bool {
        self.matches(rule.finding_type, &rule.id)
    }

    pub fn matches_finding(&self, finding: &AnalysisPoint) -> bool {
        self.matches(finding.finding_type, &finding.rule_id)
    }

    pub fn matches_capability_evidence(&self, evidence: &CapabilityEvidence) -> bool {
        self.matches(evidence.finding_type, &evidence.rule_id)
    }

    fn matches(&self, finding_type: FindingType, rule_id: &str) -> bool {
        self.group
            .is_none_or(|group| finding_type.rule_group() == group)
            && self.matcher.is_match(rule_id.as_bytes())
    }
}

pub fn parse_rule_selector(value: &str) -> Result<RuleSelector> {
    let (group, rule_id_glob) = match value.split_once(':') {
        Some((group, rule_id_glob)) => {
            let group = RuleGroup::parse(group).ok_or_else(|| Error::InvalidConfiguration {
                message: format!("invalid rule group {group:?} in selector {value:?}"),
            })?;
            (Some(group), rule_id_glob)
        }
        None => (None, value),
    };

    if rule_id_glob.is_empty()
        || !rule_id_glob.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.' | b'*' | b'?')
        })
    {
        return Err(Error::InvalidConfiguration {
            message: format!("invalid rule selector {value:?}"),
        });
    }

    let matcher =
        Regex::new(&glob_regex(rule_id_glob)).map_err(|error| Error::InvalidConfiguration {
            message: format!("invalid rule selector {value:?}: {error}"),
        })?;

    Ok(RuleSelector {
        group,
        rule_id_glob: rule_id_glob.to_owned(),
        matcher,
    })
}

fn glob_regex(pattern: &str) -> String {
    let mut regex = String::with_capacity(pattern.len() + 4);
    regex.push_str(r"\A(?:");
    for byte in pattern.bytes() {
        match byte {
            b'*' => regex.push_str(".*"),
            b'?' => regex.push('.'),
            byte if byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-') => {
                regex.push(byte as char);
            }
            b'.' => regex.push_str(r"\."),
            _ => unreachable!("rule selector syntax was validated before regex compilation"),
        }
    }
    regex.push_str(r")\z");
    regex
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RulePack {
    #[serde(default)]
    rules: Vec<Rule>,
}

pub fn load_rule_pack(path: &Path) -> Result<Vec<Rule>> {
    let text = fs::read_to_string(path).map_err(|source| Error::Io {
        operation: "read rule pack".to_owned(),
        path: path.to_owned(),
        source,
    })?;
    let pack = parse_rule_pack(path, &text)?;

    if pack.rules.is_empty() {
        return Err(Error::InvalidConfiguration {
            message: format!("rule pack {} contains no rules", path.display()),
        });
    }

    validate_rules(&pack.rules)?;
    Ok(pack.rules)
}

fn parse_rule_pack(path: &Path, text: &str) -> Result<RulePack> {
    let parse_error = |error: &dyn std::fmt::Display| Error::InvalidConfiguration {
        message: format!("invalid rule pack {}: {error}", path.display()),
    };

    match path.extension().and_then(|extension| extension.to_str()) {
        Some("json") => serde_json::from_str(text).map_err(|error| parse_error(&error)),
        Some("yaml" | "yml") => serde_yaml::from_str(text).map_err(|error| parse_error(&error)),
        _ => Err(Error::InvalidConfiguration {
            message: format!(
                "rule pack {} must use a .json, .yaml, or .yml extension",
                path.display()
            ),
        }),
    }
}

pub fn validate_rules(rules: &[Rule]) -> Result<()> {
    let mut ids = HashSet::new();

    for rule in rules {
        validate_rule(rule)?;
        ensure_unique_rule_id(&mut ids, rule)?;
    }

    Ok(())
}

fn validate_rule(rule: &Rule) -> Result<()> {
    validate_rule_id(&rule.id)?;

    if rule.version == 0 {
        return Err(Error::InvalidConfiguration {
            message: format!("rule {} has version 0", rule.id),
        });
    }

    if rule
        .entropy
        .as_ref()
        .is_some_and(has_invalid_entropy_limits)
    {
        return Err(Error::InvalidConfiguration {
            message: format!(
                "rule {} has invalid entropy limits (length must be positive, entropy must be finite between 0 and 8, and whitespace ratio must be finite between 0 and 1)",
                rule.id
            ),
        });
    }

    Ok(())
}

pub fn validate_rule_id(id: &str) -> Result<()> {
    if !id.is_empty()
        && id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.'))
    {
        return Ok(());
    }

    Err(Error::InvalidConfiguration {
        message: format!("invalid rule id {id:?}"),
    })
}

fn has_invalid_entropy_limits(entropy: &crate::model::EntropyMatcher) -> bool {
    entropy.minimum_length == 0
        || !entropy.minimum_entropy.is_finite()
        || !(0.0..=8.0).contains(&entropy.minimum_entropy)
        || !entropy.maximum_whitespace_ratio.is_finite()
        || !(0.0..=1.0).contains(&entropy.maximum_whitespace_ratio)
}

fn ensure_unique_rule_id(ids: &mut HashSet<String>, rule: &Rule) -> Result<()> {
    if ids.insert(rule.id.clone()) {
        return Ok(());
    }

    Err(Error::InvalidConfiguration {
        message: format!("duplicate rule id {}", rule.id),
    })
}

#[cfg(test)]
mod tests;
