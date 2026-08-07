use std::{collections::HashSet, fs, path::Path};

use serde::Deserialize;

use crate::{
    error::{Error, Result},
    model::{AnalysisPoint, Confidence, FindingType, Language, Risk, Rule, RuleGroup},
};

macro_rules! rule {
    ($id:expr, $language:expr, $kind:expr, $risk:expr, $confidence:expr, $rationale:expr, $remediation:expr, $query:expr) => {
        super::standard_rule(
            $id,
            $language,
            super::RuleDefinition {
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
        id: id.to_owned(),
        version: 1,
        language,
        finding_type: definition.finding_type,
        risk: definition.risk,
        confidence: definition.confidence,
        rationale: definition.rationale.to_owned(),
        remediation: definition.remediation.to_owned(),
        query: definition.query.to_owned(),
        entropy: None,
    }
}

mod built_in;
mod guarddog;

pub use built_in::built_in_rules;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuleSelector {
    group: Option<RuleGroup>,
    rule_id_glob: String,
}

impl RuleSelector {
    pub fn matches_rule(&self, rule: &Rule) -> bool {
        self.matches(rule.finding_type, &rule.id)
    }

    pub fn matches_finding(&self, finding: &AnalysisPoint) -> bool {
        self.matches(finding.finding_type, &finding.rule_id)
    }

    fn matches(&self, finding_type: FindingType, rule_id: &str) -> bool {
        self.group
            .is_none_or(|group| finding_type.rule_group() == group)
            && glob_matches(&self.rule_id_glob, rule_id)
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

    Ok(RuleSelector {
        group,
        rule_id_glob: rule_id_glob.to_owned(),
    })
}

fn glob_matches(pattern: &str, value: &str) -> bool {
    let (pattern, value) = (pattern.as_bytes(), value.as_bytes());
    let (mut pattern_index, mut value_index) = (0, 0);
    let (mut star_index, mut star_value_index) = (None, 0);

    while value_index < value.len() {
        if pattern_index < pattern.len()
            && (pattern[pattern_index] == b'?' || pattern[pattern_index] == value[value_index])
        {
            pattern_index += 1;
            value_index += 1;
        } else if pattern_index < pattern.len() && pattern[pattern_index] == b'*' {
            star_index = Some(pattern_index);
            pattern_index += 1;
            star_value_index = value_index;
        } else if let Some(star) = star_index {
            pattern_index = star + 1;
            star_value_index += 1;
            value_index = star_value_index;
        } else {
            return false;
        }
    }

    while pattern_index < pattern.len() && pattern[pattern_index] == b'*' {
        pattern_index += 1;
    }
    pattern_index == pattern.len()
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
mod tests {
    use super::*;
    use crate::model::{Confidence, EntropyMatcher, FindingType, Language, Risk};

    fn rule(entropy: Option<EntropyMatcher>) -> Rule {
        Rule {
            id: "CUSTOM".to_owned(),
            version: 1,
            language: Language::Python,
            finding_type: FindingType::CodeObfuscation,
            risk: Risk::Medium,
            confidence: Confidence::Medium,
            rationale: "rationale".to_owned(),
            remediation: "remediation".to_owned(),
            query: "(string) @match".to_owned(),
            entropy,
        }
    }

    #[test]
    fn rejects_invalid_entropy_limits() {
        for entropy in [
            EntropyMatcher {
                minimum_length: 0,
                minimum_entropy: 4.0,
                maximum_whitespace_ratio: 0.05,
            },
            EntropyMatcher {
                minimum_length: 1,
                minimum_entropy: -1.0,
                maximum_whitespace_ratio: 0.05,
            },
            EntropyMatcher {
                minimum_length: 1,
                minimum_entropy: 8.1,
                maximum_whitespace_ratio: 0.05,
            },
            EntropyMatcher {
                minimum_length: 1,
                minimum_entropy: f64::NAN,
                maximum_whitespace_ratio: 0.05,
            },
        ] {
            assert!(validate_rules(&[rule(Some(entropy))]).is_err());
        }
    }

    #[test]
    fn accepts_entropy_limits_at_shannon_bounds() {
        assert!(
            validate_rules(&[rule(Some(EntropyMatcher {
                minimum_length: 1,
                minimum_entropy: 8.0,
                maximum_whitespace_ratio: 0.05,
            }))])
            .is_ok()
        );
    }

    #[test]
    fn rule_selectors_match_grouped_globs() {
        let filesystem = Rule {
            id: "GD_CAPABILITY_FILESYSTEM_READ_PY".to_owned(),
            finding_type: FindingType::FilesystemAccess,
            ..rule(None)
        };
        let network = Rule {
            id: "GD_CAPABILITY_NETWORK_DOWNLOAD_PY".to_owned(),
            finding_type: FindingType::NetworkAccess,
            ..rule(None)
        };

        let selector = parse_rule_selector("filesystem:GD_CAPABILITY_*").unwrap();
        assert!(selector.matches_rule(&filesystem));
        assert!(!selector.matches_rule(&network));
        assert!(
            parse_rule_selector("network:*")
                .unwrap()
                .matches_rule(&network)
        );
        assert!(
            parse_rule_selector("CUSTOM")
                .unwrap()
                .matches_rule(&rule(None))
        );
    }

    #[test]
    fn rule_selectors_reject_unknown_groups_and_invalid_globs() {
        assert!(parse_rule_selector("unknown:*").is_err());
        assert!(parse_rule_selector("network:").is_err());
        assert!(parse_rule_selector("network:bad/id").is_err());
    }
}
