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
        capability: None,
        query: "(string) @match".to_owned(),
        entropy,
    }
}

#[test]
fn default_catalog_preserves_the_rule_group_boundaries() {
    let built_in = built_in_rules();
    let capabilities = capability_rules();
    let default = default_rules();

    assert!(!built_in.is_empty());
    assert!(
        built_in
            .iter()
            .any(|rule| rule.id.starts_with("chainsec.py.detection.guarddog."))
    );
    assert!(!capabilities.is_empty());
    assert!(capabilities.iter().all(|rule| rule.capability.is_some()));
    assert!(
        default
            .iter()
            .all(|rule| !rule.id.bytes().any(|byte| byte.is_ascii_uppercase()))
    );
    assert_eq!(default.len(), built_in.len() + capabilities.len());
    validate_rules(&default).unwrap();
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
        id: "chainsec.py.capability.filesystem-read".to_owned(),
        finding_type: FindingType::FilesystemAccess,
        ..rule(None)
    };
    let network = Rule {
        id: "chainsec.py.capability.network-download".to_owned(),
        finding_type: FindingType::NetworkAccess,
        ..rule(None)
    };

    let selector = parse_rule_selector("filesystem:chainsec.py.capability.*").unwrap();
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
fn rule_selector_dots_are_literal_for_ignore_and_suppression_selectors() {
    let dotted_rule = Rule {
        id: "chainsec.py.detection.example".to_owned(),
        ..rule(None)
    };
    let lookalike = Rule {
        id: "chainsecXpyXdetectionXexample".to_owned(),
        ..rule(None)
    };

    for selector in [
        parse_rule_selector("chainsec.py.detection.example").unwrap(),
        parse_rule_selector("obfuscation:chainsec.py.detection.*").unwrap(),
    ] {
        assert!(selector.matches_rule(&dotted_rule));
        assert!(!selector.matches_rule(&lookalike));
    }
}

#[test]
fn rule_selectors_reject_unknown_groups_and_invalid_globs() {
    assert!(parse_rule_selector("unknown:*").is_err());
    assert!(parse_rule_selector("network:").is_err());
    assert!(parse_rule_selector("network:bad/id").is_err());
}
