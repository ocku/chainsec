use chainsec::{
    model::{Report, Suppression},
    rules::{self, RuleSelector},
};

use crate::app::config::SuppressionConfig;

#[derive(Debug)]
pub struct ConfiguredSuppression {
    selector: RuleSelector,
    package: Option<String>,
    reason: String,
}

pub fn configured_suppressions(
    suppressions: &[SuppressionConfig],
) -> chainsec::Result<Vec<ConfiguredSuppression>> {
    suppressions
        .iter()
        .map(|suppression| {
            Ok(ConfiguredSuppression {
                selector: rules::parse_rule_selector(&suppression.rule)?,
                package: suppression.package.clone(),
                reason: suppression.reason.clone(),
            })
        })
        .collect()
}

fn package_without_integrity(package: &str) -> &str {
    package
        .split_once('#')
        .map_or(package, |(identity, _)| identity)
}

fn suppression_package_matches(configured: &str, reported: &str) -> bool {
    if configured == reported {
        return true;
    }
    if configured == "root" || reported == "root" || configured.contains('#') {
        return false;
    }

    configured == package_without_integrity(reported)
}

pub fn apply_suppressions(report: &mut Report, suppressions: &[ConfiguredSuppression]) {
    for finding in &mut report.findings {
        if let Some(suppression) = suppressions.iter().find(|suppression| {
            suppression.selector.matches_finding(finding)
                && suppression
                    .package
                    .as_deref()
                    .is_none_or(|package| suppression_package_matches(package, &finding.package))
        }) {
            finding.suppressed = true;
            finding.suppression = Some(Suppression {
                reason: suppression.reason.clone(),
            });
        }
    }

    for capability in &mut report.capabilities {
        for evidence in &mut capability.evidence {
            if let Some(suppression) = suppressions.iter().find(|suppression| {
                suppression.selector.matches_capability_evidence(evidence)
                    && suppression.package.as_deref().is_none_or(|package| {
                        suppression_package_matches(package, &evidence.package)
                    })
            }) {
                evidence.suppressed = true;
                evidence.suppression = Some(Suppression {
                    reason: suppression.reason.clone(),
                });
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::suppression_package_matches;

    #[test]
    fn suppression_package_matching_uses_digest_free_canonical_ids() {
        assert!(suppression_package_matches(
            "npm:example@1.2.3",
            "npm:example@1.2.3#sha512-abcdef"
        ));
        assert!(suppression_package_matches(
            "npm:example@1.2.3#sha512-configured",
            "npm:example@1.2.3#sha512-configured"
        ));
        assert!(!suppression_package_matches(
            "npm:example@1.2.3#sha512-configured",
            "npm:example@1.2.3#sha512-reported"
        ));
        assert!(suppression_package_matches("root", "root"));
        assert!(!suppression_package_matches(
            "root",
            "npm:root@1.0.0#sha512-abcdef"
        ));
        assert!(!suppression_package_matches(
            "npm:example@1.2.3",
            "npm:example@1.2.30#sha512-abcdef"
        ));
    }
}
