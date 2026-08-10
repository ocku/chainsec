use std::time::Duration;

use chainsec::{
    Engine, EngineLimits, FetchPolicy, SourceFetcher,
    model::{Report, Risk, Suppression},
    rules,
};
use tracing::info;

use super::{
    cli::{Cli, OutputFormat},
    config::SuppressionConfig,
    output::{human_report, sarif_report},
    remote,
};

pub(super) fn engine_limits(cli: &Cli) -> EngineLimits {
    EngineLimits {
        max_depth: cli.max_depth,
        max_packages: cli.max_packages,
        max_archive_bytes: cli.max_archive_bytes,
        max_extracted_bytes: cli.max_extracted_bytes,
        max_extracted_files: cli.max_extracted_files,
        max_source_file_bytes: cli.max_source_file_bytes,
        max_scan_duration: Duration::from_secs(cli.max_scan_seconds),
        ..EngineLimits::default()
    }
}

fn fetch_policy(cli: &Cli) -> FetchPolicy {
    FetchPolicy {
        offline: !cli.online,
        allow_unlocked: cli.allow_unlocked,
        allowed_hosts: cli.allowed_hosts.clone(),
        repositories: cli.artifactories.clone(),
        trust_local_input: cli.trust_local_input,
        ..FetchPolicy::default()
    }
}

fn rule_selectors(cli: &Cli) -> chainsec::Result<Vec<chainsec::rules::RuleSelector>> {
    cli.ignored_rules
        .iter()
        .map(|selector| rules::parse_rule_selector(selector))
        .collect()
}

struct ConfiguredSuppression {
    selector: chainsec::rules::RuleSelector,
    package: Option<String>,
    reason: String,
}

fn configured_suppressions(
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

fn apply_suppressions(report: &mut Report, suppressions: &[ConfiguredSuppression]) {
    for finding in &mut report.findings {
        if let Some(suppression) = suppressions.iter().find(|suppression| {
            suppression.selector.matches_finding(finding)
                && suppression
                    .package
                    .as_deref()
                    .is_none_or(|package| package == finding.package)
        }) {
            finding.suppressed = true;
            finding.suppression = Some(Suppression {
                reason: suppression.reason.clone(),
            });
        }
    }
}

fn configured_rules(cli: &Cli) -> chainsec::Result<Vec<chainsec::model::Rule>> {
    let selectors = rule_selectors(cli)?;
    let mut configured_rules = if cli.no_default_rules {
        Vec::new()
    } else {
        rules::default_rules()
    };

    for path in &cli.rule_packs {
        configured_rules.extend(rules::load_rule_pack(path)?);
    }

    rules::validate_rules(&configured_rules)?;
    configured_rules.retain(|rule| !selectors.iter().any(|selector| selector.matches_rule(rule)));

    if configured_rules.is_empty() {
        return Err(chainsec::Error::InvalidConfiguration {
            message: "no rules configured".to_owned(),
        });
    }

    Ok(configured_rules)
}

async fn analyze(
    cli: &Cli,
    configured_rules: &[chainsec::model::Rule],
    fetcher: &SourceFetcher,
    limits: EngineLimits,
    ignored_packages: &[String],
    ignored_paths: &[String],
    suppressions: &[ConfiguredSuppression],
) -> chainsec::Result<Report> {
    let engine = Engine::new(
        configured_rules,
        fetcher,
        limits,
        !cli.allow_unlocked,
        !cli.online,
        cli.allowed_hosts.clone(),
        cli.trust_local_input,
    )
    .with_max_analysis_threads(cli.threads)
    .with_ignored_packages(ignored_packages.iter().cloned())
    .with_ignored_root_paths(ignored_paths.iter().cloned());

    let mut report = if let Some(remote) = &cli.remote {
        let fetched = fetcher
            .fetch_remote_root(remote::dependency(remote)?)
            .await?;
        engine.analyze_fetched_root(fetched).await?
    } else {
        engine.analyze(&cli.path).await?
    };
    apply_suppressions(&mut report, suppressions);
    Ok(report)
}

fn render_report(
    format: OutputFormat,
    report: &Report,
    configured_rules: &[chainsec::model::Rule],
    threshold: Risk,
    verbose: bool,
    color: bool,
) -> chainsec::Result<String> {
    match format {
        OutputFormat::Json => serde_json::to_string_pretty(report).map_err(rendering_error),
        OutputFormat::Human => Ok(human_report(
            report,
            configured_rules,
            threshold,
            verbose,
            color,
        )),
        OutputFormat::Sarif => {
            serde_json::to_string_pretty(&sarif_report(report, configured_rules))
                .map_err(rendering_error)
        }
    }
}

fn rendering_error(error: serde_json::Error) -> chainsec::Error {
    chainsec::Error::InvalidConfiguration {
        message: error.to_string(),
    }
}

pub(super) async fn run(
    cli: &Cli,
    ignored_packages: &[String],
    ignored_paths: &[String],
    suppressions: &[SuppressionConfig],
    color: bool,
) -> chainsec::Result<(Report, String)> {
    let limits = engine_limits(cli);
    let fetcher = SourceFetcher::new(
        cli.cache
            .clone()
            .expect("cache path is resolved before analysis"),
        fetch_policy(cli),
        limits.clone(),
    )?;
    let configured_rules = configured_rules(cli)?;
    let suppressions = configured_suppressions(suppressions)?;

    info!(path = %cli.path.display(), "starting analysis");
    let report = analyze(
        cli,
        &configured_rules,
        &fetcher,
        limits,
        ignored_packages,
        ignored_paths,
        &suppressions,
    )
    .await?;
    info!(
        packages = report.statistics.packages,
        findings = report.statistics.findings,
        issues = report.issues.len(),
        "analysis complete"
    );
    let rendered = render_report(
        cli.format,
        &report,
        &configured_rules,
        cli.fail_on.into(),
        cli.verbose,
        color,
    )?;

    Ok((report, rendered))
}
