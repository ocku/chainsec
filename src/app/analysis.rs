use std::time::Duration;

use chainsec::{
    Engine, EngineLimits, FetchPolicy, RemoteVersionSelection, SourceFetcher,
    engine::effective_analysis_threads,
    model::{Report, Risk, Suppression},
    rules,
};
use futures::{StreamExt, TryStreamExt, stream};
use tracing::info;

use super::{
    cli::{AnalysisOptions, OutputFormat},
    config::SuppressionConfig,
    diff::{self, VersionReport},
    output::{human_report, sarif_report},
    remote,
};

fn engine_limits(cli: &AnalysisOptions) -> EngineLimits {
    EngineLimits {
        max_depth: cli.max_depth,
        max_packages: cli.max_packages,
        max_network_requests: cli.max_network_requests,
        max_acquisition_duration: Duration::from_secs(cli.max_acquisition_seconds),
        max_archive_bytes: cli.max_archive_bytes,
        max_extracted_bytes: cli.max_extracted_bytes,
        max_extracted_files: cli.max_extracted_files,
        max_source_file_bytes: cli.max_source_file_bytes,
        max_findings: cli.max_findings,
        max_scan_duration: Duration::from_secs(cli.max_scan_seconds),
        fail_on_parse_error: cli.fail_on_parse_error,
        ..EngineLimits::default()
    }
}

fn fetch_policy(cli: &AnalysisOptions) -> FetchPolicy {
    FetchPolicy {
        offline: !cli.online,
        allow_unlocked: cli.allow_unlocked,
        allowed_hosts: cli.allowed_hosts.clone(),
        repositories: cli.artifactories.clone(),
        trust_local_input: cli.trust_local_input,
        allow_insecure_http: cli.allow_insecure_http,
        ..FetchPolicy::default()
    }
}

fn rule_selectors(cli: &AnalysisOptions) -> chainsec::Result<Vec<chainsec::rules::RuleSelector>> {
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

    for capability in &mut report.capabilities {
        for evidence in &mut capability.evidence {
            if let Some(suppression) = suppressions.iter().find(|suppression| {
                suppression.selector.matches_capability_evidence(evidence)
                    && suppression
                        .package
                        .as_deref()
                        .is_none_or(|package| package == evidence.package)
            }) {
                evidence.suppressed = true;
                evidence.suppression = Some(Suppression {
                    reason: suppression.reason.clone(),
                });
            }
        }
    }
}

fn configured_rules(cli: &AnalysisOptions) -> chainsec::Result<Vec<chainsec::model::Rule>> {
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

struct AnalysisContext {
    limits: EngineLimits,
    fetcher: SourceFetcher,
    rules: Vec<chainsec::model::Rule>,
    suppressions: Vec<ConfiguredSuppression>,
}

impl AnalysisContext {
    fn new(
        options: &AnalysisOptions,
        suppressions: &[SuppressionConfig],
    ) -> chainsec::Result<Self> {
        let limits = engine_limits(options);
        let fetcher = SourceFetcher::new(
            options
                .cache
                .clone()
                .expect("cache path is resolved before analysis"),
            fetch_policy(options),
            limits.clone(),
        )?;

        Ok(Self {
            limits,
            fetcher,
            rules: configured_rules(options)?,
            suppressions: configured_suppressions(suppressions)?,
        })
    }

    fn engine<'a>(
        &'a self,
        options: &AnalysisOptions,
        ignored_packages: &[String],
        ignored_paths: &[String],
    ) -> Engine<'a> {
        Engine::new(
            &self.rules,
            &self.fetcher,
            self.limits.clone(),
            !options.allow_unlocked,
            !options.online,
            options.allowed_hosts.clone(),
            options.trust_local_input,
        )
        .with_allow_insecure_http(options.allow_insecure_http)
        .with_max_analysis_threads(options.threads)
        .with_ignored_packages(ignored_packages.iter().cloned())
        .with_ignored_root_paths(ignored_paths.iter().cloned())
    }

    fn suppress(&self, report: &mut Report) {
        apply_suppressions(report, &self.suppressions);
    }
}

#[derive(Clone, Copy)]
pub(super) enum ScanTarget<'a> {
    Local(&'a std::path::Path),
    Remote(&'a str),
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
        OutputFormat::Human => Ok(human_report(report, threshold, verbose, color)),
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

pub(super) async fn run_diff(
    cli: &AnalysisOptions,
    package: &str,
    selection: RemoteVersionSelection,
    ignored_packages: &[String],
    ignored_paths: &[String],
    suppressions: &[SuppressionConfig],
    color: bool,
) -> chainsec::Result<(Vec<VersionReport>, String)> {
    let format = diff::Format::try_from(cli.format)?;
    let analysis = AnalysisContext::new(cli, suppressions)?;
    let dependencies = analysis
        .fetcher
        .resolve_remote_version_selection(remote::dependency(package)?, selection)
        .await?;
    let downloads = stream::iter(dependencies).map(|dependency| async {
        let version = dependency
            .resolved_version
            .clone()
            .expect("historical remote roots are resolved");
        info!(package, version, "downloading version for batch analysis");
        let fetched = analysis.fetcher.fetch_remote_root(dependency).await?;
        Ok::<_, chainsec::Error>((version, fetched))
    });
    let downloaded = downloads
        .buffered(effective_analysis_threads(cli.threads))
        .try_collect::<Vec<_>>()
        .await?;
    let (versions, fetched): (Vec<_>, Vec<_>) = downloaded.into_iter().unzip();
    let engine = analysis.engine(cli, ignored_packages, ignored_paths);
    let analyzed = engine.analyze_fetched_roots(fetched).await?;
    let mut reports = Vec::with_capacity(analyzed.len());

    for (version, mut report) in versions.into_iter().zip(analyzed) {
        analysis.suppress(&mut report);
        info!(
            package,
            version,
            packages = report.statistics.packages,
            files = report.statistics.source_files,
            bytes = report.statistics.source_bytes,
            findings = report.statistics.findings,
            capabilities = report.capabilities.len(),
            issues = report.issues.len(),
            "version analysis complete"
        );
        reports.push(VersionReport { version, report });
    }

    let rendered = diff::render(
        package,
        &reports,
        format,
        cli.fail_on.into(),
        cli.verbose,
        color,
    )?;
    Ok((reports, rendered))
}

pub(super) async fn run(
    cli: &AnalysisOptions,
    target: ScanTarget<'_>,
    ignored_packages: &[String],
    ignored_paths: &[String],
    suppressions: &[SuppressionConfig],
    color: bool,
) -> chainsec::Result<(Report, String)> {
    let analysis = AnalysisContext::new(cli, suppressions)?;

    match target {
        ScanTarget::Local(path) => info!(path = %path.display(), "starting analysis"),
        ScanTarget::Remote(package) => info!(package, "starting analysis"),
    }
    let engine = analysis.engine(cli, ignored_packages, ignored_paths);
    let mut report = match target {
        ScanTarget::Remote(package) => {
            let fetched = analysis
                .fetcher
                .fetch_remote_root(remote::dependency(package)?)
                .await?;
            engine.analyze_fetched_root(fetched).await?
        }
        ScanTarget::Local(path) => engine.analyze(path).await?,
    };
    analysis.suppress(&mut report);
    info!(
        packages = report.statistics.packages,
        files = report.statistics.source_files,
        bytes = report.statistics.source_bytes,
        findings = report.statistics.findings,
        issues = report.issues.len(),
        "analysis complete"
    );
    let rendered = render_report(
        cli.format,
        &report,
        &analysis.rules,
        cli.fail_on.into(),
        cli.verbose,
        color,
    )?;

    Ok((report, rendered))
}
