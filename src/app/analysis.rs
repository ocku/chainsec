use std::time::Duration;

use chainsec::{
    RemoteVersionSelection,
    model::{Report, Risk},
    rules,
};

use super::{
    cli::{AnalysisOptions, OutputFormat},
    config::SuppressionConfig,
    core::{
        AnalysisInput, AnalysisRunOptions, ConfiguredSuppression, Pipeline, VersionReport,
        apply_suppressions, configured_suppressions,
    },
    diff::{self},
    output::{human_report, sarif_report},
};

const GENERATED_FINDING_SELECTORS: [&str; 2] = [
    "install:chainsec.*.detection.manifest.install-hook",
    "file:chainsec.detection.file.*",
];

fn engine_limits(cli: &AnalysisOptions) -> chainsec::EngineLimits {
    chainsec::EngineLimits {
        max_package_depth: cli.max_package_depth,
        max_packages: cli.max_packages,
        max_network_requests: cli.max_network_requests,
        max_redirect_hops: cli.max_redirect_hops,
        request_timeout: Duration::from_secs(cli.request_timeout_seconds),
        max_acquisition_duration: Duration::from_secs(cli.max_acquisition_seconds),
        max_archive_size: cli.max_archive_size,
        max_extracted_size: cli.max_extracted_size,
        max_extracted_files: cli.max_extracted_files,
        max_file_depth: cli.max_file_depth,
        max_manifest_file_size: cli.max_manifest_file_size,
        max_source_file_size: cli.max_source_file_size,
        max_source_files: cli.max_source_files,
        max_findings: cli.max_findings,
        max_scan_duration: Duration::from_secs(cli.max_scan_seconds),
        fail_on_parse_error: cli.fail_on_parse_error,
    }
}

fn fetch_policy(cli: &AnalysisOptions) -> chainsec::FetchPolicy {
    chainsec::FetchPolicy {
        offline: !cli.online,
        allow_unlocked: cli.allow_unlocked,
        allowed_hosts: cli.allowed_hosts.clone(),
        repositories: cli.artifactories.clone(),
        trust_local_input: cli.trust_local_input,
        allow_insecure_http: cli.allow_insecure_http,
    }
}

fn rule_selectors(cli: &AnalysisOptions) -> chainsec::Result<Vec<chainsec::rules::RuleSelector>> {
    cli.ignored_rules
        .iter()
        .map(|selector| rules::parse_rule_selector(selector))
        .collect()
}

fn configured_rules(
    cli: &AnalysisOptions,
    ignored_rule_selectors: &[chainsec::rules::RuleSelector],
) -> chainsec::Result<Vec<chainsec::model::Rule>> {
    let mut configured_rules = if cli.no_default_rules {
        Vec::new()
    } else {
        rules::default_rules()
    };

    for path in &cli.rule_packs {
        let pack = rules::load_rule_pack(path).map_err(|error| match error {
            error @ chainsec::Error::Io { .. } => chainsec::Error::InvalidConfiguration {
                message: error.to_string(),
            },
            error => error,
        })?;
        configured_rules.extend(pack);
    }

    rules::validate_rules(&configured_rules)?;
    configured_rules.retain(|rule| {
        !ignored_rule_selectors
            .iter()
            .any(|selector| selector.matches_rule(rule))
    });

    if configured_rules.is_empty() {
        return Err(chainsec::Error::InvalidConfiguration {
            message: "no rules configured".to_owned(),
        });
    }

    Ok(configured_rules)
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
    let (pipeline, suppressions, ignored_rule_selectors) = build_pipeline(cli, suppressions)?;
    let options = run_options(
        cli,
        &ignored_rule_selectors,
        ignored_packages,
        ignored_paths,
    );

    let mut result = pipeline
        .execute()
        .analyze_diff(package, selection, &options)
        .await?;

    for version_report in &mut result.versions {
        apply_suppressions(&mut version_report.report, &suppressions);
    }

    let rendered = diff::render(
        package,
        &result.versions,
        format,
        cli.fail_on.into(),
        cli.verbose,
        color,
    )?;
    Ok((result.versions, rendered))
}

pub(super) async fn run(
    cli: &AnalysisOptions,
    target: ScanTarget<'_>,
    ignored_packages: &[String],
    ignored_paths: &[String],
    suppressions: &[SuppressionConfig],
    color: bool,
) -> chainsec::Result<(Report, String)> {
    let (pipeline, config_suppressions, ignored_rule_selectors) =
        build_pipeline(cli, suppressions)?;
    let options = run_options(
        cli,
        &ignored_rule_selectors,
        ignored_packages,
        ignored_paths,
    );

    let input = match target {
        ScanTarget::Local(path) => AnalysisInput::Local(path),
        ScanTarget::Remote(package) => AnalysisInput::Remote(package),
    };

    let result = pipeline.execute().analyze(input, &options).await?;
    let mut report = result.report;
    apply_suppressions(&mut report, &config_suppressions);

    let rendered = render_report(
        cli.format,
        &report,
        &result.rules,
        cli.fail_on.into(),
        cli.verbose,
        color,
    )?;

    Ok((report, rendered))
}

fn build_pipeline(
    cli: &AnalysisOptions,
    suppressions: &[SuppressionConfig],
) -> chainsec::Result<(
    Pipeline,
    Vec<ConfiguredSuppression>,
    Vec<chainsec::rules::RuleSelector>,
)> {
    let mut ignored_rule_selectors = rule_selectors(cli)?;
    let rules = configured_rules(cli, &ignored_rule_selectors)?;
    let configured_suppressions = configured_suppressions(suppressions)?;
    if cli.no_default_rules {
        ignored_rule_selectors.extend(
            GENERATED_FINDING_SELECTORS
                .into_iter()
                .map(rules::parse_rule_selector)
                .collect::<chainsec::Result<Vec<_>>>()?,
        );
    }

    let pipeline = Pipeline::builder()
        .limits(engine_limits(cli))
        .fetch_policy(fetch_policy(cli))
        .cache(
            cli.cache
                .clone()
                .expect("cache path is resolved before analysis"),
        )
        .rules(rules)
        .build()?;

    Ok((pipeline, configured_suppressions, ignored_rule_selectors))
}

fn run_options<'a>(
    cli: &'a AnalysisOptions,
    ignored_rule_selectors: &'a [chainsec::rules::RuleSelector],
    ignored_packages: &'a [String],
    ignored_paths: &'a [String],
) -> AnalysisRunOptions<'a> {
    AnalysisRunOptions {
        threads: cli.threads,
        ignored_rule_selectors: ignored_rule_selectors.to_vec(),
        ignored_packages,
        ignored_root_paths: ignored_paths,
    }
}
