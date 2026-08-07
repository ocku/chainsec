mod config;
mod output;

use std::{
    fs,
    io::{self, IsTerminal},
    path::{Path, PathBuf},
    process::ExitCode,
    time::Duration,
};

use chainsec::{
    Engine, EngineLimits, FetchPolicy, SafeSourceFetcher,
    model::{Report, Risk},
    rules,
};
use clap::{CommandFactory, FromArgMatches, Parser, ValueEnum};
use config::parse_human_size;
use output::{exit_status, human_report, sarif_report};
use tracing::{debug, error, info};
use tracing_subscriber::EnvFilter;

#[derive(Debug, Clone, Copy, serde::Deserialize, ValueEnum)]
#[serde(rename_all = "lowercase")]
enum OutputFormat {
    Json,
    Human,
    Sarif,
}

#[derive(Debug, Clone, Copy, serde::Deserialize, ValueEnum)]
#[serde(rename_all = "lowercase")]
enum Severity {
    Low,
    Medium,
    High,
    Critical,
}

impl From<Severity> for Risk {
    fn from(value: Severity) -> Self {
        match value {
            Severity::Low => Risk::Low,
            Severity::Medium => Risk::Medium,
            Severity::High => Risk::High,
            Severity::Critical => Risk::Critical,
        }
    }
}

#[derive(Debug, Clone, Parser)]
#[command(
    about = "Safely scan Python, JavaScript, and TypeScript dependency source",
    version
)]
struct Cli {
    /// Project directory to analyze.
    #[arg(default_value = ".")]
    path: PathBuf,

    /// Create a conservative chainsec.toml in the project root and exit.
    #[arg(long)]
    init: bool,

    /// Maximum dependency depth to acquire and analyze.
    #[arg(long, default_value_t = 3)]
    max_depth: usize,

    #[arg(long, default_value_t = 500)]
    max_packages: usize,
    /// Maximum downloaded archive size (for example, `100MiB`, `100M`, or `100m`).
    #[arg(long = "max-archive", default_value = "100MiB", value_parser = parse_human_size)]
    max_archive_bytes: u64,
    /// Maximum expanded dependency size (for example, `500MiB`, `500M`, or `500m`).
    #[arg(long = "max-extracted", default_value = "500MiB", value_parser = parse_human_size)]
    max_extracted_bytes: u64,
    #[arg(long, default_value_t = 50_000)]
    max_extracted_files: u64,
    /// Maximum individual source file size (for example, `2MiB`, `2M`, or `2m`).
    #[arg(long = "max-source-file", default_value = "2MiB", value_parser = parse_human_size)]
    max_source_file_bytes: u64,

    #[arg(long, default_value_t = 300)]
    max_scan_seconds: u64,

    /// Directory used for content-identified dependency source.
    #[arg(long, default_value = ".chainsec-cache")]
    cache: PathBuf,

    /// Permit dependencies not fully identified by a supported lockfile.
    #[arg(long)]
    allow_unlocked: bool,

    /// Permit local dependencies to resolve outside the package that declares them.
    #[arg(long)]
    trust_local_input: bool,

    /// Enable HTTP(S) acquisition. Network is disabled unless this is set.
    #[arg(long)]
    online: bool,

    /// Host permitted for HTTP(S) acquisition; repeat for multiple hosts. Supports `*.example.com` and `*` for all hosts.
    #[arg(long = "allow-host")]
    allowed_hosts: Vec<String>,

    /// Load additional rules from a JSON or YAML rule pack; repeat for multiple packs.
    #[arg(long = "rule-pack")]
    rule_packs: Vec<PathBuf>,

    /// Disable the built-in rule catalog (requires at least one --rule-pack).
    #[arg(long)]
    no_default_rules: bool,

    /// Ignore rules matching GROUP:GLOB (for example, network:*); repeat for multiple selectors.
    #[arg(
        long = "ignore-rule",
        visible_alias = "exclude-rule",
        value_name = "GROUP:GLOB"
    )]
    ignored_rules: Vec<String>,

    /// Report format.
    #[arg(long, value_enum, default_value_t = OutputFormat::Json)]
    format: OutputFormat,

    /// Exit 1 when an unsuppressed finding meets this severity.
    #[arg(long, value_enum, default_value_t = Severity::High)]
    fail_on: Severity,

    /// Write the analysis report to this file instead of stdout.
    #[arg(short, long, value_name = "PATH")]
    output: Option<PathBuf>,
}

fn validate_cli(cli: &Cli) -> chainsec::Result<()> {
    if cli.online && cli.allowed_hosts.is_empty() {
        return Err(chainsec::Error::InvalidConfiguration {
            message: "--online requires at least one --allow-host".to_owned(),
        });
    }

    Ok(())
}

fn engine_limits(cli: &Cli) -> EngineLimits {
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

fn configured_rules(cli: &Cli) -> chainsec::Result<Vec<chainsec::model::Rule>> {
    let selectors = rule_selectors(cli)?;
    let mut configured_rules = if cli.no_default_rules {
        Vec::new()
    } else {
        rules::built_in_rules()
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

    chainsec::scanner::validate_rules(&configured_rules)?;

    Ok(configured_rules)
}

async fn analyze(
    cli: &Cli,
    configured_rules: &[chainsec::model::Rule],
    fetcher: &SafeSourceFetcher,
    limits: EngineLimits,
    ignored_packages: &[String],
    ignored_paths: &[String],
) -> chainsec::Result<Report> {
    Engine::new(
        configured_rules,
        fetcher,
        limits,
        !cli.allow_unlocked,
        !cli.online,
        cli.allowed_hosts.clone(),
        cli.trust_local_input,
    )
    .with_ignored_rule_selectors(rule_selectors(cli)?)
    .with_ignored_packages(ignored_packages.iter().cloned())
    .with_ignored_root_paths(ignored_paths.iter().cloned())
    .analyze(&cli.path)
    .await
}

fn render_report(
    format: OutputFormat,
    report: &Report,
    configured_rules: &[chainsec::model::Rule],
    color: bool,
) -> chainsec::Result<String> {
    match format {
        OutputFormat::Json => serde_json::to_string_pretty(report).map_err(rendering_error),
        OutputFormat::Human => Ok(human_report(report, color)),
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

async fn run(
    cli: &Cli,
    ignored_packages: &[String],
    ignored_paths: &[String],
    color: bool,
) -> chainsec::Result<(Report, String)> {
    validate_cli(cli)?;
    debug!(path = %cli.path.display(), format = ?cli.format, "validated CLI configuration");

    let limits = engine_limits(cli);
    let fetcher = SafeSourceFetcher::new(cli.cache.clone(), fetch_policy(cli), limits.clone())?;
    let configured_rules = configured_rules(cli)?;

    info!(path = %cli.path.display(), "starting analysis");
    let report = analyze(
        cli,
        &configured_rules,
        &fetcher,
        limits,
        ignored_packages,
        ignored_paths,
    )
    .await?;
    info!(
        packages = report.statistics.packages,
        findings = report.statistics.findings,
        issues = report.issues.len(),
        "analysis complete"
    );
    let rendered = render_report(cli.format, &report, &configured_rules, color)?;

    Ok((report, rendered))
}

fn write_report(output_path: Option<&Path>, rendered: &str) -> io::Result<()> {
    if let Some(path) = output_path {
        std::fs::write(path, rendered)
    } else {
        println!("{rendered}");
        Ok(())
    }
}

fn configure_tracing() {
    if !io::stdout().is_terminal() {
        return;
    }

    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_writer(io::stdout)
        .with_ansi(true)
        .without_time()
        .with_target(false)
        .init();
}

#[tokio::main]
async fn main() -> ExitCode {
    let matches = Cli::command().get_matches();
    let mut cli = Cli::from_arg_matches(&matches).expect("clap parsed its own arguments");
    let root = fs::canonicalize(&cli.path).map_err(|source| chainsec::Error::Io {
        operation: "resolve project directory".to_owned(),
        path: cli.path.clone(),
        source,
    });
    let root = match root {
        Ok(root) => root,
        Err(error) => {
            eprintln!("chainsec: {error}");
            return ExitCode::from(2);
        }
    };
    if cli.init {
        return match config::initialize(&root) {
            Ok(path) => {
                println!("created {}", path.display());
                ExitCode::SUCCESS
            }
            Err(error) => {
                eprintln!("chainsec: {error}");
                ExitCode::from(2)
            }
        };
    }
    let configuration = config::load(&root);
    let (config, config_path) = match configuration {
        Ok(value) => value,
        Err(error) => {
            eprintln!("chainsec: {error}");
            return ExitCode::from(2);
        }
    };
    let (ignored_packages, ignored_paths) =
        match config::apply(&mut cli, config, config_path.as_deref(), &matches) {
            Ok(value) => value,
            Err(error) => {
                eprintln!("chainsec: {error}");
                return ExitCode::from(2);
            }
        };
    let stdout_is_terminal = io::stdout().is_terminal();
    configure_tracing();
    let threshold = Risk::from(cli.fail_on);
    let color =
        matches!(cli.format, OutputFormat::Human) && cli.output.is_none() && stdout_is_terminal;

    match run(&cli, &ignored_packages, &ignored_paths, color).await {
        Ok((report, rendered)) => {
            if let Err(error) = write_report(cli.output.as_deref(), &rendered) {
                if let Some(path) = &cli.output {
                    error!(path = %path.display(), error = %error, "could not write analysis report");
                    eprintln!("chainsec: could not write {}: {error}", path.display());
                } else {
                    eprintln!("chainsec: could not write report: {error}");
                }
                return ExitCode::from(3);
            }

            ExitCode::from(exit_status(&report, threshold))
        }
        Err(error) => {
            error!(error = %error, "analysis failed");
            eprintln!("chainsec: {error}");
            ExitCode::from(if error.is_policy() { 4 } else { 2 })
        }
    }
}
