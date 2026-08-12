use std::path::PathBuf;

use chainsec::{ArtifactRepositories, engine::MAX_ANALYSIS_THREADS, model::Risk};
use clap::{ArgGroup, Args, Parser, Subcommand, ValueEnum};

use super::config::parse_human_size;

pub(crate) fn validate_positive_usize(value: usize) -> Result<usize, String> {
    (value > 0)
        .then_some(value)
        .ok_or_else(|| "must be at least 1".to_owned())
}

pub(crate) fn validate_analysis_threads(value: usize) -> Result<usize, String> {
    (1..=MAX_ANALYSIS_THREADS)
        .contains(&value)
        .then_some(value)
        .ok_or_else(|| format!("must be between 1 and {MAX_ANALYSIS_THREADS}"))
}

fn parse_positive_usize(value: &str) -> Result<usize, String> {
    value
        .parse::<usize>()
        .map_err(|_| "must be a positive integer".to_owned())
        .and_then(validate_positive_usize)
}

fn parse_analysis_threads(value: &str) -> Result<usize, String> {
    value
        .parse::<usize>()
        .map_err(|_| "must be a positive integer".to_owned())
        .and_then(validate_analysis_threads)
}

fn parse_diff_count(value: &str) -> Result<usize, String> {
    value
        .parse::<usize>()
        .map_err(|_| "must be a positive integer".to_owned())
        .and_then(|value| {
            (value >= 2)
                .then_some(value)
                .ok_or_else(|| "must be at least 2 to provide a comparison baseline".to_owned())
        })
}

#[derive(Debug, Clone, Copy, serde::Deserialize, ValueEnum)]
#[serde(rename_all = "lowercase")]
pub(crate) enum OutputFormat {
    Json,
    Human,
    Sarif,
}

#[derive(Debug, Clone, Copy, serde::Deserialize, ValueEnum)]
#[serde(rename_all = "lowercase")]
pub(crate) enum Severity {
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

#[derive(Debug, Parser)]
#[command(
    about = "Safely scan Python, JavaScript, and TypeScript dependency source",
    version
)]
pub(crate) struct Cli {
    #[command(subcommand)]
    pub(crate) command: Command,
}

#[derive(Debug, Subcommand)]
pub(crate) enum Command {
    /// Scan a local project directory.
    Scan(LocalScan),
    /// Scan or diff packages fetched from supported remote sources.
    Remote(RemoteCommand),
    /// Create a conservative chainsec.toml in a project directory.
    Init(Init),
    /// Manage the dependency source cache.
    Cache(CacheCommand),
}

#[derive(Debug, Args)]
pub(crate) struct LocalScan {
    /// Project directory to analyze.
    #[arg(default_value = ".")]
    pub(crate) path: PathBuf,
    #[command(flatten)]
    pub(crate) options: AnalysisOptions,
}

#[derive(Debug, Args)]
pub(crate) struct RemoteCommand {
    #[command(subcommand)]
    pub(crate) command: RemoteSubcommand,
}

#[derive(Debug, Subcommand)]
pub(crate) enum RemoteSubcommand {
    /// Fetch and analyze a package as the traversal root.
    Scan(RemoteScan),
    /// Fetch and compare selected remote package versions.
    Diff(RemoteDiff),
}

#[derive(Debug, Args)]
pub(crate) struct RemoteScan {
    /// Package selector: github:OWNER/REPO@COMMIT, pypi:PACKAGE, jsr:@SCOPE/PACKAGE, or npm:PACKAGE[@VERSION].
    pub(crate) package: String,
    /// Scan this many releases, starting at the resolved version, and diff adjacent reports.
    #[arg(long, value_name = "VERSIONS", value_parser = parse_diff_count)]
    pub(crate) diff: Option<usize>,
    #[command(flatten)]
    pub(crate) options: AnalysisOptions,
}

#[derive(Debug, Args)]
#[command(group(
    ArgGroup::new("selection")
        .required(true)
        .multiple(false)
        .args(["last", "compare", "range"])
))]
pub(crate) struct RemoteDiff {
    /// Package selector: pypi:PACKAGE, jsr:@SCOPE/PACKAGE, or npm:PACKAGE.
    pub(crate) package: String,
    /// Compare this many releases, starting at the resolved version.
    #[arg(long, value_name = "N", value_parser = parse_diff_count)]
    pub(crate) last: Option<usize>,
    /// Compare exactly two versions.
    #[arg(long, value_names = ["FROM", "TO"], num_args = 2)]
    pub(crate) compare: Option<Vec<String>>,
    /// Compare every pullable version in an inclusive range.
    #[arg(long, value_names = ["FROM", "TO"], num_args = 2)]
    pub(crate) range: Option<Vec<String>>,
    #[command(flatten)]
    pub(crate) options: AnalysisOptions,
}

impl RemoteDiff {
    pub(crate) fn selection(&self) -> chainsec::RemoteVersionSelection {
        match (&self.last, self.compare.as_deref(), self.range.as_deref()) {
            (Some(count), None, None) => chainsec::RemoteVersionSelection::Last(*count),
            (None, Some([from, to]), None) => chainsec::RemoteVersionSelection::Compare {
                from: from.clone(),
                to: to.clone(),
            },
            (None, None, Some([from, to])) => chainsec::RemoteVersionSelection::Range {
                from: from.clone(),
                to: to.clone(),
            },
            _ => unreachable!("clap requires exactly one remote diff selection"),
        }
    }
}

#[derive(Debug, Args)]
pub(crate) struct Init {
    /// Project directory in which to create chainsec.toml.
    #[arg(default_value = ".")]
    pub(crate) path: PathBuf,
}

#[derive(Debug, Args)]
pub(crate) struct CacheCommand {
    #[command(subcommand)]
    pub(crate) command: CacheSubcommand,
}

#[derive(Debug, Subcommand)]
pub(crate) enum CacheSubcommand {
    /// Delete cached contents while retaining coordination metadata.
    Purge(CachePurge),
}

#[derive(Debug, Args)]
pub(crate) struct CachePurge {
    /// Directory used for content-identified dependency source.
    #[arg(long)]
    pub(crate) cache: Option<PathBuf>,
}

#[derive(Debug, Args)]
pub(crate) struct AnalysisOptions {
    /// Maximum dependency depth to acquire and analyze.
    #[arg(long, default_value_t = 3)]
    pub(crate) max_depth: usize,
    /// Maximum packages per traversal and aggregate unique work in a remote diff batch.
    #[arg(long, default_value_t = 500)]
    pub(crate) max_packages: usize,
    /// Maximum HTTP requests during one package acquisition, including redirects.
    #[arg(long, default_value_t = 1_000, value_parser = parse_positive_usize)]
    pub(crate) max_network_requests: usize,
    /// Maximum end-to-end network acquisition time for one package.
    #[arg(long, default_value_t = 300)]
    pub(crate) max_acquisition_seconds: u64,
    /// Maximum downloaded archive size (for example, `100MiB`, `100M`, or `100m`).
    #[arg(long = "max-archive", default_value = "100MiB", value_parser = parse_human_size)]
    pub(crate) max_archive_bytes: u64,
    /// Maximum expanded dependency size (for example, `500MiB`, `500M`, or `500m`).
    #[arg(long = "max-extracted", default_value = "500MiB", value_parser = parse_human_size)]
    pub(crate) max_extracted_bytes: u64,
    #[arg(long, default_value_t = 50_000)]
    pub(crate) max_extracted_files: u64,
    /// Maximum individual source file size (for example, `2MiB`, `2M`, or `2m`).
    #[arg(long = "max-source-file", default_value = "2MiB", value_parser = parse_human_size)]
    pub(crate) max_source_file_bytes: u64,
    /// Maximum findings emitted during one package scan.
    #[arg(long, default_value_t = 100_000)]
    pub(crate) max_findings: u64,
    #[arg(long, default_value_t = 300)]
    pub(crate) max_scan_seconds: u64,
    /// Stop scanning a package when Tree-sitter recovers from malformed source.
    #[arg(long)]
    pub(crate) fail_on_parse_error: bool,
    /// Maximum concurrent package downloads and analyses (1-64).
    #[arg(long, value_name = "THREADS", default_value_t = 16, value_parser = parse_analysis_threads)]
    pub(crate) threads: usize,
    /// Directory used for content-identified dependency source.
    #[arg(long)]
    pub(crate) cache: Option<PathBuf>,
    /// Permit dependencies not fully identified by a supported lockfile.
    #[arg(long)]
    pub(crate) allow_unlocked: bool,
    /// Permit local dependencies to resolve outside the package that declares them.
    #[arg(long)]
    pub(crate) trust_local_input: bool,
    /// Permit insecure HTTP only for localhost or loopback artifact repositories.
    #[arg(long)]
    pub(crate) allow_insecure_http: bool,
    /// Enable HTTP(S) acquisition for local dependency scans.
    #[arg(long)]
    pub(crate) online: bool,
    /// Host permitted for HTTP(S) acquisition; repeat for multiple hosts. Supports `*.example.com` and `*` for all hosts.
    #[arg(long = "allow-host")]
    pub(crate) allowed_hosts: Vec<String>,
    #[arg(skip = ArtifactRepositories::default())]
    pub(crate) artifactories: ArtifactRepositories,
    /// Load additional rules from a JSON or YAML rule pack; repeat for multiple packs.
    #[arg(long = "rule-pack")]
    pub(crate) rule_packs: Vec<PathBuf>,
    /// Disable the built-in rule catalog (requires at least one --rule-pack).
    #[arg(long)]
    pub(crate) no_default_rules: bool,
    /// Ignore rules matching GROUP:GLOB (for example, network:*); repeat for multiple selectors.
    #[arg(long = "ignore-rule", value_name = "GROUP:GLOB")]
    pub(crate) ignored_rules: Vec<String>,
    /// Ignore root-project paths matching GLOB (for example, tests/**); repeat for multiple globs.
    #[arg(long = "ignore-path", value_name = "GLOB")]
    pub(crate) ignored_paths: Vec<String>,
    /// Report format.
    #[arg(long, value_enum, default_value_t = OutputFormat::Human)]
    pub(crate) format: OutputFormat,
    /// Exit 1 when an unsuppressed finding meets this severity.
    #[arg(long, value_enum, default_value_t = Severity::High)]
    pub(crate) fail_on: Severity,
    /// Include findings below --fail-on in the human-readable report.
    #[arg(long)]
    pub(crate) verbose: bool,
    /// Write the analysis report to this file instead of stdout.
    #[arg(short, long, value_name = "PATH")]
    pub(crate) output: Option<PathBuf>,
}

#[cfg(test)]
mod tests;
