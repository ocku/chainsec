use std::path::PathBuf;

use chainsec::{ArtifactRepositories, model::Risk};
use clap::{Parser, ValueEnum, builder::ArgPredicate};

use super::config::parse_human_size;

fn parse_positive_usize(value: &str) -> Result<usize, String> {
    value
        .parse::<usize>()
        .map_err(|_| "must be a positive integer".to_owned())
        .and_then(|value| {
            (value > 0)
                .then_some(value)
                .ok_or_else(|| "must be at least 1".to_owned())
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

#[derive(Debug, Clone, Parser)]
#[command(
    about = "Safely scan Python, JavaScript, and TypeScript dependency source",
    version
)]
pub(crate) struct Cli {
    /// Project directory to analyze.
    #[arg(default_value = ".")]
    pub(crate) path: PathBuf,

    /// Fetch and analyze a remote package as the traversal root: github:OWNER/REPO@COMMIT, pypi:PACKAGE, jsr:@SCOPE/PACKAGE, or npm:PACKAGE[@VERSION].
    #[arg(long, value_name = "SOURCE:PACKAGE")]
    pub(crate) remote: Option<String>,

    /// Create a conservative chainsec.toml in the project root and exit.
    #[arg(long)]
    pub(crate) init: bool,

    /// Maximum dependency depth to acquire and analyze.
    #[arg(long, default_value_t = 3)]
    pub(crate) max_depth: usize,

    #[arg(long, default_value_t = 500)]
    pub(crate) max_packages: usize,
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

    #[arg(long, default_value_t = 300)]
    pub(crate) max_scan_seconds: u64,

    /// Maximum number of worker threads used for concurrent package analysis.
    #[arg(long, value_name = "THREADS", default_value_t = 16, value_parser = parse_positive_usize)]
    pub(crate) threads: usize,

    /// Directory used for content-identified dependency source.
    #[arg(long)]
    pub(crate) cache: Option<PathBuf>,

    /// Delete the resolved cache directory and exit without scanning.
    #[arg(long)]
    pub(crate) cache_purge: bool,

    /// Permit dependencies not fully identified by a supported lockfile.
    #[arg(long)]
    pub(crate) allow_unlocked: bool,

    /// Permit local dependencies to resolve outside the package that declares them.
    #[arg(long)]
    pub(crate) trust_local_input: bool,

    /// Enable HTTP(S) acquisition. Enabled automatically when `--remote` is used.
    #[arg(long, default_value_if("remote", ArgPredicate::IsPresent, "true"))]
    pub(crate) online: bool,

    /// Host permitted for HTTP(S) acquisition; repeat for multiple hosts. Supports `*.example.com` and `*` for all hosts.
    #[arg(long = "allow-host")]
    pub(crate) allowed_hosts: Vec<String>,

    // Repository endpoints are intentionally configuration-file only: they are
    // deployment policy, not per-invocation package input.
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
mod tests {
    use clap::Parser;

    use super::Cli;

    #[test]
    fn remote_enables_online_by_default() {
        let cli = Cli::try_parse_from(["chainsec", "--remote", "npm:express"]).unwrap();

        assert!(cli.online);
    }

    #[test]
    fn online_remains_disabled_without_a_remote() {
        let cli = Cli::try_parse_from(["chainsec"]).unwrap();

        assert!(!cli.online);
    }

    #[test]
    fn threads_default_to_sixteen_and_must_be_positive() {
        let cli = Cli::try_parse_from(["chainsec"]).unwrap();
        assert_eq!(cli.threads, 16);

        assert!(Cli::try_parse_from(["chainsec", "--threads", "0"]).is_err());

        let cli = Cli::try_parse_from(["chainsec", "--threads", "2"]).unwrap();
        assert_eq!(cli.threads, 2);
    }

    #[test]
    fn ignore_path_accepts_repeated_globs() {
        let cli = Cli::try_parse_from([
            "chainsec",
            "--ignore-path",
            "tests/**",
            "--ignore-path",
            "generated/**",
        ])
        .unwrap();

        assert_eq!(cli.ignored_paths, ["tests/**", "generated/**"]);
    }
}
