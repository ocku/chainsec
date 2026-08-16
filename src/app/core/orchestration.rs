use std::path::PathBuf;

use chainsec::{
    Engine,
    engine::effective_analysis_threads,
    error::Result,
    fetcher::{FetchPolicy, RemoteVersionSelection, SourceFetcher},
    model::{EngineLimits, PolicySummary, Report, SerializableLimits},
    parse_remote_package,
};
use futures::{StreamExt, TryStreamExt, stream};
use tracing::info;

/// Builds the engine + fetcher pair that executes one analysis run.
///
/// This is the application's core: it owns the configured rules, fetch policy,
/// cache location, and limits, then hands off a ready-to-use [`PipelineExecution`]
/// to the scan and diff entry points.
pub struct Pipeline {
    limits: EngineLimits,
    fetch_policy: FetchPolicy,
    cache: PathBuf,
    rules: Vec<chainsec::model::Rule>,
}

impl Pipeline {
    pub fn builder() -> PipelineBuilder {
        PipelineBuilder::default()
    }

    pub fn execute(self) -> PipelineExecution {
        let policy_summary = PolicySummary {
            require_lockfile: !self.fetch_policy.allow_unlocked,
            offline: self.fetch_policy.offline,
            trust_local_input: self.fetch_policy.trust_local_input,
            allow_insecure_http: self.fetch_policy.allow_insecure_http,
            allowed_hosts: self.fetch_policy.allowed_hosts.clone(),
            limits: SerializableLimits::from(&self.limits),
        };

        let fetcher = SourceFetcher::new(self.cache, self.fetch_policy, self.limits.clone())
            .expect("Pipeline validated configuration before building");

        PipelineExecution {
            fetcher,
            rules: self.rules,
            policy_summary,
        }
    }
}

pub struct PipelineBuilder {
    limits: Option<EngineLimits>,
    fetch_policy: Option<FetchPolicy>,
    cache: Option<PathBuf>,
    rules: Vec<chainsec::model::Rule>,
}

impl Default for PipelineBuilder {
    fn default() -> Self {
        Self {
            limits: None,
            fetch_policy: None,
            cache: None,
            rules: chainsec::rules::default_rules(),
        }
    }
}

impl PipelineBuilder {
    pub fn limits(mut self, limits: EngineLimits) -> Self {
        self.limits = Some(limits);
        self
    }

    pub fn fetch_policy(mut self, policy: FetchPolicy) -> Self {
        self.fetch_policy = Some(policy);
        self
    }

    pub fn cache(mut self, cache: PathBuf) -> Self {
        self.cache = Some(cache);
        self
    }

    pub fn rules(mut self, rules: Vec<chainsec::model::Rule>) -> Self {
        self.rules = rules;
        self
    }

    pub fn build(self) -> Result<Pipeline> {
        Ok(Pipeline {
            limits: self
                .limits
                .ok_or_else(|| chainsec::Error::InvalidConfiguration {
                    message: "engine limits must be set".to_owned(),
                })?,
            fetch_policy: self.fetch_policy.ok_or_else(|| {
                chainsec::Error::InvalidConfiguration {
                    message: "fetch policy must be set".to_owned(),
                }
            })?,
            cache: self
                .cache
                .ok_or_else(|| chainsec::Error::InvalidConfiguration {
                    message: "cache path must be set".to_owned(),
                })?,
            rules: self.rules,
        })
    }
}

pub struct PipelineExecution {
    fetcher: SourceFetcher,
    rules: Vec<chainsec::model::Rule>,
    policy_summary: PolicySummary,
}

impl PipelineExecution {
    /// Runs a single analysis (local or remote) and returns an [`AnalysisResult`]
    /// ready for formatting.
    pub async fn analyze(
        &self,
        input: AnalysisInput<'_>,
        options: &AnalysisRunOptions<'_>,
    ) -> Result<AnalysisResult> {
        run(self, input, options).await
    }

    /// Runs a diff analysis comparing remote package versions.
    pub async fn analyze_diff(
        &self,
        package: &str,
        selection: RemoteVersionSelection,
        options: &AnalysisRunOptions<'_>,
    ) -> Result<DiffResult> {
        run_diff(self, package, selection, options).await
    }

    pub fn fetcher(&self) -> &SourceFetcher {
        &self.fetcher
    }

    pub fn rules(&self) -> &[chainsec::model::Rule] {
        &self.rules
    }

    pub fn policy_summary(&self) -> &PolicySummary {
        &self.policy_summary
    }
}

/// Describes what to analyze.
pub enum AnalysisInput<'a> {
    /// Analyze a local project directory.
    Local(&'a std::path::Path),
    /// Analyze a remote package specifier (e.g., `"npm:express"`).
    Remote(&'a str),
}

/// Tunables provided to every analysis run.
#[derive(Default)]
pub struct AnalysisRunOptions<'a> {
    pub threads: usize,
    pub ignored_rule_selectors: Vec<chainsec::rules::RuleSelector>,
    pub ignored_packages: &'a [String],
    pub ignored_root_paths: &'a [String],
}

/// The result of a single analysis — data, not presentation.
pub struct AnalysisResult {
    pub report: Report,
    pub rules: Vec<chainsec::model::Rule>,
}

/// The result of a diff analysis across package versions.
pub struct DiffResult {
    pub versions: Vec<VersionReport>,
}

/// One version's worth of analysis in a diff.
pub struct VersionReport {
    pub version: String,
    pub report: Report,
}

fn engine<'a>(execution: &'a PipelineExecution, options: &AnalysisRunOptions<'_>) -> Engine<'a> {
    Engine::new(
        &execution.rules,
        execution.fetcher(),
        execution.policy_summary().clone(),
    )
    .with_max_analysis_threads(options.threads)
    .with_ignored_rule_selectors(options.ignored_rule_selectors.iter().cloned())
    .with_ignored_packages(options.ignored_packages.iter().cloned())
    .with_ignored_root_paths(options.ignored_root_paths.iter().cloned())
}

async fn run(
    execution: &PipelineExecution,
    input: AnalysisInput<'_>,
    options: &AnalysisRunOptions<'_>,
) -> Result<AnalysisResult> {
    let engine = engine(execution, options);

    match input {
        AnalysisInput::Remote(package) => {
            info!(package, "starting analysis");
            let dependency = parse_remote_package(package)?;
            let fetched = execution.fetcher().fetch_remote_root(dependency).await?;
            let report = engine.analyze_fetched_root(fetched).await?;
            Ok(AnalysisResult {
                report,
                rules: execution.rules().to_vec(),
            })
        }
        AnalysisInput::Local(path) => {
            info!(path = %path.display(), "starting analysis");
            let report = engine.analyze(path).await?;
            Ok(AnalysisResult {
                report,
                rules: execution.rules().to_vec(),
            })
        }
    }
}

async fn run_diff(
    execution: &PipelineExecution,
    package: &str,
    selection: RemoteVersionSelection,
    options: &AnalysisRunOptions<'_>,
) -> Result<DiffResult> {
    let dependency = parse_remote_package(package)?;
    let dependencies = execution
        .fetcher()
        .resolve_remote_version_selection(dependency, selection)
        .await?;
    let downloads = stream::iter(dependencies).map(|dependency| async {
        let version = dependency
            .resolved_version
            .clone()
            .expect("historical remote roots are resolved");
        info!(package, version, "downloading version for batch analysis");
        let fetched = execution.fetcher().fetch_remote_root(dependency).await?;
        Ok::<_, chainsec::error::Error>((version, fetched))
    });
    let downloaded = downloads
        .buffered(effective_analysis_threads(options.threads))
        .try_collect::<Vec<_>>()
        .await?;
    let (versions, fetched): (Vec<_>, Vec<_>) = downloaded.into_iter().unzip();
    let engine = engine(execution, options);
    let analyzed = engine.analyze_fetched_roots(fetched).await?;

    let reports = versions
        .into_iter()
        .zip(analyzed)
        .map(|(version, report)| {
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
            VersionReport { version, report }
        })
        .collect();

    Ok(DiffResult { versions: reports })
}
