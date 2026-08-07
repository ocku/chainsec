use async_trait::async_trait;

use super::*;
use crate::{
    fetcher::SourceFetcher,
    model::{Dependency, FetchMetadata},
};

struct NeverFetch;
#[async_trait]
impl SourceFetcher for NeverFetch {
    async fn fetch(
        &self,
        dependency: Dependency,
        _declared_from: PathBuf,
    ) -> Result<FetchMetadata> {
        panic!("unexpected fetch for {}", dependency.id())
    }
}

struct FixtureFetcher {
    packages: PathBuf,
}

#[async_trait]
impl SourceFetcher for FixtureFetcher {
    async fn fetch(
        &self,
        dependency: Dependency,
        _declared_from: PathBuf,
    ) -> Result<FetchMetadata> {
        Ok(FetchMetadata {
            source: self.packages.join(&dependency.name),
            package_id: dependency.id(),
            resolved_version: dependency.resolved_version.clone().unwrap(),
            digest: dependency.integrity.clone().unwrap(),
            source_url: dependency
                .source_url
                .unwrap_or_else(|| "https://fixtures.example.test/package.tar.gz".to_owned()),
            cache_hit: false,
        })
    }
}

#[tokio::test]
async fn unlocked_dependencies_are_policy_issues() {
    let root = tempfile::tempdir().unwrap();
    fs::write(
        root.path().join("package.json"),
        r#"{"dependencies":{"left-pad":"^1"}}"#,
    )
    .unwrap();
    let rules = crate::rules::built_in_rules();
    let report = Engine::new(
        &rules,
        &NeverFetch,
        EngineLimits::default(),
        true,
        true,
        vec![],
        false,
    )
    .analyze(root.path())
    .await
    .unwrap();
    assert_eq!(report.packages.len(), 1);
    assert!(
        report
            .issues
            .iter()
            .any(|issue| issue.code == "policy_error")
    );
}

#[tokio::test]
async fn root_python_lock_resolves_transitive_dependencies() {
    let root = tempfile::tempdir().unwrap();
    let packages = tempfile::tempdir().unwrap();
    fs::write(
        root.path().join("pyproject.toml"),
        r#"[tool.poetry.dependencies]
python = "^3.11"
pandas = "^2.3.3"
"#,
    )
    .unwrap();
    fs::write(
        root.path().join("poetry.lock"),
        r#"[[package]]
name = "pandas"
version = "2.3.3"
files = [{file = "pandas.whl", hash = "sha256:pandas"}]

[[package]]
name = "numpy"
version = "2.3.3"
files = [{file = "numpy.whl", hash = "sha256:numpy"}]

[[package]]
name = "python-dateutil"
version = "2.9.0"
files = [{file = "dateutil.whl", hash = "sha256:dateutil"}]

[[package]]
name = "tzdata"
version = "2025.2"
files = [{file = "tzdata.whl", hash = "sha256:tzdata"}]
"#,
    )
    .unwrap();
    fs::create_dir(packages.path().join("pandas")).unwrap();
    fs::write(
        packages.path().join("pandas/pyproject.toml"),
        r#"[project]
dependencies = [
  "numpy>=1.26.0; python_version < '3.14'",
  "numpy>=2.3.3; python_version >= '3.14'",
  "python-dateutil>=2.8.2",
  "tzdata; sys_platform == 'emscripten'",
  "tzdata; sys_platform == 'win32'",
]
"#,
    )
    .unwrap();
    for package in ["numpy", "python-dateutil", "tzdata"] {
        fs::create_dir(packages.path().join(package)).unwrap();
    }

    let fetcher = FixtureFetcher {
        packages: packages.path().to_owned(),
    };
    let report = Engine::new(
        &[],
        &fetcher,
        EngineLimits::default(),
        true,
        true,
        vec![],
        false,
    )
    .analyze(root.path())
    .await
    .unwrap();

    assert!(report.issues.is_empty(), "{:?}", report.issues);
    assert!(
        report
            .packages
            .iter()
            .any(|package| package.package_id.starts_with("python:numpy@2.3.3#"))
    );
}

#[tokio::test]
async fn root_npm_lock_resolves_hoisted_transitive_dependencies() {
    let root = tempfile::tempdir().unwrap();
    let packages = tempfile::tempdir().unwrap();
    fs::write(
        root.path().join("package.json"),
        r#"{"dependencies":{"ip-address":"^9.0.5"}}"#,
    )
    .unwrap();
    fs::write(
            root.path().join("package-lock.json"),
            r#"{
                "lockfileVersion": 3,
                "packages": {
                    "": {"dependencies":{"ip-address":"^9.0.5"}},
                    "node_modules/ip-address": {
                        "version":"9.0.5",
                        "resolved":"https://registry.npmjs.org/ip-address/-/ip-address-9.0.5.tgz",
                        "integrity":"sha512-ip-address"
                    },
                    "node_modules/smart-buffer": {
                        "version":"4.2.0",
                        "resolved":"https://registry.npmjs.org/smart-buffer/-/smart-buffer-4.2.0.tgz",
                        "integrity":"sha512-smart-buffer"
                    }
                }
            }"#,
        )
        .unwrap();
    fs::create_dir(packages.path().join("ip-address")).unwrap();
    fs::write(
        packages.path().join("ip-address/package.json"),
        r#"{"dependencies":{"smart-buffer":"^4.2.0"}}"#,
    )
    .unwrap();
    fs::create_dir(packages.path().join("smart-buffer")).unwrap();
    fs::write(
        packages.path().join("smart-buffer/package.json"),
        r#"{"name":"smart-buffer","version":"4.2.0"}"#,
    )
    .unwrap();

    let fetcher = FixtureFetcher {
        packages: packages.path().to_owned(),
    };
    let report = Engine::new(
        &[],
        &fetcher,
        EngineLimits::default(),
        true,
        true,
        vec![],
        false,
    )
    .analyze(root.path())
    .await
    .unwrap();

    assert_eq!(report.packages.len(), 3);
    assert!(report.issues.is_empty(), "{:?}", report.issues);
    assert!(
        report
            .packages
            .iter()
            .any(|package| package.package_id.starts_with("npm:smart-buffer@4.2.0#"))
    );
}

#[tokio::test]
async fn root_npm_lock_dependency_cycle_terminates_and_analyzes_each_package_once() {
    let root = tempfile::tempdir().unwrap();
    let packages = tempfile::tempdir().unwrap();
    fs::write(
        root.path().join("package.json"),
        r#"{"dependencies":{"a":"1.0.0"}}"#,
    )
    .unwrap();
    fs::write(
        root.path().join("package-lock.json"),
        r#"{
            "lockfileVersion": 3,
            "packages": {
                "": {"dependencies":{"a":"1.0.0"}},
                "node_modules/a": {
                    "version":"1.0.0",
                    "resolved":"https://registry.npmjs.org/a/-/a-1.0.0.tgz",
                    "integrity":"sha512-a"
                },
                "node_modules/b": {
                    "version":"1.0.0",
                    "resolved":"https://registry.npmjs.org/b/-/b-1.0.0.tgz",
                    "integrity":"sha512-b"
                }
            }
        }"#,
    )
    .unwrap();
    fs::create_dir(packages.path().join("a")).unwrap();
    fs::write(
        packages.path().join("a/package.json"),
        r#"{"dependencies":{"b":"1.0.0"}}"#,
    )
    .unwrap();
    fs::create_dir(packages.path().join("b")).unwrap();
    fs::write(
        packages.path().join("b/package.json"),
        r#"{"dependencies":{"a":"1.0.0"}}"#,
    )
    .unwrap();

    let fetcher = FixtureFetcher {
        packages: packages.path().to_owned(),
    };
    let report = Engine::new(
        &[],
        &fetcher,
        EngineLimits::default(),
        true,
        true,
        vec![],
        false,
    )
    .analyze(root.path())
    .await
    .unwrap();

    assert!(report.issues.is_empty(), "{:?}", report.issues);
    assert_eq!(report.packages.len(), 3);
    for package_id in ["root", "npm:a@1.0.0#sha512-a", "npm:b@1.0.0#sha512-b"] {
        assert_eq!(
            report
                .packages
                .iter()
                .filter(|package| package.package_id == package_id)
                .count(),
            1,
            "expected {package_id} to be analyzed exactly once"
        );
    }
}
