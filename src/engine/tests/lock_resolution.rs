use super::*;

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
files = [{file = "pandas.whl", hash = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}]

[[package]]
name = "numpy"
version = "2.3.3"
files = [{file = "numpy.whl", hash = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}]

[[package]]
name = "python-dateutil"
version = "2.9.0"
files = [{file = "dateutil.whl", hash = "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"}]

[[package]]
name = "tzdata"
version = "2025.2"
files = [{file = "tzdata.whl", hash = "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"}]

[metadata]
lock-version = "2.0"
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
                        "integrity":"sha512-ip-address",
                        "dependencies":{"smart-buffer":"^4.2.0"}
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
async fn shared_npm_artifact_preserves_distinct_lock_path_contexts() {
    let root = tempfile::tempdir().unwrap();
    let packages = tempfile::tempdir().unwrap();
    fs::write(
        root.path().join("package.json"),
        r#"{"dependencies":{"parent-a":"1.0.0","parent-b":"1.0.0"}}"#,
    )
    .unwrap();
    fs::write(
        root.path().join("package-lock.json"),
        r#"{
            "lockfileVersion": 3,
            "packages": {
                "": {"dependencies":{"parent-a":"1.0.0","parent-b":"1.0.0"}},
                "node_modules/parent-a": {"version":"1.0.0","resolved":"https://registry.example.test/parent-a.tgz","integrity":"sha512-parent-a","dependencies":{"shared":"1.0.0"}},
                "node_modules/parent-b": {"version":"1.0.0","resolved":"https://registry.example.test/parent-b.tgz","integrity":"sha512-parent-b","dependencies":{"shared":"1.0.0"}},
                "node_modules/parent-a/node_modules/shared": {"version":"1.0.0","resolved":"https://registry.example.test/shared.tgz","integrity":"sha512-shared","dependencies":{"child":"*"}},
                "node_modules/parent-b/node_modules/shared": {"version":"1.0.0","resolved":"https://registry.example.test/shared.tgz","integrity":"sha512-shared","dependencies":{"child":"*"}},
                "node_modules/parent-a/node_modules/shared/node_modules/child": {"version":"1.0.0","resolved":"https://registry.example.test/child-1.tgz","integrity":"sha512-child-1"},
                "node_modules/parent-b/node_modules/shared/node_modules/child": {"version":"2.0.0","resolved":"https://registry.example.test/child-2.tgz","integrity":"sha512-child-2"}
            }
        }"#,
    )
    .unwrap();

    for package in [
        "parent-a",
        "parent-b",
        "shared",
        "child-1.0.0",
        "child-2.0.0",
    ] {
        fs::create_dir(packages.path().join(package)).unwrap();
    }
    for parent in ["parent-a", "parent-b"] {
        fs::write(
            packages.path().join(parent).join("package.json"),
            r#"{"dependencies":{"shared":"1.0.0"}}"#,
        )
        .unwrap();
    }
    fs::write(
        packages.path().join("shared/package.json"),
        r#"{"name":"shared","version":"1.0.0","dependencies":{"child":"*"}}"#,
    )
    .unwrap();
    fs::write(
        packages.path().join("shared/index.js"),
        "module.exports = {};\n",
    )
    .unwrap();
    for version in ["1.0.0", "2.0.0"] {
        fs::write(
            packages
                .path()
                .join(format!("child-{version}/package.json")),
            format!(r#"{{"name":"child","version":"{version}"}}"#),
        )
        .unwrap();
    }

    let fetches = Arc::new(Mutex::new(HashMap::new()));
    let fetcher = ContextFixtureFetcher {
        packages: packages.path().to_owned(),
        fetches: Arc::clone(&fetches),
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
    for child in [
        "npm:child@1.0.0#sha512-child-1",
        "npm:child@2.0.0#sha512-child-2",
    ] {
        assert!(
            report
                .packages
                .iter()
                .any(|package| package.package_id == child),
            "expected {child} to be scanned"
        );
    }
    let shared = report
        .packages
        .iter()
        .filter(|package| package.package_id == "npm:shared@1.0.0#sha512-shared")
        .collect::<Vec<_>>();
    assert_eq!(shared.len(), 1, "shared artifact should be reported once");
    assert_eq!(
        shared[0].scanned_files, 1,
        "shared artifact should be scanned once"
    );
    assert_eq!(
        fetches
            .lock()
            .unwrap()
            .get("npm:shared@1.0.0#sha512-shared"),
        Some(&1),
        "shared artifact should be fetched once"
    );
}

#[tokio::test]
async fn shared_python_artifact_preserves_distinct_lock_contexts() {
    let root = tempfile::tempdir().unwrap();
    let packages = tempfile::tempdir().unwrap();
    for package in ["parent-a", "parent-b", "shared", "child-a", "child-b"] {
        fs::create_dir(packages.path().join(package)).unwrap();
    }

    fs::write(
        root.path().join("pyproject.toml"),
        r#"[project]
dependencies = ["parent-a", "parent-b"]
"#,
    )
    .unwrap();
    fs::write(
        root.path().join("uv.lock"),
        r#"version = 1

[[package]]
name = "parent-a"
version = "1.0.0"
sdist = { url = "https://registry.example.test/parent-a.tar.gz", hash = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" }

[[package]]
name = "parent-b"
version = "1.0.0"
sdist = { url = "https://registry.example.test/parent-b.tar.gz", hash = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb" }
"#,
    )
    .unwrap();
    for parent in ["parent-a", "parent-b"] {
        fs::write(
            packages.path().join(parent).join("pyproject.toml"),
            r#"[project]
dependencies = ["shared"]
"#,
        )
        .unwrap();
    }
    for (parent, child, digest) in [
        (
            "parent-a",
            "child-a",
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        ),
        (
            "parent-b",
            "child-b",
            "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        ),
    ] {
        fs::write(
            packages.path().join(parent).join("uv.lock"),
            format!(
                r#"version = 1

[[package]]
name = "shared"
version = "1.0.0"
sdist = {{ url = "https://registry.example.test/shared.tar.gz", hash = "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc" }}

[[package]]
name = "{child}"
version = "1.0.0"
sdist = {{ url = "https://registry.example.test/{child}.tar.gz", hash = "sha256:{digest}" }}
"#,
            ),
        )
        .unwrap();
    }
    fs::write(
        packages.path().join("shared/pyproject.toml"),
        r#"[project]
dependencies = ["child-a", "child-b"]
"#,
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
    for child in ["child-a", "child-b"] {
        assert!(
            report.packages.iter().any(|package| package
                .package_id
                .starts_with(&format!("python:{child}@1.0.0#"))),
            "expected {child} to be scanned"
        );
    }
}
