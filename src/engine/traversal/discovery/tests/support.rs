use std::{fs, path::Path};

use crate::{
    engine::{
        Engine,
        traversal::state::{DiscoveryContexts, FetchRequest, PendingPackage},
    },
    fetcher::SourceFetcher,
    manifests,
    model::{EngineLimits, PolicySummary, Report, SerializableLimits},
};

#[derive(Debug, Clone, Copy)]
pub(super) enum LockfileFixture {
    None,
    PackageLock,
    Pnpm,
    Yarn,
}

impl LockfileFixture {
    pub(super) const ALL: [Self; 4] = [Self::None, Self::PackageLock, Self::Pnpm, Self::Yarn];
}

pub(super) fn workspace_requests(
    root: &Path,
    fetcher: &SourceFetcher,
    trust_local_input: bool,
) -> Vec<FetchRequest> {
    let outcome =
        manifests::discover_with_contexts_and_limits(root, &[], &[], &EngineLimits::default());
    assert!(outcome.errors.is_empty(), "{:?}", outcome.errors);
    let pending = PendingPackage {
        package_id: "root".to_owned(),
        source: root.to_owned(),
        depth: 0,
        fetched: None,
        contexts: DiscoveryContexts::default(),
        report_source: true,
    };
    let limits = EngineLimits::default();
    let policy = PolicySummary {
        require_lockfile: false,
        offline: true,
        trust_local_input,
        allow_insecure_http: false,
        allowed_hosts: Vec::new(),
        limits: SerializableLimits::from(&limits),
    };
    let engine = Engine::new(&[], fetcher, policy);
    let mut report = Report::new(root.to_owned(), engine.policy.clone());
    let requests = engine
        .fetch_requests_for(
            &pending,
            &outcome.discovery,
            outcome.python_contexts,
            &mut report,
        )
        .collect();
    assert!(report.issues.is_empty(), "{:?}", report.issues);
    requests
}

pub(super) fn workspace_fixture(fixture: LockfileFixture) -> tempfile::TempDir {
    let root = tempfile::tempdir().unwrap();
    fs::create_dir_all(root.path().join("packages/member")).unwrap();
    fs::create_dir_all(root.path().join("packages/sibling")).unwrap();
    fs::write(
        root.path().join("package.json"),
        r#"{"workspaces":["packages/*"]}"#,
    )
    .unwrap();
    fs::write(
        root.path().join("packages/member/package.json"),
        r#"{"dependencies":{"sibling":"file:../sibling"}}"#,
    )
    .unwrap();
    fs::write(
        root.path().join("packages/sibling/package.json"),
        r#"{"name":"sibling","version":"1.0.0"}"#,
    )
    .unwrap();

    match fixture {
        LockfileFixture::None => {}
        LockfileFixture::PackageLock => fs::write(
            root.path().join("package-lock.json"),
            r#"{
                "lockfileVersion": 3,
                "packages": {
                    "": {},
                    "packages/member": {"dependencies":{"sibling":"file:../sibling"}},
                    "packages/member/node_modules/sibling": {
                        "resolved":"packages/sibling",
                        "link":true
                    },
                    "packages/sibling": {"name":"sibling","version":"1.0.0"}
                }
            }"#,
        )
        .unwrap(),
        LockfileFixture::Pnpm => fs::write(
            root.path().join("pnpm-lock.yaml"),
            r#"
lockfileVersion: '9.0'
importers:
  packages/member:
    dependencies:
      sibling:
        specifier: file:../sibling
        version: link:../sibling
packages: {}
"#,
        )
        .unwrap(),
        LockfileFixture::Yarn => fs::write(
            root.path().join("yarn.lock"),
            r#"
__metadata:
  version: 8

"sibling@file:../sibling":
  version: 0.0.0-use.local
  resolution: "sibling@file:../sibling"
  linkType: soft
"#,
        )
        .unwrap(),
    }

    root
}
