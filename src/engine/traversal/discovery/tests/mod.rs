mod support;

use std::{collections::BTreeSet, fs};

use crate::{
    error::Error,
    fetcher::{FetchPolicy, Fetcher, SourceFetcher},
    model::EngineLimits,
};

use support::{LockfileFixture, workspace_fixture, workspace_requests};

#[tokio::test]
async fn workspace_member_local_dependencies_keep_member_confinement_for_every_lock_mode() {
    for fixture in LockfileFixture::ALL {
        let root = workspace_fixture(fixture);
        let member = root.path().join("packages/member");
        let expected = format!("{fixture:?}");
        fs::write(root.path().join("packages/sibling/marker.txt"), &expected).unwrap();

        let untrusted_cache = tempfile::tempdir().unwrap();
        let untrusted = SourceFetcher::new(
            untrusted_cache.path().join("cache"),
            FetchPolicy::default(),
            EngineLimits::default(),
        )
        .unwrap();
        let mut requests = workspace_requests(root.path(), &untrusted, false);
        assert_eq!(requests.len(), 1, "{fixture:?}");
        let request = requests.pop().unwrap();
        assert_eq!(request.declared_from, member, "{fixture:?}");
        let error = untrusted
            .fetch(request.dependency, request.declared_from)
            .await
            .unwrap_err();
        assert!(
            matches!(
                &error,
                Error::Policy { operation, message }
                    if operation == "local dependency"
                        && message.contains("escapes")
                        && message.contains("--trust-local-input")
            ),
            "{fixture:?}: {error}"
        );

        let trusted_cache = tempfile::tempdir().unwrap();
        let trusted = SourceFetcher::new(
            trusted_cache.path().join("cache"),
            FetchPolicy {
                trust_local_input: true,
                ..FetchPolicy::default()
            },
            EngineLimits::default(),
        )
        .unwrap();
        let mut requests = workspace_requests(root.path(), &trusted, true);
        assert_eq!(requests.len(), 1, "{fixture:?}");
        let request = requests.pop().unwrap();
        assert_eq!(request.declared_from, member, "{fixture:?}");
        let metadata = trusted
            .fetch(request.dependency, request.declared_from)
            .await
            .unwrap();
        assert_eq!(
            fs::read_to_string(metadata.source.join("marker.txt")).unwrap(),
            expected,
            "{fixture:?}"
        );
    }
}

#[test]
fn identical_local_declarations_from_distinct_members_create_distinct_requests() {
    let root = tempfile::tempdir().unwrap();
    fs::create_dir_all(root.path().join("packages/a")).unwrap();
    fs::create_dir_all(root.path().join("packages/b")).unwrap();
    fs::create_dir_all(root.path().join("packages/sibling")).unwrap();
    fs::write(
        root.path().join("package.json"),
        r#"{"workspaces":["packages/*"]}"#,
    )
    .unwrap();
    for member in ["a", "b"] {
        fs::write(
            root.path()
                .join("packages")
                .join(member)
                .join("package.json"),
            r#"{"dependencies":{"sibling":"file:../sibling"}}"#,
        )
        .unwrap();
    }
    fs::write(root.path().join("packages/sibling/package.json"), "{}").unwrap();

    let cache = tempfile::tempdir().unwrap();
    let fetcher = SourceFetcher::new(
        cache.path().join("cache"),
        FetchPolicy::default(),
        EngineLimits::default(),
    )
    .unwrap();
    let requests = workspace_requests(root.path(), &fetcher, false);
    let declared_from = requests
        .into_iter()
        .map(|request| request.declared_from)
        .collect::<BTreeSet<_>>();

    assert_eq!(
        declared_from,
        BTreeSet::from([
            root.path().join("packages/a"),
            root.path().join("packages/b"),
        ])
    );
}
