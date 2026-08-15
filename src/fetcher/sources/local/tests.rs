use std::fs;

use crate::{
    fetcher::{FetchPolicy, SourceFetcher},
    model::{Dependency, Ecosystem, EngineLimits},
};

fn fetch_local_with_limits(
    project: &std::path::Path,
    limits: EngineLimits,
) -> crate::Result<crate::model::FetchMetadata> {
    let cache = tempfile::tempdir().unwrap();
    let fetcher =
        SourceFetcher::new(cache.path().join("cache"), FetchPolicy::default(), limits).unwrap();
    let dependency = Dependency::declared(Ecosystem::Npm, "dep", "file:./dep");
    fetcher.fetch_local_dependency(&dependency, project)
}

#[test]
fn local_dependencies_are_snapshotted_before_analysis() {
    let project = tempfile::tempdir().unwrap();
    let dependency_directory = project.path().join("dep");
    fs::create_dir(&dependency_directory).unwrap();
    fs::write(
        dependency_directory.join("index.js"),
        "const value = 'original';",
    )
    .unwrap();

    let cache = tempfile::tempdir().unwrap();
    let fetcher = SourceFetcher::new(
        cache.path().join("cache"),
        FetchPolicy::default(),
        EngineLimits::default(),
    )
    .unwrap();
    let dependency = Dependency::declared(Ecosystem::Npm, "dep", "file:./dep");

    let metadata = fetcher
        .fetch_local_dependency(&dependency, project.path())
        .unwrap();
    fs::write(
        dependency_directory.join("index.js"),
        "const value = 'replacement';",
    )
    .unwrap();

    assert_eq!(
        fs::read_to_string(metadata.source.join("index.js")).unwrap(),
        "const value = 'original';"
    );
    assert_ne!(metadata.source, dependency_directory);
}

#[test]
fn local_package_identity_is_stable_across_snapshot_workspaces() {
    let project = tempfile::tempdir().unwrap();
    let dependency_directory = project.path().join("dep");
    fs::create_dir(&dependency_directory).unwrap();
    fs::write(dependency_directory.join("index.js"), "source").unwrap();

    let cache = tempfile::tempdir().unwrap();
    let fetcher = SourceFetcher::new(
        cache.path().join("cache"),
        FetchPolicy::default(),
        EngineLimits::default(),
    )
    .unwrap();
    let dependency = Dependency::declared(Ecosystem::Npm, "dep", "file:./dep");

    let first = fetcher
        .fetch_local_dependency(&dependency, project.path())
        .unwrap();
    let second = fetcher
        .fetch_local_dependency(&dependency, project.path())
        .unwrap();

    assert_ne!(first.source, second.source);
    assert_eq!(first.package_id, second.package_id);
    assert!(
        first
            .package_id
            .starts_with("npm:dep@file:./dep#unverified@local-source:sha256:")
    );
    assert_eq!(first.digest, "local-unverified");
}

#[test]
fn equal_local_declarations_at_distinct_sources_have_distinct_package_ids() {
    let root = tempfile::tempdir().unwrap();
    let cache = tempfile::tempdir().unwrap();
    let fetcher = SourceFetcher::new(
        cache.path().join("cache"),
        FetchPolicy::default(),
        EngineLimits::default(),
    )
    .unwrap();
    let dependency = Dependency::declared(Ecosystem::Npm, "dep", "file:./dep");
    let mut package_ids = Vec::new();

    for parent in ["parent-a", "parent-b"] {
        let parent = root.path().join(parent);
        fs::create_dir_all(parent.join("dep")).unwrap();
        fs::write(parent.join("dep/index.js"), "same source").unwrap();
        package_ids.push(
            fetcher
                .fetch_local_dependency(&dependency, &parent)
                .unwrap()
                .package_id,
        );
    }

    assert_ne!(package_ids[0], package_ids[1]);
}

#[test]
fn link_and_portal_dependencies_resolve_relative_to_the_declaring_package() {
    let project = tempfile::tempdir().unwrap();
    let dependency_directory = project.path().join("dep");
    fs::create_dir(&dependency_directory).unwrap();
    fs::write(dependency_directory.join("index.js"), "local source").unwrap();
    let cache = tempfile::tempdir().unwrap();
    let fetcher = SourceFetcher::new(
        cache.path().join("cache"),
        FetchPolicy::default(),
        EngineLimits::default(),
    )
    .unwrap();

    for protocol in ["link:", "portal:"] {
        let dependency = Dependency::declared(Ecosystem::Deno, "dep", format!("{protocol}./dep"));
        let metadata = fetcher
            .fetch_local_dependency(&dependency, project.path())
            .unwrap();

        assert_eq!(
            fs::read_to_string(metadata.source.join("index.js")).unwrap(),
            "local source"
        );
        assert_eq!(metadata.source_url, "file:./dep");
    }
}

#[test]
fn link_and_portal_dependencies_retain_local_confinement() {
    let root = tempfile::tempdir().unwrap();
    let project = root.path().join("project");
    fs::create_dir(&project).unwrap();
    fs::create_dir(root.path().join("outside")).unwrap();
    let cache = tempfile::tempdir().unwrap();
    let fetcher = SourceFetcher::new(
        cache.path().join("cache"),
        FetchPolicy::default(),
        EngineLimits::default(),
    )
    .unwrap();

    for protocol in ["link:", "portal:"] {
        let dependency =
            Dependency::declared(Ecosystem::Deno, "outside", format!("{protocol}../outside"));
        let error = fetcher
            .fetch_local_dependency(&dependency, &project)
            .unwrap_err();

        assert!(matches!(
            error,
            crate::Error::Policy { operation, message }
                if operation == "local dependency" && message.contains("escapes")
        ));
    }
}

#[test]
fn trusted_local_dependency_outside_declaring_root_is_snapshotted() {
    let root = tempfile::tempdir().unwrap();
    let project = root.path().join("project");
    let dependency_directory = root.path().join("shared-dep");
    fs::create_dir(&project).unwrap();
    fs::create_dir(&dependency_directory).unwrap();
    fs::write(dependency_directory.join("index.js"), "trusted original").unwrap();

    let cache = tempfile::tempdir().unwrap();
    let policy = FetchPolicy {
        trust_local_input: true,
        ..FetchPolicy::default()
    };
    let fetcher =
        SourceFetcher::new(cache.path().join("cache"), policy, EngineLimits::default()).unwrap();
    let dependency = Dependency::declared(Ecosystem::Npm, "dep", "file:../shared-dep");

    let metadata = fetcher
        .fetch_local_dependency(&dependency, &project)
        .unwrap();
    fs::write(dependency_directory.join("index.js"), "replacement").unwrap();

    assert_eq!(
        fs::read_to_string(metadata.source.join("index.js")).unwrap(),
        "trusted original"
    );
    assert_ne!(metadata.source, dependency_directory);
}

#[test]
fn untrusted_local_dependency_outside_declaring_root_is_rejected() {
    let root = tempfile::tempdir().unwrap();
    let project = root.path().join("project");
    let dependency_directory = root.path().join("shared-dep");
    fs::create_dir(&project).unwrap();
    fs::create_dir(&dependency_directory).unwrap();

    let cache = tempfile::tempdir().unwrap();
    let fetcher = SourceFetcher::new(
        cache.path().join("cache"),
        FetchPolicy::default(),
        EngineLimits::default(),
    )
    .unwrap();
    let dependency = Dependency::declared(Ecosystem::Npm, "dep", "file:../shared-dep");

    let error = fetcher
        .fetch_local_dependency(&dependency, &project)
        .unwrap_err();

    assert!(matches!(
        error,
        crate::Error::Policy { operation, message }
            if operation == "local dependency"
                && message.contains("escapes")
                && message.contains("--trust-local-input")
    ));
}

#[cfg(unix)]
#[test]
fn trusted_external_local_snapshot_does_not_follow_symlinked_files() {
    use std::os::unix::fs::symlink;

    let root = tempfile::tempdir().unwrap();
    let project = root.path().join("project");
    let dependency_directory = root.path().join("shared-dep");
    fs::create_dir(&project).unwrap();
    fs::create_dir(&dependency_directory).unwrap();
    fs::write(root.path().join("secret"), "secret").unwrap();
    symlink(
        root.path().join("secret"),
        dependency_directory.join("index.js"),
    )
    .unwrap();

    let cache = tempfile::tempdir().unwrap();
    let policy = FetchPolicy {
        trust_local_input: true,
        ..FetchPolicy::default()
    };
    let fetcher =
        SourceFetcher::new(cache.path().join("cache"), policy, EngineLimits::default()).unwrap();
    let dependency = Dependency::declared(Ecosystem::Npm, "dep", "file:../shared-dep");

    let error = fetcher
        .fetch_local_dependency(&dependency, &project)
        .unwrap_err();

    assert!(matches!(
        error,
        crate::Error::Policy { operation, message }
            if operation == "local dependency" && message.contains("refusing unsafe path")
    ));
}

#[test]
fn local_snapshot_honors_the_acquisition_deadline() {
    let project = tempfile::tempdir().unwrap();
    let dependency_directory = project.path().join("dep");
    fs::create_dir(&dependency_directory).unwrap();
    fs::write(dependency_directory.join("index.js"), "source").unwrap();
    let limits = EngineLimits {
        max_acquisition_duration: std::time::Duration::ZERO,
        ..EngineLimits::default()
    };

    let error = fetch_local_with_limits(project.path(), limits).unwrap_err();

    assert_eq!(error.code(), "limit_exceeded", "{error}");
    assert!(error.to_string().contains("package acquisition seconds"));
}

#[test]
fn local_dependency_snapshot_rejects_too_many_entries() {
    let project = tempfile::tempdir().unwrap();
    let dependency_directory = project.path().join("dep");
    fs::create_dir(&dependency_directory).unwrap();
    fs::write(dependency_directory.join("first.js"), "first").unwrap();
    fs::write(dependency_directory.join("second.js"), "second").unwrap();
    let limits = EngineLimits {
        max_extracted_files: 1,
        ..EngineLimits::default()
    };

    let error = fetch_local_with_limits(project.path(), limits).unwrap_err();

    assert!(matches!(
        error,
        crate::Error::LimitExceeded { resource, limit }
            if resource == "extracted files" && limit == 1
    ));
}

#[test]
fn local_dependency_snapshot_accepts_bytes_at_the_exact_limit() {
    let project = tempfile::tempdir().unwrap();
    let dependency_directory = project.path().join("dep");
    fs::create_dir(&dependency_directory).unwrap();
    fs::write(dependency_directory.join("index.js"), b"12345").unwrap();
    let limits = EngineLimits {
        max_extracted_size: 5,
        ..EngineLimits::default()
    };

    fetch_local_with_limits(project.path(), limits).unwrap();
}

#[test]
fn local_dependency_snapshot_rejects_too_many_bytes() {
    let project = tempfile::tempdir().unwrap();
    let dependency_directory = project.path().join("dep");
    fs::create_dir(&dependency_directory).unwrap();
    fs::write(dependency_directory.join("index.js"), b"123456").unwrap();
    let limits = EngineLimits {
        max_extracted_size: 5,
        ..EngineLimits::default()
    };

    let error = fetch_local_with_limits(project.path(), limits).unwrap_err();

    assert!(matches!(
        error,
        crate::Error::LimitExceeded { resource, limit }
            if resource == "extracted bytes" && limit == 5
    ));
}

#[test]
fn local_dependency_snapshot_rejects_excessive_path_depth() {
    let project = tempfile::tempdir().unwrap();
    let mut directory = project.path().join("dep");
    fs::create_dir(&directory).unwrap();
    let limits = EngineLimits {
        max_file_depth: 4,
        ..EngineLimits::default()
    };
    for _ in 0..=limits.max_file_depth {
        directory = directory.join("nested");
        fs::create_dir(&directory).unwrap();
    }

    let error = fetch_local_with_limits(project.path(), limits).unwrap_err();

    assert!(matches!(
        error,
        crate::Error::Policy { operation, message }
            if operation == "local dependency" && message.contains("deeper than 4 components")
    ));
}
