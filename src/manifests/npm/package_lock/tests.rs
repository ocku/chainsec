use std::{collections::HashMap, fs};

use crate::model::Ecosystem;

use super::*;

fn enrich_fixture(
    lockfile: &str,
    package_path: &str,
    name: &str,
    requirement: &str,
) -> (Dependency, HashMap<String, NpmLockContext>) {
    let temporary = tempfile::tempdir().unwrap();
    let path = temporary.path().join("package-lock.json");
    fs::write(&path, lockfile).unwrap();
    let context = NpmLockContext {
        lockfile: path,
        package_path: package_path.to_owned(),
    };
    let mut dependencies = [Dependency::declared(Ecosystem::Npm, name, requirement)];
    let contexts = enrich(&context, &mut dependencies).unwrap();
    (dependencies.into_iter().next().unwrap(), contexts)
}

#[test]
fn rejects_non_object_roots_and_missing_or_non_integer_versions() {
    for lockfile in ["[]", r#"{}"#, r#"{"lockfileVersion":"3"}"#] {
        let temporary = tempfile::tempdir().unwrap();
        let path = temporary.path().join("package-lock.json");
        fs::write(&path, lockfile).unwrap();
        let context = NpmLockContext {
            lockfile: path,
            package_path: String::new(),
        };
        let mut dependencies = [];
        assert!(enrich(&context, &mut dependencies).is_err());
    }
}

#[test]
fn requires_the_current_importer_specifier_to_match_before_enrichment() {
    let lockfile = r#"{
        "lockfileVersion":3,
        "packages":{
            "":{"dependencies":{"child":"^2"}},
            "node_modules/child":{"version":"2.1.0","integrity":"sha512-child"}
        }
    }"#;

    let (dependency, _) = enrich_fixture(lockfile, "", "child", "^1");

    assert!(dependency.resolved_version.is_none());
    assert!(dependency.lockfile.is_none());
}

#[test]
fn enriches_development_dependency() {
    let lockfile = r#"{
        "lockfileVersion":3,
        "packages":{
            "":{"devDependencies":{"child":"^2"}},
            "node_modules/child":{"version":"2.1.0","integrity":"sha512-child"}
        }
    }"#;

    let (dependency, _) = enrich_fixture(lockfile, "", "child", "^2");

    assert_eq!(dependency.resolved_version.as_deref(), Some("2.1.0"));
    assert_eq!(dependency.integrity.as_deref(), Some("sha512-child"));
    assert!(dependency.lockfile.is_some());
}

#[test]
fn inherited_context_uses_its_importer_and_preserves_hoisted_lookup() {
    let lockfile = r#"{
        "lockfileVersion":3,
        "packages":{
            "":{"dependencies":{"parent":"1.0.0"}},
            "node_modules/parent":{
                "version":"1.0.0",
                "dependencies":{"child":"^2.0.0"}
            },
            "node_modules/child":{"version":"2.3.0","integrity":"sha512-child"}
        }
    }"#;

    let (dependency, contexts) = enrich_fixture(lockfile, "node_modules/parent", "child", "^2.0.0");

    assert_eq!(dependency.resolved_version.as_deref(), Some("2.3.0"));
    assert!(dependency.lockfile.is_some());
    assert_eq!(contexts.len(), 1);
}

#[test]
fn missing_registry_artifact_data_defers_integrity_to_configured_registry() {
    let lockfile = r#"{
        "lockfileVersion":3,
        "packages":{
            "":{"dependencies":{"child":"1.0.0"}},
            "node_modules/child":{"version":"1.0.0"}
        }
    }"#;

    let (dependency, _) = enrich_fixture(lockfile, "", "child", "1.0.0");

    assert_eq!(dependency.resolved_version.as_deref(), Some("1.0.0"));
    assert!(dependency.source_url.is_none());
    assert!(dependency.registry_integrity_required);
}

#[test]
fn registry_dependency_does_not_adopt_a_github_archive_identity() {
    let resolved =
        "https://codeload.github.com/attacker/repo/tar.gz/0123456789012345678901234567890123456789";
    let lockfile = format!(
        r#"{{
            "lockfileVersion":3,
            "packages":{{
                "":{{"dependencies":{{"child":"^1"}}}},
                "node_modules/child":{{
                    "version":"1.2.3",
                    "resolved":"{resolved}",
                    "integrity":"sha512-child"
                }}
            }}
        }}"#
    );

    let (dependency, _) = enrich_fixture(&lockfile, "", "child", "^1");

    assert_eq!(dependency.resolved_version.as_deref(), Some("1.2.3"));
    assert_eq!(dependency.source_url.as_deref(), Some(resolved));
    assert_eq!(dependency.integrity.as_deref(), Some("sha512-child"));
    assert!(!dependency.registry_integrity_required);
}

#[test]
fn pinned_github_archive_requires_a_matching_codeload_resolution() {
    let requirement = "github:owner/repository#0123456789012345678901234567890123456789";
    for resolved in [
        "https://registry.example.test/child.tgz",
        "https://codeload.github.com/owner/repository/tar.gz/1111111111111111111111111111111111111111",
        "https://codeload.github.com/other/repository/tar.gz/0123456789012345678901234567890123456789",
    ] {
        let lockfile = format!(
            r#"{{
                "lockfileVersion":3,
                "packages":{{
                    "":{{"dependencies":{{"child":"{requirement}"}}}},
                    "node_modules/child":{{"version":"1.0.0","resolved":"{resolved}"}}
                }}
            }}"#
        );
        let (dependency, contexts) = enrich_fixture(&lockfile, "", "child", requirement);

        assert!(dependency.resolved_version.is_none(), "{resolved}");
        assert!(dependency.source_url.is_none(), "{resolved}");
        assert!(dependency.lockfile.is_none(), "{resolved}");
        assert!(contexts.is_empty(), "{resolved}");
    }

    let lockfile = format!(
        r#"{{"lockfileVersion":3,"packages":{{"":{{"dependencies":{{"child":"{requirement}"}}}},"node_modules/child":{{"resolved":"https://codeload.github.com/owner/repository/tar.gz/0123456789012345678901234567890123456789"}}}}}}"#
    );
    let (dependency, _) = enrich_fixture(&lockfile, "", "child", requirement);
    assert_eq!(
        dependency.source_url.as_deref(),
        Some(
            "https://codeload.github.com/owner/repository/tar.gz/0123456789012345678901234567890123456789"
        )
    );
}

#[test]
fn modern_lock_rejects_a_version_outside_the_declared_range() {
    let lockfile = r#"{
        "lockfileVersion":3,
        "packages":{
            "":{"dependencies":{"child":"^1.0.0"}},
            "node_modules/child":{
                "version":"9.0.0",
                "resolved":"https://attacker.example/child.tgz",
                "integrity":"sha512-child"
            }
        }
    }"#;
    let temporary = tempfile::tempdir().unwrap();
    let path = temporary.path().join("package-lock.json");
    fs::write(&path, lockfile).unwrap();
    let context = NpmLockContext {
        lockfile: path,
        package_path: String::new(),
    };
    let mut dependencies = [Dependency::declared(Ecosystem::Npm, "child", "^1.0.0")];

    assert!(enrich(&context, &mut dependencies).is_err());
    assert!(dependencies[0].resolved_version.is_none());
}

#[test]
fn modern_lock_rejects_an_alias_with_mismatched_locked_package_identity() {
    let lockfile = r#"{
        "lockfileVersion":3,
        "packages":{
            "":{"dependencies":{"alias":"npm:target@^1.0.0"}},
            "node_modules/alias":{
                "name":"other-target",
                "version":"1.2.0",
                "resolved":"https://registry.example.test/target-1.2.0.tgz",
                "integrity":"sha512-target"
            }
        }
    }"#;

    let (dependency, contexts) = enrich_fixture(lockfile, "", "alias", "npm:target@^1.0.0");

    assert!(dependency.resolved_version.is_none());
    assert!(dependency.lockfile.is_none());
    assert!(contexts.is_empty());
}

#[test]
fn modern_lock_rejects_an_alias_with_mismatched_locked_artifact_identity() {
    let lockfile = r#"{
        "lockfileVersion":3,
        "packages":{
            "":{"dependencies":{"alias":"npm:target@^1.0.0"}},
            "node_modules/alias":{
                "version":"1.2.0",
                "resolved":"https://registry.example.test/other-target-1.2.0.tgz",
                "integrity":"sha512-target"
            }
        }
    }"#;

    let (dependency, contexts) = enrich_fixture(lockfile, "", "alias", "npm:target@^1.0.0");

    assert!(dependency.resolved_version.is_none());
    assert!(dependency.lockfile.is_none());
    assert!(contexts.is_empty());
}

#[test]
fn modern_lock_accepts_a_version_inside_the_declared_range() {
    let lockfile = r#"{
        "lockfileVersion":3,
        "packages":{
            "":{"dependencies":{"child":"^1.0.0"}},
            "node_modules/child":{"version":"1.4.0","integrity":"sha512-child"}
        }
    }"#;

    let (dependency, _) = enrich_fixture(lockfile, "", "child", "^1.0.0");

    assert_eq!(dependency.resolved_version.as_deref(), Some("1.4.0"));
}

#[test]
fn modern_workspace_link_uses_local_source_and_linked_package_context() {
    let lockfile = r#"{
        "lockfileVersion":3,
        "packages":{
            "":{"dependencies":{"workspace-child":"workspace:*"}},
            "packages/child":{
                "version":"1.2.3",
                "dependencies":{"grandchild":"^2"}
            },
            "node_modules/workspace-child":{"resolved":"packages/child","link":true},
            "packages/child/node_modules/grandchild":{
                "version":"2.1.0",
                "integrity":"sha512-grandchild"
            }
        }
    }"#;

    let (dependency, contexts) = enrich_fixture(lockfile, "", "workspace-child", "workspace:*");

    assert_eq!(dependency.resolved_version.as_deref(), Some("1.2.3"));
    assert!(
        dependency
            .source_url
            .as_deref()
            .is_some_and(|url| { url.starts_with("file://") && url.ends_with("/packages/child") })
    );
    assert!(dependency.is_local());
    assert_eq!(
        contexts
            .get(&dependency.id())
            .map(|context| context.package_path.as_str()),
        Some("packages/child")
    );
}

#[test]
fn legacy_from_prevents_mismatched_enrichment_when_available() {
    let lockfile = r#"{
        "lockfileVersion":1,
        "dependencies":{
            "child":{"version":"2.0.0","from":"child@^2"}
        }
    }"#;

    let (dependency, _) = enrich_fixture(lockfile, "", "child", "^1");

    assert!(dependency.resolved_version.is_none());
}

#[test]
fn legacy_without_from_uses_semver_instead_of_package_name_alone() {
    let lockfile = r#"{
        "lockfileVersion":1,
        "dependencies":{
            "child":{"version":"2.3.0","integrity":"sha512-child"}
        }
    }"#;

    let (compatible, contexts) = enrich_fixture(lockfile, "", "child", "^2.0.0");
    assert_eq!(compatible.resolved_version.as_deref(), Some("2.3.0"));
    assert_eq!(contexts.len(), 1);

    for requirement in ["^1.0.0", "latest", "github:owner/repository"] {
        let (dependency, contexts) = enrich_fixture(lockfile, "", "child", requirement);
        assert!(dependency.resolved_version.is_none(), "bound {requirement}");
        assert!(dependency.lockfile.is_none());
        assert!(contexts.is_empty());
    }
}

#[test]
fn legacy_without_from_rejects_non_semver_locked_versions() {
    let lockfile = r#"{
        "lockfileVersion":1,
        "dependencies":{
            "child":{"version":"not-semver","integrity":"sha512-child"}
        }
    }"#;

    let (dependency, contexts) = enrich_fixture(lockfile, "", "child", "^1");

    assert!(dependency.resolved_version.is_none());
    assert!(dependency.lockfile.is_none());
    assert!(contexts.is_empty());
}

#[test]
fn legacy_rejects_file_resolution_for_non_local_declarations() {
    let lockfile = r#"{
        "lockfileVersion":1,
        "dependencies":{
            "child":{"version":"1.0.0","resolved":"file:../stale-child"}
        }
    }"#;

    let (remote, contexts) = enrich_fixture(lockfile, "", "child", "^1");
    assert!(remote.resolved_version.is_none());
    assert!(remote.source_url.is_none());
    assert!(remote.lockfile.is_none());
    assert!(contexts.is_empty());

    let (local, contexts) = enrich_fixture(lockfile, "", "child", "file:../stale-child");
    assert_eq!(local.resolved_version.as_deref(), Some("1.0.0"));
    assert_eq!(local.source_url.as_deref(), Some("file:../stale-child"));
    assert!(local.lockfile.is_some());
    assert_eq!(contexts.len(), 1);
}

#[test]
fn legacy_nested_context_resolves_transitive_dependencies() {
    let lockfile = r#"{
        "lockfileVersion":1,
        "dependencies":{
            "parent":{
                "version":"1.0.0",
                "integrity":"sha512-parent",
                "requires":{"child":"^2.0.0"},
                "dependencies":{
                    "child":{
                        "version":"2.4.0",
                        "integrity":"sha512-child",
                        "requires":{"grandchild":"~3.1.0"},
                        "dependencies":{
                            "grandchild":{"version":"3.1.2","integrity":"sha512-grandchild"}
                        }
                    }
                }
            }
        }
    }"#;

    let (parent, parent_contexts) = enrich_fixture(lockfile, "", "parent", "^1");
    let parent_context = parent_contexts.get(&parent.id()).unwrap();
    let (child, child_contexts) =
        enrich_fixture(lockfile, &parent_context.package_path, "child", "^2.0.0");
    let child_context = child_contexts.get(&child.id()).unwrap();
    let (grandchild, _) = enrich_fixture(
        lockfile,
        &child_context.package_path,
        "grandchild",
        "~3.1.0",
    );

    assert_eq!(child.resolved_version.as_deref(), Some("2.4.0"));
    assert_eq!(grandchild.resolved_version.as_deref(), Some("3.1.2"));
}

#[test]
fn legacy_nested_context_requires_the_importers_locked_declaration() {
    let lockfile = r#"{
        "lockfileVersion":1,
        "dependencies":{
            "parent":{
                "version":"1.0.0",
                "requires":{"child":"^2"},
                "dependencies":{
                    "child":{"version":"2.1.0","integrity":"sha512-child"}
                }
            }
        }
    }"#;

    let (parent, parent_contexts) = enrich_fixture(lockfile, "", "parent", "1.0.0");
    let context = parent_contexts.get(&parent.id()).unwrap();
    let (child, contexts) = enrich_fixture(lockfile, &context.package_path, "child", "^1");

    assert!(child.resolved_version.is_none());
    assert!(contexts.is_empty());
}

#[test]
fn legacy_nested_context_resolves_hoisted_dependencies() {
    let lockfile = r#"{
        "lockfileVersion":1,
        "dependencies":{
            "parent":{
                "version":"1.0.0",
                "requires":{"child":"^2"}
            },
            "child":{"version":"2.2.0","integrity":"sha512-child"}
        }
    }"#;

    let (parent, parent_contexts) = enrich_fixture(lockfile, "", "parent", "1.0.0");
    let context = parent_contexts.get(&parent.id()).unwrap();
    let (child, contexts) = enrich_fixture(lockfile, &context.package_path, "child", "^2");

    assert_eq!(child.resolved_version.as_deref(), Some("2.2.0"));
    assert_eq!(contexts.len(), 1);
}
