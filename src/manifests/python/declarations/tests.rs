use std::path::Path;

use super::*;

fn dependency(requirement: &str) -> Dependency {
    dependency_from_requirement(requirement)
}

fn parse_manifest(contents: &str) -> Result<Vec<Dependency>> {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("pyproject.toml");
    std::fs::write(&path, contents).unwrap();
    parse(&path)
}

#[test]
fn canonicalizes_pep503_names_and_declared_requirements() {
    let dependency = dependency("My...Package___Name>=1");
    assert_eq!(normalize("My...Package___Name"), "my-package-name");
    assert_eq!(dependency.name, "my-package-name");
    assert_eq!(dependency.requirement, "my-package-name>=1");
}

#[test]
fn rejects_dynamic_pep621_dependencies() {
    let error = parse_manifest(
        r#"
[project]
dynamic = ["dependencies"]
"#,
    )
    .unwrap_err();

    assert!(error.to_string().contains("dynamic dependencies"));
}

#[test]
fn rejects_dynamic_pep621_optional_dependencies() {
    let error = parse_manifest(
        r#"
[project]
dynamic = ["optional-dependencies"]
"#,
    )
    .unwrap_err();

    assert!(error.to_string().contains("dynamic dependencies"));
}

#[test]
fn parses_pep621_optional_dependencies() {
    let dependencies = parse_manifest(
        r#"
[project]
dependencies = ["core>=1"]
[project.optional-dependencies]
audit = ["Bandit>=1.8", "pip-audit"]
docs = ["sphinx"]
"#,
    )
    .unwrap();

    assert_eq!(
        dependencies
            .iter()
            .map(|dependency| dependency.name.as_str())
            .collect::<Vec<_>>(),
        ["core", "bandit", "pip-audit", "sphinx"]
    );
}

#[test]
fn recursively_parses_pep735_dependency_group_includes_once() {
    let dependencies = parse_manifest(
        r#"
[dependency-groups]
base = ["pytest>=8"]
lint = ["ruff", {include-group = "base"}]
audit = [{include-group = "lint"}, {include-group = "base"}, "bandit"]
"#,
    )
    .unwrap();

    let mut names = dependencies
        .iter()
        .map(|dependency| dependency.name.as_str())
        .collect::<Vec<_>>();
    names.sort_unstable();
    assert_eq!(names, ["bandit", "pytest", "ruff"]);
}

#[test]
fn rejects_pep735_include_cycles_and_missing_groups() {
    let cycle = parse_manifest(
        r#"
[dependency-groups]
a = [{include-group = "b"}]
b = [{include-group = "a"}]
"#,
    )
    .unwrap_err();
    assert!(cycle.to_string().contains("a -> b -> a"));

    let missing = parse_manifest(
        r#"
[dependency-groups]
a = [{include-group = "missing"}]
"#,
    )
    .unwrap_err();
    assert!(
        missing
            .to_string()
            .contains("dependency-group missing is missing")
    );
}

#[test]
fn translates_poetry_native_constraints_to_pep440() {
    assert_eq!(
        poetry_requirement(
            Path::new("pyproject.toml"),
            "demo",
            &TomlValue::String("^1.2.3".into())
        )
        .unwrap(),
        "demo>=1.2.3,<2"
    );
    assert_eq!(
        poetry_requirement(
            Path::new("pyproject.toml"),
            "demo",
            &TomlValue::String("^0.2.3".into())
        )
        .unwrap(),
        "demo>=0.2.3,<0.3"
    );
    assert_eq!(
        poetry_requirement(
            Path::new("pyproject.toml"),
            "demo",
            &TomlValue::String("~1.2".into())
        )
        .unwrap(),
        "demo>=1.2,<1.3"
    );
    assert_eq!(
        poetry_requirement(
            Path::new("pyproject.toml"),
            "demo",
            &TomlValue::String("^1!2.3rc1.dev2".into())
        )
        .unwrap(),
        "demo>=1!2.3rc1.dev2,<1!3"
    );
    assert_eq!(
        poetry_requirement(
            Path::new("pyproject.toml"),
            "demo",
            &TomlValue::String("~1!2.3.dev4".into())
        )
        .unwrap(),
        "demo>=1!2.3.dev4,<1!2.4"
    );
    assert_eq!(
        poetry_requirement(
            Path::new("pyproject.toml"),
            "demo",
            &TomlValue::String("1.*".into())
        )
        .unwrap(),
        "demo==1.*"
    );
    assert_eq!(
        poetry_requirement(
            Path::new("pyproject.toml"),
            "demo",
            &TomlValue::String(">=1 <2".into())
        )
        .unwrap(),
        "demo>=1,<2"
    );
}

#[test]
fn poetry_direct_url_sets_source_url() {
    let spec: TomlValue = toml::from_str("url = 'https://example.test/demo.tar.gz'").unwrap();
    let dependency = poetry_dependency(Path::new("pyproject.toml"), "Demo", &spec).unwrap();
    assert_eq!(dependency.name, "demo");
    assert_eq!(
        dependency.source_url.as_deref(),
        Some("https://example.test/demo.tar.gz")
    );
}

#[test]
fn rejects_unsupported_poetry_constraints() {
    let path = Path::new("pyproject.toml");
    for constraint in ["1.2.3 - 2.3.4", "not-a-version"] {
        assert!(poetry_requirement(path, "demo", &TomlValue::String(constraint.into())).is_err());
    }
}

#[test]
fn rejects_poetry_compatible_ranges_that_overflow() {
    let path = Path::new("pyproject.toml");
    for constraint in ["^18446744073709551615", "~18446744073709551615"] {
        assert!(poetry_requirement(path, "demo", &TomlValue::String(constraint.into())).is_err());
    }
}

#[test]
fn rejects_poetry_version_unions_and_unpinned_git_dependencies() {
    let path = Path::new("pyproject.toml");
    assert!(poetry_requirement(path, "demo", &TomlValue::String("^1 || ^3".into())).is_err());

    let unpinned_git: TomlValue =
        toml::from_str("git = 'https://github.com/acme/demo.git'\nbranch = 'main'").unwrap();
    assert!(poetry_dependency(path, "demo", &unpinned_git).is_err());

    let pinned_git: TomlValue = toml::from_str(
        "git = 'https://github.com/acme/demo.git'\nrev = '0123456789abcdef0123456789abcdef01234567'",
    )
    .unwrap();
    let dependency = poetry_dependency(path, "demo", &pinned_git).unwrap();
    assert_eq!(
        dependency.source_url.as_deref(),
        Some(
            "https://codeload.github.com/acme/demo/tar.gz/0123456789abcdef0123456789abcdef01234567"
        )
    );
}
