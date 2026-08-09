use std::{fs::File, io::Read, path::Path};

use globset::{Glob, GlobSet, GlobSetBuilder};
use walkdir::DirEntry;

use crate::{
    error::{Error, Result},
    model::{EngineLimits, Language},
};

pub(super) const MAX_NON_SOURCE_ANALYSIS_BYTES: u64 = 1024 * 1024;

pub(super) fn read_entry_contents(
    entry: &DirEntry,
    language: Option<Language>,
    limits: &EngineLimits,
) -> Result<(Vec<u8>, u64)> {
    let metadata = entry.metadata().map_err(|error| Error::Scan {
        path: entry.path().to_owned(),
        message: error.to_string(),
    })?;
    let file_size = metadata.len();

    if language.is_some() && file_size > limits.max_source_file_bytes {
        return Err(Error::LimitExceeded {
            resource: format!("source file bytes ({})", entry.path().display()),
            limit: limits.max_source_file_bytes,
        });
    }

    let contents = match language {
        Some(_) => read_source_file(entry.path(), limits.max_source_file_bytes)?,
        None => read_non_source_prefix(entry.path())?,
    };
    let observed_size = if language.is_some() {
        contents.len() as u64
    } else {
        file_size
    };

    Ok((contents, observed_size))
}

pub(super) fn compile_ignored_paths(patterns: &[String]) -> Result<Option<GlobSet>> {
    if patterns.is_empty() {
        return Ok(None);
    }

    let mut builder = GlobSetBuilder::new();
    for pattern in patterns {
        builder.add(
            Glob::new(pattern).map_err(|error| Error::InvalidConfiguration {
                message: format!("invalid ignored path glob {pattern:?}: {error}"),
            })?,
        );
    }
    builder
        .build()
        .map(Some)
        .map_err(|error| Error::InvalidConfiguration {
            message: format!("could not build ignored path globs: {error}"),
        })
}

pub(super) fn included(entry: &DirEntry, root: &Path, ignored_paths: Option<&GlobSet>) -> bool {
    if entry.depth() == 0 {
        return true;
    }

    let relative = entry.path().strip_prefix(root).unwrap_or(entry.path());
    if ignored_paths.is_some_and(|patterns| patterns.is_match(relative)) {
        return false;
    }

    !matches!(
        entry.file_name().to_str(),
        Some(
            ".git"
                | ".chainsec-cache"
                | "node_modules"
                | "target"
                | ".venv"
                | "venv"
                | "__pycache__"
        )
    )
}

pub(super) fn is_test_fixture(path: &Path) -> bool {
    let components = path
        .components()
        .filter_map(|component| component.as_os_str().to_str())
        .collect::<Vec<_>>();

    components.iter().any(|component| {
        matches!(
            *component,
            "fixtures" | "fixture" | "testdata" | "__fixtures__"
        )
    }) || components.iter().enumerate().any(|(index, component)| {
        matches!(*component, "test" | "tests")
            && components[index + 1..]
                .iter()
                .any(|component| matches!(*component, "data" | "resources"))
    })
}

pub(super) fn language_for(path: &Path) -> Option<Language> {
    match path.extension()?.to_str()? {
        "py" | "pyx" | "pyi" => Some(Language::Python),
        "js" | "jsx" | "mjs" | "cjs" => Some(Language::JavaScript),
        "ts" | "tsx" | "mts" | "cts" => Some(Language::TypeScript),
        _ => None,
    }
}

fn read_source_file(path: &Path, limit: u64) -> Result<Vec<u8>> {
    let file = File::open(path).map_err(|error| Error::Scan {
        path: path.to_owned(),
        message: error.to_string(),
    })?;
    let mut bytes = Vec::new();
    file.take(limit.saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|error| Error::Scan {
            path: path.to_owned(),
            message: error.to_string(),
        })?;
    if bytes.len() as u64 > limit {
        return Err(Error::LimitExceeded {
            resource: format!("source file bytes ({})", path.display()),
            limit,
        });
    }
    Ok(bytes)
}

fn read_non_source_prefix(path: &Path) -> Result<Vec<u8>> {
    let file = File::open(path).map_err(|error| Error::Scan {
        path: path.to_owned(),
        message: error.to_string(),
    })?;
    let mut bytes = Vec::new();
    file.take(MAX_NON_SOURCE_ANALYSIS_BYTES)
        .read_to_end(&mut bytes)
        .map_err(|error| Error::Scan {
            path: path.to_owned(),
            message: error.to_string(),
        })?;
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use std::io::Write;

    use std::path::Path;

    use crate::model::Language;

    use super::{language_for, read_source_file};

    #[test]
    fn source_reads_are_limited_even_when_metadata_is_stale() {
        let file = tempfile::NamedTempFile::new().unwrap();
        file.as_file().write_all(b"oversized").unwrap();

        assert!(read_source_file(file.path(), 8).is_err());
    }

    #[test]
    fn recognizes_python_source_extensions() {
        for extension in ["py", "pyx", "pyi"] {
            assert_eq!(
                language_for(Path::new(&format!("module.{extension}"))),
                Some(Language::Python)
            );
        }
    }
}
