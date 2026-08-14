use std::io::Write;

use std::path::Path;

use crate::model::{EngineLimits, Language};

use super::{language_for, read_entry, read_source_file};

#[test]
fn source_reads_are_limited_even_when_metadata_is_stale() {
    let file = tempfile::NamedTempFile::new().unwrap();
    file.as_file().write_all(b"oversized").unwrap();

    assert!(read_source_file(file.path(), 8).is_err());
}

#[cfg(unix)]
#[test]
fn source_reads_reject_symlinks() {
    use std::os::unix::fs::symlink;

    let directory = tempfile::tempdir().unwrap();
    let target = directory.path().join("target.py");
    let link = directory.path().join("link.py");
    std::fs::write(&target, "safe").unwrap();
    symlink(&target, &link).unwrap();

    assert!(read_source_file(&link, 1024).is_err());
}

#[test]
fn extensionless_source_is_detected_and_read_from_one_stream() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("postinstall");
    let source = b"#!/usr/bin/env python3\neval(payload)\n";
    std::fs::write(&path, source).unwrap();
    let entry = walkdir::WalkDir::new(&path)
        .into_iter()
        .next()
        .unwrap()
        .unwrap();

    let (language, contents, size) =
        read_entry(&entry, &path, &EngineLimits::default(), None).unwrap();

    assert_eq!(language, Some(Language::Python));
    assert_eq!(contents, source);
    assert_eq!(size, source.len() as u64);
}

#[test]
fn extensionless_source_reads_still_enforce_the_source_limit() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("postinstall");
    std::fs::write(&path, b"#!/usr/bin/env python3\neval(payload)\n").unwrap();
    let entry = walkdir::WalkDir::new(&path)
        .into_iter()
        .next()
        .unwrap()
        .unwrap();
    let limits = EngineLimits {
        max_source_file_size: 16,
        ..EngineLimits::default()
    };

    assert!(read_entry(&entry, &path, &limits, None).is_err());
}

#[test]
fn recognizes_source_extensions() {
    for extension in ["py", "pyi"] {
        assert_eq!(
            language_for(Path::new(&format!("module.{extension}")), b""),
            Some(Language::Python)
        );
    }
    for extension in ["js", "mjs", "cjs", "jsx"] {
        assert_eq!(
            language_for(Path::new(&format!("module.{extension}")), b""),
            Some(Language::JavaScript)
        );
    }
    for extension in ["ts", "mts", "cts", "tsx"] {
        assert_eq!(
            language_for(Path::new(&format!("module.{extension}")), b""),
            Some(Language::TypeScript)
        );
    }
}

#[test]
fn excludes_python_extension_and_bytecode_files() {
    for extension in ["pyx", "pyc"] {
        assert_eq!(
            language_for(Path::new(&format!("module.{extension}")), b""),
            None
        );
    }
}

#[test]
fn recognizes_uppercase_source_extensions() {
    assert_eq!(
        language_for(Path::new("module.PY"), &[]),
        Some(Language::Python)
    );
    assert_eq!(
        language_for(Path::new("module.JS"), &[]),
        Some(Language::JavaScript)
    );
    assert_eq!(
        language_for(Path::new("module.JSX"), &[]),
        Some(Language::JavaScript)
    );
    assert_eq!(
        language_for(Path::new("module.TS"), &[]),
        Some(Language::TypeScript)
    );
    assert_eq!(
        language_for(Path::new("module.TSX"), &[]),
        Some(Language::TypeScript)
    );
}

#[test]
fn recognizes_shebang_languages_without_source_extensions() {
    assert_eq!(
        language_for(
            Path::new("postinstall"),
            b"#!/usr/bin/env python3\neval(payload)\n"
        ),
        Some(Language::Python)
    );
    assert_eq!(
        language_for(
            Path::new("launcher"),
            b"#!/usr/bin/node\nrequire('child_process')\n"
        ),
        Some(Language::JavaScript)
    );
    for shebang in [
        b"#!/usr/bin/tsx\nfetch(url)\n".as_slice(),
        b"#!/usr/bin/env tsx\nfetch(url)\n",
        b"#!/usr/bin/env -S tsx\nfetch(url)\n",
    ] {
        assert_eq!(
            language_for(Path::new("launcher"), shebang),
            Some(Language::TypeScript)
        );
    }
}
