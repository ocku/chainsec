use std::{fs, fs::File};

use super::*;

#[test]
fn rejects_oversized_files() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("package-lock.json");
    let file = File::create(&path).unwrap();
    file.set_len(MAX_MANIFEST_BYTES + 1).unwrap();

    let error = read(&path).unwrap_err();
    assert!(error.to_string().contains("read limit"));
}

#[cfg(unix)]
#[test]
fn rejects_symlinks() {
    use std::os::unix::fs::symlink;

    let directory = tempfile::tempdir().unwrap();
    let target = directory.path().join("target.json");
    let path = directory.path().join("package.json");
    fs::write(&target, "{}").unwrap();
    symlink(&target, &path).unwrap();

    let error = read(&path).unwrap_err();
    assert!(error.to_string().contains("symbolic link"));
}

#[cfg(unix)]
#[test]
fn rejects_fifo_without_waiting_for_a_writer() {
    use std::{ffi::CString, os::unix::ffi::OsStrExt, time::Instant};

    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("package.json");
    let c_path = CString::new(path.as_os_str().as_bytes()).unwrap();
    // SAFETY: `c_path` is a valid NUL-terminated path and the mode is valid for `mkfifo`.
    assert_eq!(unsafe { libc::mkfifo(c_path.as_ptr(), 0o600) }, 0);

    let started = Instant::now();
    let error = read(&path).unwrap_err();
    assert!(started.elapsed() < std::time::Duration::from_secs(2));
    assert!(error.to_string().contains("not a regular file"));
}

#[cfg(unix)]
#[test]
fn manifest_root_rejects_symlinked_path_components() {
    use std::os::unix::fs::symlink;

    let directory = tempfile::tempdir().unwrap();
    let real = directory.path().join("real");
    fs::create_dir(&real).unwrap();
    let linked = directory.path().join("linked");
    symlink(&real, &linked).unwrap();

    let error = ManifestRoot::open(&linked).err().unwrap();
    assert!(matches!(error, Error::Io { .. }));
}

#[cfg(unix)]
#[test]
fn manifest_root_rejects_intermediate_symlinked_path_components() {
    use std::os::unix::fs::symlink;

    let trusted = tempfile::tempdir().unwrap();
    let outside = tempfile::tempdir().unwrap();
    fs::create_dir(outside.path().join("project")).unwrap();
    symlink(outside.path(), trusted.path().join("link")).unwrap();

    let result = ManifestRoot::open(&trusted.path().join("link/project"));
    assert!(matches!(result, Err(Error::Io { .. })));
}

#[cfg(unix)]
#[test]
fn rooted_read_rejects_symlinked_intermediate_directories() {
    use std::os::unix::fs::symlink;

    let directory = tempfile::tempdir().unwrap();
    let outside = tempfile::tempdir().unwrap();
    fs::write(outside.path().join("package.json"), "outside").unwrap();
    symlink(outside.path(), directory.path().join("nested")).unwrap();
    let root = ManifestRoot::open(directory.path()).unwrap();

    let error = with_manifest_roots(std::slice::from_ref(&root), || {
        read(&directory.path().join("nested/package.json"))
    })
    .unwrap()
    .unwrap_err();

    assert!(matches!(error, Error::Io { .. }));
}

#[cfg(unix)]
#[test]
fn rooted_read_survives_root_path_replacement_without_following_it() {
    let parent = tempfile::tempdir().unwrap();
    let root_path = parent.path().join("root");
    fs::create_dir(&root_path).unwrap();
    fs::write(root_path.join("package.json"), "trusted").unwrap();
    let root = ManifestRoot::open(&root_path).unwrap();

    fs::rename(&root_path, parent.path().join("original")).unwrap();
    fs::create_dir(&root_path).unwrap();
    fs::write(root_path.join("package.json"), "replacement").unwrap();

    let contents = with_manifest_roots(std::slice::from_ref(&root), || {
        read(&root_path.join("package.json"))
    })
    .unwrap()
    .unwrap();

    assert_eq!(contents, "trusted");
}
