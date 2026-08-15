use std::path::{Path, PathBuf};

use super::{validate_child_name, validate_relative_path};

#[test]
fn validators_reject_malformed_components_portably() {
    for malformed in [
        Path::new("../escape"),
        Path::new("child/../escape"),
        Path::new("/"),
    ] {
        assert!(validate_relative_path(malformed, false).is_err());
    }

    for malformed in [
        Path::new(""),
        Path::new("../escape"),
        Path::new("child/escape"),
        Path::new("/"),
    ] {
        assert!(validate_child_name(malformed).is_err());
    }

    assert!(validate_relative_path(Path::new(""), true).is_ok());
    assert!(validate_relative_path(Path::new("child/nested"), false).is_ok());
    assert!(validate_child_name(Path::new("child")).is_ok());
}

#[cfg(unix)]
#[test]
fn trusted_directory_rejects_malformed_relative_components() {
    use super::TrustedDir;

    let temporary = tempfile::tempdir().unwrap();
    let trusted = TrustedDir::open(temporary.path()).unwrap();

    for malformed in [
        Path::new("../escape"),
        Path::new("child/../escape"),
        Path::new("/"),
    ] {
        assert!(trusted.open_subdirectory(malformed).is_err());
        assert!(trusted.create_dir_all(malformed).is_err());
        assert!(trusted.open_file_no_follow(malformed).is_err());
        assert!(trusted.create_new_file(malformed).is_err());
    }
}

#[cfg(unix)]
#[test]
fn rejects_an_intermediate_symlink_in_a_trusted_directory_path() {
    use std::os::unix::fs::symlink;

    use super::TrustedDir;

    let temporary = tempfile::tempdir().unwrap();
    let outside = tempfile::tempdir().unwrap();
    std::fs::create_dir(outside.path().join("cache")).unwrap();
    let link = temporary.path().join("redirect");
    symlink(outside.path(), &link).unwrap();

    assert!(TrustedDir::open(&link.join("cache")).is_err());
}

#[cfg(unix)]
#[test]
fn bounded_child_listing_stops_at_the_requested_count() {
    use super::TrustedDir;

    let temporary = tempfile::tempdir().unwrap();
    for name in ["first", "second", "third"] {
        std::fs::write(temporary.path().join(name), "").unwrap();
    }

    let names = TrustedDir::open(temporary.path())
        .unwrap()
        .list_child_names_up_to(2)
        .unwrap();

    assert_eq!(names.len(), 2);
}

#[cfg(unix)]
#[test]
fn listing_children_does_not_consume_the_trusted_directory_cursor() {
    use super::TrustedDir;

    let temporary = tempfile::tempdir().unwrap();
    std::fs::write(temporary.path().join("first"), "").unwrap();
    std::fs::write(temporary.path().join("second"), "").unwrap();
    let trusted = TrustedDir::open(temporary.path()).unwrap();

    let mut first_listing = trusted.list_child_names().unwrap();
    let mut second_listing = trusted.list_child_names().unwrap();
    first_listing.sort();
    second_listing.sort();

    assert_eq!(first_listing, second_listing);
    assert_eq!(
        first_listing,
        vec![PathBuf::from("first"), PathBuf::from("second")]
    );
}
