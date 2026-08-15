use std::io::{self, Cursor};

use super::super::{extract, extract_tar};
use crate::model::EngineLimits;
use tar::Builder;

#[test]
fn corrupt_compressed_tar_is_rejected_without_creating_files() {
    let destination = tempfile::tempdir().unwrap();
    assert!(
        extract(
            b"not a gzip stream",
            "corrupt.tar.gz",
            destination.path(),
            &EngineLimits::default()
        )
        .is_err()
    );
    assert_eq!(destination.path().read_dir().unwrap().count(), 0);
}

#[test]
fn tar_declared_size_mismatch_is_rejected() {
    let mut header = tar::Header::new_gnu();
    header.set_size(10);
    header.set_path("short.py").unwrap();
    header.set_cksum();
    let mut bytes = header.as_bytes().to_vec();
    bytes.extend_from_slice(b"short");

    let destination = tempfile::tempdir().unwrap();
    assert!(
        extract_tar(
            Cursor::new(bytes),
            "short.tar",
            destination.path(),
            &EngineLimits::default()
        )
        .is_err()
    );
}

#[test]
fn tar_pax_global_headers_are_ignored() {
    let mut bytes = Cursor::new(Vec::new());
    {
        let mut builder = Builder::new(&mut bytes);
        let mut pax_header = tar::Header::new_gnu();
        pax_header.set_entry_type(tar::EntryType::new(b'g'));
        pax_header.set_size(0);
        pax_header.set_cksum();
        builder
            .append_data(&mut pax_header, "pax_global_header", io::empty())
            .unwrap();

        let content = b"safe source";
        let mut file_header = tar::Header::new_gnu();
        file_header.set_size(content.len() as u64);
        file_header.set_cksum();
        builder
            .append_data(&mut file_header, "package/index.js", content.as_slice())
            .unwrap();
        builder.finish().unwrap();
    }

    let destination = tempfile::tempdir().unwrap();
    let stats = extract_tar(
        Cursor::new(bytes.into_inner()),
        "github.tar.gz",
        destination.path(),
        &EngineLimits::default(),
    )
    .unwrap();

    assert_eq!(stats.files, 3);
    assert_eq!(stats.bytes, 11);
    assert_eq!(
        std::fs::read(destination.path().join("package/index.js")).unwrap(),
        b"safe source"
    );
    assert!(!destination.path().join("pax_global_header").exists());
}
