use std::io::{Cursor, Write};

use super::super::extract_zip;
use crate::model::EngineLimits;
use zip::{ZipWriter, write::SimpleFileOptions};

#[test]
fn corrupt_zip_is_rejected_without_creating_files() {
    let destination = tempfile::tempdir().unwrap();
    assert!(extract_zip(b"not a zip", destination.path(), &EngineLimits::default()).is_err());
    assert_eq!(destination.path().read_dir().unwrap().count(), 0);
}

#[test]
fn zip_declared_size_mismatch_is_rejected() {
    let mut bytes = Cursor::new(Vec::new());
    {
        let mut writer = ZipWriter::new(&mut bytes);
        writer
            .start_file(
                "short.py",
                SimpleFileOptions::default().compression_method(zip::CompressionMethod::Stored),
            )
            .unwrap();
        writer.write_all(b"short").unwrap();
        writer.finish().unwrap();
    }
    let mut bytes = bytes.into_inner();
    let central_directory = bytes
        .windows(4)
        .position(|window| window == b"PK\x01\x02")
        .unwrap();
    bytes[central_directory + 24..central_directory + 28].copy_from_slice(&10u32.to_le_bytes());

    let destination = tempfile::tempdir().unwrap();
    assert!(extract_zip(&bytes, destination.path(), &EngineLimits::default()).is_err());
}

#[test]
fn underdeclared_compressed_zip_entry_is_rejected_after_one_extra_byte() {
    let mut bytes = Cursor::new(Vec::new());
    {
        let mut writer = ZipWriter::new(&mut bytes);
        writer
            .start_file(
                "expanded.bin",
                SimpleFileOptions::default().compression_method(zip::CompressionMethod::Deflated),
            )
            .unwrap();
        writer.write_all(&vec![b'x'; 1024 * 1024]).unwrap();
        writer.finish().unwrap();
    }
    let mut bytes = bytes.into_inner();
    let central_directory = bytes
        .windows(4)
        .position(|window| window == b"PK\x01\x02")
        .unwrap();
    bytes[central_directory + 24..central_directory + 28].copy_from_slice(&1u32.to_le_bytes());

    let destination = tempfile::tempdir().unwrap();
    let error = extract_zip(&bytes, destination.path(), &EngineLimits::default()).unwrap_err();

    assert!(
        error
            .to_string()
            .contains("has at least 2 bytes, expected 1")
    );
    assert_eq!(destination.path().read_dir().unwrap().count(), 0);
}
