use std::io::{self, Cursor, Write};

use super::super::{extract_tar, extract_zip, preflight_zip_entry_count};
use crate::model::EngineLimits;
use tar::Builder;
use zip::{ZipWriter, write::SimpleFileOptions};

#[test]
fn oversized_zip_is_rejected_before_write() {
    let mut bytes = Cursor::new(Vec::new());
    {
        let mut writer = ZipWriter::new(&mut bytes);
        writer
            .start_file("large.py", SimpleFileOptions::default())
            .unwrap();
        writer.write_all(b"0123456789").unwrap();
        writer.finish().unwrap();
    }
    let destination = tempfile::tempdir().unwrap();
    let limits = EngineLimits {
        max_extracted_size: 5,
        ..EngineLimits::default()
    };
    assert!(extract_zip(&bytes.into_inner(), destination.path(), &limits).is_err());
    assert!(!destination.path().join("large.py").exists());
}

#[test]
fn tar_file_limit_is_rejected_before_any_entry_is_written() {
    let mut bytes = Cursor::new(Vec::new());
    {
        let mut builder = Builder::new(&mut bytes);
        for path in ["first", "second"] {
            let mut header = tar::Header::new_gnu();
            header.set_entry_type(tar::EntryType::new(b'5'));
            header.set_size(0);
            header.set_cksum();
            builder.append_data(&mut header, path, io::empty()).unwrap();
        }
        builder.finish().unwrap();
    }

    let destination = tempfile::tempdir().unwrap();
    let limits = EngineLimits {
        max_extracted_files: 1,
        ..EngineLimits::default()
    };
    let error = extract_tar(
        Cursor::new(bytes.into_inner()),
        "directories.tar",
        destination.path(),
        &limits,
    )
    .unwrap_err();

    assert_eq!(error.code(), "limit_exceeded");
    assert_eq!(destination.path().read_dir().unwrap().count(), 0);
}

#[test]
fn tar_implicit_parent_directories_count_toward_the_file_limit() {
    let mut bytes = Cursor::new(Vec::new());
    {
        let mut builder = Builder::new(&mut bytes);
        let mut header = tar::Header::new_gnu();
        header.set_size(7);
        header.set_cksum();
        builder
            .append_data(&mut header, "nested/file.py", b"payload".as_slice())
            .unwrap();
        builder.finish().unwrap();
    }

    let destination = tempfile::tempdir().unwrap();
    let limits = EngineLimits {
        max_extracted_files: 1,
        ..EngineLimits::default()
    };
    let error = extract_tar(
        Cursor::new(bytes.into_inner()),
        "nested.tar",
        destination.path(),
        &limits,
    )
    .unwrap_err();

    assert_eq!(error.code(), "limit_exceeded");
    assert_eq!(destination.path().read_dir().unwrap().count(), 0);
}

#[test]
fn zip_implicit_parent_directories_count_toward_the_file_limit() {
    let mut bytes = Cursor::new(Vec::new());
    {
        let mut writer = ZipWriter::new(&mut bytes);
        writer
            .start_file("nested/file.py", SimpleFileOptions::default())
            .unwrap();
        writer.write_all(b"payload").unwrap();
        writer.finish().unwrap();
    }

    let destination = tempfile::tempdir().unwrap();
    let limits = EngineLimits {
        max_extracted_files: 1,
        ..EngineLimits::default()
    };
    let error = extract_zip(bytes.get_ref(), destination.path(), &limits).unwrap_err();

    assert_eq!(error.code(), "limit_exceeded");
    assert_eq!(destination.path().read_dir().unwrap().count(), 0);
}

#[test]
fn zip_entry_limit_is_checked_before_central_directory_is_parsed_or_files_are_written() {
    let mut bytes = Cursor::new(Vec::new());
    {
        let mut writer = ZipWriter::new(&mut bytes);
        for path in ["first.py", "second.py"] {
            writer
                .start_file(path, SimpleFileOptions::default())
                .unwrap();
            writer.write_all(b"payload").unwrap();
        }
        writer.finish().unwrap();
    }

    let destination = tempfile::tempdir().unwrap();
    let limits = EngineLimits {
        max_extracted_files: 1,
        ..EngineLimits::default()
    };
    let error = extract_zip(bytes.get_ref(), destination.path(), &limits).unwrap_err();

    assert_eq!(error.code(), "limit_exceeded");
    assert_eq!(destination.path().read_dir().unwrap().count(), 0);
}

#[test]
fn zip64_entry_limit_is_checked_before_archive_construction() {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(b"PK\x06\x06");
    bytes.extend_from_slice(&44_u64.to_le_bytes());
    bytes.extend_from_slice(&45_u16.to_le_bytes());
    bytes.extend_from_slice(&45_u16.to_le_bytes());
    bytes.extend_from_slice(&0_u32.to_le_bytes());
    bytes.extend_from_slice(&0_u32.to_le_bytes());
    bytes.extend_from_slice(&2_u64.to_le_bytes());
    bytes.extend_from_slice(&2_u64.to_le_bytes());
    bytes.extend_from_slice(&0_u64.to_le_bytes());
    bytes.extend_from_slice(&0_u64.to_le_bytes());
    bytes.extend_from_slice(b"PK\x06\x07");
    bytes.extend_from_slice(&0_u32.to_le_bytes());
    bytes.extend_from_slice(&0_u64.to_le_bytes());
    bytes.extend_from_slice(&1_u32.to_le_bytes());
    bytes.extend_from_slice(b"PK\x05\x06");
    bytes.extend_from_slice(&0_u16.to_le_bytes());
    bytes.extend_from_slice(&0_u16.to_le_bytes());
    bytes.extend_from_slice(&u16::MAX.to_le_bytes());
    bytes.extend_from_slice(&u16::MAX.to_le_bytes());
    bytes.extend_from_slice(&0_u32.to_le_bytes());
    bytes.extend_from_slice(&0_u32.to_le_bytes());
    bytes.extend_from_slice(&0_u16.to_le_bytes());

    let limits = EngineLimits {
        max_extracted_files: 1,
        ..EngineLimits::default()
    };
    let error = preflight_zip_entry_count(&bytes, &limits).unwrap_err();

    assert_eq!(error.code(), "limit_exceeded");
}

#[test]
fn zip_directory_entries_count_toward_the_file_limit() {
    let mut bytes = Cursor::new(Vec::new());
    {
        let mut writer = ZipWriter::new(&mut bytes);
        writer
            .add_directory("first/", SimpleFileOptions::default())
            .unwrap();
        writer
            .add_directory("second/", SimpleFileOptions::default())
            .unwrap();
        writer.finish().unwrap();
    }

    let destination = tempfile::tempdir().unwrap();
    let limits = EngineLimits {
        max_extracted_files: 1,
        ..EngineLimits::default()
    };
    let error = extract_zip(bytes.get_ref(), destination.path(), &limits).unwrap_err();

    assert_eq!(error.code(), "limit_exceeded");
    assert_eq!(destination.path().read_dir().unwrap().count(), 0);
}

#[test]
fn zip_paths_exceeding_the_depth_limit_are_rejected() {
    let path = (0..129).map(|_| "nested").collect::<Vec<_>>().join("/") + "/file.js";
    let mut bytes = Cursor::new(Vec::new());
    {
        let mut writer = ZipWriter::new(&mut bytes);
        writer
            .start_file(path, SimpleFileOptions::default())
            .unwrap();
        writer.write_all(b"payload").unwrap();
        writer.finish().unwrap();
    }

    let destination = tempfile::tempdir().unwrap();
    assert!(
        extract_zip(
            bytes.get_ref(),
            destination.path(),
            &EngineLimits::default()
        )
        .is_err()
    );
}

#[test]
fn tar_payload_at_exact_extraction_limit_is_accepted() {
    let content = vec![b'x'; 4096];
    let mut bytes = Cursor::new(Vec::new());
    {
        let mut builder = Builder::new(&mut bytes);
        let mut header = tar::Header::new_gnu();
        header.set_size(content.len() as u64);
        header.set_cksum();
        builder
            .append_data(&mut header, "exact.bin", content.as_slice())
            .unwrap();
        builder.finish().unwrap();
    }

    let destination = tempfile::tempdir().unwrap();
    let limits = EngineLimits {
        max_extracted_size: content.len() as u64,
        max_extracted_files: 1,
        ..EngineLimits::default()
    };
    let stats = extract_tar(
        Cursor::new(bytes.into_inner()),
        "exact.tar",
        destination.path(),
        &limits,
    )
    .unwrap();

    assert_eq!(stats.bytes, content.len() as u64);
    assert_eq!(
        std::fs::read(destination.path().join("exact.bin")).unwrap(),
        content
    );
}

fn tar_with_hidden_extension(entry_type: u8, content: &[u8]) -> Vec<u8> {
    let mut bytes = Cursor::new(Vec::new());
    {
        let mut builder = Builder::new(&mut bytes);
        let mut extension = tar::Header::new_gnu();
        extension.set_entry_type(tar::EntryType::new(entry_type));
        extension.set_size(content.len() as u64);
        extension.set_cksum();
        builder
            .append_data(&mut extension, "extension", content)
            .unwrap();

        let mut file = tar::Header::new_gnu();
        file.set_size(0);
        file.set_cksum();
        builder
            .append_data(&mut file, "safe.txt", io::empty())
            .unwrap();
        builder.finish().unwrap();
    }
    bytes.into_inner()
}

fn assert_hidden_tar_metadata_is_bounded(entry_type: u8, content: &[u8], name: &str) {
    let destination = tempfile::tempdir().unwrap();
    let limits = EngineLimits {
        max_extracted_size: 0,
        max_extracted_files: 1,
        ..EngineLimits::default()
    };
    let error = extract_tar(
        Cursor::new(tar_with_hidden_extension(entry_type, content)),
        name,
        destination.path(),
        &limits,
    )
    .unwrap_err();

    assert_eq!(error.code(), "limit_exceeded");
    assert_eq!(destination.path().read_dir().unwrap().count(), 0);
}

#[test]
fn oversized_local_pax_metadata_is_rejected_before_tar_buffers_it_unbounded() {
    let value = "x".repeat(2 * 1024 * 1024);
    let mut record_length = value.len() + " comment=\n".len() + 7;
    loop {
        let record = format!("{record_length} comment={value}\n");
        if record.len() == record_length {
            assert_hidden_tar_metadata_is_bounded(b'x', record.as_bytes(), "local-pax.tar");
            break;
        }
        record_length = record.len();
    }
}

#[test]
fn oversized_gnu_long_name_and_link_metadata_is_rejected_before_tar_buffers_it_unbounded() {
    let mut metadata = vec![b'a'; 2 * 1024 * 1024];
    metadata.push(0);

    for (entry_type, name) in [(b'L', "long-name.tar"), (b'K', "long-link.tar")] {
        assert_hidden_tar_metadata_is_bounded(entry_type, &metadata, name);
    }
}

#[test]
fn oversized_pax_header_is_rejected_by_the_extraction_limit() {
    let content = b"13 path=name\n";
    let mut bytes = Cursor::new(Vec::new());
    {
        let mut builder = Builder::new(&mut bytes);
        let mut header = tar::Header::new_gnu();
        header.set_entry_type(tar::EntryType::new(b'g'));
        header.set_size(content.len() as u64);
        header.set_cksum();
        builder
            .append_data(&mut header, "pax_global_header", content.as_slice())
            .unwrap();
        builder.finish().unwrap();
    }

    let destination = tempfile::tempdir().unwrap();
    let limits = EngineLimits {
        max_extracted_size: 0,
        ..EngineLimits::default()
    };
    let error = extract_tar(
        Cursor::new(bytes.into_inner()),
        "pax.tar",
        destination.path(),
        &limits,
    )
    .unwrap_err();

    assert_eq!(error.code(), "limit_exceeded");
}
