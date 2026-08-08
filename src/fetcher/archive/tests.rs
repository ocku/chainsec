use std::{
    io::{self, Cursor, Write},
    path::Path,
};

use super::{extract, extract_tar, extract_zip, safe_relative};
use crate::model::EngineLimits;
use tar::Builder;
use zip::{ZipWriter, write::SimpleFileOptions};

#[test]
fn traversal_paths_are_rejected() {
    assert!(!safe_relative(Path::new("../escape")));
    assert!(!safe_relative(Path::new("/absolute")));
    assert!(safe_relative(Path::new("package/src/lib.js")));
}

#[test]
fn zip_traversal_is_rejected() {
    let mut bytes = Cursor::new(Vec::new());
    {
        let mut writer = ZipWriter::new(&mut bytes);
        writer
            .start_file("../escape.py", SimpleFileOptions::default())
            .unwrap();
        writer.write_all(b"eval(payload)").unwrap();
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
    assert!(
        !destination
            .path()
            .parent()
            .unwrap()
            .join("escape.py")
            .exists()
    );
}

#[test]
fn corrupt_zip_is_rejected_without_creating_files() {
    let destination = tempfile::tempdir().unwrap();
    assert!(extract_zip(b"not a zip", destination.path(), &EngineLimits::default()).is_err());
    assert_eq!(destination.path().read_dir().unwrap().count(), 0);
}

#[test]
fn zip_symlink_is_rejected() {
    let mut bytes = Cursor::new(Vec::new());
    {
        let mut writer = ZipWriter::new(&mut bytes);
        writer
            .start_file(
                "escape.py",
                SimpleFileOptions::default().unix_permissions(0o120777),
            )
            .unwrap();
        writer.write_all(b"../../outside").unwrap();
        writer.finish().unwrap();
    }

    let mut bytes = bytes.into_inner();
    let central_directory = bytes
        .windows(4)
        .position(|window| window == b"PK\x01\x02")
        .unwrap();
    bytes[central_directory + 38..central_directory + 42]
        .copy_from_slice(&(0o120777u32 << 16).to_le_bytes());

    let destination = tempfile::tempdir().unwrap();
    assert!(extract_zip(&bytes, destination.path(), &EngineLimits::default()).is_err());
    assert!(!destination.path().join("escape.py").exists());
}

#[test]
fn zip_special_file_is_rejected() {
    let mut bytes = Cursor::new(Vec::new());
    {
        let mut writer = ZipWriter::new(&mut bytes);
        writer
            .start_file(
                "pipe.py",
                SimpleFileOptions::default().unix_permissions(0o010644),
            )
            .unwrap();
        writer.write_all(b"payload").unwrap();
        writer.finish().unwrap();
    }

    let mut bytes = bytes.into_inner();
    let central_directory = bytes
        .windows(4)
        .position(|window| window == b"PK\x01\x02")
        .unwrap();
    bytes[central_directory + 38..central_directory + 42]
        .copy_from_slice(&(0o010644u32 << 16).to_le_bytes());

    let destination = tempfile::tempdir().unwrap();
    assert!(extract_zip(&bytes, destination.path(), &EngineLimits::default()).is_err());
    assert!(!destination.path().join("pipe.py").exists());
}

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
fn tar_traversal_path_is_rejected() {
    let mut header = tar::Header::new_gnu();
    header.as_mut_bytes()[..12].copy_from_slice(b"../escape.py");
    header.set_size(7);
    header.set_cksum();
    let mut bytes = header.as_bytes().to_vec();
    bytes.extend_from_slice(b"payload");

    let destination = tempfile::tempdir().unwrap();
    assert!(
        extract_tar(
            Cursor::new(bytes),
            "traversal.tar",
            destination.path(),
            &EngineLimits::default()
        )
        .is_err()
    );
    assert!(
        !destination
            .path()
            .parent()
            .unwrap()
            .join("escape.py")
            .exists()
    );
}

#[test]
fn tar_absolute_path_is_rejected() {
    let destination = tempfile::tempdir().unwrap();
    let outside = destination.path().parent().unwrap().join("absolute.py");
    let mut header = tar::Header::new_gnu();
    header.set_path_absolute(&outside).unwrap();
    header.set_size(7);
    header.set_cksum();
    let mut bytes = header.as_bytes().to_vec();
    bytes.extend_from_slice(b"payload");

    assert!(
        extract_tar(
            Cursor::new(bytes),
            "absolute.tar",
            destination.path(),
            &EngineLimits::default()
        )
        .is_err()
    );
    assert!(!outside.exists());
}

#[test]
fn duplicate_tar_paths_are_rejected() {
    let mut bytes = Cursor::new(Vec::new());
    {
        let mut builder = Builder::new(&mut bytes);
        for content in [b"one".as_slice(), b"two".as_slice()] {
            let mut header = tar::Header::new_gnu();
            header.set_size(content.len() as u64);
            header.set_cksum();
            builder
                .append_data(&mut header, "same.py", content)
                .unwrap();
        }
        builder.finish().unwrap();
    }
    let destination = tempfile::tempdir().unwrap();
    assert!(
        extract_tar(
            Cursor::new(bytes.into_inner()),
            "duplicate.tar",
            destination.path(),
            &EngineLimits::default()
        )
        .is_err()
    );
}

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
        max_extracted_bytes: 5,
        ..EngineLimits::default()
    };
    assert!(extract_zip(&bytes.into_inner(), destination.path(), &limits).is_err());
    assert!(!destination.path().join("large.py").exists());
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

#[cfg(unix)]
#[test]
fn existing_symlinked_parent_is_rejected() {
    use std::os::unix::fs::symlink;

    let outside = tempfile::tempdir().unwrap();
    let destination = tempfile::tempdir().unwrap();
    symlink(outside.path(), destination.path().join("nested")).unwrap();

    let mut bytes = Cursor::new(Vec::new());
    {
        let mut writer = ZipWriter::new(&mut bytes);
        writer
            .start_file("nested/file.py", SimpleFileOptions::default())
            .unwrap();
        writer.write_all(b"payload").unwrap();
        writer.finish().unwrap();
    }

    assert!(
        extract_zip(
            &bytes.into_inner(),
            destination.path(),
            &EngineLimits::default()
        )
        .is_err()
    );
    assert!(!outside.path().join("file.py").exists());
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

    assert_eq!(stats.files, 1);
    assert_eq!(stats.bytes, 11);
    assert_eq!(
        std::fs::read(destination.path().join("package/index.js")).unwrap(),
        b"safe source"
    );
    assert!(!destination.path().join("pax_global_header").exists());
}

#[test]
fn tar_links_are_rejected() {
    let mut bytes = Cursor::new(Vec::new());
    {
        let mut builder = Builder::new(&mut bytes);
        let mut header = tar::Header::new_gnu();
        header.set_entry_type(tar::EntryType::symlink());
        header.set_size(0);
        header.set_cksum();
        builder
            .append_link(&mut header, "escape.py", "../../outside")
            .unwrap();
        builder.finish().unwrap();
    }
    let destination = tempfile::tempdir().unwrap();
    assert!(
        extract_tar(
            Cursor::new(bytes.into_inner()),
            "links.tar",
            destination.path(),
            &EngineLimits::default()
        )
        .is_err()
    );
}

#[test]
fn tar_hard_links_are_rejected() {
    let mut bytes = Cursor::new(Vec::new());
    {
        let mut builder = Builder::new(&mut bytes);
        let mut header = tar::Header::new_gnu();
        header.set_entry_type(tar::EntryType::hard_link());
        header.set_size(0);
        header.set_cksum();
        builder
            .append_link(&mut header, "escape.py", "../../outside")
            .unwrap();
        builder.finish().unwrap();
    }

    let destination = tempfile::tempdir().unwrap();
    assert!(
        extract_tar(
            Cursor::new(bytes.into_inner()),
            "hard-link.tar",
            destination.path(),
            &EngineLimits::default()
        )
        .is_err()
    );
    assert!(!destination.path().join("escape.py").exists());
}

#[test]
fn tar_special_files_are_rejected() {
    let mut bytes = Cursor::new(Vec::new());
    {
        let mut builder = Builder::new(&mut bytes);
        let mut header = tar::Header::new_gnu();
        header.set_entry_type(tar::EntryType::fifo());
        header.set_size(0);
        header.set_cksum();
        builder
            .append_data(&mut header, "named-pipe", io::empty())
            .unwrap();
        builder.finish().unwrap();
    }

    let destination = tempfile::tempdir().unwrap();
    assert!(
        extract_tar(
            Cursor::new(bytes.into_inner()),
            "special.tar",
            destination.path(),
            &EngineLimits::default()
        )
        .is_err()
    );
    assert!(!destination.path().join("named-pipe").exists());
}
