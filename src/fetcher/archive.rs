use std::{
    collections::HashSet,
    fs::{self, File, OpenOptions},
    io::{self, Cursor, Read, Write},
    path::{Component, Path, PathBuf},
};

use bzip2::read::BzDecoder;
use flate2::read::GzDecoder;
use tar::Archive;
use xz2::read::XzDecoder;
use zip::ZipArchive;

use crate::{
    error::{Error, Result},
    model::EngineLimits,
};

#[derive(Debug, Default)]
pub(super) struct ExtractionStats {
    pub(super) files: u64,
    pub(super) bytes: u64,
}

pub(super) fn safe_relative(path: &Path) -> bool {
    !path.is_absolute()
        && path.components().count() <= 128
        && path
            .components()
            .all(|component| matches!(component, Component::Normal(_) | Component::CurDir))
}

pub(super) fn check_extraction_limits(
    stats: &ExtractionStats,
    limits: &EngineLimits,
) -> Result<()> {
    if stats.files > limits.max_extracted_files {
        return Err(Error::LimitExceeded {
            resource: "extracted files".to_owned(),
            limit: limits.max_extracted_files,
        });
    }
    if stats.bytes > limits.max_extracted_bytes {
        return Err(Error::LimitExceeded {
            resource: "extracted bytes".to_owned(),
            limit: limits.max_extracted_bytes,
        });
    }
    Ok(())
}

pub(super) fn extract(
    bytes: &[u8],
    name: &str,
    destination: &Path,
    limits: &EngineLimits,
) -> Result<ExtractionStats> {
    let lower = name.to_ascii_lowercase();
    if lower.ends_with(".whl") || lower.ends_with(".zip") {
        extract_zip(bytes, destination, limits)
    } else if lower.ends_with(".tar.gz") || lower.ends_with(".tgz") {
        extract_tar(
            GzDecoder::new(Cursor::new(bytes)),
            name,
            destination,
            limits,
        )
    } else if lower.ends_with(".tar.bz2") {
        extract_tar(
            BzDecoder::new(Cursor::new(bytes)),
            name,
            destination,
            limits,
        )
    } else if lower.ends_with(".tar.xz") {
        extract_tar(
            XzDecoder::new(Cursor::new(bytes)),
            name,
            destination,
            limits,
        )
    } else if lower.ends_with(".tar") {
        extract_tar(Cursor::new(bytes), name, destination, limits)
    } else {
        Err(Error::Extraction {
            archive: PathBuf::from(name),
            message: "unsupported archive format".to_owned(),
        })
    }
}

fn reject_symlink_components(path: &Path, archive: &Path, context: &str) -> Result<()> {
    let mut current = PathBuf::new();
    for component in path.components() {
        current.push(component.as_os_str());
        match fs::symlink_metadata(&current) {
            Ok(metadata) if metadata.file_type().is_symlink() => {
                return Err(Error::Extraction {
                    archive: archive.to_owned(),
                    message: format!("symlink in extracted path {}", current.display()),
                });
            }
            Ok(_) => {}
            Err(source) if source.kind() == io::ErrorKind::NotFound => break,
            Err(source) => {
                return Err(Error::Io {
                    operation: context.to_owned(),
                    path: current,
                    source,
                });
            }
        }
    }
    Ok(())
}

fn create_extracted_file(path: &Path) -> io::Result<File> {
    OpenOptions::new().write(true).create_new(true).open(path)
}

fn extract_tar<R: Read>(
    reader: R,
    name: &str,
    destination: &Path,
    limits: &EngineLimits,
) -> Result<ExtractionStats> {
    let mut archive = Archive::new(reader);
    let mut stats = ExtractionStats::default();
    let mut seen = HashSet::new();
    let entries = archive.entries().map_err(|error| Error::Extraction {
        archive: PathBuf::from(name),
        message: error.to_string(),
    })?;
    for entry in entries {
        let mut entry = entry.map_err(|error| Error::Extraction {
            archive: PathBuf::from(name),
            message: error.to_string(),
        })?;
        let path = entry
            .path()
            .map_err(|error| Error::Extraction {
                archive: PathBuf::from(name),
                message: error.to_string(),
            })?
            .into_owned();
        if !safe_relative(&path) {
            return Err(Error::Extraction {
                archive: PathBuf::from(name),
                message: format!("unsafe or excessively deep path {}", path.display()),
            });
        }
        if !seen.insert(path.clone()) {
            return Err(Error::Extraction {
                archive: PathBuf::from(name),
                message: format!("duplicate path {}", path.display()),
            });
        }
        let kind = entry.header().entry_type();
        if kind.is_symlink() || kind.is_hard_link() || !(kind.is_file() || kind.is_dir()) {
            return Err(Error::Extraction {
                archive: PathBuf::from(name),
                message: format!("special file rejected: {}", path.display()),
            });
        }
        let output = destination.join(&path);
        reject_symlink_components(&output, Path::new(name), "inspect extracted directory")?;
        if kind.is_dir() {
            fs::create_dir_all(&output).map_err(|source| Error::Io {
                operation: "create extracted directory".to_owned(),
                path: output.clone(),
                source,
            })?;
            reject_symlink_components(&output, Path::new(name), "inspect extracted directory")?;
            continue;
        }
        let entry_size = entry.size();
        stats.files += 1;
        stats.bytes = stats.bytes.saturating_add(entry_size);
        check_extraction_limits(&stats, limits)?;
        if let Some(parent) = output.parent() {
            fs::create_dir_all(parent).map_err(|source| Error::Io {
                operation: "create extracted parent".to_owned(),
                path: parent.to_owned(),
                source,
            })?;
        }
        reject_symlink_components(&output, Path::new(name), "inspect extracted path")?;
        let mut file = create_extracted_file(&output).map_err(|source| Error::Io {
            operation: "create extracted file".to_owned(),
            path: output.clone(),
            source,
        })?;
        let copied =
            io::copy(&mut entry.by_ref().take(entry_size), &mut file).map_err(|source| {
                Error::Io {
                    operation: "write extracted file".to_owned(),
                    path: output.clone(),
                    source,
                }
            })?;
        if copied != entry_size {
            return Err(Error::Extraction {
                archive: PathBuf::from(name),
                message: format!(
                    "extracted file {} has {} bytes, expected {}",
                    path.display(),
                    copied,
                    entry_size
                ),
            });
        }
    }
    Ok(stats)
}

fn extract_zip(bytes: &[u8], destination: &Path, limits: &EngineLimits) -> Result<ExtractionStats> {
    let mut archive = ZipArchive::new(Cursor::new(bytes)).map_err(|error| Error::Extraction {
        archive: PathBuf::from("zip"),
        message: error.to_string(),
    })?;
    let mut stats = ExtractionStats::default();
    let mut seen = HashSet::new();
    for index in 0..archive.len() {
        let mut entry = archive.by_index(index).map_err(|error| Error::Extraction {
            archive: PathBuf::from("zip"),
            message: error.to_string(),
        })?;
        let path = entry
            .enclosed_name()
            .ok_or_else(|| Error::Extraction {
                archive: PathBuf::from("zip"),
                message: format!("unsafe path {}", entry.name()),
            })?
            .to_owned();
        if !seen.insert(path.clone()) {
            return Err(Error::Extraction {
                archive: PathBuf::from("zip"),
                message: format!("duplicate path {}", path.display()),
            });
        }
        if entry
            .unix_mode()
            .is_some_and(|mode| mode & 0o170000 == 0o120000)
        {
            return Err(Error::Extraction {
                archive: PathBuf::from("zip"),
                message: format!("symlink rejected: {}", path.display()),
            });
        }
        let output = destination.join(&path);
        reject_symlink_components(&output, Path::new("zip"), "inspect extracted path")?;
        if entry.is_dir() {
            fs::create_dir_all(&output).map_err(|source| Error::Io {
                operation: "create extracted directory".to_owned(),
                path: output.clone(),
                source,
            })?;
            reject_symlink_components(&output, Path::new("zip"), "inspect extracted path")?;
            continue;
        }
        stats.files += 1;
        stats.bytes = stats.bytes.saturating_add(entry.size());
        check_extraction_limits(&stats, limits)?;
        if let Some(parent) = output.parent() {
            fs::create_dir_all(parent).map_err(|source| Error::Io {
                operation: "create extracted parent".to_owned(),
                path: parent.to_owned(),
                source,
            })?;
        }
        reject_symlink_components(&output, Path::new("zip"), "inspect extracted path")?;
        let mut file = create_extracted_file(&output).map_err(|source| Error::Io {
            operation: "create extracted file".to_owned(),
            path: output.clone(),
            source,
        })?;
        let declared_size = entry.size();
        let copied = io::copy(&mut entry, &mut file).map_err(|source| Error::Io {
            operation: "write extracted file".to_owned(),
            path: output.clone(),
            source,
        })?;
        if copied != declared_size {
            return Err(Error::Extraction {
                archive: PathBuf::from("zip"),
                message: format!(
                    "extracted file {} has {} bytes, expected {}",
                    path.display(),
                    copied,
                    declared_size
                ),
            });
        }
        file.flush().map_err(|source| Error::Io {
            operation: "flush extracted file".to_owned(),
            path: output,
            source,
        })?;
    }
    Ok(stats)
}

pub(super) fn single_root_or_self(source: &Path) -> Result<PathBuf> {
    let entries = fs::read_dir(source)
        .map_err(|source_error| Error::Io {
            operation: "inspect extraction root".to_owned(),
            path: source.to_owned(),
            source: source_error,
        })?
        .collect::<std::result::Result<Vec<_>, _>>()
        .map_err(|source_error| Error::Io {
            operation: "inspect extraction root".to_owned(),
            path: source.to_owned(),
            source: source_error,
        })?;
    if entries.len() == 1 && entries[0].path().is_dir() {
        Ok(entries[0].path())
    } else {
        Ok(source.to_owned())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
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
}
