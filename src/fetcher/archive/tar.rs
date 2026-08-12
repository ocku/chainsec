use std::{
    cell::Cell,
    collections::HashSet,
    io::{self, Read},
    path::{Path, PathBuf},
    rc::Rc,
};

use tar::Archive;

use crate::error::{Error, Result};
use crate::model::EngineLimits;

use super::support::{
    ExtractionStats, account_extracted_entry, create_extracted_directory, open_extraction_root,
    reject_duplicate_path, safe_relative, write_extracted_file,
};

const TAR_BLOCK_SIZE: u64 = 512;
const TAR_METADATA_ALLOWANCE: u64 = 1024 * 1024;

pub fn extract<R: Read>(
    reader: R,
    name: &str,
    destination: &Path,
    limits: &EngineLimits,
) -> Result<ExtractionStats> {
    let root = open_extraction_root(destination)?;
    let input_limit = input_budget(limits);
    let budget_exceeded = Rc::new(Cell::new(false));
    let reader = InputBudget {
        inner: reader,
        remaining: input_limit,
        exceeded: Rc::clone(&budget_exceeded),
    };
    let mut archive = Archive::new(reader);
    let mut stats = ExtractionStats::default();
    let mut seen = HashSet::new();
    let entries = archive
        .entries()
        .map_err(|error| archive_error(error, name, &budget_exceeded, input_limit))?;

    for entry in entries {
        let mut entry =
            entry.map_err(|error| archive_error(error, name, &budget_exceeded, input_limit))?;
        let kind = entry.header().entry_type();
        let entry_size = entry.size();
        if kind.is_pax_global_extensions() || kind.is_pax_local_extensions() {
            account_extracted_entry(&mut stats, entry_size, limits)?;
            continue;
        }

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
        reject_duplicate_path(&mut seen, &path, Path::new(name))?;
        if kind.is_symlink() || kind.is_hard_link() || !(kind.is_file() || kind.is_dir()) {
            return Err(Error::Extraction {
                archive: PathBuf::from(name),
                message: format!("special file rejected: {}", path.display()),
            });
        }

        account_extracted_entry(&mut stats, entry_size, limits)?;
        let output = destination.join(&path);
        if kind.is_dir() {
            create_extracted_directory(&root, destination, &output)?;
        } else {
            write_extracted_file(
                &mut entry,
                entry_size,
                &root,
                destination,
                &output,
                Path::new(name),
            )?;
        }
    }
    Ok(stats)
}

fn input_budget(limits: &EngineLimits) -> u64 {
    let framing = limits
        .max_extracted_files
        .saturating_mul(TAR_BLOCK_SIZE * 2)
        .saturating_add(TAR_BLOCK_SIZE * 2);
    limits
        .max_extracted_bytes
        .saturating_add(framing)
        .saturating_add(TAR_METADATA_ALLOWANCE)
}

struct InputBudget<R> {
    inner: R,
    remaining: u64,
    exceeded: Rc<Cell<bool>>,
}

impl<R: Read> Read for InputBudget<R> {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        if buffer.is_empty() {
            return Ok(0);
        }
        if self.remaining == 0 {
            let mut byte = [0];
            return match self.inner.read(&mut byte)? {
                0 => Ok(0),
                _ => {
                    self.exceeded.set(true);
                    Err(io::Error::other("decompressed TAR input budget exceeded"))
                }
            };
        }
        let maximum = usize::try_from(self.remaining)
            .unwrap_or(usize::MAX)
            .min(buffer.len());
        let read = self.inner.read(&mut buffer[..maximum])?;
        self.remaining -= read as u64;
        Ok(read)
    }
}

fn archive_error(error: io::Error, name: &str, exceeded: &Cell<bool>, limit: u64) -> Error {
    if exceeded.get() {
        Error::LimitExceeded {
            resource: "decompressed TAR input bytes".to_owned(),
            limit,
        }
    } else {
        Error::Extraction {
            archive: PathBuf::from(name),
            message: error.to_string(),
        }
    }
}
