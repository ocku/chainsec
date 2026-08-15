mod files;
mod lifecycle;
mod locks;

#[cfg(test)]
pub(in crate::fetcher) use files::write_cached_artifact;
pub(super) use files::{copy_cache_payload, read_bounded_regular_file, write_child_file_before};
pub(in crate::fetcher) use files::{is_unsafe_cache_open_error, write_cached_artifact_before};
pub(in crate::fetcher) use lifecycle::{prepare_cache, purge_cache};
pub(in crate::fetcher) use locks::CacheLock;
#[cfg(test)]
pub(super) use locks::lock_entry;
pub(super) use locks::{lock_entry_before, lock_entry_shared_before, validate_cache_directory};
