mod bounded;
mod dependencies;
mod rooted_fs;
mod workspace;

pub(super) use bounded::{
    BoundedDependencyCollector, extend_dependencies_bounded, optional_json_string,
    optional_toml_string, parse_bounded_yaml_json,
};
pub(super) use dependencies::{
    github_archive, is_npm_dist_tag, is_sha256_integrity, package_json_dependencies,
    strip_url_fragment,
};
#[allow(unused_imports)]
pub(super) use rooted_fs::MAX_MANIFEST_FILE_BYTES;
#[cfg(test)]
pub(super) use rooted_fs::with_manifest_roots;
pub(super) use rooted_fs::{
    ManifestRoot, is_file_beneath, manifest_error, read, read_beneath,
    with_manifest_roots_and_limit,
};
#[cfg(unix)]
#[allow(unused_imports)]
pub(super) use workspace::walk_beneath;
#[cfg(unix)]
pub(super) use workspace::walk_workspace_beneath;
pub(super) use workspace::{
    RootedFileType, push_workspace_member_bounded, workspace_depth_exceeded,
    workspace_pattern_may_match_descendant,
};

#[cfg(test)]
use std::path::Path;

#[cfg(test)]
use crate::error::Error;

#[cfg(test)]
mod tests;
