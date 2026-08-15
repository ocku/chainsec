use std::{fs, path::Path};

use ::toml::Value as TomlValue;
use tempfile::tempdir;

use super::{
    PythonLockContext,
    artifact::expand_file_artifacts,
    enrich, pipfile,
    toml::{enrich_pdm, enrich_poetry, enrich_uv},
};
use crate::{
    manifests::{
        python::{
            declarations::dependency_from_requirement,
            matching::{find_package, index_toml_packages},
        },
        shared::{ManifestRoot, with_manifest_roots},
    },
    model::Dependency,
};

fn dependency(requirement: &str) -> Dependency {
    dependency_from_requirement(requirement)
}

fn write_lock(name: &str, contents: &str) -> (tempfile::TempDir, std::path::PathBuf) {
    let directory = tempdir().unwrap();
    let path = directory.path().join(name);
    let contents = match name {
        "poetry.lock" => format!("[metadata]\nlock-version = \"2.0\"\n{contents}"),
        "uv.lock" => format!("version = 1\n{contents}"),
        "pdm.lock" => format!("[metadata]\nlock_version = \"4.5.0\"\n{contents}"),
        "Pipfile.lock" => {
            let mut value: serde_json::Value = serde_json::from_str(contents).unwrap();
            value
                .as_object_mut()
                .unwrap()
                .insert("_meta".into(), serde_json::json!({"pipfile-spec": 6}));
            serde_json::to_string(&value).unwrap()
        }
        _ => contents.to_owned(),
    };
    fs::write(&path, contents).unwrap();
    (directory, path)
}

type LockEnricher = fn(&Path, &mut Vec<Dependency>) -> crate::error::Result<()>;

mod context;
mod formats;
mod pipfile_format;
mod security;
