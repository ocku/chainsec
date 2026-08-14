use std::{
    cell::{Cell, RefCell},
    collections::{HashMap, HashSet},
    fmt,
    fs::{self, File, OpenOptions},
    io::{self, Read},
    path::{Component, Path, PathBuf},
    rc::Rc,
};

use serde::de::{self, DeserializeSeed, MapAccess, SeqAccess, Visitor};
use serde_json::{Map as JsonMap, Number as JsonNumber, Value as JsonValue};

#[cfg(unix)]
use std::{
    ffi::{CStr, CString, OsStr},
    os::{
        fd::{AsRawFd, FromRawFd, IntoRawFd, RawFd},
        unix::{ffi::OsStrExt, fs::OpenOptionsExt},
    },
};

use crate::{
    error::{Error, Result},
    model::{DEFAULT_MAX_MANIFEST_FILE_SIZE, Dependency},
};

/// Maximum bytes accepted from any declaration, workspace manifest, import map, or lockfile.
///
/// Manifest parsers share this boundary so no ecosystem can accidentally accept larger untrusted
/// parser inputs than another. This is intentionally independent of source and archive limits.
pub(super) const MAX_MANIFEST_FILE_BYTES: u64 = DEFAULT_MAX_MANIFEST_FILE_SIZE;

thread_local! {
    static ACTIVE_MANIFEST_FILE_LIMITS: RefCell<Vec<u64>> = const { RefCell::new(Vec::new()) };
}

/// Collects unique manifest dependencies while enforcing the package budget at insertion time.
///
/// Parsers use this directly while expanding declaration sections, groups, and workspaces so they
/// never need to build an over-limit intermediate dependency vector.
pub(super) struct BoundedDependencyCollector {
    dependencies: Vec<Dependency>,
    known: HashSet<Dependency>,
    max_packages: usize,
}

impl BoundedDependencyCollector {
    pub(super) fn new(max_packages: usize) -> Self {
        Self {
            dependencies: Vec::new(),
            known: HashSet::new(),
            max_packages,
        }
    }

    pub(super) fn from_dependencies(
        dependencies: Vec<Dependency>,
        max_packages: usize,
    ) -> Result<Self> {
        let mut collector = Self::new(max_packages);
        collector.extend(dependencies)?;
        Ok(collector)
    }

    pub(super) fn push(&mut self, dependency: Dependency) -> Result<()> {
        if self.known.contains(&dependency) {
            return Ok(());
        }
        if self.dependencies.len() >= self.max_packages {
            return Err(Error::LimitExceeded {
                resource: "manifest dependencies".to_owned(),
                limit: u64::try_from(self.max_packages).unwrap_or(u64::MAX),
            });
        }
        self.known.insert(dependency.clone());
        self.dependencies.push(dependency);
        Ok(())
    }

    pub(super) fn extend(&mut self, incoming: impl IntoIterator<Item = Dependency>) -> Result<()> {
        for dependency in incoming {
            self.push(dependency)?;
        }
        Ok(())
    }

    pub(super) fn into_dependencies(self) -> Vec<Dependency> {
        self.dependencies
    }
}

pub(super) fn extend_dependencies_bounded(
    dependencies: &mut Vec<Dependency>,
    incoming: impl IntoIterator<Item = Dependency>,
    max_packages: usize,
) -> Result<()> {
    let existing = std::mem::take(dependencies);
    let mut collector = BoundedDependencyCollector::from_dependencies(existing, max_packages)?;
    let result = collector.extend(incoming);
    *dependencies = collector.into_dependencies();
    result
}

/// Retains a unique workspace member without allowing workspace expansion to exceed the same
/// configured package budget used by every manifest ecosystem.
pub(super) fn push_workspace_member_bounded(
    members: &mut Vec<PathBuf>,
    member: PathBuf,
    max_packages: usize,
) -> Result<()> {
    if members.contains(&member) {
        return Ok(());
    }
    if members.len() >= max_packages {
        return Err(Error::LimitExceeded {
            resource: "workspace members".to_owned(),
            limit: u64::try_from(max_packages).unwrap_or(u64::MAX),
        });
    }
    members.push(member);
    Ok(())
}

thread_local! {
    static ACTIVE_ROOTS: RefCell<Vec<ActiveRoot>> = const { RefCell::new(Vec::new()) };
}

struct ActiveRoot {
    path: PathBuf,
    directory: File,
}

/// An opened manifest directory used as the authority for all paths beneath it.
///
/// Keeping this descriptor open makes later checks and reads independent of replacement of the
/// root path or any of its parent path components.
pub(super) struct ManifestRoot {
    path: PathBuf,
    directory: File,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum RootedFileType {
    Directory,
    File,
    Symlink,
    Other,
}

impl ManifestRoot {
    pub(super) fn open(path: &Path) -> Result<Self> {
        let path = absolute_lexical(path).map_err(|source| io_error(path, source))?;
        let directory = open_directory(&path)?;
        Ok(Self { path, directory })
    }

    pub(super) fn path(&self) -> &Path {
        &self.path
    }

    pub(super) fn is_file(&self, relative: &Path) -> Result<bool> {
        is_open_file(self.open_relative(relative), &self.path.join(relative))
    }

    fn open_relative(&self, relative: &Path) -> Result<File> {
        open_beneath(&self.directory, &self.path, relative)
    }
}

pub(super) fn is_file_beneath(directory: &Path, relative: &Path) -> Result<bool> {
    let directory = absolute_lexical(directory).map_err(|source| io_error(directory, source))?;
    let rooted = ACTIVE_ROOTS.with(|roots| {
        roots
            .borrow()
            .iter()
            .find(|root| root.path == directory)
            .map(|root| open_beneath(&root.directory, &root.path, relative))
    });
    match rooted {
        Some(file) => is_open_file(file, &directory.join(relative)),
        None => ManifestRoot::open(&directory)?.is_file(relative),
    }
}

fn is_open_file(file: Result<File>, path: &Path) -> Result<bool> {
    match file {
        Ok(file) => file
            .metadata()
            .map(|metadata| metadata.file_type().is_file())
            .map_err(|source| io_error(path, source)),
        Err(Error::Io { source, .. }) if source.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error),
    }
}

#[cfg(unix)]
pub(super) fn walk_beneath(
    directory: &Path,
    max_package_depth: usize,
    visit: &mut impl FnMut(&Path, usize, RootedFileType) -> Result<()>,
) -> Result<()> {
    let directory = absolute_lexical(directory).map_err(|source| io_error(directory, source))?;
    let rooted = ACTIVE_ROOTS.with(|roots| {
        roots
            .borrow()
            .iter()
            .find(|root| root.path == directory)
            .map(|root| {
                root.directory
                    .try_clone()
                    .map_err(|source| io_error(&directory, source))
            })
    });
    let descriptor = match rooted {
        Some(descriptor) => descriptor?,
        None => ManifestRoot::open(&directory)?.directory,
    };
    walk_directory(
        descriptor,
        &directory,
        Path::new(""),
        0,
        max_package_depth,
        visit,
    )
}

#[cfg(unix)]
pub(super) fn walk_workspace_beneath(
    directory: &Path,
    max_package_depth: usize,
    max_entries: u64,
    visit: &mut impl FnMut(&Path, usize, RootedFileType) -> Result<()>,
) -> Result<()> {
    let mut visited_entries = 0u64;
    walk_beneath(directory, max_package_depth, &mut |entry, depth, kind| {
        visited_entries = visited_entries.saturating_add(1);
        if visited_entries > max_entries {
            return Err(Error::LimitExceeded {
                resource: "workspace entries".to_owned(),
                limit: max_entries,
            });
        }
        visit(entry, depth, kind)
    })
}

pub(super) fn workspace_depth_exceeded(
    kind: RootedFileType,
    depth: usize,
    max_package_depth: usize,
    included: bool,
) -> bool {
    kind == RootedFileType::Directory && depth >= max_package_depth && included
}

#[cfg(test)]
pub(super) fn with_manifest_roots<T>(
    roots: &[ManifestRoot],
    operation: impl FnOnce() -> T,
) -> Result<T> {
    with_manifest_roots_and_limit(roots, MAX_MANIFEST_FILE_BYTES, operation)
}

pub(super) fn with_manifest_roots_and_limit<T>(
    roots: &[ManifestRoot],
    max_manifest_file_size: u64,
    operation: impl FnOnce() -> T,
) -> Result<T> {
    let active = roots
        .iter()
        .map(|root| {
            Ok(ActiveRoot {
                path: root.path.clone(),
                directory: root
                    .directory
                    .try_clone()
                    .map_err(|source| io_error(&root.path, source))?,
            })
        })
        .collect::<Result<Vec<_>>>()?;
    let previous_len = ACTIVE_ROOTS.with(|roots| {
        let mut roots = roots.borrow_mut();
        let previous_len = roots.len();
        roots.extend(active);
        previous_len
    });
    let guard = ActiveRootsGuard(previous_len);
    ACTIVE_MANIFEST_FILE_LIMITS.with(|limits| limits.borrow_mut().push(max_manifest_file_size));
    let limit_guard = ActiveManifestFileLimitGuard;
    let result = operation();
    drop(limit_guard);
    drop(guard);
    Ok(result)
}

struct ActiveManifestFileLimitGuard;

impl Drop for ActiveManifestFileLimitGuard {
    fn drop(&mut self) {
        ACTIVE_MANIFEST_FILE_LIMITS.with(|limits| {
            limits.borrow_mut().pop();
        });
    }
}

struct ActiveRootsGuard(usize);

impl Drop for ActiveRootsGuard {
    fn drop(&mut self) {
        ACTIVE_ROOTS.with(|roots| roots.borrow_mut().truncate(self.0));
    }
}

pub(super) fn read(path: &Path) -> Result<String> {
    let absolute = absolute_lexical(path).map_err(|source| io_error(path, source))?;
    let rooted = ACTIVE_ROOTS.with(|roots| {
        roots
            .borrow()
            .iter()
            .filter_map(|root| {
                absolute
                    .strip_prefix(&root.path)
                    .ok()
                    .map(|relative| (root.path.components().count(), root, relative.to_owned()))
            })
            .max_by_key(|(depth, _, _)| *depth)
            .map(|(_, root, relative)| open_beneath(&root.directory, &root.path, &relative))
    });
    if let Some(file) = rooted {
        return read_open_file(path, file?);
    }
    if ACTIVE_ROOTS.with(|roots| !roots.borrow().is_empty()) {
        return Err(manifest_error(
            path,
            "manifest path is outside the active discovery root",
        ));
    }

    reject_symlink(path)?;
    let file = open_file(path)?;
    read_open_file(path, file)
}

#[cfg(unix)]
pub(super) fn read_beneath(directory: &Path, relative: &Path) -> Result<String> {
    let directory = absolute_lexical(directory).map_err(|source| io_error(directory, source))?;
    let rooted = ACTIVE_ROOTS.with(|roots| {
        roots
            .borrow()
            .iter()
            .find(|root| root.path == directory)
            .map(|root| open_beneath(&root.directory, &root.path, relative))
    });
    if let Some(file) = rooted {
        return read_open_file(&directory.join(relative), file?);
    }

    let root = ManifestRoot::open(&directory)?;
    let path = root.path.join(relative);
    read_open_file(&path, root.open_relative(relative)?)
}

#[cfg(not(unix))]
pub(super) fn read_beneath(directory: &Path, relative: &Path) -> Result<String> {
    Err(manifest_error(
        &directory.join(relative),
        "safe manifest reads are unsupported on this platform",
    ))
}

fn read_open_file(path: &Path, mut file: File) -> Result<String> {
    let limit = ACTIVE_MANIFEST_FILE_LIMITS.with(|limits| {
        limits
            .borrow()
            .last()
            .copied()
            .unwrap_or(MAX_MANIFEST_FILE_BYTES)
    });
    let metadata = file.metadata().map_err(|source| io_error(path, source))?;
    if !metadata.file_type().is_file() {
        return Err(manifest_error(path, "manifest is not a regular file"));
    }
    if metadata.len() > limit {
        return Err(manifest_file_limit_error(path, limit));
    }

    // The descriptor may refer to a concurrently growing file. `take` ensures the allocation and
    // read remain bounded even when the size observed above becomes stale.
    let capacity = usize::try_from(metadata.len().min(limit)).unwrap_or(0);
    let mut bytes = Vec::with_capacity(capacity);
    file.by_ref()
        .take(limit.saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|source| io_error(path, source))?;
    if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > limit {
        return Err(manifest_file_limit_error(path, limit));
    }
    String::from_utf8(bytes).map_err(|source| {
        io_error(
            path,
            io::Error::new(io::ErrorKind::InvalidData, source.utf8_error()),
        )
    })
}

fn reject_symlink(path: &Path) -> Result<()> {
    let metadata = fs::symlink_metadata(path).map_err(|source| io_error(path, source))?;
    if metadata.file_type().is_symlink() {
        return Err(manifest_error(path, "refusing to read a symbolic link"));
    }
    Ok(())
}

fn absolute_lexical(path: &Path) -> io::Result<PathBuf> {
    let path = if path.is_absolute() {
        path.to_owned()
    } else {
        std::env::current_dir()?.join(path)
    };
    let mut normalized = PathBuf::new();
    for component in path.components() {
        match component {
            Component::Prefix(prefix) => normalized.push(prefix.as_os_str()),
            Component::RootDir => normalized.push(Path::new("/")),
            Component::CurDir => {}
            Component::ParentDir => {
                normalized.pop();
            }
            Component::Normal(component) => normalized.push(component),
        }
    }
    Ok(normalized)
}

#[cfg(unix)]
fn open_directory(path: &Path) -> Result<File> {
    let mut directory = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NONBLOCK)
        .open(Path::new("/"))
        .map_err(|source| io_error(path, source))?;

    // `O_NOFOLLOW` protects only the final component passed to `open`. Traverse from the
    // filesystem root with descriptor-relative opens so no ancestor can redirect the root.
    for component in path.components() {
        match component {
            Component::RootDir | Component::CurDir => {}
            Component::Normal(name) => {
                directory = open_at(
                    directory.as_raw_fd(),
                    Path::new(name),
                    libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_NONBLOCK,
                )
                .map_err(|source| io_error(path, source))?;
            }
            Component::ParentDir | Component::Prefix(_) => {
                return Err(manifest_error(
                    path,
                    "manifest root must be an absolute directory",
                ));
            }
        }
    }
    Ok(directory)
}

#[cfg(not(unix))]
fn open_directory(path: &Path) -> Result<File> {
    Err(manifest_error(
        path,
        "safe manifest reads are unsupported on this platform",
    ))
}

#[cfg(unix)]
fn open_beneath(directory: &File, root: &Path, relative: &Path) -> Result<File> {
    let mut current = directory
        .try_clone()
        .map_err(|source| io_error(root, source))?;
    let components = relative.components().collect::<Vec<_>>();
    if components.is_empty() {
        return Err(manifest_error(root, "manifest path does not name a file"));
    }
    for (index, component) in components.iter().enumerate() {
        match component {
            Component::CurDir => {}
            Component::Normal(name) => {
                let directory_component = index + 1 < components.len();
                let flags = libc::O_RDONLY
                    | libc::O_NOFOLLOW
                    | libc::O_NONBLOCK
                    | if directory_component {
                        libc::O_DIRECTORY
                    } else {
                        0
                    };
                current = open_at(current.as_raw_fd(), Path::new(name), flags)
                    .map_err(|source| io_error(&root.join(relative), source))?;
            }
            Component::ParentDir | Component::RootDir | Component::Prefix(_) => {
                return Err(manifest_error(
                    &root.join(relative),
                    "manifest path must remain within its discovery root",
                ));
            }
        }
    }
    Ok(current)
}

#[cfg(not(unix))]
fn open_beneath(_directory: &File, root: &Path, relative: &Path) -> Result<File> {
    Err(manifest_error(
        &root.join(relative),
        "safe manifest reads are unsupported on this platform",
    ))
}

#[cfg(unix)]
struct DirectoryStream(*mut libc::DIR);

#[cfg(unix)]
impl Drop for DirectoryStream {
    fn drop(&mut self) {
        // SAFETY: the stream is uniquely owned by this guard.
        unsafe { libc::closedir(self.0) };
    }
}

#[cfg(unix)]
fn walk_directory(
    directory: File,
    root: &Path,
    relative: &Path,
    depth: usize,
    max_package_depth: usize,
    visit: &mut impl FnMut(&Path, usize, RootedFileType) -> Result<()>,
) -> Result<()> {
    let descriptor = directory.into_raw_fd();
    // SAFETY: ownership of `descriptor` is transferred to `fdopendir` on success.
    let stream = unsafe { libc::fdopendir(descriptor) };
    if stream.is_null() {
        let source = io::Error::last_os_error();
        // SAFETY: `fdopendir` failed, so ownership of `descriptor` remains here.
        drop(unsafe { File::from_raw_fd(descriptor) });
        return Err(io_error(&root.join(relative), source));
    }
    let stream = DirectoryStream(stream);

    loop {
        clear_errno();
        // SAFETY: `stream` remains valid and uniquely owned for the duration of the call.
        let entry = unsafe { libc::readdir(stream.0) };
        if entry.is_null() {
            let source = io::Error::last_os_error();
            if source.raw_os_error() == Some(0) {
                return Ok(());
            }
            return Err(io_error(&root.join(relative), source));
        }
        // SAFETY: `readdir` returned a valid entry whose name is NUL terminated.
        let name = unsafe { CStr::from_ptr((*entry).d_name.as_ptr()) };
        if matches!(name.to_bytes(), b"." | b"..") {
            continue;
        }
        let name_path = Path::new(OsStr::from_bytes(name.to_bytes()));
        let child_relative = relative.join(name_path);
        let mut status = std::mem::MaybeUninit::<libc::stat>::uninit();
        // SAFETY: all pointers are valid and `status` is initialized on success.
        if unsafe {
            libc::fstatat(
                libc::dirfd(stream.0),
                name.as_ptr(),
                status.as_mut_ptr(),
                libc::AT_SYMLINK_NOFOLLOW,
            )
        } != 0
        {
            return Err(io_error(
                &root.join(&child_relative),
                io::Error::last_os_error(),
            ));
        }
        // SAFETY: `fstatat` succeeded.
        let status = unsafe { status.assume_init() };
        let kind = match status.st_mode & libc::S_IFMT {
            libc::S_IFDIR => RootedFileType::Directory,
            libc::S_IFREG => RootedFileType::File,
            libc::S_IFLNK => RootedFileType::Symlink,
            _ => RootedFileType::Other,
        };
        if kind == RootedFileType::Directory && excluded_directory(name.to_bytes()) {
            continue;
        }
        let child_depth = depth + 1;
        visit(&child_relative, child_depth, kind)?;
        if kind == RootedFileType::Directory && child_depth < max_package_depth {
            // SAFETY: `stream` is a valid open directory stream.
            let directory_fd = unsafe { libc::dirfd(stream.0) };
            let child = open_at(
                directory_fd,
                name_path,
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_NONBLOCK,
            )
            .map_err(|source| io_error(&root.join(&child_relative), source))?;
            walk_directory(
                child,
                root,
                &child_relative,
                child_depth,
                max_package_depth,
                visit,
            )?;
        }
    }
}

#[cfg(any(target_os = "macos", target_os = "ios"))]
fn clear_errno() {
    // SAFETY: the platform returns a valid pointer to thread-local errno.
    unsafe { *libc::__error() = 0 };
}

#[cfg(all(unix, not(any(target_os = "macos", target_os = "ios"))))]
fn clear_errno() {
    // SAFETY: the platform returns a valid pointer to thread-local errno.
    unsafe { *libc::__errno_location() = 0 };
}

#[cfg(unix)]
fn open_file(path: &Path) -> Result<File> {
    OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
        .map_err(|source| io_error(path, source))
}

#[cfg(unix)]
fn open_at(directory: RawFd, path: &Path, flags: i32) -> io::Result<File> {
    let path = CString::new(path.as_os_str().as_bytes())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "path contains NUL"))?;
    // SAFETY: `path` is NUL terminated and the returned descriptor is uniquely owned here.
    let descriptor = unsafe { libc::openat(directory, path.as_ptr(), flags | libc::O_CLOEXEC) };
    if descriptor < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: `descriptor` was returned by `openat` and ownership is transferred to `File`.
    Ok(unsafe { File::from_raw_fd(descriptor) })
}

#[cfg(not(unix))]
fn open_file(path: &Path) -> Result<File> {
    Err(manifest_error(
        path,
        "safe manifest reads are unsupported on this platform",
    ))
}

fn io_error(path: &Path, source: io::Error) -> Error {
    Error::Io {
        operation: "read".to_owned(),
        path: path.to_owned(),
        source,
    }
}

fn excluded_directory(name: &[u8]) -> bool {
    [
        b".git".as_slice(),
        b".chainsec-cache".as_slice(),
        b"node_modules".as_slice(),
        b"target".as_slice(),
        b".venv".as_slice(),
        b"venv".as_slice(),
        b"env".as_slice(),
        b"__pycache__".as_slice(),
    ]
    .contains(&name)
}

fn manifest_file_limit_error(path: &Path, limit: u64) -> Error {
    manifest_error(
        path,
        format!("manifest exceeds the shared {limit}-byte file limit"),
    )
}

pub(super) fn manifest_error(path: &Path, error: impl ToString) -> Error {
    Error::Manifest {
        path: path.to_owned(),
        message: error.to_string(),
    }
}

/// Parses a YAML manifest without allowing aliases to expand into an object graph larger than the
/// bounded input itself. The budget is derived from the actual file bytes, so Yarn and pnpm share
/// the configured manifest limit rather than gaining a separate parser-specific limit.
pub(super) fn parse_bounded_yaml_json(path: &Path, text: &str) -> Result<JsonValue> {
    let budget = Rc::new(YamlNodeBudget {
        remaining: Cell::new(text.len().saturating_add(1)),
    });
    BoundedJsonSeed { budget }
        .deserialize(serde_yaml::Deserializer::from_str(text))
        .map_err(|error| manifest_error(path, error))
}

struct YamlNodeBudget {
    remaining: Cell<usize>,
}

impl YamlNodeBudget {
    fn charge<E: de::Error>(&self) -> std::result::Result<(), E> {
        let remaining = self.remaining.get();
        if remaining == 0 {
            return Err(E::custom(
                "expanded YAML node count exceeds the bounded manifest input size",
            ));
        }
        self.remaining.set(remaining - 1);
        Ok(())
    }
}

#[derive(Clone)]
struct BoundedJsonSeed {
    budget: Rc<YamlNodeBudget>,
}

impl<'de> DeserializeSeed<'de> for BoundedJsonSeed {
    type Value = JsonValue;

    fn deserialize<D>(self, deserializer: D) -> std::result::Result<Self::Value, D::Error>
    where
        D: de::Deserializer<'de>,
    {
        self.budget.charge()?;
        deserializer.deserialize_any(BoundedJsonVisitor {
            budget: self.budget,
        })
    }
}

struct BoundedJsonVisitor {
    budget: Rc<YamlNodeBudget>,
}

impl BoundedJsonVisitor {
    fn seed(&self) -> BoundedJsonSeed {
        BoundedJsonSeed {
            budget: Rc::clone(&self.budget),
        }
    }
}

impl<'de> Visitor<'de> for BoundedJsonVisitor {
    type Value = JsonValue;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a YAML value representable as JSON")
    }

    fn visit_bool<E>(self, value: bool) -> std::result::Result<Self::Value, E> {
        Ok(JsonValue::Bool(value))
    }

    fn visit_i64<E>(self, value: i64) -> std::result::Result<Self::Value, E> {
        Ok(JsonValue::Number(value.into()))
    }

    fn visit_u64<E>(self, value: u64) -> std::result::Result<Self::Value, E> {
        Ok(JsonValue::Number(value.into()))
    }

    fn visit_f64<E: de::Error>(self, value: f64) -> std::result::Result<Self::Value, E> {
        JsonNumber::from_f64(value)
            .map(JsonValue::Number)
            .ok_or_else(|| E::custom("non-finite YAML number cannot be represented as JSON"))
    }

    fn visit_str<E>(self, value: &str) -> std::result::Result<Self::Value, E> {
        Ok(JsonValue::String(value.to_owned()))
    }

    fn visit_string<E>(self, value: String) -> std::result::Result<Self::Value, E> {
        Ok(JsonValue::String(value))
    }

    fn visit_none<E>(self) -> std::result::Result<Self::Value, E> {
        Ok(JsonValue::Null)
    }

    fn visit_unit<E>(self) -> std::result::Result<Self::Value, E> {
        Ok(JsonValue::Null)
    }

    fn visit_some<D>(self, deserializer: D) -> std::result::Result<Self::Value, D::Error>
    where
        D: de::Deserializer<'de>,
    {
        self.seed().deserialize(deserializer)
    }

    fn visit_seq<A>(self, mut sequence: A) -> std::result::Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        let mut values = Vec::with_capacity(sequence.size_hint().unwrap_or(0));
        while let Some(value) = sequence.next_element_seed(self.seed())? {
            values.push(value);
        }
        Ok(JsonValue::Array(values))
    }

    fn visit_map<A>(self, mut mapping: A) -> std::result::Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut values = JsonMap::with_capacity(mapping.size_hint().unwrap_or(0));
        while let Some(key) = mapping.next_key_seed(self.seed())? {
            let JsonValue::String(key) = key else {
                return Err(de::Error::custom("YAML mapping keys must be strings"));
            };
            values.insert(key, mapping.next_value_seed(self.seed())?);
        }
        Ok(JsonValue::Object(values))
    }
}

pub(super) fn optional_json_string<'a>(
    path: &Path,
    object: &'a JsonMap<String, JsonValue>,
    field: &str,
    context: &str,
) -> Result<Option<&'a str>> {
    object
        .get(field)
        .map(|value| {
            value
                .as_str()
                .ok_or_else(|| manifest_error(path, format!("{context} {field} must be a string")))
        })
        .transpose()
}

pub(super) fn optional_toml_string<'a>(
    path: &Path,
    table: &'a ::toml::value::Table,
    field: &str,
    context: &str,
) -> Result<Option<&'a str>> {
    table
        .get(field)
        .map(|value| {
            value
                .as_str()
                .ok_or_else(|| manifest_error(path, format!("{context} {field} must be a string")))
        })
        .transpose()
}

pub(super) fn is_sha256_integrity(value: &str) -> bool {
    value.strip_prefix("sha256:").is_some_and(|digest| {
        digest.len() == 64 && digest.bytes().all(|byte| byte.is_ascii_hexdigit())
    })
}

/// Collects package dependencies using npm's cross-section precedence.
pub(super) fn package_json_dependencies(
    path: &Path,
    package: &JsonMap<String, JsonValue>,
    max_packages: usize,
) -> Result<HashMap<String, String>> {
    let mut by_name = HashMap::new();
    // Peer dependencies are a fallback only. Development dependencies are included
    // by default, while normal and optional dependencies take precedence, matching
    // npm's duplicate-section semantics.
    for section in [
        "peerDependencies",
        "devDependencies",
        "dependencies",
        "optionalDependencies",
    ] {
        let Some(value) = package.get(section) else {
            continue;
        };
        let entries = value
            .as_object()
            .ok_or_else(|| manifest_error(path, format!("{section} must be an object")))?;
        for (name, value) in entries {
            let requirement = value.as_str().ok_or_else(|| {
                manifest_error(path, format!("{section}.{name} must be a string"))
            })?;
            let is_new = !by_name.contains_key(name);
            if is_new && by_name.len() >= max_packages {
                return Err(Error::LimitExceeded {
                    resource: "manifest dependencies".to_owned(),
                    limit: u64::try_from(max_packages).unwrap_or(u64::MAX),
                });
            }
            by_name.insert(name.clone(), requirement.to_owned());
        }
    }
    Ok(by_name)
}

pub(super) fn strip_url_fragment(url: &str) -> String {
    url.split('#').next().unwrap_or(url).to_owned()
}

pub(super) fn github_archive(reference: &str) -> Option<(String, String)> {
    let reference = reference
        .split_once(" @ ")
        .map_or(reference.trim(), |(_, source)| source.trim());
    let (repository, commit) = reference
        .rsplit_once('#')
        .or_else(|| reference.rsplit_once(".git@"))?;
    if commit.len() != 40 || !commit.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return None;
    }
    let repository = repository.strip_prefix("git+").unwrap_or(repository);
    let repository = repository
        .strip_prefix("https://github.com/")
        .or_else(|| repository.strip_prefix("ssh://git@github.com/"))
        .or_else(|| repository.strip_prefix("git://github.com/"))
        .or_else(|| repository.strip_prefix("git@github.com:"))
        .or_else(|| repository.strip_prefix("github:"))
        .unwrap_or(repository);
    let repository = repository.strip_suffix(".git").unwrap_or(repository);
    let mut parts = repository.split('/');
    let owner = parts.next()?;
    let name = parts.next()?;
    if parts.next().is_some()
        || owner.is_empty()
        || name.is_empty()
        || !owner
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        || !name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
    {
        return None;
    }
    let commit = commit.to_ascii_lowercase();
    Some((
        format!("https://codeload.github.com/{owner}/{name}/tar.gz/{commit}"),
        commit,
    ))
}

#[cfg(test)]
mod tests;
