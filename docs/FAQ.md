# Frequently asked questions

## Does `chainsec` install or run the packages it scans?

No. Package source is parsed, never installed or executed. Acquisition and extraction are implemented in Rust; `chainsec` does not launch `python`, package managers, Git, shell commands, or archive executables. Install hooks such as npm `preinstall`/`install`/`postinstall` and `setup.py` are reported as findings but never run.

## Why is network access off by default?

Scanning untrusted dependency source should not require trusting the network. Network access is disabled unless you pass `--online` or run a `chainsec remote` command, and each requested host must be explicitly allowed through `allowed_hosts`, `--allow-host`, the selected remote package's configured metadata or PyPI artifact host, or a configured Artifactory endpoint. Artifact hosts returned by registry metadata and redirects are checked against the same allowlist; metadata cannot add a host by itself. This keeps the default local-scan path fully offline and auditable.

## How do I configure a PyPI mirror with separate metadata and download hosts?

Configure both endpoints in `chainsec.toml`; ChainSec automatically allows these two configured hosts while online, but does not trust a third host merely because metadata names it.

```toml
[artifactories.pypi]
metadata_base_url = "https://metadata.packages.example/pypi"
artifact_base_url = "https://artifacts.packages.example/packages"
```

Omit `artifact_base_url` when one repository-manager endpoint serves both. The public defaults remain `pypi.org` for metadata and `files.pythonhosted.org` for artifacts.

## What does `--allow-unlocked` do?

By default, a dependency must be fully identified by a supported lockfile (exact version plus integrity). `--allow-unlocked` relaxes that for supported PyPI and npm registry requirements: the highest release matching the declared version range is selected and pinned to the registry-published artifact URL and integrity before download. It never downloads unverified remote artifacts. Unsupported unlocked forms remain unresolved.

## Can I scan only my own project without dependencies?

Yes. `chainsec scan --max-depth 0` scans only the root project and does not traverse dependencies. This is also the recommended way to verify an installation.

## How do I scan dependencies safely?

Use a locked project and an explicit network policy:

```sh
chainsec scan /path/to/project \
  --online \
  --allow-host pypi.org \
  --allow-host files.pythonhosted.org \
  --allow-host registry.npmjs.org \
  --format sarif \
  --output report.sarif
```

Narrow exact hosts are safer than wildcards. Prefer HTTPS; HTTP is plaintext.

## What does the exit code mean?

| Code | Meaning |
| --- | --- |
| `0` | Scan completed below the finding threshold |
| `1` | At least one finding met the threshold |
| `2` | Invalid input or configuration |
| `3` | Manifest, scan, resolution, or fetch issue |
| `4` | Policy or resource-limit violation |

See [Rules, reports, and exit status](RULES_AND_REPORTS.md) for the full precedence rules.

## How do I ignore a rule or a package?

- `--ignore-rule <GROUP:GLOB>` omits matching rules from scanning and reports, for example `--ignore-rule network:*` or `--ignore-rule filesystem:chainsec.py.detection.filesystem-open`.
- `ignored_packages = ["npm:legacy-package@1.2.3"]` in `chainsec.toml` omits a resolved dependency before it is fetched or scanned.
- `--ignore-path <GLOB>` omits matching root-project paths for one scan; repeat it for multiple globs. Configure `ignored_paths = ["tests/**"]` for persistent exclusions. It does not affect dependency source.

## How do I add my own rules?

Write a JSON or YAML rule pack with a non-empty `rules` array, each rule supplying `id`, `version`, `language`, `finding_type`, `risk`, `confidence`, `rationale`, `remediation`, and a Tree-sitter `query` with an `@match` capture. Load it with `--rule-pack <path>` (repeatable) or `rule_packs` in `chainsec.toml`. See [Rules, reports, and exit status](RULES_AND_REPORTS.md).

## Where is the cache, and can I move or purge it?

When the current directory contains `chainsec.toml`, the default cache is `.chainsec-cache` there. Otherwise, ChainSec uses `$XDG_CACHE_HOME/chainsec`, then `$HOME/.cache/chainsec`, and finally the system temporary directory. Set `--cache <dir>` or `cache` in `chainsec.toml` to choose a different location. Run `chainsec cache purge` to delete cached contents without scanning, or combine it with `--cache <dir>` to purge a specific cache. Purge removes everything except the cache directory and its internal `.lock`, so fetchers and purge operations continue to coordinate on one stable lock without creating a sibling file. On Unix, a running fetcher or purge rechecks the cache directory identity before cache acquisition, staging, and purge mutations; a detected rename or symlink replacement fails closed rather than continuing against the replacement. Cache entries are content-identified and published under per-entry locks: valid winners are retained, while invalid entries are atomically quarantined and replaced. Registry artifacts are integrity-checked and safely reconstructed into unique owner-only workspaces under the platform temporary directory, outside the configured cache, on every hit rather than trusting cached extracted source. These workspaces are removed when the owning fetcher is dropped. Full GitHub commit references do not provide an independent archive digest, so their cache entries are not reused. The Docker image uses `/cache`.

### How should I secure the cache?

Put the cache in a directory owned by the account running ChainSec and not writable by other users or services. Do not share a cache directory across trust boundaries. Cache locks only coordinate cooperating ChainSec processes; they are not an access-control mechanism. ChainSec uses Unix descriptor-relative no-follow operations for cache, extraction, and JSR workspaces, which prevents a directory replacement after the workspace root is opened from redirecting those operations. ChainSec compiles only for Unix targets.

## Does `chainsec` guarantee a package is safe?

No. Static analysis reduces risk but is not a malware-containment boundary and does not guarantee that source is benign. See the [security model](SECURITY_MODEL.md) for the precise trust model and remaining limitations.

## Which ecosystems and lockfiles are supported?

Python (PEP 621 and Poetry declarations; `poetry.lock`, `Pipfile.lock`, `uv.lock`, `pdm.lock`), npm (lock/shrinkwrap 1–3, Yarn Classic, pnpm 5.3/5.4/6/9), Deno (`deno.lock` versions 1–5), and public GitHub full-commit references. GitHub commit archives are origin-pinned to `codeload.github.com` but do not have an independently verified archive/tree digest. See [Dependency resolution and acquisition](RESOLUTION.md) and the [security model](SECURITY_MODEL.md) for details and limitations.
