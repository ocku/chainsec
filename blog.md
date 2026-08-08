# ChainSec 0.2.0: remote scans, layered configuration, and safer acquisition

ChainSec 0.2.0 has been released, and with it comes remote package scanning, layered configuration, configurable registry metadata endpoints, PDM lockfile support, and cache lifecycle controls.

## What was added

### Scan a package directly

Use `--remote <source:package>` to fetch and scan an npm, PyPI, JSR, or public GitHub package as the traversal root. The selected root does not need a lockfile; dependencies discovered beneath it still follow the normal lockfile policy.

```sh
# Scan the latest express package.
chainsec --remote npm:express \
  --allow-host registry.npmjs.org

# Scan a versioned PyPI package.
chainsec --remote pypi:urllib3 \
  --allow-host files.pythonhosted.org

# Scan a public GitHub repository pinned to an immutable full commit.
chainsec --remote github:owner/repository@40_HEX_COMMIT
```

A remote scan enables online mode automatically. The selected source's metadata host—or GitHub's archive host—is allowed for the root lookup; separate artifact-download hosts returned by registry metadata must still be explicitly allowlisted.

### Layered configuration and system defaults

ChainSec now overlays user configuration with a project configuration, then applies command-line values last:

1. `$HOME/.config/chainsec/config.toml`
2. Project `chainsec.toml`
3. Command-line options

The legacy global `chainsec.toml` filename remains supported. When neither user-local nor project configuration is available, `/etc/chainsec/chainsec.toml` provides a machine-wide fallback. `allowed_hosts` is additive across global configuration, project configuration, and repeated `--allow-host` arguments; duplicates are removed in that order.

```toml
# ~/.config/chainsec/config.toml
online = true
allowed_hosts = ["registry.corp.example"]

[artifactories.npm]
metadata_base_url = "https://registry.corp.example/npm"

[artifactories.npm.credential]
scope = "https://registry.corp.example/"
bearer_token_env = "CHAINSEC_REGISTRY_TOKEN"
```

```toml
# ./chainsec.toml
allowed_hosts = ["artifacts.corp.example"]
max_depth = 2
```

Registry credentials stay out of configuration: `bearer_token_env` names the environment variable containing the token. Credentials are scoped by scheme, host, port, and path prefix, and their eligibility is re-evaluated on redirects.

### Private registry metadata endpoints

npm, PyPI, and JSR metadata endpoints can now be configured for registry proxies and artifact repositories. This separates metadata lookup from public registry hosts while preserving the existing integrity verification and host policy for downloaded artifacts.

```toml
[artifactories.pypi]
metadata_base_url = "https://packages.example/pypi"

[artifactories.jsr]
metadata_base_url = "https://packages.example/jsr"
```

Configured metadata hosts are automatically allowed in online mode. If metadata returns artifacts from another host, add that host to `allowed_hosts` or pass `--allow-host`.

### PDM and cache maintenance

Python dependency resolution now supports `pdm.lock`. Cache management also gains `--cache-purge`, which removes the resolved dependency cache without performing a scan.

```sh
# Remove the default resolved dependency cache.
chainsec --cache-purge

# Remove a specific cache directory.
chainsec --cache .chainsec-cache --cache-purge
```

## Update notes

Human-readable output is now the default report format. CI and other report consumers must explicitly request a machine-readable format:

```sh
chainsec /path/to/project --format json --output report.json
chainsec /path/to/project --format sarif --output report.sarif
```

Human finding lines now include the package identifier.

HTTP acquisition is asynchronous in 0.2.0. Redirects are checked against policy manually, and credential scope is evaluated at every hop. Cache hits additionally validate completion metadata, source identity and limits, extracted-tree safety, and a deterministic content-tree digest. Source-byte and scan-duration limits are enforced throughout reading, traversal, and analysis.

The default cache remains `.chainsec-cache` when the current working directory contains `chainsec.toml`. Other invocations use the XDG/user cache directory, falling back to the system temporary directory. `chainsec --init` now adds `.chainsec-cache` to `.gitignore`.
