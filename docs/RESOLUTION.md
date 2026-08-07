# Dependency resolution and acquisition

## Supported ecosystems

| Ecosystem | Declarations | Lockfiles | Artifacts |
| --- | --- | --- | --- |
| Python | PEP 621 and Poetry dependencies | `poetry.lock`, `Pipfile.lock`, `uv.lock` | wheels, ZIP, `.tar`, `.tar.gz`, `.tar.bz2`, `.tar.xz` |
| npm | dependencies, optional dependencies, peer dependencies | npm lock/shrinkwrap 1–3, Yarn Classic, Yarn Berry 4–8, pnpm 5.3/5.4/6/9 | integrity-checked npm tarballs |
| Deno | JSON/JSONC imports and scoped imports | `deno.lock` versions 1–4 | bounded HTTP(S) graphs, locked npm tarballs, and manifest-verified JSR packages |
| GitHub | npm and Python Git declarations pinned to a full commit | declaration or supported package lock | bounded `codeload.github.com` source archives |

Deno URL graphs are syntax-aware rather than full Deno runtime resolution: static HTTP(S) and URL-relative literals in imports, exports, and dynamic `import()` calls are followed. Bare specifiers, `npm:`, `jsr:`, non-HTTP schemes, computed/template expressions, escaped literals, and custom-loader resolution are not expanded by the URL graph fetcher; `npm:` and `jsr:` dependencies are handled only when represented as supported manifest or lockfile entries.

## Limitations and unlocked resolution

Unsupported forms fail or remain unresolved rather than silently selecting `latest`. `--allow-unlocked` is the explicit exception for supported PyPI and npm registry requirements, where the highest release matching the declared version range is selected.

Yarn Berry lockfiles are parsed for supported versions 4–8, but ordinary Berry registry entries remain unresolved in locked mode: Berry cache checksums are not treated as npm tarball integrity values, and the current implementation does not derive an independently usable registry artifact integrity from Berry entries.

Git acquisition is deliberately limited to public GitHub repositories pinned to full 40-hex commits; branches, tags, short revisions, other hosts, submodules, and Git LFS acquisition are unsupported.

Python requirements files, workspace graph semantics, environment-marker evaluation, and native/binary semantic analysis are not yet implemented. File-level checks may still flag binary, compressed, and high-entropy files.
