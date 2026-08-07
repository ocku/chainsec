# Security policy

## Supported versions

`chainsec` is an early `0.x` project. Security fixes are provided for the latest released version only; the default branch receives fixes before the next release. Older releases are unsupported.

| Version | Supported |
| --- | --- |
| Latest release | Yes |
| Older releases | No |

The scanner is not currently a sandbox for hostile packages. Review the [security model](docs/SECURITY_MODEL.md), especially the documented archive, cache, network, parser, and resource-limit boundaries, before scanning untrusted dependencies. Package installers, lifecycle hooks, Git, shells, and archive executables are not invoked, but static analysis is not a guarantee that source is benign.

## Reporting a vulnerability

Please report suspected vulnerabilities privately:

1. Use the repository's **Security** tab and select **Report a vulnerability** to open a private security advisory.
2. If private reporting is unavailable, contact a maintainer through a private channel listed on their repository profile. Do not include exploit details in a public issue.

Include, when possible:

- The affected version or commit.
- The affected boundary: acquisition, archive extraction, cache validation, report generation, source analysis, custom rule-pack loading, or CLI policy/exit status.
- The relevant command-line flags, especially whether `--online`, `--allow-unlocked`, `--trust-local-input`, or custom rule packs were used.
- Operating system and relevant external-tool versions.
- A minimal reproduction or proof of concept.
- Expected and observed behavior.
- Security impact and required preconditions.
- Whether the report or reproduction contains sensitive data.

Do not test against systems or data you do not own or have permission to use. Avoid destructive testing and redact credentials, tokens, personal data, and proprietary source. Generated reports may contain absolute paths, dependency URLs, source excerpts, and secrets present in scanned code; treat them as sensitive.

Maintainers will acknowledge receipt when the report is reviewed, investigate impact, coordinate a fix and disclosure timeline, and credit reporters who request it. Response times are best effort until the project publishes a formal service-level objective.

## Maintainer release process

Before publishing a release, maintainers should run the complete checklist in [`docs/SECURITY_MODEL.md`](docs/SECURITY_MODEL.md), including `cargo audit` against the committed lockfile and the locked CI-equivalent format, Clippy, test, and release-build commands. Review every dependency change and triage every audit advisory; do not silently suppress an advisory. Build signed artifacts and checksums from a clean, pinned environment, and record security fixes in the changelog and release notes.

The CI dependency-audit job is a merge gate, not a substitute for release review. A release must not be cut from a failed or bypassed audit, and generated reports or test fixtures must not contain credentials or other sensitive data.

## Disclosure and advisories

Please allow maintainers a reasonable opportunity to release a fix before public disclosure. Confirmed vulnerabilities should be documented through a repository security advisory and release notes. Dependency advisories detected by `cargo audit` are triaged under the same process.
