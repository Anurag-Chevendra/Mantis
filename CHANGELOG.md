# Changelog

All notable changes are documented here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added

* `mantis deps`: offline inventory from npm (lockfile v1 to v3, shrinkwrap), pnpm (v5 to v9), Yarn classic, Yarn Berry and Bun text lockfiles. Text, JSON (schema v1) and CycloneDX 1.5 output.
* `mantis scan`: bulk check against the Cohen API, privacy policy for private scopes and registries, `--dry-run`, `--analyze` with confirmation, stable exit codes.
* `mantis login` / `logout` / `whoami`: OAuth 2.0 device flow, OS keychain storage, server side revocation.
* `.mantis.yml` project policy.
* pnpm 11+ lockfiles with two YAML documents are read in full.
* Login polls survive dropped connections; quota errors (`daily_cap`, `allowance_spent`) fail fast instead of waiting out Retry-After.
* `scan --analyze` checks the key's scopes first; `--analyze --yes` sends one request; logging in again revokes this machine's previous key.
* * `scan --open` shows the report immediately and fills it in as results arrive; checks go in batches of 300 with progress and retry notices in the terminal.
* `scan` reads the bulk API's per package results: known malware with its OSV or npm source, versions not on npm, packages Cohen could not check (never shown as clean; exit 4 in CI), known vulnerabilities, queue position and estimated wait, and the monthly allowance.
* One run is one scan in the console (`X-Scan-Id`); Ctrl+C while watching offers to cancel the analyses that have not started.
* HTML report (`--format html`, `--open`) for `deps` and `scan`: self contained, no network, CSP pinned by hash.
* Projects with only a `package.json` are resolved before the first install: Mantis rebuilds npm's ideal tree from registry metadata (no tarballs, no scripts), with `--offline`, `--prod` and `--registry`. Private and excluded names are never looked up.
