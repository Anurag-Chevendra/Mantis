# Mantis

Mantis reads a project's lockfiles and lists every npm package version it pins. It can then check those versions against [Cohen](https://cohen.snappyfeet.org), which installs and imports each package in a disposable sandbox and records what it actually does.

Mantis is built to be safe to run on code you do not trust and easy to approve in a regulated company:

* **It never runs a package manager.** It never installs, builds, executes or downloads anything. It reads lockfiles as text.
* **Works before the first install.** With a lockfile, `mantis deps` makes no network calls at all. With only a `package.json`, it works out the exact versions `npm install` would pick by reading public registry metadata, the same documents npm reads first. No tarball is downloaded and nothing is run. Private names are never looked up, and `--offline` turns lookups off entirely.
* **Checking sends package names and versions only.** No source code, file paths, environment variables, hostnames or lockfile contents. `mantis scan --dry-run` prints the exact request body before anything is sent.
* **Private code stays private.** Local, git, tarball and workspace packages, private scopes and anything resolved from a private registry are never sent. Each one is reported with the reason it was held back.
* **Login without pasting keys.** `mantis login` uses the OAuth 2.0 device flow, the same flow as `gh auth login` and the Azure CLI. The key lives in your operating system's credential store and `mantis logout` revokes it on the server.
* **One static binary**, two runtime dependencies, no telemetry. Releases are signed with Sigstore and ship with an SBOM and build provenance.

## Install

Download a binary from [Releases](https://github.com/Anurag-Chevendra/mantis/releases) and verify it (see [Verifying a release](#verifying-a-release)), or build from source with Go 1.24 or later:

```sh
go install github.com/Anurag-Chevendra/mantis/cmd/mantis@latest
```

## Quick start

```sh
# Every package that would be installed (works with or without a lockfile)
mantis deps

# Sign in once (opens the Cohen console in your browser)
mantis login

# Check the project; exit code 1 if anything needs review
mantis scan

# Same check, as a report in your browser
mantis scan --open
```

`--open` writes a single self contained HTML report (filterable table, review findings with links to their evidence, every held back package with its reason) and opens it in your default browser. The file loads nothing from the network: its Content Security Policy blocks every request and allows only its own inline script, pinned by hash. It is safe to attach to a ticket or email.

```
  MANTIS 0.1.0 · dependency check

  package-lock.json                  npm v3               812 packages
  apps/edge/pnpm-lock.yaml           pnpm v9.0            204 packages

  unique versions        923
  checkable              910  (public npm; only name@version is ever sent)
  held back               13  (git 2 · local 4 · private 7; never sent)

  checked                910 versions · 1.2s
  clean                  907
  review                   1
  no verdict yet           2  (--analyze queues them)

  REVIEW  example-postinstall-writer@0.4.1
          https://trail.snappyfeet.org/?p=example-postinstall-writer%400.4.1
          pinned in package-lock.json
```

## Supported lockfiles

| File | Package manager | Versions |
|---|---|---|
| `package-lock.json`, `npm-shrinkwrap.json` | npm | lockfile v1, v2, v3 |
| `pnpm-lock.yaml` | pnpm | v5.x, v6.0, v7 to v9 |
| `yarn.lock` | Yarn classic | v1 |
| `yarn.lock` | Yarn Berry | v2 and later (`__metadata` format) |
| `bun.lock` | Bun | text lockfile (Bun 1.2+). Binary `bun.lockb` is detected and reported; convert it with `bun install --save-text-lockfile` |

Mantis walks the given folder, skips `node_modules`, VCS folders and caches, and groups every `package.json` under the nearest lockfile above it. A `package.json` with no lockfile above it is resolved the way npm would resolve it: Mantis rebuilds npm's ideal tree from registry metadata (dist tag `latest` when it satisfies the range, otherwise the highest satisfying non deprecated version; reuse and nesting follow npm's placement rules; peer dependencies included). On real projects of 450 to 500 packages the result matched `npm install --package-lock-only` version for version. It is a prediction of what an install would fetch today, so the output is labelled `no lockfile` and a lockfile is still the way to make installs repeatable.

| Flag | Meaning |
|---|---|
| `--offline` | Never contact a registry. A `package.json` without a lockfile is skipped and reported |
| `--prod` | When resolving a `package.json`, leave out `devDependencies` |
| `--registry URL` | Registry used for resolution (default `https://registry.npmjs.org`; https only, no credentials are sent) |

Details per format, including aliases, patches, peer suffixes and git dependencies: [docs/lockfiles.md](docs/lockfiles.md).

## Commands

### `mantis deps [path]`

Lists every version that is pinned, or that would be installed. No network when a lockfile exists.

| Flag | Meaning |
|---|---|
| `--format text\|json\|cyclonedx\|html` | `json` is a stable schema (`schema_version: 1`); `cyclonedx` is a CycloneDX 1.5 SBOM with purls and SHA-512 hashes; `html` is the browser report |
| `--open` | Write the HTML report and open it in your browser |
| `--output FILE` | Write to a file instead of stdout |
| `--quiet` | List only, no summary |
| `--include-fixtures` | Also read lockfiles under `fixtures/`, `testdata/`, `examples/` |
| `--allow-custom-registry` | Treat packages from a non public registry host as checkable (see [Privacy rules](#privacy-rules)) |
| `--max-depth N` | Folder depth limit (default 24) |

### `mantis scan [path]`

Everything `deps` does, then checks every checkable version in batches of up to 5,000.

| Flag | Meaning |
|---|---|
| `--dry-run` | Print the exact request body and stop. No network, no login needed |
| `--fail-on review\|none` | Exit 1 when anything needs review (default), or never |
| `--analyze` | Queue a deep analysis for versions with no verdict yet. Uses your monthly allowance and asks first |
| `--yes` | Do not ask before queueing (CI). Without a terminal, `--analyze` requires `--yes` |
| `--format text\|json\|html`, `--output FILE` | JSON report includes the inventory and the check result; `html` is the browser report |
| `--open` | Also write the HTML report and open it in your browser |
| `--project NAME` | Name shown in your console's scan history (default: folder name) |
| `--api URL` | API base URL |

### `mantis login`, `mantis logout`, `mantis whoami`

| Command | What it does |
|---|---|
| `mantis login` | Shows a link and a short code. You open the link, check the code matches, and approve. The new key is stored in the OS credential store |
| `mantis login --no-browser` | Never offers to open a browser; for SSH sessions |
| `mantis login --with-token < key.txt` | Store an existing key instead of using the browser |
| `mantis login --insecure-storage` | For machines with no keyring: store the key in a file readable only by you (`0600`) |
| `mantis logout` | Revokes the key in the console and deletes it locally. `--local-only` skips the revoke |
| `mantis whoami` | Plan, scopes and allowance of the key in use. Never prints the key |

### Exit codes

| Code | Meaning |
|---|---|
| 0 | Completed; nothing needs review |
| 1 | Completed; at least one package needs review |
| 2 | Usage or configuration error, or no lockfile or package.json found |
| 3 | Not logged in, or the key is invalid, expired or lacks a scope |
| 4 | API or console unreachable, or answered with an error |
| 5 | Internal error |

## CI

Create a key in the console, store it as a secret, and set `MANTIS_TOKEN`. A stored login is never needed in CI.

```yaml
# .github/workflows/dependencies.yml
on: [pull_request]
permissions:
  contents: read
jobs:
  mantis:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v7
      - name: Install Mantis
        run: go install github.com/Anurag-Chevendra/mantis/cmd/mantis@v0.1.0
      - name: Check dependencies
        env:
          MANTIS_TOKEN: ${{ secrets.MANTIS_TOKEN }}
        run: mantis scan --format json --output mantis-report.json
```

## Privacy rules

A package is sent only when all of these hold:

1. It comes from a registry (not `file:`, `link:`, `workspace:`, git or a bare tarball URL).
2. Its registry host is public npm (`registry.npmjs.org`, `registry.yarnpkg.com`), or the lockfile does not say and the project's default registry is public.
3. Its scope is not mapped to a private registry in the project's `.npmrc` or `.yarnrc.yml`.
4. It is not excluded in `.mantis.yml`.
5. Its name and version are valid npm values.

Mantis reads only the `registry` lines of `.npmrc` and `.yarnrc.yml` in the project. It never parses auth lines and never reads your home directory's config.

If your company proxies public npm through Artifactory, Nexus or similar, every package resolves from that host and is held back by default. Pass `--allow-custom-registry`, or set it in `.mantis.yml`, once you have confirmed the mirror only serves public packages. Private scopes stay private either way.

### `.mantis.yml`

Optional, at the root of the scan:

```yaml
project: checkout-service
fail_on: review              # or none
allow_custom_registry: false
public_registries:           # extra hosts that serve public npm
  - npm.mirror.example.com
exclude:
  scopes: ["@acme"]          # never sent
  packages: ["acme-*"]       # path.Match globs, never sent
```

Unknown keys are an error, so a typo cannot silently disable a rule.

## Environment

| Variable | Meaning |
|---|---|
| `MANTIS_TOKEN` | API key; overrides the stored login |
| `MANTIS_API_URL` | API base URL, default `https://api.snappyfeet.org` |
| `MANTIS_CONSOLE_URL` | Console base URL, default `https://console.snappyfeet.org` |
| `HTTPS_PROXY`, `NO_PROXY` | Honoured for every request |
| `NO_COLOR` | Disables color |

TLS uses the operating system's trust store, so corporate inspection CAs installed on the machine work without extra flags. Plain `http` is refused for every host except loopback.

## Verifying a release

Each release publishes `checksums.txt`, a Sigstore signature and certificate for it, an SPDX SBOM per archive, and GitHub build provenance.

```sh
cosign verify-blob \
  --certificate checksums.txt.pem --signature checksums.txt.sig \
  --certificate-identity-regexp '^https://github.com/Anurag-Chevendra/mantis/\.github/workflows/release\.yml@refs/tags/v' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  checksums.txt
sha256sum --ignore-missing -c checksums.txt

gh attestation verify mantis_0.1.0_linux_amd64.tar.gz --repo Anurag-Chevendra/mantis
```

## Documentation

* [docs/security-model.md](docs/security-model.md): what is read, sent and stored, and the threat model
* [docs/console-protocol.md](docs/console-protocol.md): the device login and API contract a Cohen console implements
* [docs/lockfiles.md](docs/lockfiles.md): parsing rules per format
* [SECURITY.md](SECURITY.md): reporting a vulnerability
* [CONTRIBUTING.md](CONTRIBUTING.md)

## License

Apache License 2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE).
