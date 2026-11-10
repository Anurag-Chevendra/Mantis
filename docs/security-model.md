# Security model

This page is written for the person who has to approve Mantis inside an organisation. Every claim here is enforced in code and covered by a test; the file and test names are given so you can check.

## What Mantis reads

| Read | Why | Where |
|---|---|---|
| Directory listings under the path you give | Find lockfiles | `internal/discover` |
| `package-lock.json`, `npm-shrinkwrap.json`, `pnpm-lock.yaml`, `yarn.lock`, `bun.lock` | The pinned versions | `internal/lockfile` |
| `.mantis.yml` at the scan root | Your policy | `internal/config` |
| `registry` lines of the project's `.npmrc` and `.yarnrc.yml` | Recognise private scopes and registries | `internal/config/config.go` `readNpmrc` |
| The stored login, from the OS credential store | Authenticate | `internal/auth/store.go` |

It does not follow symlinks, does not descend into `node_modules`, does not read files in your home directory other than its own credential, and refuses lockfiles over 256 MB. Auth lines in `.npmrc` (`//host/:_authToken=...`) are skipped before parsing (`TestReadRegistriesIgnoresAuth`).

## What Mantis sends

`mantis deps` sends nothing. It opens no sockets.

`mantis scan` sends, per batch of at most 5,000:

```json
{"versions": ["lodash@4.17.21", "debug@2.6.9"], "queue_unknown": false}
```

plus the headers `Authorization: Bearer <key>`, `User-Agent: mantis/<version>`, `X-Client: mantis/<version>`, `X-Project: <project name>` and a random `Idempotency-Key`. Nothing else. Run `mantis scan --dry-run` to see the exact body for your project without sending it (`TestDryRunMakesNoRequest`).

The project name defaults to the folder name. Set `project:` in `.mantis.yml` or pass `--project` if folder names are sensitive.

Packages that are never sent: local (`file:`, `link:`, `portal:`, workspace members), git, bare tarball URLs, scopes mapped to a private registry, packages resolved from a non public registry host unless you opt in, names excluded in `.mantis.yml`, and anything that is not a valid npm name and version (`internal/policy`, `TestDecide`, `TestCustomRegistryOptIn`).

`mantis login` additionally sends the device name it shows you (`Mantis on <hostname>` unless you pass `--device-name`) so you can recognise the key on your Keys page.

## Network

* Hosts contacted: the API (`api.snappyfeet.org`) and, for login and logout only, the console (`console.snappyfeet.org`). Both overridable for self hosted deployments.
* Only when a `package.json` has no lockfile: the public npm registry (`registry.npmjs.org`, or `--registry`), for the abbreviated metadata document of each public package name, exactly as `npm install` would request it first. No credentials and no `.npmrc` tokens are sent, no tarball is downloaded, nothing is written to disk. Names that would be held back (private scopes, private registries, names excluded in `.mantis.yml`) are never requested, because a lookup itself reveals that the name exists in your project (`TestHeldNamesAreNeverRequested`). `--offline` disables this entirely.
* HTTPS only, TLS 1.2 minimum, operating system trust store. `http` is accepted only for loopback addresses (`TestValidateBaseURL`).
* Redirects to another host are refused, so the key can never be forwarded (`TestNoCrossHostRedirect`).
* `HTTPS_PROXY` and `NO_PROXY` are honoured.
* No telemetry, no update checks, no analytics.
* The HTML report (`--format html`, `--open`) is one file with no external resources. Its Content Security Policy is `default-src 'none'` with the inline style and script allowed only by SHA-256 hash, so opening it makes no request. Package names are untrusted input and are inserted only as text, never as markup (`TestHTMLIsSelfContainedAndPinned`). `--open` hands the file path to the platform opener (`open`, `xdg-open`, `rundll32 url.dll`) as a single argument, never through a shell.

## Login

`mantis login` implements the OAuth 2.0 Device Authorization Grant, RFC 8628.

1. Mantis asks the console for a device code and a short user code.
2. You open the console's own page in your own browser, sign in there (Google), and approve after checking the code matches the one in your terminal.
3. Mantis polls until you approve, then receives a normal API key scoped to `read queue`.
4. Mantis calls `GET /api/key` with it to confirm it works, then stores it.

Properties:

* Mantis never sees your password, your Google session or any browser cookie.
* Nothing listens on a local port. There is no loopback redirect for another local process to intercept.
* The verification link is checked to be HTTPS on the configured console host before it is shown, so a misbehaving server cannot send you to a look alike domain (`TestRejectsForeignVerificationURL`).
* A browser is opened only when you press Enter, and the URL is passed to the OS opener as one argument, never through a shell.
* If the key cannot be stored, it is revoked immediately rather than left orphaned on your account.

## Storage

| Where | When |
|---|---|
| macOS Keychain, Windows Credential Manager, Linux Secret Service | Default |
| `<user config dir>/mantis/credentials.json`, mode `0600` in a `0700` folder, written atomically | Only with `--insecure-storage`. Mantis refuses to read it if its permissions are widened (`TestFileStore`) |
| Nowhere | `MANTIS_TOKEN` is used in memory only |

`mantis logout` revokes the key on the server (RFC 7009) and deletes it locally. The key is never printed; `whoami` shows plan and scopes only.

## Spending

Checking a version that already has a verdict is free. Starting a new deep analysis spends one from the monthly allowance, and Mantis does it only with `--analyze`. Interactively it asks first and states the number; without a terminal it refuses unless `--yes` is also given (`TestLoginScanWhoamiLogout`). Every batch carries an idempotency key that is reused on retry, so a network retry never spends twice (`TestCheckBatchesAndRetries`).

## Untrusted input

Lockfiles in a repository you are reviewing may be hostile. Mantis treats them as data:

* No code from the project is executed, ever.
* Parsers are fuzz tested (`FuzzParse`) and never panic on malformed input.
* Every name and version is validated before it can be sent; a crafted entry cannot inject into the request or a header (`TestValidName`, `TestSanitizeHeader`).
* Paths in reports are relative to the scan root, so a shared report does not reveal your home directory (`TestDepsJSON`).

## Supply chain of Mantis itself

* Two direct dependencies: `github.com/goccy/go-yaml` and `github.com/zalando/go-keyring`. Both pinned in `go.sum`.
* Release binaries are built with `CGO_ENABLED=0 -trimpath` in GitHub Actions, signed keyless with Sigstore cosign, and published with an SPDX SBOM per archive and SLSA build provenance. See the README for verification.
* Every GitHub Action is pinned to a full commit SHA; Dependabot proposes updates.
* `govulncheck` and CodeQL run on every pull request.
