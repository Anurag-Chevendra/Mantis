# Lockfile parsing rules

Each parser returns `name`, `version`, `source` (`registry`, `git`, `tarball`, `local`), and when known the resolved URL, registry host, SRI integrity, dev and optional flags. Duplicate `name@version` entries are merged. Test fixtures in `testdata/` were produced by the real package managers (npm 10, pnpm 10, Yarn 1.22, Yarn 4, Bun 1.2) except where marked handwritten.

## npm: `package-lock.json`, `npm-shrinkwrap.json`

* v2 and v3: the `packages` map is authoritative. A key's name is the text after the last `node_modules/`. An entry's own `name` field wins (npm aliases: `"lod": "npm:lodash@4"` installs at `node_modules/lod` with `name: lodash`).
* Entries without `node_modules/` are workspace source folders and are skipped. `link: true` entries become `local` packages, versioned from their target folder.
* v1: the nested `dependencies` tree is walked. `version: "npm:real@1.2.3"` is an alias; git specs and `file:` paths live in `version`.
* `dev` and `devOptional` mark dev packages; `optional` and `devOptional` mark optional ones.
* Source comes from `resolved`: `git+ssh://` and GitHub codeload URLs are `git`, registry tarball paths (`/<name>/-/<file>.tgz`) are `registry`, other URLs are `tarball`.

## pnpm: `pnpm-lock.yaml`

| lockfileVersion | Key format |
|---|---|
| 5.x (handwritten fixture) | `/name/1.2.3`, `/@scope/name/1.2.3_peer+suffix` |
| 6.0 (handwritten fixture) | `/name@1.2.3`, `/@scope/name@1.2.3(peer@1.0.0)` |
| 7 to 9 | `name@1.2.3` |

* Peer suffixes (`_…` in v5, `(…)` in v6+) are removed from the version.
* Explicit `name` and `version` fields win; non registry entries use them.
* `resolution.tarball` gives the registry host or marks a tarball; `resolution.type: git` or `repo` marks git; `type: directory` and `file:`/`link:` mark local.
* `dev` is read where the lockfile records it (v5 and v6). v7+ dropped the field, so `dev` is unknown there.
* pnpm does not record the registry for registry packages. The project's `.npmrc` decides (see the privacy rules in the README).

## Yarn classic: `yarn.lock` v1

* Header lines list one or more specs: `"lodash@^4.17.0", "lodash@^4.17.21":`. The name is taken from the first spec; `alias@npm:real@^1` resolves to `real`.
* `version`, `resolved` (fragment after `#` removed) and `integrity` are read. Nested `dependencies:` blocks hold ranges, not pins, and are ignored.
* `file:`/`link:` specs are local; `github:` and git URLs are git.

## Yarn Berry: `yarn.lock` with `__metadata`

Parsed as YAML. The `resolution` field decides:

| Resolution | Source |
|---|---|
| `name@npm:1.2.3` | registry |
| `name@patch:name@npm%3A1.2.3#…` | registry, the base package (the patch is a local diff on top) |
| `workspace:`, `portal:`, `link:`, `file:`, `exec:` | local |
| `git:`, `git+ssh:`, `git+https:`, `github:` and git URLs | git |
| other `http(s)` URLs | tarball |

Berry's `checksum` is Yarn's own cache hash, not an npm SRI string, so it is not reported as integrity.

## Bun: `bun.lock`

* JSON with trailing commas. Element 0 of each `packages` entry is `name@version-or-spec`; element 1 is the registry URL (`""` for the default); the last string element starting with `sha` is the SRI.
* `workspace:`, `file:`, `link:` are local; `github:` and `git+` are git; URLs are classified like npm's `resolved`.
* The binary `bun.lockb` is not parsed. Mantis reports it and suggests `bun install --save-text-lockfile`.

## No lockfile: `package.json` only

Resolved from registry metadata by simulating npm's ideal tree builder (`internal/resolve/tree.go`):

* Nodes are processed in npm's queue order: depth first, then path compared the way npm does.
* Version choice: dist tag `latest` if it satisfies the range, otherwise the highest satisfying version that is not deprecated (npm-pick-manifest).
* Placement walks up from the dependent and stops at the first conflict; an existing copy is kept when it satisfies, replaced only by a newer version that satisfies every dependent, otherwise the new version is nested.
* Peer dependencies are installed; optional peers only when the name is already in the tree and does not satisfy.
* `overrides` with plain string values, `npm:` aliases and npm workspaces are honoured. Nested overrides are reported, not applied.
* Ranges follow npm's semver exactly; `internal/semver` is checked against npm's own semver on a corpus of 383 ranges.

Reported with format `package.json` and labelled `no lockfile`. Packages that cannot be found are reported as unresolved with the reason.
