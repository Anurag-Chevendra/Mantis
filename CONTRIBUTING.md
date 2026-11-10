# Contributing

Thanks for helping. Issues and pull requests are welcome.

## Ground rules

* Mantis must never execute, install or download anything from a scanned project. Changes that would are out of scope.
* Anything that changes what is sent over the network, read from disk or stored needs a matching update to [docs/security-model.md](docs/security-model.md) and a test that proves it.
* New runtime dependencies need a strong reason. Prefer the standard library.
* The JSON report schema (`schema_version`) and exit codes are a public interface. Breaking changes need a major version.

## Development

```sh
go test -race ./...                          # unit and end to end tests
go test -run=^$ -fuzz=FuzzParse -fuzztime=60s ./internal/lockfile/
gofmt -l . && go vet ./...
go run ./cmd/mantis deps testdata/npm-v3
```

## Adding a lockfile format or fixing a parser

1. Generate a real lockfile with the package manager (use `--ignore-scripts`) and add it under `testdata/<format>/` with its `package.json`.
2. Add expectations to `internal/lockfile/lockfile_test.go`.
3. Document the rules in `docs/lockfiles.md`.

## Commits and pull requests

* One logical change per pull request, with a test.
* Sign off your commits (`git commit -s`) to certify the [Developer Certificate of Origin](https://developercertificate.org/).
* By contributing you agree your work is licensed under the Apache License 2.0.

## Conduct

This project follows the [Contributor Covenant 2.1](https://www.contributor-covenant.org/version/2/1/code_of_conduct/). See [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md).
