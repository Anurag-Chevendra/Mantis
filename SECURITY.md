# Security policy

## Reporting a vulnerability

Please report privately. Do not open a public issue.

* GitHub: **Security** tab > **Report a vulnerability** (private advisory), or
* Email: contact@snappyfeet.org with "Mantis security" in the subject.

Include the version (`mantis version`), your OS, and steps or a lockfile that reproduces it.

You will get an acknowledgement within 3 working days and a status update at least every 7 days. Fixes are released as a patch version with a GitHub Security Advisory and, where applicable, a CVE. Reporters are credited unless they ask not to be.

## Supported versions

The latest minor release receives security fixes.

## Scope

In scope: anything that makes Mantis send data its documentation says it does not, store or print a credential unsafely, execute or fetch code from a scanned project, follow a redirect or proxy a key to another host, or crash on hostile input.

The Cohen service itself (console and API) has its own disclosure address: contact@snappyfeet.org.

How Mantis is meant to behave is described in [docs/security-model.md](docs/security-model.md).
