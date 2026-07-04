# Security Policy

oath is a security-focused package manager, so security reports get priority.

## Supported Versions

The latest released version is supported. Older releases may receive fixes when
the issue is severe and the patch can be applied safely.

## Reporting a Vulnerability

Please do not open a public issue for an active vulnerability.

Email security@generalizedlabs.com with:

- affected oath version or commit
- operating system and architecture
- a minimal reproduction or proof of concept
- whether the issue is already public

We aim to acknowledge reports within 3 business days and will coordinate a fix,
release, and credit before public disclosure.

## Scope

In scope:

- tarball extraction, integrity verification, and store/linker path safety
- install script handling and policy bypasses
- malicious package analysis and `oath exec` decision gates
- release artifacts, installer checksums, and CI/CD supply chain issues

Out of scope:

- denial-of-service-only reports without a concrete security impact
- vulnerabilities in third-party registries or packages unless oath makes them worse
- social engineering or physical attacks

## Disclosure

After a fix is released, we will publish a security advisory when the impact
warrants one. Please give users time to upgrade before sharing exploit details.
