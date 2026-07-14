# Supported platforms and compatibility policy

## Developer preview

| Surface | Supported baseline | Failure policy |
| --- | --- | --- |
| npm behavior reference | npm 11.12.1, canary against latest npm 11 | Uncovered workflows are documented; no silent npm fallback |
| Node.js | Node 22.14+ and 24.x in evidence workflows | Unsupported runtimes fail before package execution |
| Linux | Ubuntu 24.04 strict native containment; Ubuntu 22.04 fail-closed capability evidence | Missing Landlock/seccomp/bubblewrap controls deny strict execution |
| macOS | Apple Silicon and x86-64 CLI; compatibility sandbox mode | Native OS process containment is not yet a GA claim |
| Windows | Server 2022/2025 containment evidence; x86-64 and ARM64 release builds | Missing AppContainer, token, ACL, or Job Object controls deny strict execution |
| Registry | PostgreSQL 17 plus local, S3/R2, or GCS object storage | Readiness fails on unavailable PostgreSQL or object storage |

The reviewed behavioral contract currently contains ten named workflows. A
workflow is supported only after npm and Oath produce the same exit status,
lock snapshot, and materialized tree, or a reviewed security divergence is
documented. Generated repetitions do not increase the independent-workflow
denominator.

## Classifications

- **Fail closed:** integrity ambiguity, unsupported strict sandbox, denied
  server publish verdict, invalid schema/signature, private-tenant auth failure.
- **Explicit compatibility mode:** a user requests a documented weaker sandbox
  and the assessment records the degraded boundary.
- **Planned incompatibility:** the workflow is outside the published contract;
  Oath reports the limitation and does not silently invoke npm.

The GA matrix is frozen at release-candidate cut and can only grow in patch
releases. Removing a supported platform or workflow requires a major release.
