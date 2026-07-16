# Supported platforms and compatibility policy

## Developer preview

| Surface | Supported baseline | Failure policy |
| --- | --- | --- |
| npm behavior reference | npm 11.12.1, canary against latest npm 11 | Uncovered workflows are documented; no silent npm fallback |
| Node.js | Node 22.14+ and 24.x in evidence workflows | Unsupported runtimes fail before package execution |
| Linux | Ubuntu 24.04 strict native containment; Ubuntu 22.04 fail-closed capability evidence | Missing Landlock/seccomp/bubblewrap controls deny strict execution |
| macOS | Apple Silicon and x86-64 CLI; explicitly acknowledged Node permission mode | Agent/auto execution denies when native containment is unavailable unless policy passes `--allow-degraded-sandbox`. For strong execution containment, use a Linux strict runner; Oath does not treat deprecated `sandbox-exec`/Seatbelt as sufficient proof. |
| Windows | Server 2022/2025 containment evidence; x86-64 and ARM64 release builds | Missing AppContainer, token, ACL, or Job Object controls deny strict execution |
| Registry | PostgreSQL 17 plus local, S3/R2, or GCS object storage | Readiness fails on unavailable PostgreSQL or object storage |

The executable behavioral matrix contains 100 named command/state cases derived
from ten reviewed npm behavior fixtures, two commands, and five execution
modes. Independent external review of all 100 remains a GA evidence gate. A
workflow is supported only after npm and Oath produce the same exit status,
lock snapshot, and materialized tree, or a reviewed security divergence is
documented. Generated repetitions do not increase the independent-workflow
denominator.

## Classifications

- **Fail closed:** integrity ambiguity, unsupported strict sandbox, denied
  server publish verdict, invalid schema/signature, private-tenant auth failure.
- **Explicit compatibility mode:** a user passes `--allow-degraded-sandbox` for
  documented Node permission isolation and the signed assessment records the
  degraded boundary.
- **Planned incompatibility:** the workflow is outside the published contract;
  Oath reports the limitation and does not silently invoke npm.

The GA matrix is frozen at release-candidate cut and can only grow in patch
releases. Removing a supported platform or workflow requires a major release.
