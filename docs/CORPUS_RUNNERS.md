# Large-disk compatibility runner contract

The real-project corpus runs on the approved Blacksmith label
`blacksmith-16vcpu-ubuntu-2404`. There is deliberately no small-disk fallback:
a missing runner must leave the job queued rather than turn an infrastructure
shortage into a skipped compatibility claim.

## Required runner shape

- Ubuntu 24.04 x86-64
- 16 vCPU
- 64 GB RAM
- 750 GB runner disk, at least 280 GiB visible capacity, and at least 200 GiB
  free at job start (the image and tool cache consume part of the disk)
- one job per runner; destroy or reimage after every job
- outbound HTTPS to GitHub and configured npm registries
- no organization or registry write credentials
- lifecycle scripts disabled during corpus qualification

## Provisioning and trust boundary

1. Keep the Blacksmith GitHub App restricted to `Generalized-Labs/oath`.
2. Use `blacksmith-16vcpu-ubuntu-2404`; do not silently select another label.
3. Set a hard monthly spend limit and alert at 50%, 75%, and 90%.
4. Run `project-corpus-refresh.yml` only when intentionally changing the pinned
   corpus. Review and commit its version-2 manifest and compressed lock bundle
   before running complete evidence.
5. Record the runner name, OS, architecture, total disk, free disk, shard, and
   workflow commit in the retained artifacts.

Blacksmith is a third-party execution environment. Corpus jobs receive the
checked-out repository and GitHub's job token under the declared workflow
permissions. They receive no organization, npm-publish, or private-registry
write credentials. Lifecycle scripts remain disabled during qualification.

## Acceptance check

The runner pool is accepted only when all 20 corpus shards start, each meets the
capacity and free-space floors above, and the generated evidence records runner
identity. Merely changing the YAML label does not satisfy this contract.

## Transport and checkout failures

The harness makes three attempts for GitHub network operations by default,
removes partial clone destinations between clone attempts, and applies bounded
backoff. Local checkouts have a separate five-minute timeout so repositories
with large working trees are not mislabeled as network failures. These defaults
can be changed with `OATH_GIT_NETWORK_ATTEMPTS`, `OATH_GIT_RETRY_DELAY_MS`,
`OATH_GIT_NETWORK_TIMEOUT_MS`, and `OATH_GIT_CHECKOUT_TIMEOUT_MS`.

Exhausted clone, fetch, or reference retries remain evidence failures. The
artifact records the phase, attempt count, and process error; infrastructure
loss must be rerun and may never be counted as a compatibility pass.

## Immutable dependency inputs

`tests/compat/projects.lock.json` binds every source commit to an exact,
checked-in gzip-compressed npm lockfile under `tests/compat/project-locks/`.
Corpus execution verifies the decompressed SHA-256 before either installer
runs and gives npm and Oath the same bytes. The real-project contract compares
ordinary `npm install` materialization. npm may rewrite only the lockfile's
paired `devOptional: true` classification to `dev: true`; the harness emits
every changed JSON path and rejects all other mutations. Versions, resolved
URLs, integrity, dependency edges, package contents, and installed paths must
remain exact. Evidence runs never regenerate the pinned input from mutable
registry metadata. A corpus refresh emits new lock artifacts, validates them
through the same install path, and makes them release inputs only through a
reviewed source change.
