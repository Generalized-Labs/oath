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
4. Run `project-corpus-refresh.yml` before the complete evidence workflow.
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
