# 300 GB compatibility runner contract

The real-project corpus requires runners labeled `oath-ubuntu-300gb`. There is
deliberately no small-disk fallback: a missing runner must leave the job queued
rather than turn an infrastructure shortage into a skipped compatibility claim.

## Required runner shape

- Ubuntu 24.04 x86-64
- 8 vCPU or more
- 32 GB RAM or more
- 300 GB ephemeral SSD, at least 280 GiB visible capacity, and at least 200 GiB
  free at job start (the image and tool cache consume part of the disk)
- one job per runner; destroy or reimage after every job
- outbound HTTPS to GitHub and configured npm registries
- no organization or registry write credentials
- lifecycle scripts disabled during corpus qualification

## Preferred provisioning order

1. Create a GitHub organization larger-runner group named `oath-corpus`.
2. Add an Ubuntu runner with the custom label `oath-ubuntu-300gb`.
3. Restrict the group to `Generalized-Labs/oath`.
4. Enable automatic scaling to 20 runners with zero idle runners.
5. Set a hard monthly spend limit and alert at 50%, 75%, and 90%.
6. Run `project-corpus-refresh.yml` before the complete evidence workflow.

If the GitHub plan does not support managed larger runners, use ephemeral
self-hosted VMs registered through a GitHub App with one-time runner tokens.
The VM image and bootstrap digest must be written into every project result.

## Acceptance check

The runner pool is provisioned only when all 20 corpus shards start, each meets
the capacity and free-space floors above, and the generated evidence records
the runner image and hardware identity. Merely adding a YAML label does not
satisfy this contract.
