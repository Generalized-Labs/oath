# Oath design-partner program

## First cohort

Recruit five teams with one primary workflow each:

1. an AI coding agent that executes npm tools;
2. a JavaScript monorepo using npm workspaces;
3. a security-sensitive CLI or CI platform;
4. a team with private scoped packages;
5. a maintainer who publishes packages from CI.

Every participant receives a named support owner, a pinned Oath build, an exit
path back to npm, and a written compatibility/security matrix. Participation
does not imply that Oath is GA or that scanning proves safety.

## Qualification interview

- Which package commands run in CI and on developer machines?
- Which commands execute packages that are not already reviewed?
- Which secrets, files, and networks are reachable from those commands?
- Which npm incompatibility would force immediate rollback?
- What evidence would justify approving or denying an unfamiliar package?
- Can the team share anonymized decision, failure, and performance data?

## Success criteria

- five accepted partners and three activated integrations;
- at least 100 real `oath exec --dry-run --json` assessments per partner;
- no silent compatibility fallback;
- every abstention, approval, denial, and sandbox backend is recorded;
- a weekly report includes denominators, failures, false positives, and latency.

The public application entry point is the `design-partner.yml` GitHub issue form.
Outbound invitations require a maintainer-approved target list and sender identity.
