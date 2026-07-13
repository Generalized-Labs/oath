# Oath release-complete plan

Oath reaches general availability only when the complete chain is proven:

```text
publish -> verify -> registry/CDN -> install/exec -> revoke -> audit/replay
```

Until every GA gate below passes, releases must be labeled developer preview or
private beta, never a production npm replacement.

## Product invariants

1. Supported npm projects behave identically under the pinned npm reference.
2. Every artifact is identity- and integrity-verified before linking or execution.
3. Package code is assessed before lifecycle hooks or binaries execute.
4. Agents receive versioned, noninteractive decisions with stable reason codes.
5. Publishing is staged, scanned, signed, approved, and logged before promotion.
6. Revocation stops new resolution without destroying reproducible locked builds.
7. Assessments and registry mutations are independently replayable and verifiable.
8. Private packages receive the same evidence and enforcement as public packages.

## Phase 1: trusted CLI

- Complete npm 11 differential coverage for resolution, fetching, lockfiles,
  workspaces, peers, aliases, overrides, scripts, shims, auth, offline behavior,
  failures, and Windows paths.
- Make installs transactional: stage, verify, atomically promote, retain the old
  layout until commit, and recover or roll back interrupted operations.
- Complete `ExecAssessment`: exact binary, publisher history, version diff,
  provenance, sizes, capabilities, findings, limitations, policy, approval, and
  effective sandbox grants.
- Bind approvals to package identity, integrity, capabilities, policy, and backend.
- Finish Linux namespaces, `no_new_privs`, resource limits, seccomp, Landlock,
  descriptor closing, environment filtering, and adversarial escape tests.
- Implement Windows path/shim/locking parity plus restricted tokens, Job Objects,
  ACL workspaces, process-tree termination, and explicit AppContainer degradation.

Exit gate: required compatibility fixtures pass on Linux, macOS, and Windows;
there are no successful sandbox escapes and no unexplained behavior differences.

## Phase 2: safe publishing

Implement `pack -> inspect -> scan -> attest -> stage -> approve -> promote`.
Every staged release includes an exact file manifest, secret scan, previous-version
diff, capability change, lifecycle change, SBOM, provenance, dependency assessment,
signature, and versioned `PublishAssessment`. Promotion changes metadata pointers;
it never mutates artifacts.

Exit gate: a release can be staged, independently inspected, approved, promoted,
and rejected without a direct-publish bypass.

## Phase 3: registry, metadata, and private packages

- PostgreSQL owns organizations, identities, namespace ownership, versions,
  channels, policy, revocation state, approvals, billing, and audit state.
- Content-addressed object storage plus CDN owns tarballs, source snapshots, SBOMs,
  provenance, assessments, diffs, and log batches.
- Expose npm-compatible packuments, tarballs, dist-tags, auth, scoped routing, and
  immutable version identity.
- Metadata includes publisher/ownership history, age, downloads, source, license,
  provenance, signatures, hooks, capabilities, native/obfuscation status, risk,
  limitations, revocation state, and transparency proof.
- Private registries support OIDC/SSO, roles, service accounts, short-lived tokens,
  policy, audit export, retention, mirrors, air-gap bundles, and explicit precedence.

Exit gate: install, exec, and publish work completely against an Oath registry.

## Phase 4: revocation and transparency

- States: active, deprecated, quarantined, revoked-for-resolution, admin-blocked.
- Revoked versions remain immutable; dist-tags roll back to the last eligible
  version and signed tombstones explain actor, time, reason, and replacement.
- New resolution skips revoked versions. Locked builds may retrieve them only under
  policy; confirmed malware remains denied without an emergency override.
- Replace unsigned JSONL trust with hash-chained local records and a public Merkle
  log supporting signed tree heads, inclusion/consistency proofs, witnesses, and
  immutable checkpoints.
- Reproduce decisions from artifact, scanner, rule-bundle, metadata, and policy
  digests. AI evidence records model/input/output provenance but does not silently
  override deterministic policy.

Exit gate: rollback propagates within the SLO and all state transitions verify.

## Phase 5: evidence and business beta

### Technical GA gates

- Compatibility: a reviewed independent behavioral specification for every
  supported workflow slice, >=500 generated stress executions, >=100 pinned real
  projects, required workflows at 100%, and zero unexplained graph/content/
  lifecycle/shim/exit-code differences. Generated repetitions never count as
  independent workflow coverage.
- Detection: >=98% known-malware recall, >=95% private adversarial recall, <=0.5%
  clean-corpus false positives, and 100% block for secret-plus-exfiltration cases.
- Sandbox: zero escapes, secret leaks, outside writes, unauthorized connections, or
  child-policy bypasses on supported operating systems.
- Performance: warm install no slower than npm at p95; cold install <=20% slower
  with scanning; cached assessment <100 ms p95; cached exec decision <2 s p95.
- Service: metadata <150 ms p95, tarball availability >=99.95%, control plane
  >=99.9%, revocation propagation <60 s p95, RPO <=5 min, RTO <=60 min.
- Evidence always publishes raw artifacts, harness/rule versions, hardware, sample
  sizes, confidence intervals, known limitations, and reproducible commands.

### Commercial GA gates

- 50 design partners; 20 teams active in CI; 10 teams using private packages.
- 10,000 weekly exec assessments; >=40% second-week retention.
- >=25% activated-team rate and >=10% activated free-to-paid conversion.
- >=70% hosted-assessment gross margin and <5% monthly paid logo churn.
- At least five documented cases where Oath prevented or surfaced material risk.

### Packaging

- Community: open CLI, public installs, local scanning/exec/transparency.
- Pro: hosted assessments, private packages, CI policy, 30-day audit history.
- Team: SSO, organization policy, hosted private registry, approval workflows,
  exports, alerts, analytics, and one-year retention.
- Enterprise: SCIM, custom retention, CMK/storage, regions, SLA, air-gap support,
  policy packs, security review support, and incident response.

## GA release checklist

- All mandatory gates green with immutable evidence artifacts.
- Independent security review has no unresolved critical findings.
- macOS, Linux, and Windows binaries are signed and checksum-verified.
- Registry/CDN backup, restore, failover, revocation, and split-view drills pass.
- Status page, support, terms, privacy, DPA, incident response, and billing are live.
- Ten design partners confirm replacement of their existing workflow.
- Every launch claim maps to a current public evidence artifact.
