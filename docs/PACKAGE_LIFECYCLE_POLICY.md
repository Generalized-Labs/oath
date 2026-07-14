# Package lifecycle policy

- A package name has one immutable owning organization. A published
  name/version pair is never reused and its bytes are never replaced.
- Staged artifacts are not resolvable. Rejection is permanent for that stage;
  a corrected release uses a new stage and, when required, a new version.
- Deprecation leaves bytes resolvable and adds a warning. Revocation or
  quarantine removes the version from active metadata, writes a signed
  tombstone, and moves affected tags to the highest remaining active semantic
  version.
- Confirmed malware, credential exposure, legal orders, ownership compromise,
  or severe integrity failures may trigger emergency quarantine. Ordinary
  maintainer mistakes use deprecation or revocation, never byte replacement.
- Appeals preserve the original tombstone and add a new signed decision. Audit
  history is append-only even when package availability is restored.

Every emergency action records actor, reason, timestamps, package digest,
before/after tags, checkpoint, propagation measurement, and customer notices.
