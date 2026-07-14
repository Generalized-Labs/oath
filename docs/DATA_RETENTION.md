# Data retention and deletion

Proposed hosted-service defaults are 30 days for request logs, 90 days for
detailed assessment evidence, and one year for organization audit events.
These windows are not yet enforced by automated retention jobs and therefore
remain a GA blocker. Immutable package artifacts, signed release records,
revocation tombstones, billing records, and transparency checkpoints are
intended to remain for the package/account lifecycle or longer where law
requires.

Secrets and package source must be excluded from telemetry. Logs use
organization, package, artifact, policy, and request identifiers needed for
audit; access must be role-restricted and recorded. Managed deployments must
prove encryption in transit and at rest for private package bytes before the
hosted service can satisfy the GA gate; the local development backend is not
evidence of that control.

Account deletion removes active credentials, memberships, invitations, and
non-required personal data. It does not erase immutable package history,
security evidence, tombstones, or financial records where erasure would break
integrity or a legal obligation. GA requires counsel-approved Privacy Policy,
DPA, subprocessor list, regional transfer terms, and customer-facing deletion
workflow; this engineering policy is not a substitute for those documents.
