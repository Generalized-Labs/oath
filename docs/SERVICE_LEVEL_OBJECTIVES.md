# Service level objectives

Oath Cloud is not yet covered by a GA SLA. These objectives define the required
60-day production-beta evidence window before an SLA can become effective.

| Indicator | GA objective | Measurement |
| --- | ---: | --- |
| Public/private metadata availability | 99.95% | Valid requests returning non-5xx per region |
| Tarball availability | 99.95% | Authorized immutable object reads returning complete bytes |
| Control-plane availability | 99.9% | Auth, stage, approve, revoke, and policy requests returning non-5xx |
| Metadata latency | <150 ms p95 | Edge-to-service duration, excluding client network |
| Revocation propagation | <60 s p95 | Commit timestamp to every active metadata/cache region |
| Recovery point | <=5 min | Latest restorable committed control-plane transaction |
| Recovery time | <=60 min | Incident declaration to validated service restoration |

Scheduled maintenance, customer-caused invalid requests, and documented force
majeure events are reported separately but never removed from raw telemetry.
The public status report includes numerator, denominator, excluded requests,
regional breakdown, and error-budget consumption.
