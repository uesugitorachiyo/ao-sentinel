# AO Sentinel Monitoring

## Monitor Cycle

AO Sentinel v0.1 does not create a resident daemon. The `watch dry-run` command
simulates bounded monitor cycles and writes a cycle ledger under `tmp/`.

Each cycle performs:

1. target validation;
2. baseline validation;
3. safety scan;
4. regression suite run;
5. baseline comparison;
6. verdict evaluation;
7. optional hold packet;
8. optional incident packet;
9. public report rendering.

## Signals

| Signal | Source | Blocks when |
| --- | --- | --- |
| `public_safety` | safety scan | findings count is non-zero or finding values are unredacted |
| `regression` | regression diff | failed cases, missing cases, or exceeded duration budget |
| `baseline_freshness` | baseline contract | `expires_at_utc` is in the past |
| `contract_drift` | contract fingerprints | expected schema or fixture digest changed |
| `target_policy` | target contract | live mutation requested or unknown platform matrix |
| `readiness_decay` | verdict history | prior clear state becomes hold or incident |

## Severity

| Severity | Meaning |
| --- | --- |
| `critical` | Must hold promotion and create incident packet. |
| `high` | Must hold promotion; incident packet may be omitted when rollback is not recommended. |
| `medium` | Report and require operator follow-up before release. |
| `low` | Report only. |

## Verdict Semantics

- `clear`: no blockers, no safety findings, no regression failures.
- `hold`: promotion must stop, but rollback is not yet recommended.
- `incident`: promotion must stop and active-stack rollback or investigation is recommended.

## Promoter Hold Semantics

AO Sentinel emits a promoter hold when:

- safety scan fails;
- regression diff fails;
- baseline is stale;
- target requests live mutation;
- contract drift is critical;
- incident packet is created.

The hold packet is machine-readable and contains no private prompts, local
absolute paths, or unredacted evidence.
