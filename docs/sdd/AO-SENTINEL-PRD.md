# AO Sentinel PRD

## Product Summary

AO Sentinel is the safety and regression monitor for the AO orchestration
framework. It runs after AO Promoter has a candidate or active stack to watch.
It continuously asks one question: is the current AO stack still safe,
behaviorally stable, and promotion-worthy compared with the trusted baseline?

## Users And Jobs

| User | Job |
| --- | --- |
| AO operator | Run a local dry-run watch and know whether the stack is clear, held, or incident-worthy. |
| Release owner | Block promotion when safety findings, regressions, or drift appear. |
| Framework maintainer | Compare a current run against a known-good baseline without reading every artifact manually. |
| Public reviewer | Read a redacted Sentinel report without secrets, local paths, or private prompts. |

## v0.1 Goals

1. Validate monitor targets and regression baselines.
2. Run a fixture-backed public-safety scan with redacted findings.
3. Run a deterministic regression suite from local fixtures.
4. Compare current regression output against a trusted baseline.
5. Evaluate a Sentinel verdict with stable severity and reason codes.
6. Emit a promoter hold packet when safety or regression gates fail.
7. Emit an incident packet when active-stack safety or regression health decays.
8. Render a public-safe operator report.
9. Support a one-iteration dry-run watch loop.
10. Fail closed on missing evidence, stale baselines, unsafe findings, schema mismatch, live mutation, or output outside `tmp/`.

## Non-Goals

- Do not run live model providers in v0.1 default paths.
- Do not create a resident daemon or background service in v0.1.
- Do not push, tag, release, upload, deploy, or mutate sibling repositories.
- Do not write live control-plane state.
- Do not store credentials, local absolute paths, private prompts, or unredacted evidence in durable public artifacts.
- Do not replace AO Promoter; AO Sentinel feeds holds and incidents into it.

## Success Metrics

- A clean clone can run the full dry-run monitor gate.
- Valid fixtures produce `verdict=clear`.
- Safety findings produce `verdict=hold` or `verdict=incident`.
- Regression failures produce stable blocker codes.
- A junior engineer can implement the CLI from the SDD without inventing commands, contracts, or fixture names.

## Production Readiness Definition

AO Sentinel v0.1 is 100/100 production-ready for its scoped release when the
product gate in `AO-SENTINEL-ACCEPTANCE-GATES.md` passes from a clean clone,
public-safety scans are clean, the valid Sentinel verdict is `clear`, dry-run
watch reports no mutation, and every invalid fixture is covered by tests.
