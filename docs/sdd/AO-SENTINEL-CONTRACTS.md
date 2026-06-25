# AO Sentinel Contracts

## Contract Families

| Contract | Planned schema path | Purpose |
| --- | --- | --- |
| Target | `docs/contracts/sentinel-target-v0.1.schema.json` | AO stack or candidate surface to monitor. |
| Baseline | `docs/contracts/sentinel-baseline-v0.1.schema.json` | Known-good safety, regression, drift, and budget expectations. |
| Regression suite | `docs/contracts/sentinel-regression-suite-v0.1.schema.json` | Deterministic local regression cases. |
| Regression run | `docs/contracts/sentinel-regression-run-v0.1.schema.json` | Results from running a regression suite. |
| Regression diff | `docs/contracts/sentinel-regression-diff-v0.1.schema.json` | Baseline comparison and blocker list. |
| Safety scan | `docs/contracts/sentinel-safety-scan-v0.1.schema.json` | Redacted public-safety findings. |
| Sentinel verdict | `docs/contracts/sentinel-verdict-v0.1.schema.json` | Clear, hold, or incident decision. |
| Incident packet | `docs/contracts/sentinel-incident-v0.1.schema.json` | Machine-readable incident summary and recommended actions. |
| Promoter hold | `docs/contracts/sentinel-promoter-hold-v0.1.schema.json` | Hold packet AO Promoter can consume. |
| Watch run | `docs/contracts/sentinel-watch-run-v0.1.schema.json` | Dry-run monitor cycle ledger. |

## Target Required Fields

- `schema_version`: `ao.sentinel.target.v0.1`;
- `target_id`;
- `target_kind`;
- `active_stack_ref`;
- `watch_scope`;
- `watched_components`;
- `platform_matrix`;
- `risk_budget`;
- `dry_run_only`.

Allowed `target_kind` values:

- `active_stack`;
- `candidate_stack`;
- `component`;
- `release_candidate`.

`dry_run_only` must be true in v0.1 valid fixtures.

## Baseline Required Fields

- `schema_version`: `ao.sentinel.baseline.v0.1`;
- `baseline_id`;
- `target_id`;
- `created_at_utc`;
- `expires_at_utc`;
- `expected_safety_status`;
- `regression_expectations`;
- `performance_budgets`;
- `contract_fingerprints`;
- `approval_authority`.

## Regression Suite Required Fields

- `schema_version`: `ao.sentinel.regression-suite.v0.1`;
- `suite_id`;
- `target_id`;
- `cases`;
- `default_timeout_seconds`;
- `dry_run_only`.

Each case includes `case_id`, `command`, `expected_status`, `expected_output_contains`,
and `max_duration_ms`.

## Verdict Required Fields

- `schema_version`: `ao.sentinel.verdict.v0.1`;
- `verdict`: `clear`, `hold`, or `incident`;
- `target_id`;
- `baseline_id`;
- `safety_status`;
- `regression_status`;
- `blockers`;
- `recommended_actions`;
- `promoter_hold_required`;
- `rollback_recommended`;
- `mutates_live_state`.

## Valid Fixtures

- `examples/targets/valid/local-ao-stack.sentinel-target.json`
- `examples/baselines/valid/ao-stack.sentinel-baseline.json`
- `examples/suites/valid/ao-stack-regression.sentinel-suite.json`
- `examples/safety/valid/readme-safety.sentinel-scan.json`
- `examples/regression/valid/ao-stack-regression-run.json`
- `examples/regression/valid/ao-stack-regression-diff.json`
- `examples/verdicts/valid/clear.sentinel-verdict.json`

## Invalid Fixtures

- `examples/targets/invalid/live-mutation-target.json`
- `examples/baselines/invalid/stale-baseline.json`
- `examples/suites/invalid/missing-case-command.json`
- `examples/safety/invalid/unsafe-public-scan.json`
- `examples/regression/invalid/failing-regression-run.json`
- `examples/regression/invalid/budget-regression-diff.json`
- `examples/verdicts/invalid/incident-without-hold.json`

## Validation Rules

- Reject unknown schema versions.
- Reject `dry_run_only: false` in v0.1 defaults.
- Reject missing regression case commands.
- Reject stale baselines.
- Reject target and baseline ID mismatches.
- Reject safety findings with unredacted matched values.
- Reject regression diffs whose failing cases do not appear in the suite.
- Reject verdicts that recommend rollback without requiring a promoter hold.
- Reject output paths outside `tmp/`.
