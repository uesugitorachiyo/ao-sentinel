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
| CI signal | `docs/contracts/sentinel-ci-signal-v0.1.schema.json` | Read-only CI/observability signal for repair triage. |
| CI triage | `docs/contracts/sentinel-ci-triage-v0.1.schema.json` | Deterministic repair packet for AO Forge. |
| Security review request | `docs/contracts/sentinel-security-review-request-v0.1.schema.json` | Requested security scopes and evidence for a candidate change. |
| Security review | `docs/contracts/sentinel-security-review-v0.1.schema.json` | Clear or hold packet from non-mutating security review. |
| Live mutation hold | `docs/contracts/sentinel-live-mutation-hold-v0.1.schema.json` | Read-only hold or clear verdict for dry-run governed live-mutation readiness evidence. |

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

## Security Review Required Fields

Security review requests use
`ao.sentinel.security-review-request.v0.1` and must include `review_id`,
`target_id`, `repository`, `change_summary`, `scopes`, `evidence`, and
`observed_at_utc`.

Security review packets use `ao.sentinel.security-review.v0.1` and include
`status`, `severity`, `scopes_checked`, `findings`, `recommended_actions`,
`promoter_hold_required`, and `mutates_live_state`. `mutates_live_state` must
be false. Missing evidence for requested scopes becomes a hold instead of an
automatic repair.

## Live Mutation Hold Required Fields

Live mutation hold packets use `ao.sentinel.live-mutation-hold.v0.1` and must
include `status`, `mutation_class`, `class_hold_verdict`, `hold_required`,
`promoter_hold_required`, `rollback_recommended`, `blockers`,
`recommended_actions`, `source_artifacts`, and dry-run boundary fields.
`operator_mode` must be `read_only`; `mutates_live_state`,
`mutates_repositories`, `schedules_work`, `executes_work`, `approves_work`,
`provider_calls_allowed`, and `release_or_publish_allowed` must be false.

The Sentinel live-mutation hold command consumes AO Command live-mutation
status, Sentinel safety scan, and Sentinel regression diff evidence. It holds
when approval-gate, worktree-preparation, docs-only allowlist,
rollback-rehearsal, operator kill-switch, verification, public-safety,
regression, test coverage, class-bound rollback proof, diff size, file class,
evidence freshness, or CI status is missing, failed, stale, too broad, or not
ready.

## Valid Fixtures

- `examples/targets/valid/local-ao-stack.sentinel-target.json`
- `examples/baselines/valid/ao-stack.sentinel-baseline.json`
- `examples/suites/valid/ao-stack-regression.sentinel-suite.json`
- `examples/safety/valid/readme-safety.sentinel-scan.json`
- `examples/regression/valid/ao-stack-regression-run.json`
- `examples/regression/valid/ao-stack-regression-diff.json`
- `examples/verdicts/valid/clear.sentinel-verdict.json`
- `examples/security/valid/ao-forge.security-review-request.json`
- `examples/security/valid/ao-forge.security-review.json`
- `examples/live-mutation/valid/command-status.ready.json`
- `examples/live-mutation/valid/clear.sentinel-live-mutation-hold.json`

## Invalid Fixtures

- `examples/targets/invalid/live-mutation-target.json`
- `examples/baselines/invalid/stale-baseline.json`
- `examples/suites/invalid/missing-case-command.json`
- `examples/safety/invalid/unsafe-public-scan.json`
- `examples/regression/invalid/failing-regression-run.json`
- `examples/regression/invalid/budget-regression-diff.json`
- `examples/verdicts/invalid/incident-without-hold.json`
- `examples/live-mutation/invalid/command-status.missing-approval.json`
- `examples/live-mutation/invalid/command-status.missing-rollback.json`
- `examples/live-mutation/invalid/command-status.missing-verification.json`
- `examples/live-mutation/invalid/command-status.test-coverage-insufficient.json`
- `examples/live-mutation/invalid/command-status.rollback-proof-missing.json`
- `examples/live-mutation/invalid/command-status.diff-size-exceeded.json`
- `examples/live-mutation/invalid/command-status.file-class-forbidden.json`
- `examples/live-mutation/invalid/command-status.evidence-stale.json`
- `examples/live-mutation/invalid/command-status.ci-status-insufficient.json`
- `examples/live-mutation/invalid/command-status.forbidden-authority.json`
- `examples/live-mutation/invalid/hold-missing-rollback.sentinel-live-mutation-hold.json`

## Validation Rules

- Reject unknown schema versions.
- Reject `dry_run_only: false` in v0.1 defaults.
- Reject missing regression case commands.
- Reject stale baselines.
- Reject target and baseline ID mismatches.
- Reject safety findings with unredacted matched values.
- Reject regression diffs whose failing cases do not appear in the suite.
- Reject verdicts that recommend rollback without requiring a promoter hold.
- Reject live-mutation evidence that claims scheduling, execution, approval,
  provider, release, or repository mutation authority.
- Hold docs-only live-mutation readiness when approval-gate,
  worktree-preparation, docs-only allowlist, rollback-rehearsal, operator
  kill-switch, or verification evidence is missing.
- Hold mutation-class readiness when test coverage, class-bound rollback proof,
  diff size, file class, evidence freshness, or CI status is insufficient.
- Hold `multi_repo_low_risk` readiness when ordered PR dependencies,
  per-repo rollback, per-repo CI, fresh repo-state evidence, or the operator
  kill switch is insufficient.
- Reject output paths outside `tmp/`.
