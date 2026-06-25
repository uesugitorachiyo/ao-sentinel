# AO Sentinel Regression

## Regression Suite Model

A regression suite is deterministic and local. v0.1 cases are command fixtures
that can be executed without network, credentials, sibling repositories, or
live model providers.

Each case defines:

- `case_id`;
- `command`;
- `expected_status`;
- `expected_output_contains`;
- `max_duration_ms`;
- `severity_on_failure`.

## Baseline Comparison

`sentinel compare regression` compares a regression run to the baseline by:

1. matching case IDs;
2. checking expected status;
3. checking expected output markers;
4. checking max duration budget;
5. detecting missing or extra critical cases;
6. producing stable blocker IDs.

## Regression Status

- `passed`: every required case matches the baseline.
- `failed`: one or more required cases fail.
- `blocked`: comparison cannot be trusted because baseline, run, or suite data is incomplete.

## Budgets

Baseline budgets include:

- `max_total_duration_ms`;
- per-case `max_duration_ms`;
- `allowed_failure_count`, which must be zero for critical cases;
- `schema_drift_allowed`, which must be false in v0.1 valid fixtures.

## Required Negative Coverage

The implementation must test:

- missing case command;
- failed case status;
- missing expected output marker;
- exceeded duration budget;
- stale baseline;
- target ID mismatch;
- untrusted schema drift.

## Output Contract

Regression diff outputs include:

- `schema_version`: `ao.sentinel.regression-diff.v0.1`;
- `status`: `passed`, `failed`, or `blocked`;
- `baseline_id`;
- `run_id`;
- `case_results`;
- `blockers`;
- `summary`.
