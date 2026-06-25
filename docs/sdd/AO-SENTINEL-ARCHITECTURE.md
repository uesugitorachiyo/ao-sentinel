# AO Sentinel Architecture

## Runtime Shape

AO Sentinel is a Go CLI with small internal packages. The v0.1 execution model
is local, deterministic, fixture-backed, and dry-run only. Every command that
writes output requires an explicit `--out` path under `tmp/`.

## CLI Commands

| Command | Purpose |
| --- | --- |
| `sentinel target validate --target <json>` | Validate the monitored AO stack target. |
| `sentinel baseline validate --baseline <json>` | Validate known-good safety and regression baselines. |
| `sentinel safety scan --path <path> --out <json>` | Scan public files for secret-like values, local paths, and forbidden actions. |
| `sentinel run regression --suite <json> --out <json>` | Execute deterministic local regression fixtures. |
| `sentinel compare regression --baseline <json> --run <json> --out <json>` | Compare current regression run to baseline budgets. |
| `sentinel monitor evaluate --target <json> --baseline <json> --safety <json> --regression <json> --out <json>` | Emit the final Sentinel verdict. |
| `sentinel incident render --verdict <json> --out <json>` | Render an incident packet from a non-clear verdict. |
| `sentinel hold emit --verdict <json> --out <json>` | Emit a promoter hold packet when promotion should be blocked. |
| `sentinel report render --verdict <json> --incident <json> --out <markdown>` | Render a public-safe report. |
| `sentinel watch dry-run --target <json> --suite <json> --baseline <json> --iterations <n> --out <json>` | Simulate one or more monitor cycles without background state. |

## Packages

| Package | Responsibility |
| --- | --- |
| `internal/cli` | Argument parsing, command routing, exit codes, and help text. |
| `internal/contracts` | Shared JSON structures, schema constants, and fixture validators. |
| `internal/safety` | Public-safety scanner and redacted finding model. |
| `internal/regression` | Regression suite runner and baseline comparison. |
| `internal/monitor` | Verdict assembly, severity ordering, and hold/incident decisions. |
| `internal/report` | Markdown and machine-readable report rendering. |
| `internal/watch` | One-iteration dry-run monitor loop and cycle ledger. |

## Data Flow

1. Validate target and baseline contracts.
2. Run safety scan and regression suite.
3. Compare regression run against baseline thresholds.
4. Evaluate Sentinel verdict from target, baseline, safety, and regression.
5. Emit promoter hold and incident packets when verdict is not `clear`.
6. Render public-safe report.
7. Run dry-run watch by executing the same cycle without live mutation.

## Storage Layout

- `docs/contracts/*.schema.json`: public JSON schemas.
- `examples/targets/valid/*.json`: valid monitor targets.
- `examples/baselines/valid/*.json`: valid baselines.
- `examples/suites/valid/*.json`: valid regression suites.
- `examples/*/invalid/*.json`: negative fixtures for fail-closed tests.
- `tmp/*.json`: generated local outputs.

## Error Handling

- Unknown schema versions fail.
- Missing required fields fail.
- Output outside `tmp/` fails.
- Safety findings never print matched secret-like values.
- Missing regression baseline entries fail.
- Stale baselines fail.
- Any live mutation request fails in v0.1.
