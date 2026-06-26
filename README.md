# AO Sentinel

AO Sentinel is the safety and regression monitor for the AO orchestration
framework. It watches candidate and active-stack evidence, compares current
runs against trusted baselines, detects public-safety leaks and behavioral
regressions, then emits deterministic verdicts, promoter holds, incident
packets, and public-safe operator reports.

AO Sentinel v0.1 is specified as a local-first Go CLI. Default execution is
fixture and dry-run only. It does not run live providers, push, tag, release,
upload, deploy, mutate sibling repositories, or write live control-plane state.

## Product Gate Commands

```sh
go test ./...
go vet ./...
go build -o tmp/bin/sentinel ./cmd/sentinel
PATH="$PWD/tmp/bin:$PATH" sentinel target validate --target examples/targets/valid/local-ao-stack.sentinel-target.json
PATH="$PWD/tmp/bin:$PATH" sentinel baseline validate --baseline examples/baselines/valid/ao-stack.sentinel-baseline.json
PATH="$PWD/tmp/bin:$PATH" sentinel safety scan --path README.md --out tmp/readme-safety.json
PATH="$PWD/tmp/bin:$PATH" sentinel run regression --suite examples/suites/valid/ao-stack-regression.sentinel-suite.json --out tmp/regression-run.json
PATH="$PWD/tmp/bin:$PATH" sentinel compare regression --baseline examples/baselines/valid/ao-stack.sentinel-baseline.json --run tmp/regression-run.json --out tmp/regression-diff.json
PATH="$PWD/tmp/bin:$PATH" sentinel monitor evaluate --target examples/targets/valid/local-ao-stack.sentinel-target.json --baseline examples/baselines/valid/ao-stack.sentinel-baseline.json --safety tmp/readme-safety.json --regression tmp/regression-diff.json --out tmp/sentinel-verdict.json
PATH="$PWD/tmp/bin:$PATH" sentinel incident render --verdict tmp/sentinel-verdict.json --out tmp/incident-packet.json
PATH="$PWD/tmp/bin:$PATH" sentinel hold emit --verdict tmp/sentinel-verdict.json --out tmp/promoter-hold.json
PATH="$PWD/tmp/bin:$PATH" sentinel report render --verdict tmp/sentinel-verdict.json --incident tmp/incident-packet.json --out tmp/sentinel-report.md
PATH="$PWD/tmp/bin:$PATH" sentinel watch dry-run --target examples/targets/valid/local-ao-stack.sentinel-target.json --suite examples/suites/valid/ao-stack-regression.sentinel-suite.json --baseline examples/baselines/valid/ao-stack.sentinel-baseline.json --iterations 1 --out tmp/watch-dry-run.json
PATH="$PWD/tmp/bin:$PATH" sentinel triage ci --signal examples/triage/ci-contract-schema.sentinel-ci-signal.json --out tmp/ci-triage.json
PATH="$PWD/tmp/bin:$PATH" sentinel security review --request examples/security/valid/ao-forge.security-review-request.json --out tmp/security-review.json
git diff --check
```

## SDD Files

| File | Purpose |
| --- | --- |
| `docs/sdd/AO-SENTINEL-PRD.md` | Product scope, users, goals, non-goals, and readiness definition. |
| `docs/sdd/AO-SENTINEL-ARCHITECTURE.md` | CLI, package boundaries, data flow, storage, and error handling. |
| `docs/sdd/AO-SENTINEL-CONTRACTS.md` | JSON contract families, fields, fixtures, and validation rules. |
| `docs/sdd/AO-SENTINEL-MONITORING.md` | Monitor cycle, signals, severity, hold, and incident semantics. |
| `docs/sdd/AO-SENTINEL-REGRESSION.md` | Regression suites, baseline comparison, drift, and budgets. |
| `docs/sdd/AO-SENTINEL-SAFETY.md` | Public-safety scanner, forbidden actions, redaction, and fail-closed rules. |
| `docs/sdd/AO-SENTINEL-IMPLEMENTATION-SLICES.md` | Implementation slices in dependency order. |
| `docs/sdd/AO-SENTINEL-ACCEPTANCE-GATES.md` | SDD and product 100/100 readiness gates. |
| `docs/sdd/AO-SENTINEL-SDD-HANDOFF.md` | Handoff prompt for AO Forge, AO Foundry, or Codex. |

## Local Planner Artifacts

AO2 SDD planner artifacts can be written under `target/` during local
automation runs. The directory is not part of the public release surface
because runspecs may include local machine paths.

## License

AO Sentinel is licensed under `Apache-2.0`. See `LICENSE`.
