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
PATH="$PWD/tmp/bin:$PATH" sentinel live-mutation hold --status examples/live-mutation/valid/command-status.ready.json --safety examples/safety/valid/readme-safety.sentinel-scan.json --regression examples/regression/valid/ao-stack-regression-diff.json --out tmp/live-mutation-hold.json
git diff --check
```

## Governed Live-Mutation Hold

`sentinel live-mutation hold` is read-only and dry-run only. It consumes AO
Command live-mutation readback plus Sentinel safety and regression evidence,
then emits `ao.sentinel.live-mutation-hold.v0.1`. The packet now includes a
`mutation_class` and `class_hold_verdict` readback. Sentinel holds when
class-specific approval/class-gate, worktree-preparation, allowlist,
rollback-rehearsal, operator kill-switch, verification, public-safety,
regression, test coverage, class-bound rollback proof, diff size, file class,
evidence freshness, or CI status is missing, failed, stale, too broad, or not
digest-bound. For `multi_repo_low_risk`, the class verdict also holds on
missing ordered dependencies, incomplete per-repo rollback, incomplete per-repo
CI, stale repo-state evidence, or a disarmed kill switch. Sentinel may
remove its hold only when those inputs prove the exact approved scope is
intact, but that verdict is still not live-mutation approval. It does not grant
authority, schedule work, mutate repositories, call providers, publish,
release, or override Covenant, Foundry, Forge, Promoter, or operator approval
gates.

For `low_risk_code`, Sentinel also enforces the bounded patch packet shape:
at most one source file and one test file, a test change for source changes,
and no scripts, CI workflows, release paths, secrets, config expansion,
provider paths, or broad refactors. The resulting hold remains observer-only
and does not execute or approve repository mutation.

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
