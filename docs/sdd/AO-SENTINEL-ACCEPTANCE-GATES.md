# AO Sentinel Acceptance Gates

## SDD Readiness Gate

The SDD pack is 100/100 implementation-ready only when:

- PRD defines users, goals, non-goals, success metrics, and production readiness;
- architecture defines commands, packages, data flow, storage, and errors;
- contracts define schema families, required fields, valid fixtures, invalid fixtures, and validation rules;
- monitoring document defines signals, severity, verdicts, holds, and incident semantics;
- regression document defines suites, baselines, budgets, comparisons, and negative coverage;
- safety document defines forbidden actions, scans, redaction, and fail-closed rules;
- implementation slices define exact files, commands, tests, and final verification;
- handoff prompt needs no additional context;
- `target/ao-sentinel-plan.json` validates with AO2 SDD validation;
- placeholder scan finds no incomplete planning markers.

## Product Readiness Gate

The implemented AO Sentinel v0.1 scores 100/100 only when these pass:

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
git diff --check
```

## Competitive Gate

AO Sentinel is competitive only when it provides:

- deterministic safety and regression verdicts;
- strict baseline freshness and target matching;
- regression budgets with stable blocker IDs;
- redacted public-safety findings;
- promoter hold emission;
- incident packet emission;
- bounded dry-run watch loop;
- clean-clone reproducibility;
- no live mutation in default paths.

## Exit Condition

An autonomous implementation run stops when:

- every implementation slice is complete;
- product readiness gate passes from a clean clone;
- clean fixture emits `verdict=clear`;
- safety failure fixture emits `verdict=incident`;
- regression failure fixture emits `verdict=hold`;
- dry-run watch reports no mutation;
- public-safety scans pass with zero findings;
- final response lists verification commands and remaining non-blocking release work.
