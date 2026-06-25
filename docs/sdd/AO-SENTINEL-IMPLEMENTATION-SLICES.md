# AO Sentinel Implementation Slices

These slices are written for a junior engineer implementing the `ao-sentinel`
Go repository. Each slice is independently testable.

## Slice 01: Go CLI Foundation

Create:

- `go.mod`
- `cmd/sentinel/main.go`
- `internal/cli/cli.go`
- `internal/cli/cli_test.go`
- `.gitignore`
- `README.md`

Acceptance:

- `sentinel --help` lists `target`, `baseline`, `safety`, `run`, `compare`, `monitor`, `incident`, `hold`, `report`, and `watch`;
- unknown commands fail with non-zero exit code;
- `go test ./...` passes.

## Slice 02: Contracts And Fixtures

Create:

- `docs/contracts/sentinel-*.schema.json`
- every valid and invalid fixture named in `AO-SENTINEL-CONTRACTS.md`

Acceptance:

- every JSON fixture parses;
- contract docs and fixture filenames match;
- invalid fixtures are covered by Go tests.

## Slice 03: Target And Baseline Validation

Implement:

- `sentinel target validate --target <path>`
- `sentinel baseline validate --baseline <path>`

Acceptance:

- valid target passes;
- valid baseline passes;
- live mutation target fails;
- stale baseline fails;
- target and baseline ID mismatch fails.

## Slice 04: Public-Safety Scan

Implement:

- `sentinel safety scan --path <path> --out <json>`

Acceptance:

- public README/docs/examples pass;
- unsafe fixture fails without printing matched value;
- local absolute path fixture fails;
- forbidden action fixture fails;
- output outside `tmp/` fails.

## Slice 05: Regression Suite Runner

Implement:

- `sentinel run regression --suite <path> --out <json>`

Acceptance:

- valid suite emits passed regression run;
- missing case command fixture fails;
- command output markers are recorded;
- dry-run mutation flag remains false.

## Slice 06: Regression Baseline Comparison

Implement:

- `sentinel compare regression --baseline <path> --run <path> --out <json>`

Acceptance:

- valid run and baseline emit `status=passed`;
- failed regression run emits stable blocker IDs;
- duration budget regression fails;
- missing baseline case fails.

## Slice 07: Monitor Verdict

Implement:

- `sentinel monitor evaluate --target <path> --baseline <path> --safety <json> --regression <json> --out <json>`

Acceptance:

- clean safety and regression emit `verdict=clear`;
- safety failure emits `verdict=incident`;
- regression failure emits `verdict=hold`;
- blockers are structured and stable.

## Slice 08: Incident And Promoter Hold Packets

Implement:

- `sentinel incident render --verdict <path> --out <json>`
- `sentinel hold emit --verdict <path> --out <json>`

Acceptance:

- clear verdict creates non-incident packet with no hold required;
- hold verdict emits promoter hold;
- incident verdict recommends rollback;
- incident without hold fixture fails.

## Slice 09: Report And Watch Dry Run

Implement:

- `sentinel report render --verdict <path> --incident <path> --out <markdown>`
- `sentinel watch dry-run --target <path> --suite <path> --baseline <path> --iterations <n> --out <json>`

Acceptance:

- report is derived from verdict and incident JSON;
- watch dry-run runs exactly the requested bounded iterations;
- watch output reports `mutates_live_state=false`;
- no background process remains after command exit.

## Slice 10: Public Demo And Clean-Clone Gate

Create:

- `docs/demo/AO-SENTINEL-SAFETY-REGRESSION-MONITOR.md`
- `examples/reports/valid/ao-sentinel-v0.1.report.md`

Acceptance:

- clean clone runs the full dry-run monitor gate;
- public demo explains safety and regression monitor path;
- no live credentials or sibling repositories are required.

## Final Verification

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
