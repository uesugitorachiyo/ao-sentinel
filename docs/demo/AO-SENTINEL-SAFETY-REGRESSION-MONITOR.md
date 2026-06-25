# AO Sentinel Safety Regression Monitor Demo

AO Sentinel watches the AO orchestration framework after promotion. It checks
public safety, runs deterministic regression fixtures, compares the current run
against a trusted baseline, and emits a clear, hold, or incident verdict.

## Demo Flow

1. Validate the Sentinel target.
2. Validate the trusted baseline.
3. Run a public-safety scan.
4. Run the deterministic regression suite.
5. Compare the run against the baseline.
6. Evaluate the Sentinel verdict.
7. Render incident and promoter hold packets.
8. Render a public-safe report.
9. Run a bounded dry-run watch cycle.

## Expected Result

The canonical fixture emits:

- `tmp/readme-safety.json` with `status=passed`;
- `tmp/regression-diff.json` with `status=passed`;
- `tmp/sentinel-verdict.json` with `verdict=clear`;
- `tmp/promoter-hold.json` with `hold_required=false`;
- `tmp/watch-dry-run.json` with `mutates_live_state=false`.

AO Sentinel v0.1 does not create a resident daemon, contact live providers,
mutate sibling repositories, publish releases, upload artifacts, deploy
services, or write live control-plane state.
