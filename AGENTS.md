# AO Sentinel Agent Instructions

## Status And Role

AO Sentinel is the active safety monitor and hold producer for AO. It owns deterministic safety scans, baseline and regression comparison, evidence-freshness evaluation, incident classification, Promoter holds, CI triage, and operator safety reports.

Sentinel observes candidate and completed evidence. It does not repair findings, approve work, execute changes, mutate repositories, override policy, promote a candidate, or publish a release.

## Sources Of Truth

- [docs/sdd/AO-SENTINEL-PRD.md](docs/sdd/AO-SENTINEL-PRD.md) and [docs/sdd/AO-SENTINEL-ARCHITECTURE.md](docs/sdd/AO-SENTINEL-ARCHITECTURE.md) define scope, data flow, and component boundaries.
- [docs/sdd/AO-SENTINEL-CONTRACTS.md](docs/sdd/AO-SENTINEL-CONTRACTS.md) owns contract families and fixture semantics.
- [docs/sdd/AO-SENTINEL-MONITORING.md](docs/sdd/AO-SENTINEL-MONITORING.md), [docs/sdd/AO-SENTINEL-REGRESSION.md](docs/sdd/AO-SENTINEL-REGRESSION.md), and [docs/sdd/AO-SENTINEL-SAFETY.md](docs/sdd/AO-SENTINEL-SAFETY.md) define verdict, drift, hold, redaction, and fail-closed behavior.
- `docs/contracts/`, `internal/cli/`, and their tests are authoritative for implemented behavior. [`.github/workflows/ci.yml`](.github/workflows/ci.yml) defines the broad gate.

## Ownership And Boundaries

- Keep verdicts deterministic and bound to exact target, baseline, scan, regression, CI, source-head, digest, and freshness inputs. Missing, stale, malformed, or conflicting evidence must hold or fail closed.
- Preserve the distinction between clear, hold, and incident. A clear verdict is readback evidence, not approval, execution, mutation, promotion, release, or publication authority.
- Treat `examples/` as contract fixtures and keep valid and invalid inputs separate. Change baselines, budgets, expected results, and negative cases only with their consuming tests; never edit them to conceal regression or inflate safety.
- Keep generated scans, regression runs, verdicts, incidents, holds, watch output, reports, and binaries under ignored `tmp/` or `target/`. Do not hand-edit generated result fields.
- Preserve public-safety redaction and never record secrets, credentials, private paths, account identifiers, private findings, or unredacted provider output.
- Release rehearsal, release, deployment, publication, live mutation, credentialed operation, permission changes, and direct-main changes require separate explicit authority and remain outside Sentinel verdict authority.

## Working Method

- Change the smallest safety or monitoring surface while preserving baseline provenance, repeatability, severity ordering, evidence freshness, hold propagation, and fail-closed parsing.
- Add negative tests for stale evidence, digest drift, missing signals, unsafe content, invalid baselines, exceeded budgets, and claimed authority beyond the input contract.
- Update this file in the same pull request when durable commands, architecture, ownership, or authority boundaries change.

## Verification

- Sentinel logic and contracts: `go test ./internal/cli -count=1`.
- Format relevant Go source with `gofmt -d` over `cmd/` and `internal/`; run `go test ./... -count=1`, `go vet ./...`, and `go build -o tmp/bin/sentinel ./cmd/sentinel`.
- Run the product-gate target, baseline, scan, regression, compare, monitor, incident, hold, report, dry-run watch, triage, security-review, and live-mutation-hold commands listed in [README.md](README.md) when their surfaces change.
- For instruction changes run `python3 ../ao-architecture/scripts/verify_agent_instruction_layout.py --workspace-root .. --repository ao-sentinel`. Always run `git diff --check`.

## Evidence And Completion

- Record source heads, commands and exits, input and output digests, baseline identity, evidence age, and verdict or hold reason. Report skipped, unavailable, or failed checks explicitly.
- Completion requires focused and broad gates, green pull-request CI, clean synchronized `main`, and task-branch cleanup. Never report a clear result from missing or skipped safety inputs.
