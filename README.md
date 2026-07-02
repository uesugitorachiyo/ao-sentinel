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

## Repeated Bounded Reversible Self-Change Applications Hold

Sentinel clears only the narrow repeated bounded applications public-risk
wording and keeps unrestricted self-modification on hold. The proven class is
`public_safe_repeated_bounded_reversible_self_change_applications_four_attempts`,
from AO Foundry PR #219, commit
`88b52ce1ca9e8679cccdc64fe21c2b63340076b5`, with tracked public evidence under
`docs/evidence/unrestricted-self-modification-repeated-bounded-applications/`.
The Sentinel result is
`clear_repeated_bounded_applications_hold_unrestricted_self_modification`.
The approved public wording is exactly: "AO has public-safe repeated bounded
reversible self-change application evidence across four exact-scope
support/readback attempts under sandbox containment gates; unrestricted
self-modification, hidden instruction mutation, policy-changing autonomy, and
forbidden surface expansion remain denied."

This hold clearance does not grant execution authority, schedule work, mutate
repositories, call providers, publish, release, or override Covenant, Foundry,
Forge, Promoter, or operator approval gates. It does not prove unrestricted
self-modification, hidden instruction mutation, policy-changing autonomy,
forbidden surface expansion, direct-main mutation, concurrent mutation, or any
unrestricted RSI claim.

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

## Bounded Sandboxed Self-Change Application Readback

`public_safe_bounded_sandboxed_self_change_applications_non_readback_four_attempts`
is proven from AO Foundry PR #220, commit
`eff03edd62ba32af57defc71a7f3b800f320b8d3`, with tracked public evidence under
`docs/evidence/unrestricted-self-modification-bounded-sandbox-applications/`.
Sentinel result:
`clear_bounded_sandbox_non_readback_applications_hold_unrestricted_self_modification`.
The approved public wording is exactly: "AO has public-safe bounded sandboxed
self-change application evidence across four non-readback exact-scope evidence
tasks under sandbox containment gates; unrestricted self-modification, hidden
instruction mutation, policy-changing autonomy, and forbidden surface expansion
remain denied." This remains prior evidence. The highest proven live class is
`public_safe_bounded_sandboxed_self_change_support_code_eval_four_attempts`;
the next denied class is `unrestricted_self_modification`.

## Cross-Repo Documentation/Readback Sandboxed Self-Change Readback

`public_safe_bounded_sandboxed_self_change_cross_repo_doc_readback_four_attempts`
is proven from AO Foundry PR #221, commit
`a993f4b6284de711cdb2b3fd6f006bb2706df9c8`, with tracked public evidence under
`docs/evidence/unrestricted-self-modification-cross-repo-doc-readback/`.
Sentinel result:
`clear_cross_repo_doc_readback_hold_unrestricted_self_modification`.
The approved public wording is exactly: "AO has public-safe bounded sandboxed
self-change cross-repo documentation/readback evidence across four exact-scope
documentation consistency attempts under sandbox containment gates; unrestricted
self-modification, hidden instruction mutation, policy-changing autonomy, and
forbidden surface expansion remain denied." The mission completed `180 / 180`
nodes. The measured attempts were Architecture source-of-truth consistency
evidence quality `0.70` -> `0.94`, Component README readback parity quality
`0.68` -> `0.93`, CI/PR merge evidence linkage quality `0.67` -> `0.92`, and
stale-language denial sweep quality `0.66` -> `0.91`.

This proves only public-safe bounded sandboxed self-change cross-repo
documentation/readback evidence under sandbox containment gates. It does not
prove unrestricted self-modification, hidden instruction mutation,
policy-changing autonomy, forbidden surface expansion, policy/auth/secret/
provider/deploy/release/config/dependency expansion, credential use, provider
calls, release/deploy/publish/upload/tag authority, dependency update authority,
direct main mutation, concurrent mutation, hidden instruction changes, or any
unrestricted RSI claim.

## Support-Code/Eval Sandboxed Self-Change Readback

`public_safe_bounded_sandboxed_self_change_support_code_eval_four_attempts`
is proven from AO Foundry PR #222, commit
`9938df55959ac904295fd4d0dc0eddc52626c972`, with tracked public evidence under
`docs/evidence/unrestricted-self-modification-support-code-eval/`. Sentinel
result:
`clear_support_code_eval_hold_unrestricted_self_modification`.
The approved public wording is exactly: "AO has public-safe bounded sandboxed
self-change support-code/eval evidence across four exact-scope reversible
support-code and evaluation attempts under sandbox containment gates;
unrestricted self-modification, hidden instruction mutation, policy-changing
autonomy, and forbidden surface expansion remain denied." The mission completed
`240 / 240` nodes. The measured attempts were support-code fixture validation
quality `0.72` -> `0.95`, eval harness diagnostics quality `0.70` -> `0.94`,
rollback automation evidence quality `0.69` -> `0.93`, and sandbox containment
trace quality `0.68` -> `0.92`.

This proves only public-safe bounded sandboxed self-change support-code/eval
evidence under sandbox containment gates. Sentinel remains on hold for
unrestricted self-modification, hidden instruction mutation, policy-changing
autonomy, forbidden surface expansion, sandbox containment bypass, and any
unrestricted RSI claim.

## Multi-Surface Support/Eval Sentinel Readback

AO Sentinel clears only the narrow class `public_safe_bounded_sandboxed_self_change_multi_surface_support_eval_negative_controls_four_attempts` from AO Foundry PR #223, commit `3cd8c470538d626bebfc63262979f364ea53b081`, with tracked public evidence under `docs/evidence/unrestricted-self-modification-multi-surface-support-eval/` and final rollup `docs/evidence/unrestricted-self-modification-multi-surface-support-eval/final-rollup.json`. The Sentinel result is `clear_multi_surface_support_eval_hold_unrestricted_self_modification`. The approved public wording is exactly: "AO has public-safe bounded sandboxed self-change multi-surface support/eval negative-control evidence across four exact-scope reversible attempts under sandbox containment gates; unrestricted self-modification, hidden instruction mutation, policy-changing autonomy, and forbidden surface expansion remain denied."

Sentinel keeps holds for unrestricted self-modification, hidden instruction mutation, policy-changing autonomy, forbidden surface expansion, sandbox containment bypass, and unrestricted RSI.
## Delegated Dry-Run Authority-Gap Sentinel Readback

AO Sentinel clears only the narrow class `public_safe_bounded_sandboxed_self_change_delegated_dry_run_authority_gap_four_attempts` from AO Foundry PR #224, commit `afdd6562dfe83cec2eaa5d4172e23f9cec26c14e`, with tracked public evidence under `docs/evidence/unrestricted-self-modification-delegated-dry-run-authority-gap/` and final rollup `docs/evidence/unrestricted-self-modification-delegated-dry-run-authority-gap/final-rollup.json`. The Sentinel result is `clear_delegated_dry_run_authority_gap_hold_unrestricted_self_modification`. The approved public wording is exactly: "AO has public-safe bounded sandboxed self-change delegated dry-run authority-gap evidence across four exact-scope reversible attempts under sandbox containment gates; unrestricted self-modification, hidden instruction mutation, policy-changing autonomy, forbidden surface expansion, and sandbox containment bypass remain denied."

Sentinel keeps holds for unrestricted self-modification, hidden instruction mutation, policy-changing autonomy, forbidden surface expansion, sandbox containment bypass, and unrestricted RSI.
