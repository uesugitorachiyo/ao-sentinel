# AO Sentinel SDD Handoff

Use this prompt after reviewing the SDD pack.

```text
You are implementing AO Sentinel v0.1 from the approved SDD documents.

Repository to create:
./ao-sentinel

Goal:
Build AO Sentinel as the safety and regression monitor for the AO orchestration
framework. The v0.1 product validates monitor targets and baselines, runs a
redacted public-safety scan, runs deterministic local regression suites,
compares current results against trusted baselines, emits Sentinel verdicts,
creates promoter hold packets, creates incident packets, renders public-safe
operator reports, and supports bounded dry-run watch loops only.

Required constraints:
- Use Go for the CLI.
- Support Ubuntu, macOS, and Windows.
- Keep v0.1 fixture-backed and dry-run-only by default.
- Do not run live providers.
- Do not create a resident daemon or background service in v0.1.
- Do not push, tag, release, upload, deploy, mutate sibling repositories, or
  write live control-plane state.
- Do not store secrets, local absolute paths, private prompts, raw provider
  output, or unredacted evidence in durable artifacts.
- Implement slice by slice from AO-SENTINEL-IMPLEMENTATION-SLICES.md.
- Add failing tests before implementation code.
- Stop when AO-SENTINEL-ACCEPTANCE-GATES.md product 100/100 gate passes.

Final response must include:
- slices completed;
- files changed;
- verification commands and results;
- current production-readiness score;
- Sentinel verdict result;
- promoter hold result;
- dry-run watch result;
- remaining blocking next actions, if any.
```

## Implementation Readiness Verdict

The plan is ready to implement when:

- `target/ao-sentinel-plan.json` validates with AO2 SDD validation;
- SDD docs contain concrete requirements rather than placeholders;
- acceptance gates define exact commands;
- handoff prompt needs no additional context.
