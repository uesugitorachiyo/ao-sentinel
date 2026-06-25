# AO Sentinel SDD Planner Prompt

Use this prompt with AO2 SDD planner if the SDD pack needs regeneration.

```text
Create an ao2.sdd-plan.v1 plan for AO Sentinel.

AO Sentinel is the safety and regression monitor for the AO orchestration
framework. It validates monitor targets and baselines, runs public-safety scans,
runs deterministic local regression suites, compares current results against
trusted baselines, emits Sentinel verdicts, emits AO Promoter hold packets,
emits incident packets, renders public-safe reports, and supports bounded
dry-run watch loops.

Constraints:
- Go CLI.
- Ubuntu, macOS, and Windows support.
- Default execution is fixture and dry-run only.
- No live providers, resident daemon, background service, network mutation,
  credentials, sibling repository mutation, releases, uploads, deploys, or live
  control-plane writes.
- Public artifacts must not contain secrets, local absolute paths, private
  prompts, raw provider output, or unredacted evidence.
- The plan must be concrete enough that a junior engineer can implement the CLI
  without inventing command names, schema fields, fixture names, verdict
  semantics, regression budgets, redaction behavior, or acceptance gates.
```
