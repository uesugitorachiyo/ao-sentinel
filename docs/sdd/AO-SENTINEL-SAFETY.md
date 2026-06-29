# AO Sentinel Safety

## Default Posture

AO Sentinel v0.1 is dry-run and fail-closed. It can write local scratch outputs
under `tmp/`, but it cannot mutate live state, sibling repositories, remotes, or
control-plane state.

## Forbidden Actions

Default paths must not:

- push to remotes;
- create or delete tags;
- publish releases or packages;
- upload artifacts outside local scratch output;
- deploy services;
- mutate sibling AO repositories;
- write live control-plane state;
- store credentials;
- print secret-like values;
- write local absolute paths to durable public artifacts.

## Scanner Detectors

The scanner blocks:

- bearer-token-like strings;
- private key markers;
- GitHub token-like strings;
- cloud access-key-like strings;
- password assignment patterns;
- local absolute paths;
- forbidden action command text;
- unredacted incident evidence.

Findings report detector, file, line, severity, and summary without printing
the matched secret-like value.

## Fail-Closed Rules

Sentinel emits `hold` or `incident` when:

- safety findings are present;
- regression diff fails;
- baseline is stale;
- target and baseline IDs disagree;
- target requests live mutation;
- docs-only live mutation evidence lacks exact-scope approval, rollback proof,
  public-safety proof, verification proof, or operator kill-switch proof;
- output path is outside `tmp/`;
- schema version is unknown;
- incident packet would expose unredacted evidence.

Sentinel verdicts are evidence for hold/pass decisions only. They do not grant
live mutation authority, approve tickets, schedule work, execute patches, call
providers, publish releases, or bypass the surrounding Covenant, Foundry, Forge,
Promoter, Command, and operator gates.

## Redaction Rules

Incident packets and reports may include:

- detector name;
- file path relative to repository root;
- line number;
- severity;
- short summary;
- recommended action.

They must not include:

- matched secret-like value;
- full local absolute path;
- private prompt text;
- raw provider output;
- unreviewed logs.
