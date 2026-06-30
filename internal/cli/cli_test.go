package cli

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestHelpListsExpectedCommandsAndUnknownCommandFails(t *testing.T) {
	var out, err bytes.Buffer
	if code := Run([]string{"--help"}, &out, &err); code != 0 {
		t.Fatalf("help exit code = %d stderr = %s", code, err.String())
	}
	for _, want := range []string{"target", "baseline", "safety", "run", "compare", "monitor", "incident", "hold", "report", "watch", "triage", "security", "live-mutation"} {
		if !strings.Contains(out.String(), want) {
			t.Fatalf("help output missing %q:\n%s", want, out.String())
		}
	}

	out.Reset()
	err.Reset()
	if code := Run([]string{"definitely-not-a-command"}, &out, &err); code == 0 {
		t.Fatalf("unknown command succeeded: stdout=%s stderr=%s", out.String(), err.String())
	}
}

func TestCITriageEmitsRepairPacket(t *testing.T) {
	f := newFixtureSet(t)
	signal := map[string]any{
		"schema_version":  "ao.sentinel.ci-signal.v0.1",
		"signal_id":       "ci-ao-forge-123",
		"source":          "github-actions",
		"repository":      "ao-forge",
		"workflow":        "test",
		"job":             "go-test",
		"conclusion":      "failure",
		"log_excerpt":     "go test ./... failed: schema validation failed for goal-run-context-handoff-v0.1",
		"observed_at_utc": "2026-06-26T12:00:00Z",
	}
	signalPath := f.writeJSON("ci-signal.json", signal)
	outPath := filepath.Join(f.tmp, "ci-triage.json")

	assertRunOK(t, []string{"triage", "ci", "--signal", signalPath, "--out", outPath})
	packet := readMap(t, outPath)
	if packet["schema_version"] != "ao.sentinel.ci-triage.v0.1" ||
		packet["status"] != "repair_required" ||
		packet["root_cause"] != "contract_schema" ||
		packet["mutates_live_state"] != false ||
		packet["regression_test_required"] != true {
		t.Fatalf("unexpected CI triage packet: %#v", packet)
	}
	nextTask, ok := packet["next_forge_task"].(map[string]any)
	if !ok || !strings.Contains(nextTask["title"].(string), "Fix contract schema failure") {
		t.Fatalf("triage packet missing Forge next task: %#v", packet["next_forge_task"])
	}
	steps := packet["triage_steps"].([]any)
	if len(steps) != 5 {
		t.Fatalf("expected five triage steps, got %#v", steps)
	}

	staleSignal := cloneMap(t, signal)
	staleSignal["conclusion"] = "success"
	staleOut := filepath.Join(f.tmp, "ci-triage-success.json")
	assertRunOK(t, []string{"triage", "ci", "--signal", f.writeJSON("ci-success.json", staleSignal), "--out", staleOut})
	observed := readMap(t, staleOut)
	if observed["status"] != "observed" || observed["regression_test_required"] != false {
		t.Fatalf("successful signal should not require repair: %#v", observed)
	}
}

func TestSecurityReviewEmitsHoldForSensitiveGaps(t *testing.T) {
	f := newFixtureSet(t)
	request := map[string]any{
		"schema_version":  "ao.sentinel.security-review-request.v0.1",
		"review_id":       "security-ao-forge-001",
		"target_id":       "local-ao-stack",
		"repository":      "ao-forge",
		"change_summary":  "Adds an API endpoint that handles user input but does not describe authorization.",
		"scopes":          []any{"secrets", "input_validation", "authorization", "dependencies", "logging", "public_artifacts"},
		"evidence":        []any{"README.md", "docs/security/PUBLIC-REPO-POLICY.md"},
		"observed_at_utc": "2026-06-26T12:00:00Z",
	}
	outPath := filepath.Join(f.tmp, "security-review.json")
	assertRunOK(t, []string{"security", "review", "--request", f.writeJSON("security-request.json", request), "--out", outPath})
	packet := readMap(t, outPath)
	if packet["schema_version"] != "ao.sentinel.security-review.v0.1" ||
		packet["status"] != "hold" ||
		packet["promoter_hold_required"] != true ||
		packet["mutates_live_state"] != false {
		t.Fatalf("unexpected security review packet: %#v", packet)
	}
	findings := packet["findings"].([]any)
	if len(findings) == 0 {
		t.Fatalf("security review should include findings: %#v", packet)
	}

	clearRequest := cloneMap(t, request)
	clearRequest["change_summary"] = "No secrets. Input validation uses schemas. Authorization checks are documented. Dependencies were audited. Logs redact sensitive data. Public artifacts were scanned."
	clearOut := filepath.Join(f.tmp, "security-review-clear.json")
	assertRunOK(t, []string{"security", "review", "--request", f.writeJSON("security-clear.json", clearRequest), "--out", clearOut})
	clearPacket := readMap(t, clearOut)
	if clearPacket["status"] != "clear" || clearPacket["promoter_hold_required"] != false {
		t.Fatalf("clear security request should not hold: %#v", clearPacket)
	}
}

func TestLiveMutationHoldVerdict(t *testing.T) {
	f := newFixtureSet(t)
	status := map[string]any{
		"schema_version":       "ao.command.live-mutation-status.v0.1",
		"status":               "ready",
		"allowed_next_action":  "request_docs_only_multi_file_mutation_class",
		"first_failing_check":  "",
		"mutation_class":       "docs_only_multi_file",
		"kill_switch_state":    "armed",
		"operator_mode":        "read_only",
		"mutates_live_state":   false,
		"mutates_repositories": false,
		"schedules_work":       false,
		"executes_work":        false,
		"approves_work":        false,
		"calls_providers":      false,
		"artifacts": []any{
			map[string]any{"name": "live_docs_approval_gate", "status": "ready", "sha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},
			map[string]any{"name": "live_docs_worktree_prepare", "status": "ready", "sha256": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"},
			map[string]any{"name": "docs_only_allowlist", "status": "ready", "sha256": "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"},
			map[string]any{"name": "rollback_rehearsal", "status": "ready", "sha256": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"},
			map[string]any{"name": "operator_kill_switch", "status": "armed", "sha256": "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"},
			map[string]any{"name": "verification_evidence", "status": "passed", "sha256": "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"},
		},
		"changed_files": []any{
			map[string]any{"path": "README.md", "file_class": "docs", "change_type": "modified"},
			map[string]any{"path": "docs/live-mutation.md", "file_class": "docs", "change_type": "modified"},
		},
		"diff_summary": map[string]any{"files_changed": 2, "additions": 18, "deletions": 6, "total_lines_changed": 24},
		"test_coverage": map[string]any{
			"status": "not_required",
			"reason": "docs-only mutation class",
		},
		"rollback_proof": map[string]any{
			"status":         "ready",
			"mutation_class": "docs_only_multi_file",
			"scope":          "README.md,docs/live-mutation.md",
			"sha256":         "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
		},
		"evidence_freshness": map[string]any{
			"status":         "fresh",
			"checked_at_utc": "2026-06-29T00:00:00Z",
			"expires_at_utc": "2999-01-01T00:00:00Z",
		},
		"ci_status": map[string]any{
			"status":          "passed",
			"required":        true,
			"observed_at_utc": "2026-06-29T00:00:00Z",
			"expires_at_utc":  "2999-01-01T00:00:00Z",
		},
	}
	safety := map[string]any{
		"schema_version":     "ao.sentinel.safety-scan.v0.1",
		"status":             "passed",
		"path":               "README.md",
		"findings_count":     0,
		"findings":           []any{},
		"mutates_live_state": false,
	}
	regression := map[string]any{
		"schema_version": "ao.sentinel.regression-diff.v0.1",
		"status":         "passed",
		"baseline_id":    "ao-stack-baseline",
		"run_id":         "run-ao-stack-regression",
		"blockers":       []any{},
	}
	outPath := filepath.Join(f.tmp, "live-mutation-hold.json")
	assertRunOK(t, []string{"live-mutation", "hold", "--status", f.writeJSON("live-status.json", status), "--safety", f.writeJSON("live-safety.json", safety), "--regression", f.writeJSON("live-regression.json", regression), "--out", outPath})
	clear := readMap(t, outPath)
	if clear["schema_version"] != "ao.sentinel.live-mutation-hold.v0.1" ||
		clear["status"] != "clear" ||
		clear["hold_required"] != false ||
		clear["promoter_hold_required"] != false ||
		clear["mutates_live_state"] != false ||
		clear["mutates_repositories"] != false {
		t.Fatalf("unexpected clear live-mutation hold: %#v", clear)
	}
	if clear["mutation_class"] != "docs_only_multi_file" {
		t.Fatalf("live-mutation hold should report mutation class: %#v", clear)
	}
	classVerdict, ok := clear["class_hold_verdict"].(map[string]any)
	if !ok {
		t.Fatalf("live-mutation hold missing class verdict: %#v", clear)
	}
	if classVerdict["status"] != "clear" ||
		classVerdict["test_coverage_status"] != "not_required" ||
		classVerdict["rollback_status"] != "ready" ||
		classVerdict["diff_size_status"] != "passed" ||
		classVerdict["file_class_status"] != "passed" ||
		classVerdict["evidence_freshness_status"] != "fresh" ||
		classVerdict["ci_status"] != "passed" {
		t.Fatalf("unexpected class verdict: %#v", classVerdict)
	}
	if len(clear["source_artifacts"].([]any)) != 3 {
		t.Fatalf("live-mutation hold should hash three source artifacts: %#v", clear["source_artifacts"])
	}

	classBlockers := []struct {
		name string
		edit func(map[string]any)
		want string
	}{
		{
			name: "test coverage insufficient",
			edit: func(candidate map[string]any) {
				candidate["mutation_class"] = "test_only"
				candidate["artifacts"] = []any{
					map[string]any{"name": "test_only_class_gate", "status": "ready", "sha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},
					map[string]any{"name": "test_only_worktree_prepare", "status": "ready", "sha256": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"},
					map[string]any{"name": "test_only_allowlist", "status": "ready", "sha256": "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"},
					map[string]any{"name": "rollback_rehearsal", "status": "ready", "sha256": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"},
					map[string]any{"name": "operator_kill_switch", "status": "armed", "sha256": "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"},
					map[string]any{"name": "verification_evidence", "status": "passed", "sha256": "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"},
				}
				candidate["changed_files"] = []any{map[string]any{"path": "internal/cli/cli_test.go", "file_class": "test", "change_type": "modified"}}
				candidate["diff_summary"] = map[string]any{"files_changed": 1, "additions": 12, "deletions": 4, "total_lines_changed": 16}
				candidate["test_coverage"] = map[string]any{"status": "missing"}
				candidate["rollback_proof"] = map[string]any{"status": "ready", "mutation_class": "test_only", "scope": "internal/cli/cli_test.go", "sha256": "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"}
			},
			want: "test_coverage_insufficient",
		},
		{
			name: "rollback proof missing",
			edit: func(candidate map[string]any) {
				delete(candidate, "rollback_proof")
			},
			want: "rollback_proof_missing",
		},
		{
			name: "diff size exceeded",
			edit: func(candidate map[string]any) {
				candidate["diff_summary"] = map[string]any{"files_changed": 2, "additions": 900, "deletions": 200, "total_lines_changed": 1100}
			},
			want: "diff_size_exceeded",
		},
		{
			name: "file class forbidden",
			edit: func(candidate map[string]any) {
				candidate["changed_files"] = []any{map[string]any{"path": "internal/cli/cli.go", "file_class": "code", "change_type": "modified"}}
				candidate["diff_summary"] = map[string]any{"files_changed": 1, "additions": 4, "deletions": 1, "total_lines_changed": 5}
			},
			want: "file_class_forbidden",
		},
		{
			name: "evidence stale",
			edit: func(candidate map[string]any) {
				candidate["evidence_freshness"] = map[string]any{"status": "stale", "checked_at_utc": "2026-06-29T00:00:00Z", "expires_at_utc": "2000-01-01T00:00:00Z"}
			},
			want: "evidence_stale",
		},
		{
			name: "ci status insufficient",
			edit: func(candidate map[string]any) {
				candidate["ci_status"] = map[string]any{"status": "pending", "required": true, "observed_at_utc": "2026-06-29T00:00:00Z", "expires_at_utc": "2999-01-01T00:00:00Z"}
			},
			want: "ci_status_insufficient",
		},
	}
	for _, tc := range classBlockers {
		t.Run(tc.name, func(t *testing.T) {
			candidate := cloneMap(t, status)
			tc.edit(candidate)
			path := filepath.Join(f.tmp, strings.ReplaceAll(tc.name, " ", "-")+".json")
			assertRunOK(t, []string{"live-mutation", "hold", "--status", f.writeJSON(tc.name+".status.json", candidate), "--safety", f.writeJSON(tc.name+".safety.json", safety), "--regression", f.writeJSON(tc.name+".regression.json", regression), "--out", path})
			verdict := readMap(t, path)
			if verdict["status"] != "hold" || verdict["hold_required"] != true || verdict["first_failing_check"] != tc.want {
				t.Fatalf("%s should hold with %s: %#v", tc.name, tc.want, verdict)
			}
		})
	}

	missingRollback := cloneMap(t, status)
	missingRollback["artifacts"] = []any{
		map[string]any{"name": "live_docs_approval_gate", "status": "ready", "sha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},
		map[string]any{"name": "live_docs_worktree_prepare", "status": "ready", "sha256": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"},
		map[string]any{"name": "docs_only_allowlist", "status": "ready", "sha256": "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"},
		map[string]any{"name": "operator_kill_switch", "status": "armed", "sha256": "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"},
		map[string]any{"name": "verification_evidence", "status": "passed", "sha256": "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"},
	}
	holdPath := filepath.Join(f.tmp, "live-mutation-hold-missing-rollback.json")
	assertRunOK(t, []string{"live-mutation", "hold", "--status", f.writeJSON("missing-rollback.json", missingRollback), "--safety", f.writeJSON("safe-live.json", safety), "--regression", f.writeJSON("regression-live.json", regression), "--out", holdPath})
	hold := readMap(t, holdPath)
	if hold["status"] != "hold" || hold["hold_required"] != true || hold["first_failing_check"] != "rollback_rehearsal_missing" {
		t.Fatalf("missing rollback should hold: %#v", hold)
	}

	missingApproval := cloneMap(t, status)
	missingApproval["artifacts"] = []any{
		map[string]any{"name": "live_docs_worktree_prepare", "status": "ready", "sha256": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"},
		map[string]any{"name": "docs_only_allowlist", "status": "ready", "sha256": "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"},
		map[string]any{"name": "rollback_rehearsal", "status": "ready", "sha256": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"},
		map[string]any{"name": "operator_kill_switch", "status": "armed", "sha256": "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"},
		map[string]any{"name": "verification_evidence", "status": "passed", "sha256": "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"},
	}
	missingApprovalPath := filepath.Join(f.tmp, "live-mutation-hold-missing-approval.json")
	assertRunOK(t, []string{"live-mutation", "hold", "--status", f.writeJSON("missing-approval.json", missingApproval), "--safety", f.writeJSON("safe-live-approval.json", safety), "--regression", f.writeJSON("regression-live-approval.json", regression), "--out", missingApprovalPath})
	approvalHold := readMap(t, missingApprovalPath)
	if approvalHold["status"] != "hold" || approvalHold["first_failing_check"] != "live_docs_approval_gate_missing" {
		t.Fatalf("missing approval gate should hold: %#v", approvalHold)
	}

	missingVerification := cloneMap(t, status)
	missingVerification["artifacts"] = []any{
		map[string]any{"name": "live_docs_approval_gate", "status": "ready", "sha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},
		map[string]any{"name": "live_docs_worktree_prepare", "status": "ready", "sha256": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"},
		map[string]any{"name": "docs_only_allowlist", "status": "ready", "sha256": "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"},
		map[string]any{"name": "rollback_rehearsal", "status": "ready", "sha256": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"},
		map[string]any{"name": "operator_kill_switch", "status": "armed", "sha256": "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"},
	}
	missingVerificationPath := filepath.Join(f.tmp, "live-mutation-hold-missing-verification.json")
	assertRunOK(t, []string{"live-mutation", "hold", "--status", f.writeJSON("missing-verification.json", missingVerification), "--safety", f.writeJSON("safe-live-verification.json", safety), "--regression", f.writeJSON("regression-live-verification.json", regression), "--out", missingVerificationPath})
	verificationHold := readMap(t, missingVerificationPath)
	if verificationHold["status"] != "hold" || verificationHold["first_failing_check"] != "verification_evidence_missing" {
		t.Fatalf("missing verification evidence should hold: %#v", verificationHold)
	}

	forbidden := cloneMap(t, status)
	forbidden["mutates_repositories"] = true
	assertRunFails(t, []string{"live-mutation", "hold", "--status", f.writeJSON("forbidden-live.json", forbidden), "--safety", f.writeJSON("safe-forbidden.json", safety), "--regression", f.writeJSON("regression-forbidden.json", regression), "--out", filepath.Join(f.tmp, "forbidden-hold.json")}, "forbidden authority")
}

func TestTargetAndBaselineValidation(t *testing.T) {
	f := newFixtureSet(t)

	assertRunOK(t, []string{"target", "validate", "--target", f.targetPath})
	assertRunOK(t, []string{"baseline", "validate", "--baseline", f.baselinePath})

	liveTarget := cloneMap(t, f.target)
	liveTarget["dry_run_only"] = false
	assertRunFails(t, []string{"target", "validate", "--target", f.writeJSON("live-target.json", liveTarget)}, "dry_run_only")

	staleBaseline := cloneMap(t, f.baseline)
	staleBaseline["expires_at_utc"] = "2000-01-01T00:00:00Z"
	assertRunFails(t, []string{"baseline", "validate", "--baseline", f.writeJSON("stale-baseline.json", staleBaseline)}, "stale baseline")

	mismatchBaseline := cloneMap(t, f.baseline)
	mismatchBaseline["target_id"] = "other-target"
	safetyPath := filepath.Join(f.tmp, "safe.json")
	regressionPath := filepath.Join(f.tmp, "regression.json")
	assertRunOK(t, []string{"safety", "scan", "--path", f.safeDocPath, "--out", safetyPath})
	assertRunOK(t, []string{"run", "regression", "--suite", f.suitePath, "--out", filepath.Join(f.tmp, "run.json")})
	assertRunOK(t, []string{"compare", "regression", "--baseline", f.baselinePath, "--run", filepath.Join(f.tmp, "run.json"), "--out", regressionPath})
	assertRunFails(t, []string{"monitor", "evaluate", "--target", f.targetPath, "--baseline", f.writeJSON("mismatch-baseline.json", mismatchBaseline), "--safety", safetyPath, "--regression", regressionPath, "--out", filepath.Join(f.tmp, "verdict.json")}, "target and baseline mismatch")
}

func TestSafetyScanRedactsFindingsAndRequiresTmpOutput(t *testing.T) {
	f := newFixtureSet(t)

	outPath := filepath.Join(f.tmp, "safe-scan.json")
	assertRunOK(t, []string{"safety", "scan", "--path", f.safeDocPath, "--out", outPath})
	safe := readMap(t, outPath)
	if safe["status"] != "passed" || safe["findings_count"].(float64) != 0 {
		t.Fatalf("safe scan should pass: %#v", safe)
	}

	unsafeOut := filepath.Join(f.tmp, "unsafe-scan.json")
	var out, err bytes.Buffer
	if code := Run([]string{"safety", "scan", "--path", f.unsafeDocPath, "--out", unsafeOut}, &out, &err); code == 0 {
		t.Fatalf("unsafe scan unexpectedly passed")
	}
	if strings.Contains(err.String(), "super-secret") || strings.Contains(out.String(), "super-secret") {
		t.Fatalf("unsafe scan leaked matched value: stdout=%s stderr=%s", out.String(), err.String())
	}
	unsafe := readMap(t, unsafeOut)
	findings := unsafe["findings"].([]any)
	if len(findings) == 0 {
		t.Fatalf("unsafe scan missing findings: %#v", unsafe)
	}
	if _, ok := findings[0].(map[string]any)["matched_value"]; ok {
		t.Fatalf("finding must not expose matched value: %#v", findings[0])
	}

	assertRunFails(t, []string{"safety", "scan", "--path", f.safeDocPath, "--out", filepath.Join(f.root, "outside.json")}, "under tmp")
}

func TestRegressionRunCompareMonitorIncidentHoldReportAndWatch(t *testing.T) {
	f := newFixtureSet(t)

	runPath := filepath.Join(f.tmp, "regression-run.json")
	assertRunOK(t, []string{"run", "regression", "--suite", f.suitePath, "--out", runPath})
	run := readMap(t, runPath)
	if run["status"] != "passed" || run["mutates_live_state"] != false {
		t.Fatalf("unexpected regression run: %#v", run)
	}

	diffPath := filepath.Join(f.tmp, "regression-diff.json")
	assertRunOK(t, []string{"compare", "regression", "--baseline", f.baselinePath, "--run", runPath, "--out", diffPath})
	diff := readMap(t, diffPath)
	if diff["status"] != "passed" {
		t.Fatalf("regression diff should pass: %#v", diff)
	}

	safetyPath := filepath.Join(f.tmp, "readme-safety.json")
	assertRunOK(t, []string{"safety", "scan", "--path", f.safeDocPath, "--out", safetyPath})

	verdictPath := filepath.Join(f.tmp, "sentinel-verdict.json")
	assertRunOK(t, []string{"monitor", "evaluate", "--target", f.targetPath, "--baseline", f.baselinePath, "--safety", safetyPath, "--regression", diffPath, "--out", verdictPath})
	verdict := readMap(t, verdictPath)
	if verdict["verdict"] != "clear" || verdict["promoter_hold_required"] != false || verdict["mutates_live_state"] != false {
		t.Fatalf("clean monitor should be clear: %#v", verdict)
	}
	if blockers, ok := verdict["blockers"].([]any); !ok || len(blockers) != 0 {
		t.Fatalf("clear verdict blockers must be an empty array: %#v", verdict["blockers"])
	}
	if actions, ok := verdict["recommended_actions"].([]any); !ok || len(actions) != 0 {
		t.Fatalf("clear verdict recommended_actions must be an empty array: %#v", verdict["recommended_actions"])
	}

	incidentPath := filepath.Join(f.tmp, "incident-packet.json")
	assertRunOK(t, []string{"incident", "render", "--verdict", verdictPath, "--out", incidentPath})
	incident := readMap(t, incidentPath)
	if incident["incident_required"] != false || incident["mutates_live_state"] != false {
		t.Fatalf("clear verdict should render non-incident packet: %#v", incident)
	}

	holdPath := filepath.Join(f.tmp, "promoter-hold.json")
	assertRunOK(t, []string{"hold", "emit", "--verdict", verdictPath, "--out", holdPath})
	hold := readMap(t, holdPath)
	if hold["hold_required"] != false || hold["mutates_live_state"] != false {
		t.Fatalf("clear verdict should not require hold: %#v", hold)
	}

	reportPath := filepath.Join(f.tmp, "sentinel-report.md")
	assertRunOK(t, []string{"report", "render", "--verdict", verdictPath, "--incident", incidentPath, "--out", reportPath})
	reportBytes, err := os.ReadFile(reportPath)
	if err != nil {
		t.Fatal(err)
	}
	report := string(reportBytes)
	if !strings.Contains(report, "AO Sentinel Report") || !strings.Contains(report, "clear") {
		t.Fatalf("unexpected report:\n%s", report)
	}

	watchPath := filepath.Join(f.tmp, "watch-dry-run.json")
	assertRunOK(t, []string{"watch", "dry-run", "--target", f.targetPath, "--suite", f.suitePath, "--baseline", f.baselinePath, "--iterations", "1", "--out", watchPath})
	watch := readMap(t, watchPath)
	if watch["iterations"].(float64) != 1 || watch["mutates_live_state"] != false || watch["background_service_started"] != false {
		t.Fatalf("unexpected watch result: %#v", watch)
	}
}

func TestMonitorFailureVerdicts(t *testing.T) {
	f := newFixtureSet(t)

	unsafeScan := map[string]any{
		"schema_version":     "ao.sentinel.safety-scan.v0.1",
		"status":             "failed",
		"path":               "README.md",
		"findings_count":     1,
		"scanned_at_utc":     "2026-06-25T00:00:00Z",
		"findings":           []any{map[string]any{"detector": "password_assignment", "file": "README.md", "line": 1, "severity": "critical", "summary": "redacted"}},
		"matched_values":     []any{},
		"mutates_live_state": false,
	}
	regressionOK := map[string]any{
		"schema_version": "ao.sentinel.regression-diff.v0.1",
		"status":         "passed",
		"baseline_id":    "ao-stack-baseline",
		"run_id":         "run-ao-stack-regression",
		"case_results":   []any{},
		"blockers":       []any{},
		"summary":        map[string]any{"failed": 0},
	}
	incidentVerdictPath := filepath.Join(f.tmp, "incident-verdict.json")
	assertRunOK(t, []string{"monitor", "evaluate", "--target", f.targetPath, "--baseline", f.baselinePath, "--safety", f.writeJSON("unsafe-scan.json", unsafeScan), "--regression", f.writeJSON("regression-ok.json", regressionOK), "--out", incidentVerdictPath})
	incidentVerdict := readMap(t, incidentVerdictPath)
	if incidentVerdict["verdict"] != "incident" || incidentVerdict["promoter_hold_required"] != true || incidentVerdict["rollback_recommended"] != true {
		t.Fatalf("safety failure should create incident: %#v", incidentVerdict)
	}

	safetyOK := map[string]any{
		"schema_version": "ao.sentinel.safety-scan.v0.1",
		"status":         "passed",
		"path":           "README.md",
		"findings_count": 0,
		"scanned_at_utc": "2026-06-25T00:00:00Z",
		"findings":       []any{},
	}
	regressionFailed := map[string]any{
		"schema_version": "ao.sentinel.regression-diff.v0.1",
		"status":         "failed",
		"baseline_id":    "ao-stack-baseline",
		"run_id":         "run-ao-stack-regression",
		"case_results":   []any{},
		"blockers":       []any{map[string]any{"blocker_id": "regression_case_failed", "severity": "high", "reason": "case failed"}},
		"summary":        map[string]any{"failed": 1},
	}
	holdVerdictPath := filepath.Join(f.tmp, "hold-verdict.json")
	assertRunOK(t, []string{"monitor", "evaluate", "--target", f.targetPath, "--baseline", f.baselinePath, "--safety", f.writeJSON("safety-ok.json", safetyOK), "--regression", f.writeJSON("regression-failed.json", regressionFailed), "--out", holdVerdictPath})
	holdVerdict := readMap(t, holdVerdictPath)
	if holdVerdict["verdict"] != "hold" || holdVerdict["promoter_hold_required"] != true || holdVerdict["rollback_recommended"] != false {
		t.Fatalf("regression failure should create hold: %#v", holdVerdict)
	}
}

func TestCheckedInExamplesAreCovered(t *testing.T) {
	root := filepath.Join("..", "..")

	assertRunOK(t, []string{"target", "validate", "--target", filepath.Join(root, "examples/targets/valid/local-ao-stack.sentinel-target.json")})
	assertRunOK(t, []string{"baseline", "validate", "--baseline", filepath.Join(root, "examples/baselines/valid/ao-stack.sentinel-baseline.json")})
	assertRunOK(t, []string{"triage", "ci", "--signal", filepath.Join(root, "examples/triage/ci-contract-schema.sentinel-ci-signal.json"), "--out", filepath.Join(root, "tmp/checked-in-ci-triage.json")})
	assertRunOK(t, []string{"security", "review", "--request", filepath.Join(root, "examples/security/valid/ao-forge.security-review-request.json"), "--out", filepath.Join(root, "tmp/checked-in-security-review.json")})
	checkedInClearPath := filepath.Join(root, "tmp/checked-in-live-mutation-hold.json")
	assertRunOK(t, []string{"live-mutation", "hold", "--status", filepath.Join(root, "examples/live-mutation/valid/command-status.ready.json"), "--safety", filepath.Join(root, "examples/safety/valid/readme-safety.sentinel-scan.json"), "--regression", filepath.Join(root, "examples/regression/valid/ao-stack-regression-diff.json"), "--out", checkedInClearPath})
	checkedInClear := readMap(t, checkedInClearPath)
	if checkedInClear["status"] != "clear" || checkedInClear["mutation_class"] != "docs_only_multi_file" {
		t.Fatalf("checked-in live mutation fixture should clear with class readback: %#v", checkedInClear)
	}
	checkedInTestOnlyClearPath := filepath.Join(root, "tmp/checked-in-live-mutation-hold-test-only.json")
	assertRunOK(t, []string{"live-mutation", "hold", "--status", filepath.Join(root, "examples/live-mutation/valid/command-status.test-only-ready.json"), "--safety", filepath.Join(root, "examples/safety/valid/readme-safety.sentinel-scan.json"), "--regression", filepath.Join(root, "examples/regression/valid/ao-stack-regression-diff.json"), "--out", checkedInTestOnlyClearPath})
	checkedInTestOnlyClear := readMap(t, checkedInTestOnlyClearPath)
	testOnlyVerdict, ok := checkedInTestOnlyClear["class_hold_verdict"].(map[string]any)
	if checkedInTestOnlyClear["status"] != "clear" ||
		checkedInTestOnlyClear["mutation_class"] != "test_only" ||
		!ok ||
		testOnlyVerdict["test_coverage_status"] != "passed" {
		t.Fatalf("checked-in test_only fixture should clear with passed coverage: %#v", checkedInTestOnlyClear)
	}
	checkedInLowRiskClearPath := filepath.Join(root, "tmp/checked-in-live-mutation-hold-low-risk-code.json")
	assertRunOK(t, []string{"live-mutation", "hold", "--status", filepath.Join(root, "examples/live-mutation/valid/command-status.low-risk-code-ready.json"), "--safety", filepath.Join(root, "examples/safety/valid/readme-safety.sentinel-scan.json"), "--regression", filepath.Join(root, "examples/regression/valid/ao-stack-regression-diff.json"), "--out", checkedInLowRiskClearPath})
	checkedInLowRiskClear := readMap(t, checkedInLowRiskClearPath)
	lowRiskVerdict, ok := checkedInLowRiskClear["class_hold_verdict"].(map[string]any)
	if checkedInLowRiskClear["status"] != "clear" ||
		checkedInLowRiskClear["mutation_class"] != "low_risk_code" ||
		!ok ||
		lowRiskVerdict["test_coverage_status"] != "passed" ||
		lowRiskVerdict["file_class_status"] != "passed" ||
		lowRiskVerdict["source_files_changed"] != float64(1) ||
		lowRiskVerdict["test_files_changed"] != float64(1) {
		t.Fatalf("checked-in low_risk_code fixture should clear with coverage and file class readback: %#v", checkedInLowRiskClear)
	}
	assertRunOK(t, []string{"live-mutation", "hold", "--status", filepath.Join(root, "examples/live-mutation/invalid/command-status.missing-rollback.json"), "--safety", filepath.Join(root, "examples/safety/valid/readme-safety.sentinel-scan.json"), "--regression", filepath.Join(root, "examples/regression/valid/ao-stack-regression-diff.json"), "--out", filepath.Join(root, "tmp/checked-in-live-mutation-hold-blocked.json")})

	for _, tc := range []struct {
		name string
		want string
	}{
		{"command-status.test-coverage-insufficient.json", "test_coverage_insufficient"},
		{"command-status.rollback-proof-missing.json", "rollback_proof_missing"},
		{"command-status.diff-size-exceeded.json", "diff_size_exceeded"},
		{"command-status.file-class-forbidden.json", "file_class_forbidden"},
		{"command-status.evidence-stale.json", "evidence_stale"},
		{"command-status.ci-status-insufficient.json", "ci_status_insufficient"},
		{"command-status.low-risk-code.missing-test-change.json", "test_change_required"},
		{"command-status.low-risk-code.source-limit-exceeded.json", "source_file_limit_exceeded"},
		{"command-status.low-risk-code.forbidden-script.json", "forbidden_path_class_touched"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			outPath := filepath.Join(root, "tmp", strings.TrimSuffix(tc.name, ".json")+".hold.json")
			assertRunOK(t, []string{"live-mutation", "hold", "--status", filepath.Join(root, "examples/live-mutation/invalid", tc.name), "--safety", filepath.Join(root, "examples/safety/valid/readme-safety.sentinel-scan.json"), "--regression", filepath.Join(root, "examples/regression/valid/ao-stack-regression-diff.json"), "--out", outPath})
			hold := readMap(t, outPath)
			if hold["status"] != "hold" || hold["first_failing_check"] != tc.want {
				t.Fatalf("fixture %s should hold with %s: %#v", tc.name, tc.want, hold)
			}
		})
	}

	cases := []struct {
		name    string
		args    []string
		wantErr string
	}{
		{
			name:    "live mutation target",
			args:    []string{"target", "validate", "--target", filepath.Join(root, "examples/targets/invalid/live-mutation-target.json")},
			wantErr: "dry_run_only",
		},
		{
			name:    "stale baseline",
			args:    []string{"baseline", "validate", "--baseline", filepath.Join(root, "examples/baselines/invalid/stale-baseline.json")},
			wantErr: "stale baseline",
		},
		{
			name:    "missing command suite",
			args:    []string{"run", "regression", "--suite", filepath.Join(root, "examples/suites/invalid/missing-case-command.json"), "--out", filepath.Join(root, "tmp/invalid-run.json")},
			wantErr: "missing command",
		},
		{
			name:    "live mutation forbidden authority",
			args:    []string{"live-mutation", "hold", "--status", filepath.Join(root, "examples/live-mutation/invalid/command-status.forbidden-authority.json"), "--safety", filepath.Join(root, "examples/safety/valid/readme-safety.sentinel-scan.json"), "--regression", filepath.Join(root, "examples/regression/valid/ao-stack-regression-diff.json"), "--out", filepath.Join(root, "tmp/invalid-live-mutation-hold.json")},
			wantErr: "forbidden authority",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assertRunFails(t, tc.args, tc.wantErr)
		})
	}
}

type fixtureSet struct {
	root          string
	tmp           string
	target        map[string]any
	baseline      map[string]any
	suite         map[string]any
	targetPath    string
	baselinePath  string
	suitePath     string
	safeDocPath   string
	unsafeDocPath string
}

func newFixtureSet(t *testing.T) fixtureSet {
	t.Helper()
	root := t.TempDir()
	tmp := filepath.Join(root, "tmp")
	if err := os.MkdirAll(tmp, 0o755); err != nil {
		t.Fatal(err)
	}
	f := fixtureSet{root: root, tmp: tmp}
	f.target = map[string]any{
		"schema_version":     "ao.sentinel.target.v0.1",
		"target_id":          "local-ao-stack",
		"target_kind":        "active_stack",
		"active_stack_ref":   "examples/active/local-stack.json",
		"watch_scope":        []any{"README.md", "docs", "examples"},
		"watched_components": []any{"ao-foundry", "ao-promoter", "ao-covenant"},
		"platform_matrix":    []any{"ubuntu-latest", "macos-latest", "windows-latest"},
		"risk_budget":        map[string]any{"max_critical_findings": 0, "max_regression_failures": 0},
		"dry_run_only":       true,
	}
	f.targetPath = f.writeJSON("target.json", f.target)
	f.baseline = map[string]any{
		"schema_version":          "ao.sentinel.baseline.v0.1",
		"baseline_id":             "ao-stack-baseline",
		"target_id":               "local-ao-stack",
		"created_at_utc":          "2026-06-25T00:00:00Z",
		"expires_at_utc":          "2999-01-01T00:00:00Z",
		"expected_safety_status":  "passed",
		"regression_expectations": []any{map[string]any{"case_id": "help_lists_commands", "expected_status": "passed", "expected_output_contains": "sentinel", "max_duration_ms": 1000}},
		"performance_budgets":     map[string]any{"max_total_duration_ms": 1000, "allowed_failure_count": 0, "schema_drift_allowed": false},
		"contract_fingerprints":   map[string]any{"sentinel-target-v0.1": "fixture"},
		"approval_authority":      "fixture",
	}
	f.baselinePath = f.writeJSON("baseline.json", f.baseline)
	f.suite = map[string]any{
		"schema_version":          "ao.sentinel.regression-suite.v0.1",
		"suite_id":                "ao-stack-regression",
		"target_id":               "local-ao-stack",
		"default_timeout_seconds": 5,
		"dry_run_only":            true,
		"cases": []any{
			map[string]any{
				"case_id":                  "help_lists_commands",
				"command":                  "fixture://pass/sentinel help output",
				"expected_status":          "passed",
				"expected_output_contains": "sentinel",
				"max_duration_ms":          1000,
				"severity_on_failure":      "high",
			},
		},
	}
	f.suitePath = f.writeJSON("suite.json", f.suite)
	f.safeDocPath = filepath.Join(root, "safe.md")
	if err := os.WriteFile(f.safeDocPath, []byte("# Safe\nNo credentials here.\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	f.unsafeDocPath = filepath.Join(root, "unsafe.md")
	if err := os.WriteFile(f.unsafeDocPath, []byte("pass"+"word = \"fixture-value\"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	return f
}

func (f fixtureSet) writeJSON(name string, value any) string {
	path := filepath.Join(f.root, name)
	bytes, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		panic(err)
	}
	if err := os.WriteFile(path, append(bytes, '\n'), 0o644); err != nil {
		panic(err)
	}
	return path
}

func assertRunOK(t *testing.T, args []string) {
	t.Helper()
	var out, err bytes.Buffer
	if code := Run(args, &out, &err); code != 0 {
		t.Fatalf("Run(%v) code=%d stdout=%s stderr=%s", args, code, out.String(), err.String())
	}
}

func assertRunFails(t *testing.T, args []string, wantErr string) {
	t.Helper()
	var out, err bytes.Buffer
	if code := Run(args, &out, &err); code == 0 {
		t.Fatalf("Run(%v) unexpectedly succeeded stdout=%s stderr=%s", args, out.String(), err.String())
	}
	if !strings.Contains(err.String(), wantErr) {
		t.Fatalf("Run(%v) stderr missing %q:\n%s", args, wantErr, err.String())
	}
}

func cloneMap(t *testing.T, value map[string]any) map[string]any {
	t.Helper()
	bytes, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	var out map[string]any
	if err := json.Unmarshal(bytes, &out); err != nil {
		t.Fatal(err)
	}
	return out
}

func readMap(t *testing.T, path string) map[string]any {
	t.Helper()
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var out map[string]any
	if err := json.Unmarshal(body, &out); err != nil {
		t.Fatal(err)
	}
	return out
}
