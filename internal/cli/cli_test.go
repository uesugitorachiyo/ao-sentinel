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

func TestGatewayIntentPublicRiskFixtureScansClear(t *testing.T) {
	if err := os.MkdirAll("tmp", 0o755); err != nil {
		t.Fatal(err)
	}
	outPath := filepath.Join("tmp", "gateway-intent-public-risk-test.json")
	t.Cleanup(func() { _ = os.Remove(outPath) })
	assertRunOK(t, []string{
		"safety", "scan",
		"--path", filepath.Join("..", "..", "examples", "safety", "valid", "gateway-intent-public-risk.md"),
		"--out", outPath,
	})
	packet := readMap(t, outPath)
	if packet["schema_version"] != "ao.sentinel.safety-scan.v0.1" ||
		packet["status"] != "passed" ||
		packet["findings_count"].(float64) != 0 ||
		packet["mutates_live_state"] != false {
		t.Fatalf("gateway intent fixture should scan clear without authority widening: %#v", packet)
	}
}

func TestProducesSentinelVerdictToPromoterInputVector(t *testing.T) {
	root := filepath.Join("..", "..")
	vectorPath := filepath.Join(root, "examples", "compatibility", "sentinel-verdict-to-promoter-input-v0.1.json")
	body, err := os.ReadFile(vectorPath)
	if err != nil {
		t.Fatal(err)
	}
	var vector map[string]any
	if err := json.Unmarshal(body, &vector); err != nil {
		t.Fatal(err)
	}
	if vector["schema_version"] != "ao.compatibility.sentinel-verdict-to-promoter-input-vector.v1" ||
		vector["edge"] != "ao-sentinel.sentinel_verdict -> ao-promoter.promotion_input" {
		t.Fatalf("unexpected Sentinel compatibility vector identity: %#v", vector)
	}
	verdict := vector["sentinel_verdict"].(map[string]any)
	if verdict["schema_version"] != "ao.sentinel.verdict.v0.1" ||
		verdict["verdict"] != "clear" ||
		verdict["promoter_hold_required"] != false {
		t.Fatalf("unexpected Sentinel verdict: %#v", verdict)
	}
	expected := vector["expected_promoter_promotion_input"].(map[string]any)
	if expected["schema_version"] != "ao.promoter.promotion-input.v1" ||
		expected["source_verdict_schema"] != verdict["schema_version"] ||
		expected["promotion_input_status"] != "accepted" {
		t.Fatalf("unexpected Promoter expectation: %#v", expected)
	}
	boundaries := vector["authority_boundaries"].(map[string]any)
	for _, key := range []string{"promotion_requested", "promotion_granted", "safe_to_execute", "executes_work", "mutates_repositories", "calls_providers", "releases_or_deploys"} {
		if boundaries[key] != false {
			t.Fatalf("Sentinel vector boundary %s = %#v, want false", key, boundaries[key])
		}
	}
}

func TestGatewayIntentAuthorityWideningFixtureFails(t *testing.T) {
	if err := os.MkdirAll("tmp", 0o755); err != nil {
		t.Fatal(err)
	}
	outPath := filepath.Join("tmp", "gateway-intent-authority-widening-test.json")
	t.Cleanup(func() { _ = os.Remove(outPath) })
	assertRunFails(t, []string{
		"safety", "scan",
		"--path", filepath.Join("..", "..", "examples", "safety", "invalid", "gateway-intent-authority-widening.md"),
		"--out", outPath,
	}, "safety scan failed")
	packet := readMap(t, outPath)
	if packet["status"] != "failed" || packet["findings_count"].(float64) == 0 {
		t.Fatalf("gateway intent authority-widening fixture should fail: %#v", packet)
	}
	findings, ok := packet["findings"].([]any)
	if !ok || len(findings) == 0 {
		t.Fatalf("gateway intent authority-widening fixture missing findings: %#v", packet)
	}
	first, ok := findings[0].(map[string]any)
	if !ok || first["detector"] != "gateway_intent_authority_widening" {
		t.Fatalf("unexpected gateway intent finding: %#v", findings)
	}
}

func TestSchedulerRecoveryPublicRiskFixtureScansClear(t *testing.T) {
	if err := os.MkdirAll("tmp", 0o755); err != nil {
		t.Fatal(err)
	}
	outPath := filepath.Join("tmp", "scheduler-recovery-public-risk-test.json")
	t.Cleanup(func() { _ = os.Remove(outPath) })
	assertRunOK(t, []string{
		"safety", "scan",
		"--path", filepath.Join("..", "..", "examples", "safety", "valid", "scheduler-recovery-public-risk.md"),
		"--out", outPath,
	})
	packet := readMap(t, outPath)
	if packet["schema_version"] != "ao.sentinel.safety-scan.v0.1" ||
		packet["status"] != "passed" ||
		packet["findings_count"].(float64) != 0 ||
		packet["mutates_live_state"] != false {
		t.Fatalf("scheduler recovery fixture should scan clear without authority widening: %#v", packet)
	}
}

func TestSchedulerRecoveryAuthorityWideningFixtureFails(t *testing.T) {
	if err := os.MkdirAll("tmp", 0o755); err != nil {
		t.Fatal(err)
	}
	outPath := filepath.Join("tmp", "scheduler-recovery-authority-widening-test.json")
	t.Cleanup(func() { _ = os.Remove(outPath) })
	assertRunFails(t, []string{
		"safety", "scan",
		"--path", filepath.Join("..", "..", "examples", "safety", "invalid", "scheduler-recovery-authority-widening.md"),
		"--out", outPath,
	}, "safety scan failed")
	packet := readMap(t, outPath)
	if packet["status"] != "failed" || packet["findings_count"].(float64) == 0 {
		t.Fatalf("scheduler recovery authority-widening fixture should fail: %#v", packet)
	}
	findings, ok := packet["findings"].([]any)
	if !ok || len(findings) == 0 {
		t.Fatalf("scheduler recovery authority-widening fixture missing findings: %#v", packet)
	}
	first, ok := findings[0].(map[string]any)
	if !ok || first["detector"] != "scheduler_recovery_authority_widening" {
		t.Fatalf("unexpected scheduler recovery finding: %#v", findings)
	}
}

func TestSchedulerWakeupAuthorityWideningFixtureFails(t *testing.T) {
	if err := os.MkdirAll("tmp", 0o755); err != nil {
		t.Fatal(err)
	}
	outPath := filepath.Join("tmp", "scheduler-wakeup-authority-widening-test.json")
	t.Cleanup(func() { _ = os.Remove(outPath) })
	assertRunFails(t, []string{
		"safety", "scan",
		"--path", filepath.Join("..", "..", "examples", "safety", "invalid", "scheduler-wakeup-authority-widening.md"),
		"--out", outPath,
	}, "safety scan failed")
	packet := readMap(t, outPath)
	if packet["status"] != "failed" || packet["findings_count"].(float64) == 0 {
		t.Fatalf("scheduler wakeup authority-widening fixture should fail: %#v", packet)
	}
	findings, ok := packet["findings"].([]any)
	if !ok || len(findings) == 0 {
		t.Fatalf("scheduler wakeup authority-widening fixture missing findings: %#v", packet)
	}
	first, ok := findings[0].(map[string]any)
	if !ok || first["detector"] != "scheduler_wakeup_authority_widening" {
		t.Fatalf("unexpected scheduler wakeup finding: %#v", findings)
	}
}

func TestSchedulerPublicDocAuthorityVariantFixtureFails(t *testing.T) {
	if err := os.MkdirAll("tmp", 0o755); err != nil {
		t.Fatal(err)
	}
	outPath := filepath.Join("tmp", "scheduler-public-doc-authority-variant-test.json")
	t.Cleanup(func() { _ = os.Remove(outPath) })
	assertRunFails(t, []string{
		"safety", "scan",
		"--path", filepath.Join("..", "..", "examples", "safety", "invalid", "scheduler-public-doc-authority-variant.md"),
		"--out", outPath,
	}, "safety scan failed")
	packet := readMap(t, outPath)
	if packet["status"] != "failed" || packet["findings_count"].(float64) == 0 {
		t.Fatalf("scheduler public-doc authority variant fixture should fail: %#v", packet)
	}
	findings, ok := packet["findings"].([]any)
	if !ok || len(findings) == 0 {
		t.Fatalf("scheduler public-doc authority variant fixture missing findings: %#v", packet)
	}
	first, ok := findings[0].(map[string]any)
	if !ok || first["detector"] != "scheduler_public_doc_authority_variant" {
		t.Fatalf("unexpected scheduler public-doc authority finding: %#v", findings)
	}
}

func TestGatewayPublicDocAuthorityVariantFixtureFails(t *testing.T) {
	if err := os.MkdirAll("tmp", 0o755); err != nil {
		t.Fatal(err)
	}
	outPath := filepath.Join("tmp", "gateway-public-doc-authority-variant-test.json")
	t.Cleanup(func() { _ = os.Remove(outPath) })
	assertRunFails(t, []string{
		"safety", "scan",
		"--path", filepath.Join("..", "..", "examples", "safety", "invalid", "gateway-public-doc-authority-variant.md"),
		"--out", outPath,
	}, "safety scan failed")
	packet := readMap(t, outPath)
	if packet["status"] != "failed" || packet["findings_count"].(float64) == 0 {
		t.Fatalf("gateway public-doc authority variant fixture should fail: %#v", packet)
	}
	findings, ok := packet["findings"].([]any)
	if !ok || len(findings) == 0 {
		t.Fatalf("gateway public-doc authority variant fixture missing findings: %#v", packet)
	}
	first, ok := findings[0].(map[string]any)
	if !ok || first["detector"] != "gateway_public_doc_authority_variant" {
		t.Fatalf("unexpected gateway public-doc authority finding: %#v", findings)
	}
}

func TestGatewayFreshnessStaleLanguageFixtureFails(t *testing.T) {
	if err := os.MkdirAll("tmp", 0o755); err != nil {
		t.Fatal(err)
	}
	outPath := filepath.Join("tmp", "gateway-freshness-stale-language-test.json")
	t.Cleanup(func() { _ = os.Remove(outPath) })
	assertRunFails(t, []string{
		"safety", "scan",
		"--path", filepath.Join("..", "..", "examples", "safety", "invalid", "gateway-freshness-stale-language.md"),
		"--out", outPath,
	}, "safety scan failed")
	packet := readMap(t, outPath)
	if packet["status"] != "failed" || packet["findings_count"].(float64) == 0 {
		t.Fatalf("gateway freshness stale-language fixture should fail: %#v", packet)
	}
	findings, ok := packet["findings"].([]any)
	if !ok || len(findings) == 0 {
		t.Fatalf("gateway freshness stale-language fixture missing findings: %#v", packet)
	}
	first, ok := findings[0].(map[string]any)
	if !ok || first["detector"] != "gateway_freshness_stale_language" {
		t.Fatalf("unexpected gateway freshness finding: %#v", findings)
	}
}

func TestGatewayFreshnessPublicRiskFixtureScansClear(t *testing.T) {
	if err := os.MkdirAll("tmp", 0o755); err != nil {
		t.Fatal(err)
	}
	outPath := filepath.Join("tmp", "gateway-freshness-public-risk-test.json")
	t.Cleanup(func() { _ = os.Remove(outPath) })
	assertRunOK(t, []string{
		"safety", "scan",
		"--path", filepath.Join("..", "..", "examples", "safety", "valid", "gateway-freshness-public-risk.md"),
		"--out", outPath,
	})
	packet := readMap(t, outPath)
	if packet["schema_version"] != "ao.sentinel.safety-scan.v0.1" ||
		packet["status"] != "passed" ||
		packet["findings_count"].(float64) != 0 ||
		packet["mutates_live_state"] != false {
		t.Fatalf("gateway freshness fixture should scan clear without authority widening: %#v", packet)
	}
}

func TestLedgerCompactionPublicRiskFixtureScansClear(t *testing.T) {
	if err := os.MkdirAll("tmp", 0o755); err != nil {
		t.Fatal(err)
	}
	outPath := filepath.Join("tmp", "ledger-compaction-public-risk-test.json")
	t.Cleanup(func() { _ = os.Remove(outPath) })
	assertRunOK(t, []string{
		"safety", "scan",
		"--path", filepath.Join("..", "..", "examples", "safety", "valid", "ledger-compaction-public-risk.md"),
		"--out", outPath,
	})
	packet := readMap(t, outPath)
	if packet["schema_version"] != "ao.sentinel.safety-scan.v0.1" ||
		packet["status"] != "passed" ||
		packet["findings_count"].(float64) != 0 ||
		packet["mutates_live_state"] != false {
		t.Fatalf("ledger compaction fixture should scan clear without authority widening: %#v", packet)
	}
}

func TestLedgerCompactionAuthorityWideningFixtureFails(t *testing.T) {
	if err := os.MkdirAll("tmp", 0o755); err != nil {
		t.Fatal(err)
	}
	outPath := filepath.Join("tmp", "ledger-compaction-authority-widening-test.json")
	t.Cleanup(func() { _ = os.Remove(outPath) })
	assertRunFails(t, []string{
		"safety", "scan",
		"--path", filepath.Join("..", "..", "examples", "safety", "invalid", "ledger-compaction-authority-widening.md"),
		"--out", outPath,
	}, "safety scan failed")
	packet := readMap(t, outPath)
	if packet["status"] != "failed" || packet["findings_count"].(float64) == 0 {
		t.Fatalf("ledger compaction authority-widening fixture should fail: %#v", packet)
	}
	findings, ok := packet["findings"].([]any)
	if !ok || len(findings) == 0 {
		t.Fatalf("ledger compaction authority-widening fixture missing findings: %#v", packet)
	}
	first, ok := findings[0].(map[string]any)
	if !ok || first["detector"] != "ledger_compaction_authority_widening" {
		t.Fatalf("unexpected ledger compaction finding: %#v", findings)
	}
}

func TestPublicBetaWordingLintProfileScansClear(t *testing.T) {
	if err := os.MkdirAll("tmp", 0o755); err != nil {
		t.Fatal(err)
	}
	outPath := filepath.Join("tmp", "public-beta-wording-test.json")
	t.Cleanup(func() { _ = os.Remove(outPath) })
	assertRunOK(t, []string{
		"safety", "scan",
		"--profile", "public-beta",
		"--path", filepath.Join("..", "..", "examples", "safety", "valid", "public-beta-wording.md"),
		"--out", outPath,
	})
	packet := readMap(t, outPath)
	if packet["schema_version"] != "ao.sentinel.safety-scan.v0.1" ||
		packet["profile"] != "public-beta" ||
		packet["status"] != "passed" ||
		packet["findings_count"].(float64) != 0 ||
		packet["mutates_live_state"] != false {
		t.Fatalf("public beta wording fixture should scan clear: %#v", packet)
	}
}

func TestPublicBetaWordingLintProfileFailsAuthorityOverclaim(t *testing.T) {
	if err := os.MkdirAll("tmp", 0o755); err != nil {
		t.Fatal(err)
	}
	outPath := filepath.Join("tmp", "public-beta-authority-overclaim-test.json")
	t.Cleanup(func() { _ = os.Remove(outPath) })
	assertRunFails(t, []string{
		"safety", "scan",
		"--profile", "public-beta",
		"--path", filepath.Join("..", "..", "examples", "safety", "invalid", "public-beta-authority-overclaim.md"),
		"--out", outPath,
	}, "safety scan failed")
	packet := readMap(t, outPath)
	if packet["profile"] != "public-beta" || packet["status"] != "failed" || packet["findings_count"].(float64) == 0 {
		t.Fatalf("public beta authority overclaim fixture should fail: %#v", packet)
	}
	findings, ok := packet["findings"].([]any)
	if !ok || len(findings) == 0 {
		t.Fatalf("public beta authority overclaim fixture missing findings: %#v", packet)
	}
	seen := map[string]bool{}
	for _, item := range findings {
		finding, ok := item.(map[string]any)
		if !ok {
			t.Fatalf("unexpected public beta finding shape: %#v", item)
		}
		detector, _ := finding["detector"].(string)
		seen[detector] = true
	}
	if !seen["public_beta_authority_overclaim"] {
		t.Fatalf("public beta overclaim detector did not fire: %#v", findings)
	}
}

func TestPublicBetaWordingLintProfileFixtureIsPlanningOnly(t *testing.T) {
	profile := readMap(t, filepath.Join("..", "..", "examples", "safety", "valid", "public-beta-wording-lint-profile.json"))
	if profile["schema_version"] != "ao.sentinel.safety-lint-profile.v0.1" ||
		profile["profile"] != "public-beta" ||
		profile["status"] != "planning_only" ||
		profile["source_recommendation_rank"].(float64) != 38 ||
		profile["safety_gate"] != "planning_only_no_provider_no_release" ||
		profile["no_promotion_requested"] != true ||
		profile["provider_calls_allowed"] != false ||
		profile["credential_use_allowed"] != false ||
		profile["release_or_publish_allowed"] != false ||
		profile["claims_authority_advance"] != false ||
		profile["rsi_remains_denied"] != true {
		t.Fatalf("public beta lint profile lost planning-only boundary: %#v", profile)
	}
	detectors, ok := profile["required_detectors"].([]any)
	if !ok || len(detectors) == 0 {
		t.Fatalf("public beta lint profile missing required detectors: %#v", profile)
	}
	seen := map[string]bool{}
	for _, item := range detectors {
		detector, _ := item.(string)
		seen[detector] = true
	}
	if !seen["public_beta_authority_overclaim"] {
		t.Fatalf("public beta lint profile does not require overclaim detector: %#v", detectors)
	}
}

func TestMonth4ControlledLoopWordingProfileScansClear(t *testing.T) {
	if err := os.MkdirAll("tmp", 0o755); err != nil {
		t.Fatal(err)
	}
	outPath := filepath.Join("tmp", "month4-controlled-loop-wording-test.json")
	t.Cleanup(func() { _ = os.Remove(outPath) })
	assertRunOK(t, []string{
		"safety", "scan",
		"--profile", "month4-controlled-loop",
		"--path", filepath.Join("..", "..", "examples", "safety", "valid", "month4-controlled-loop-wording.md"),
		"--out", outPath,
	})
	packet := readMap(t, outPath)
	if packet["schema_version"] != "ao.sentinel.safety-scan.v0.1" ||
		packet["profile"] != "month4-controlled-loop" ||
		packet["status"] != "passed" ||
		packet["findings_count"].(float64) != 0 ||
		packet["mutates_live_state"] != false {
		t.Fatalf("Month 4 controlled loop wording fixture should scan clear: %#v", packet)
	}
}

func TestMonth4ControlledLoopWordingProfileFailsOverclaimsAndMissingBoundaries(t *testing.T) {
	if err := os.MkdirAll("tmp", 0o755); err != nil {
		t.Fatal(err)
	}
	outPath := filepath.Join("tmp", "month4-controlled-loop-overclaim-test.json")
	t.Cleanup(func() { _ = os.Remove(outPath) })
	assertRunFails(t, []string{
		"safety", "scan",
		"--profile", "month4-controlled-loop",
		"--path", filepath.Join("..", "..", "examples", "safety", "invalid", "month4-controlled-loop-overclaim.md"),
		"--out", outPath,
	}, "safety scan failed")
	packet := readMap(t, outPath)
	if packet["profile"] != "month4-controlled-loop" || packet["status"] != "failed" || packet["findings_count"].(float64) == 0 {
		t.Fatalf("Month 4 controlled loop overclaim fixture should fail: %#v", packet)
	}
	findings, ok := packet["findings"].([]any)
	if !ok || len(findings) == 0 {
		t.Fatalf("Month 4 controlled loop fixture missing findings: %#v", packet)
	}
	seen := map[string]bool{}
	for _, item := range findings {
		finding, ok := item.(map[string]any)
		if !ok {
			t.Fatalf("unexpected Month 4 finding shape: %#v", item)
		}
		detector, _ := finding["detector"].(string)
		seen[detector] = true
	}
	for _, want := range []string{
		"month4_rsi_activation_overclaim",
		"month4_live_self_modification_overclaim",
		"month4_external_beta_overclaim",
		"month4_promotion_overclaim",
		"month4_provider_pilot_overclaim",
		"month4_missing_dry_run_boundary",
		"month4_missing_rsi_denied_boundary",
	} {
		if !seen[want] {
			t.Fatalf("Month 4 wording profile missing detector %q in findings: %#v", want, findings)
		}
	}
}

func TestMonth4ControlledLoopWordingProfileFixtureDefinesBoundaries(t *testing.T) {
	profile := readMap(t, filepath.Join("..", "..", "examples", "safety", "valid", "month4-controlled-loop-wording-lint-profile.json"))
	if profile["schema_version"] != "ao.sentinel.safety-lint-profile.v0.1" ||
		profile["profile"] != "month4-controlled-loop" ||
		profile["status"] != "dry_run_only" ||
		profile["safety_gate"] != "controlled_self_improvement_dry_run_only" ||
		profile["dry_run_only_required"] != true ||
		profile["rsi_remains_denied"] != true ||
		profile["live_self_modification_allowed"] != false ||
		profile["provider_calls_allowed"] != false ||
		profile["promotion_requested"] != false ||
		profile["external_beta_launched"] != false {
		t.Fatalf("Month 4 controlled loop lint profile lost dry-run boundary: %#v", profile)
	}
	detectors, ok := profile["required_detectors"].([]any)
	if !ok || len(detectors) == 0 {
		t.Fatalf("Month 4 controlled loop lint profile missing required detectors: %#v", profile)
	}
	seen := map[string]bool{}
	for _, item := range detectors {
		detector, _ := item.(string)
		seen[detector] = true
	}
	for _, want := range []string{
		"month4_rsi_activation_overclaim",
		"month4_live_self_modification_overclaim",
		"month4_external_beta_overclaim",
		"month4_promotion_overclaim",
		"month4_provider_pilot_overclaim",
		"month4_missing_dry_run_boundary",
		"month4_missing_rsi_denied_boundary",
	} {
		if !seen[want] {
			t.Fatalf("Month 4 controlled loop lint profile does not require detector %q: %#v", want, detectors)
		}
	}
}

func TestMonth5OperatorWorkflowWordingProfileScansClear(t *testing.T) {
	if err := os.MkdirAll("tmp", 0o755); err != nil {
		t.Fatal(err)
	}
	outPath := filepath.Join("tmp", "month5-operator-workflow-wording-test.json")
	t.Cleanup(func() { _ = os.Remove(outPath) })
	assertRunOK(t, []string{
		"safety", "scan",
		"--profile", "month5-operator-workflow",
		"--path", filepath.Join("..", "..", "examples", "safety", "valid", "month5-operator-workflow-wording.md"),
		"--out", outPath,
	})
	packet := readMap(t, outPath)
	if packet["schema_version"] != "ao.sentinel.safety-scan.v0.1" ||
		packet["profile"] != "month5-operator-workflow" ||
		packet["status"] != "passed" ||
		packet["findings_count"].(float64) != 0 ||
		packet["mutates_live_state"] != false {
		t.Fatalf("Month 5 operator workflow wording fixture should scan clear: %#v", packet)
	}
}

func TestMonth5OperatorWorkflowWordingProfileFailsOverclaimsAndMissingBoundaries(t *testing.T) {
	if err := os.MkdirAll("tmp", 0o755); err != nil {
		t.Fatal(err)
	}
	outPath := filepath.Join("tmp", "month5-operator-workflow-overclaim-test.json")
	t.Cleanup(func() { _ = os.Remove(outPath) })
	assertRunFails(t, []string{
		"safety", "scan",
		"--profile", "month5-operator-workflow",
		"--path", filepath.Join("..", "..", "examples", "safety", "invalid", "month5-operator-workflow-overclaim.md"),
		"--out", outPath,
	}, "safety scan failed")
	packet := readMap(t, outPath)
	if packet["profile"] != "month5-operator-workflow" || packet["status"] != "failed" || packet["findings_count"].(float64) == 0 {
		t.Fatalf("Month 5 operator workflow overclaim fixture should fail: %#v", packet)
	}
	findings, ok := packet["findings"].([]any)
	if !ok || len(findings) == 0 {
		t.Fatalf("Month 5 operator workflow fixture missing findings: %#v", packet)
	}
	seen := map[string]bool{}
	for _, item := range findings {
		finding, ok := item.(map[string]any)
		if !ok {
			t.Fatalf("unexpected Month 5 finding shape: %#v", item)
		}
		detector, _ := finding["detector"].(string)
		seen[detector] = true
	}
	for _, want := range []string{
		"month5_rsi_activation_overclaim",
		"month5_live_self_modification_overclaim",
		"month5_external_beta_overclaim",
		"month5_promotion_overclaim",
		"month5_provider_pilot_overclaim",
		"month5_release_overclaim",
		"month5_missing_operator_workflow_boundary",
		"month5_missing_rsi_denied_boundary",
	} {
		if !seen[want] {
			t.Fatalf("Month 5 wording profile missing detector %q in findings: %#v", want, findings)
		}
	}
}

func TestMonth5OperatorWorkflowWordingProfileFixtureDefinesBoundaries(t *testing.T) {
	profile := readMap(t, filepath.Join("..", "..", "examples", "safety", "valid", "month5-operator-workflow-wording-lint-profile.json"))
	if profile["schema_version"] != "ao.sentinel.safety-lint-profile.v0.1" ||
		profile["profile"] != "month5-operator-workflow" ||
		profile["status"] != "operator_workflow_only" ||
		profile["safety_gate"] != "operator_workflow_no_release_no_provider_no_rsi" ||
		profile["operator_workflow_required"] != true ||
		profile["rsi_remains_denied"] != true ||
		profile["live_self_modification_allowed"] != false ||
		profile["provider_calls_allowed"] != false ||
		profile["release_or_publish_allowed"] != false ||
		profile["promotion_requested"] != false ||
		profile["external_beta_launched"] != false {
		t.Fatalf("Month 5 operator workflow lint profile lost boundary: %#v", profile)
	}
	detectors, ok := profile["required_detectors"].([]any)
	if !ok || len(detectors) == 0 {
		t.Fatalf("Month 5 operator workflow lint profile missing required detectors: %#v", profile)
	}
	seen := map[string]bool{}
	for _, item := range detectors {
		detector, _ := item.(string)
		seen[detector] = true
	}
	for _, want := range []string{
		"month5_rsi_activation_overclaim",
		"month5_live_self_modification_overclaim",
		"month5_external_beta_overclaim",
		"month5_promotion_overclaim",
		"month5_provider_pilot_overclaim",
		"month5_release_overclaim",
		"month5_missing_operator_workflow_boundary",
		"month5_missing_rsi_denied_boundary",
	} {
		if !seen[want] {
			t.Fatalf("Month 5 operator workflow lint profile does not require detector %q: %#v", want, detectors)
		}
	}
}

func TestMonth6ReleaseReadinessWordingProfileScansClear(t *testing.T) {
	if err := os.MkdirAll("tmp", 0o755); err != nil {
		t.Fatal(err)
	}
	outPath := filepath.Join("tmp", "month6-release-readiness-wording-test.json")
	t.Cleanup(func() { _ = os.Remove(outPath) })
	assertRunOK(t, []string{
		"safety", "scan",
		"--profile", "month6-release-readiness",
		"--path", filepath.Join("..", "..", "examples", "safety", "valid", "month6-release-readiness-wording.md"),
		"--out", outPath,
	})
	packet := readMap(t, outPath)
	if packet["schema_version"] != "ao.sentinel.safety-scan.v0.1" ||
		packet["profile"] != "month6-release-readiness" ||
		packet["status"] != "passed" ||
		packet["findings_count"].(float64) != 0 ||
		packet["mutates_live_state"] != false {
		t.Fatalf("Month 6 release-readiness wording fixture should scan clear: %#v", packet)
	}
}

func TestMonth6ReleaseReadinessWordingProfileFailsOverclaimsAndMissingBoundaries(t *testing.T) {
	if err := os.MkdirAll("tmp", 0o755); err != nil {
		t.Fatal(err)
	}
	outPath := filepath.Join("tmp", "month6-release-readiness-overclaim-test.json")
	t.Cleanup(func() { _ = os.Remove(outPath) })
	assertRunFails(t, []string{
		"safety", "scan",
		"--profile", "month6-release-readiness",
		"--path", filepath.Join("..", "..", "examples", "safety", "invalid", "month6-release-readiness-overclaim.md"),
		"--out", outPath,
	}, "safety scan failed")
	packet := readMap(t, outPath)
	if packet["profile"] != "month6-release-readiness" || packet["status"] != "failed" || packet["findings_count"].(float64) == 0 {
		t.Fatalf("Month 6 release-readiness overclaim fixture should fail: %#v", packet)
	}
	findings, ok := packet["findings"].([]any)
	if !ok || len(findings) == 0 {
		t.Fatalf("Month 6 release-readiness fixture missing findings: %#v", packet)
	}
	seen := map[string]bool{}
	for _, item := range findings {
		finding, ok := item.(map[string]any)
		if !ok {
			t.Fatalf("unexpected Month 6 finding shape: %#v", item)
		}
		detector, _ := finding["detector"].(string)
		seen[detector] = true
	}
	for _, want := range []string{
		"month6_rsi_activation_overclaim",
		"month6_live_self_modification_overclaim",
		"month6_external_beta_overclaim",
		"month6_promotion_overclaim",
		"month6_provider_pilot_overclaim",
		"month6_release_overclaim",
		"month6_missing_no_release_boundary",
		"month6_missing_current_pair_boundary",
		"month6_missing_rsi_denied_boundary",
	} {
		if !seen[want] {
			t.Fatalf("Month 6 wording profile missing detector %q in findings: %#v", want, findings)
		}
	}
}

func TestMonth6ReleaseReadinessWordingProfileFixtureDefinesBoundaries(t *testing.T) {
	profile := readMap(t, filepath.Join("..", "..", "examples", "safety", "valid", "month6-release-readiness-wording-lint-profile.json"))
	if profile["schema_version"] != "ao.sentinel.safety-lint-profile.v0.1" ||
		profile["profile"] != "month6-release-readiness" ||
		profile["status"] != "no_release_readiness_only" ||
		profile["safety_gate"] != "no_release_no_provider_no_external_beta_no_promotion_no_rsi" ||
		profile["no_release_decision_required"] != true ||
		profile["current_pair_required"] != true ||
		profile["rsi_remains_denied"] != true ||
		profile["live_self_modification_allowed"] != false ||
		profile["provider_calls_allowed"] != false ||
		profile["release_or_publish_allowed"] != false ||
		profile["promotion_requested"] != false ||
		profile["external_beta_launched"] != false {
		t.Fatalf("Month 6 release-readiness lint profile lost boundary: %#v", profile)
	}
	detectors, ok := profile["required_detectors"].([]any)
	if !ok || len(detectors) == 0 {
		t.Fatalf("Month 6 release-readiness lint profile missing required detectors: %#v", profile)
	}
	seen := map[string]bool{}
	for _, item := range detectors {
		detector, _ := item.(string)
		seen[detector] = true
	}
	for _, want := range []string{
		"month6_rsi_activation_overclaim",
		"month6_live_self_modification_overclaim",
		"month6_external_beta_overclaim",
		"month6_promotion_overclaim",
		"month6_provider_pilot_overclaim",
		"month6_release_overclaim",
		"month6_missing_no_release_boundary",
		"month6_missing_current_pair_boundary",
		"month6_missing_rsi_denied_boundary",
	} {
		if !seen[want] {
			t.Fatalf("Month 6 release-readiness lint profile does not require detector %q: %#v", want, detectors)
		}
	}
}

func TestAdoptionMonth1GateReadinessWordingProfileScansClear(t *testing.T) {
	if err := os.MkdirAll("tmp", 0o755); err != nil {
		t.Fatal(err)
	}
	outPath := filepath.Join("tmp", "adoption-month1-gate-readiness-wording-test.json")
	t.Cleanup(func() { _ = os.Remove(outPath) })
	assertRunOK(t, []string{
		"safety", "scan",
		"--profile", "adoption-month1-gate-readiness",
		"--path", filepath.Join("..", "..", "examples", "safety", "valid", "adoption-month1-gate-readiness-wording.md"),
		"--out", outPath,
	})
	packet := readMap(t, outPath)
	if packet["profile"] != "adoption-month1-gate-readiness" ||
		packet["status"] != "passed" ||
		packet["findings_count"].(float64) != 0 ||
		packet["mutates_live_state"] != false {
		t.Fatalf("Month 1 gate readiness wording should pass: %#v", packet)
	}
}

func TestAdoptionMonth1GateReadinessWordingProfileFailsOverclaimsAndMissingBoundaries(t *testing.T) {
	if err := os.MkdirAll("tmp", 0o755); err != nil {
		t.Fatal(err)
	}
	outPath := filepath.Join("tmp", "adoption-month1-gate-readiness-overclaim-test.json")
	t.Cleanup(func() { _ = os.Remove(outPath) })
	assertRunFails(t, []string{
		"safety", "scan",
		"--profile", "adoption-month1-gate-readiness",
		"--path", filepath.Join("..", "..", "examples", "safety", "invalid", "adoption-month1-gate-readiness-overclaim.md"),
		"--out", outPath,
	}, "safety scan failed")
	packet := readMap(t, outPath)
	findings := packet["findings"].([]any)
	seen := map[string]bool{}
	for _, finding := range findings {
		entry := finding.(map[string]any)
		seen[entry["detector"].(string)] = true
	}
	for _, want := range []string{
		"adoption_month1_gate_activation_overclaim",
		"adoption_month1_rsi_activation_overclaim",
		"adoption_month1_external_beta_overclaim",
		"adoption_month1_promotion_overclaim",
		"adoption_month1_provider_pilot_overclaim",
		"adoption_month1_release_overclaim",
		"adoption_month1_fully_autonomous_overclaim",
		"adoption_month1_missing_current_pair_boundary",
		"adoption_month1_missing_gate_ready_not_active_boundary",
		"adoption_month1_missing_rsi_denied_boundary",
	} {
		if !seen[want] {
			t.Fatalf("Month 1 gate readiness wording profile missing detector %q in findings: %#v", want, findings)
		}
	}
}

func TestAdoptionMonth1GateReadinessWordingProfileFixtureDefinesBoundaries(t *testing.T) {
	profile := readMap(t, filepath.Join("..", "..", "examples", "safety", "valid", "adoption-month1-gate-readiness-wording-lint-profile.json"))
	if profile["schema_version"] != "ao.sentinel.safety-lint-profile.v0.1" ||
		profile["profile"] != "adoption-month1-gate-readiness" ||
		profile["status"] != "gate_ready_not_active" ||
		profile["safety_gate"] != "gate_readiness_no_activation_no_provider_no_release_no_promotion_no_rsi" ||
		profile["gate_readiness_required"] != true ||
		profile["gate_activation_allowed"] != false ||
		profile["rsi_remains_denied"] != true ||
		profile["release_or_publish_allowed"] != false ||
		profile["promotion_requested"] != false ||
		profile["external_beta_launched"] != false {
		t.Fatalf("Month 1 gate readiness lint profile lost boundary: %#v", profile)
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
	checkedInMultiRepoClearPath := filepath.Join(root, "tmp/checked-in-live-mutation-hold-multi-repo-low-risk.json")
	assertRunOK(t, []string{"live-mutation", "hold", "--status", filepath.Join(root, "examples/live-mutation/valid/command-status.multi-repo-low-risk-ready.json"), "--safety", filepath.Join(root, "examples/safety/valid/readme-safety.sentinel-scan.json"), "--regression", filepath.Join(root, "examples/regression/valid/ao-stack-regression-diff.json"), "--out", checkedInMultiRepoClearPath})
	checkedInMultiRepoClear := readMap(t, checkedInMultiRepoClearPath)
	multiRepoVerdict, ok := checkedInMultiRepoClear["class_hold_verdict"].(map[string]any)
	if checkedInMultiRepoClear["status"] != "clear" ||
		checkedInMultiRepoClear["mutation_class"] != "multi_repo_low_risk" ||
		!ok ||
		multiRepoVerdict["multi_repo_dependency_status"] != "passed" ||
		multiRepoVerdict["per_repo_rollback_status"] != "ready" ||
		multiRepoVerdict["per_repo_ci_status"] != "passed" ||
		multiRepoVerdict["repo_state_status"] != "fresh" {
		t.Fatalf("checked-in multi_repo_low_risk fixture should clear with per-repo readback: %#v", checkedInMultiRepoClear)
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
		{"command-status.multi-repo-low-risk.missing-dependency.json", "multi_repo_dependency_missing"},
		{"command-status.multi-repo-low-risk.stale-repo-state.json", "multi_repo_repo_state_stale"},
		{"command-status.multi-repo-low-risk.partial-rollback.json", "multi_repo_rollback_incomplete"},
		{"command-status.multi-repo-low-risk.missing-ci.json", "multi_repo_ci_incomplete"},
		{"command-status.multi-repo-low-risk.kill-switch-disarmed.json", "kill_switch_not_armed"},
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

func TestEvidenceFreshnessWarningPanelFixtureMatchesStaleHoldReadback(t *testing.T) {
	root := filepath.Join("..", "..")
	outPath := filepath.Join(root, "tmp", "checked-in-evidence-stale-panel-hold.json")
	assertRunOK(t, []string{
		"live-mutation", "hold",
		"--status", filepath.Join(root, "examples/live-mutation/invalid/command-status.evidence-stale.json"),
		"--safety", filepath.Join(root, "examples/safety/valid/readme-safety.sentinel-scan.json"),
		"--regression", filepath.Join(root, "examples/regression/valid/ao-stack-regression-diff.json"),
		"--out", outPath,
	})
	hold := readMap(t, outPath)
	panel := readMap(t, filepath.Join(root, "examples/live-mutation/valid/evidence-freshness-warning-panel.json"))
	warnings, ok := panel["warnings"].([]any)
	if !ok || len(warnings) != 1 {
		t.Fatalf("warning panel should contain exactly one warning: %#v", panel)
	}
	warning, ok := warnings[0].(map[string]any)
	if !ok {
		t.Fatalf("warning panel warning is malformed: %#v", warnings[0])
	}
	classVerdict, ok := hold["class_hold_verdict"].(map[string]any)
	if panel["schema_version"] != "ao.sentinel.evidence-freshness-warning-panel.v0.1" ||
		panel["status"] != "warning" ||
		panel["first_failing_check"] != hold["first_failing_check"] ||
		panel["evidence_freshness_status"] != classVerdict["evidence_freshness_status"] ||
		panel["hold_required"] != hold["hold_required"] ||
		panel["promoter_hold_required"] != hold["promoter_hold_required"] ||
		panel["mutates_live_state"] != false ||
		panel["executes_work"] != false ||
		panel["approves_work"] != false ||
		panel["provider_calls_allowed"] != false ||
		panel["release_or_publish_allowed"] != false ||
		!ok {
		t.Fatalf("warning panel does not match stale hold readback:\npanel=%#v\nhold=%#v", panel, hold)
	}
	if warning["warning_id"] != "evidence_stale" ||
		warning["severity"] != "high" ||
		warning["source"] != "evidence_freshness" ||
		warning["recommended_action"] != "refresh class evidence and record a future expiry" {
		t.Fatalf("warning panel should expose the stale evidence operator action: %#v", warning)
	}
}

func TestMissionRiskWordingDiffViewerFixturePreservesSafetyBoundary(t *testing.T) {
	root := filepath.Join("..", "..")
	viewer := readMap(t, filepath.Join(root, "examples", "safety", "valid", "mission-risk-wording-diff-viewer.json"))
	if viewer["schema_version"] != "ao.sentinel.mission-risk-wording-diff-viewer.v0.1" ||
		viewer["status"] != "ready" ||
		viewer["source_recommendation_rank"] != float64(26) ||
		viewer["source_recommendation_task"] != "Add mission risk wording diff viewer fixture" ||
		viewer["no_promotion_requested"] != true ||
		viewer["provider_calls_allowed"] != false ||
		viewer["credential_use_allowed"] != false ||
		viewer["release_or_publish_allowed"] != false ||
		viewer["direct_main_mutation"] != false ||
		viewer["claims_authority_advance"] != false ||
		viewer["rsi_remains_denied"] != true {
		t.Fatalf("mission risk wording diff viewer lost governance boundary: %#v", viewer)
	}
	before, ok := viewer["before"].(map[string]any)
	if !ok || before["unsafe_text_redacted"] != true || before["raw_text_sha256"] == "" {
		t.Fatalf("viewer should redact stale source wording and pin its digest: %#v", before)
	}
	after, ok := viewer["after"].(map[string]any)
	if !ok || after["approved_public_safe_wording"] == "" {
		t.Fatalf("viewer should expose approved safe replacement wording: %#v", after)
	}
	findings, ok := viewer["findings"].([]any)
	if !ok || len(findings) < 2 {
		t.Fatalf("viewer should carry detector findings: %#v", viewer["findings"])
	}
	seen := map[string]bool{}
	for _, item := range findings {
		finding, ok := item.(map[string]any)
		if !ok {
			t.Fatalf("finding is not an object: %#v", item)
		}
		detector, _ := finding["detector"].(string)
		seen[detector] = true
		if finding["severity"] == "" || finding["replacement_ref"] == "" || finding["raw_match_redacted"] != true {
			t.Fatalf("finding should be redacted and replacement-bound: %#v", finding)
		}
	}
	for _, detector := range []string{"gateway_freshness_stale_language", "mission_risk_authority_overclaim"} {
		if !seen[detector] {
			t.Fatalf("viewer missing detector %q: %#v", detector, findings)
		}
	}
	controls, ok := viewer["viewer_controls"].(map[string]any)
	if !ok || controls["show_raw_unsafe_text"] != false || controls["show_redacted_diff_only"] != true {
		t.Fatalf("viewer controls should default to redacted diff only: %#v", controls)
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
