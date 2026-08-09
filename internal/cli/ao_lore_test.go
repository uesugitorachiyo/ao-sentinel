package cli

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestAOLoreMonitoringClearIsReadbackOnly(t *testing.T) {
	f := newAOLoreFixture(t)
	out := filepath.Join(f.tmp, "clear.json")
	assertRunOK(t, []string{"ao-lore", "evaluate", "--baseline", f.baselinePath, "--observation", f.observationPath, "--out", out})
	verdict := readMap(t, out)
	if verdict["status"] != "clear" || verdict["promoter_hold_required"] != false {
		t.Fatalf("unexpected clear verdict: %#v", verdict)
	}
	for _, field := range []string{"mutates_live_state", "approves_work", "promotes_candidate", "releases_or_publishes"} {
		if verdict[field] != false {
			t.Fatalf("clear verdict widened authority through %s: %#v", field, verdict)
		}
	}
}

func TestAOLoreMonitoringMissingAndStaleBaselinesHold(t *testing.T) {
	t.Run("missing", func(t *testing.T) {
		f := newAOLoreFixture(t)
		observation := f.observation
		observation.BaselineSHA256 = ""
		observation.BaselineID = ""
		path := writeAOLoreJSON(t, f.root, "missing-observation.json", observation)
		out := filepath.Join(f.tmp, "missing.json")
		assertRunOK(t, []string{"ao-lore", "evaluate", "--observation", path, "--out", out})
		verdict := readMap(t, out)
		if verdict["status"] != "hold" || verdict["baseline_status"] != "missing" || !findingCode(verdict, "baseline_missing") {
			t.Fatalf("missing baseline did not hold: %#v", verdict)
		}
	})

	t.Run("stale", func(t *testing.T) {
		f := newAOLoreFixture(t)
		baseline := f.baseline
		baseline.ValidUntilUTC = "2026-08-02T00:00:00Z"
		baselinePath, digest := writeAOLoreJSONDigest(t, f.root, "stale-baseline.json", baseline)
		observation := f.observation
		observation.BaselineSHA256 = digest
		observation.ObservedAtUTC = "2026-08-03T00:00:00Z"
		observationPath := writeAOLoreJSON(t, f.root, "stale-observation.json", observation)
		out := filepath.Join(f.tmp, "stale.json")
		assertRunOK(t, []string{"ao-lore", "evaluate", "--baseline", baselinePath, "--observation", observationPath, "--out", out})
		verdict := readMap(t, out)
		if verdict["status"] != "hold" || !findingCode(verdict, "baseline_stale") {
			t.Fatalf("stale baseline did not hold: %#v", verdict)
		}
	})
}

func TestAOLoreMonitoringMakesDriftAndBudgetRegressionVisible(t *testing.T) {
	f := newAOLoreFixture(t)
	observation := f.observation
	observation.Metrics.ParserSelectionScoreBasisPoints = 8000
	observation.Metrics.ParseQualityThresholdBasisPoints = 7600
	observation.Metrics.EvidenceCoverageBasisPoints = 7000
	observation.Metrics.WastedTraversalNodes = 5
	observation.Metrics.NodesPerSatisfiedRequirementMilli = 2300
	observation.Metrics.TokensPerCoveragePointMilli = 7000
	path := writeAOLoreJSON(t, f.root, "regressed.json", observation)
	out := filepath.Join(f.tmp, "regressed-verdict.json")
	assertRunOK(t, []string{"ao-lore", "evaluate", "--baseline", f.baselinePath, "--observation", path, "--out", out})
	verdict := readMap(t, out)
	if verdict["status"] != "hold" {
		t.Fatalf("regression did not hold: %#v", verdict)
	}
	for _, code := range []string{"parser_score_drift", "threshold_drift", "coverage_regression", "wasted_traversal_regression", "nodes_per_requirement_regression", "tokens_per_coverage_regression"} {
		if !findingCode(verdict, code) {
			t.Fatalf("missing %s: %#v", code, verdict)
		}
	}
}

func TestAOLoreMonitoringUnauthorizedFallbackAndTraceMismatchIncident(t *testing.T) {
	f := newAOLoreFixture(t)
	observation := f.observation
	observation.RoleFallbacks = []AOLoreRoleFallback{{Role: "navigator", FromAdapter: "navigator-local", ToAdapter: "frontier-unlisted"}}
	observation.TraceIntegrity = false
	observation.TracePolicySHA256 = strings.Repeat("9", 64)
	path := writeAOLoreJSON(t, f.root, "incident.json", observation)
	out := filepath.Join(f.tmp, "incident-verdict.json")
	assertRunOK(t, []string{"ao-lore", "evaluate", "--baseline", f.baselinePath, "--observation", path, "--out", out})
	verdict := readMap(t, out)
	if verdict["status"] != "incident" || verdict["promoter_hold_required"] != true {
		t.Fatalf("trace/fallback breach was not incident: %#v", verdict)
	}
	for _, code := range []string{"unauthorized_role_fallback", "trace_integrity_failure", "trace_policy_mismatch"} {
		if !findingCode(verdict, code) {
			t.Fatalf("missing %s: %#v", code, verdict)
		}
	}
}

func TestAOLoreMonitoringRejectsDigestDriftDuplicateKeysAndUnsafeFiles(t *testing.T) {
	t.Run("baseline digest", func(t *testing.T) {
		f := newAOLoreFixture(t)
		observation := f.observation
		observation.BaselineSHA256 = strings.Repeat("0", 64)
		path := writeAOLoreJSON(t, f.root, "drift.json", observation)
		out := filepath.Join(f.tmp, "drift-verdict.json")
		assertRunFails(t, []string{"ao-lore", "evaluate", "--baseline", f.baselinePath, "--observation", path, "--out", out}, "baseline SHA-256 mismatch")
		if _, err := os.Stat(out); !os.IsNotExist(err) {
			t.Fatalf("digest failure wrote output: %v", err)
		}
	})

	t.Run("duplicate key", func(t *testing.T) {
		f := newAOLoreFixture(t)
		path := filepath.Join(f.root, "duplicate.json")
		body := []byte(`{"schema_version":"ao.sentinel.ao-lore-observation.v0.1","schema_version":"duplicate"}`)
		if err := os.WriteFile(path, body, 0o600); err != nil {
			t.Fatal(err)
		}
		assertRunFails(t, []string{"ao-lore", "evaluate", "--observation", path, "--out", filepath.Join(f.tmp, "duplicate-out.json")}, "duplicate key")
	})

	t.Run("symlink input", func(t *testing.T) {
		f := newAOLoreFixture(t)
		link := filepath.Join(f.root, "observation-link.json")
		if err := os.Symlink(f.observationPath, link); err != nil {
			t.Skipf("symlink unavailable: %v", err)
		}
		assertRunFails(t, []string{"ao-lore", "evaluate", "--baseline", f.baselinePath, "--observation", link, "--out", filepath.Join(f.tmp, "link-out.json")}, "regular non-link file")
	})

	t.Run("existing output", func(t *testing.T) {
		f := newAOLoreFixture(t)
		out := filepath.Join(f.tmp, "existing.json")
		if err := os.WriteFile(out, []byte("preserve"), 0o600); err != nil {
			t.Fatal(err)
		}
		assertRunFails(t, []string{"ao-lore", "evaluate", "--baseline", f.baselinePath, "--observation", f.observationPath, "--out", out}, "already exists")
		body, _ := os.ReadFile(out)
		if string(body) != "preserve" {
			t.Fatalf("existing output was overwritten: %q", body)
		}
	})
}

func TestAOLoreMonitoringCLIRejectsLooseFlagsAndIsDocumented(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := Run([]string{"ao-lore", "evaluate", "--observation", "o.json", "--out", "tmp/v.json", "--live"}, &stdout, &stderr); code == 0 || !strings.Contains(stderr.String(), "unknown flag") {
		t.Fatalf("loose flags accepted: code=%d stderr=%s", code, stderr.String())
	}
	stdout.Reset()
	stderr.Reset()
	if code := Run([]string{"--help"}, &stdout, &stderr); code != 0 || !strings.Contains(stdout.String(), "ao-lore evaluate") {
		t.Fatalf("AO Lore command missing from help: %s", stdout.String())
	}
}

type aoLoreFixture struct {
	root            string
	tmp             string
	baseline        AOLoreMonitoringBaseline
	observation     AOLoreMonitoringObservation
	baselinePath    string
	observationPath string
}

func newAOLoreFixture(t *testing.T) aoLoreFixture {
	t.Helper()
	root := t.TempDir()
	tmp := filepath.Join(root, "tmp")
	if err := os.Mkdir(tmp, 0o700); err != nil {
		t.Fatal(err)
	}
	baseline := AOLoreMonitoringBaseline{
		SchemaVersion: "ao.sentinel.ao-lore-baseline.v0.1", BaselineID: "ao-lore-baseline-v1", TargetID: "ao-lore-local",
		SourceHeadSHA256: strings.Repeat("1", 64), ProfileSHA256: strings.Repeat("2", 64), GeneratedAtUTC: "2026-08-01T00:00:00Z", ValidUntilUTC: "2026-09-01T00:00:00Z",
		Metrics:              AOLoreMonitoringMetrics{ParserSelectionScoreBasisPoints: 9000, ParseQualityThresholdBasisPoints: 8000, EvidenceCoverageBasisPoints: 8500, WastedTraversalNodes: 0, NodesPerSatisfiedRequirementMilli: 1000, TokensPerCoveragePointMilli: 4000},
		Tolerances:           AOLoreMonitoringTolerances{MaxParserScoreDropBasisPoints: 500, MaxThresholdChangeBasisPoints: 250, MaxCoverageDropBasisPoints: 500, MaxWastedTraversalIncrease: 1, MaxNodesPerRequirementIncreaseMilli: 500, MaxTokensPerCoverageIncreaseMilli: 1000},
		AllowedRoleFallbacks: map[string][]string{"parser": {"parser-local->parser-local-backup"}, "distiller": {}, "navigator": {"navigator-local->navigator-local-backup"}, "synthesizer": {}},
		TracePolicySHA256:    strings.Repeat("3", 64),
	}
	baselinePath, baselineDigest := writeAOLoreJSONDigest(t, root, "baseline.json", baseline)
	observation := AOLoreMonitoringObservation{
		SchemaVersion: "ao.sentinel.ao-lore-observation.v0.1", ObservationID: "ao-lore-observation-1", TargetID: baseline.TargetID, BaselineID: baseline.BaselineID,
		BaselineSHA256: baselineDigest, SourceHeadSHA256: strings.Repeat("4", 64), ProfileSHA256: baseline.ProfileSHA256, ObservedAtUTC: "2026-08-15T00:00:00Z",
		Metrics: baseline.Metrics, RoleFallbacks: []AOLoreRoleFallback{}, TracePolicySHA256: baseline.TracePolicySHA256, TraceIntegrity: true,
	}
	observationPath := writeAOLoreJSON(t, root, "observation.json", observation)
	return aoLoreFixture{root: root, tmp: tmp, baseline: baseline, observation: observation, baselinePath: baselinePath, observationPath: observationPath}
}

func writeAOLoreJSON(t *testing.T, dir, name string, value any) string {
	t.Helper()
	path, _ := writeAOLoreJSONDigest(t, dir, name, value)
	return path
}

func writeAOLoreJSONDigest(t *testing.T, dir, name string, value any) (string, string) {
	t.Helper()
	body, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	body = append(body, '\n')
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, body, 0o600); err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(body)
	return path, hex.EncodeToString(digest[:])
}

func findingCode(verdict map[string]any, code string) bool {
	for _, raw := range verdict["findings"].([]any) {
		if raw.(map[string]any)["code"] == code {
			return true
		}
	}
	return false
}
