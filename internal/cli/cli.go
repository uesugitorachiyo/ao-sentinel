package cli

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

var allowedTargetKinds = setOf("active_stack", "candidate_stack", "component", "release_candidate")

type mutationClassPolicy struct {
	MaxFiles                int
	MaxLinesChanged         int
	MaxSourceFiles          int
	MaxTestFiles            int
	RequireTestFileWithCode bool
	AllowedPaths            []string
	ForbiddenPaths          []string
	AllowedFileClass        map[string]bool
	CoverageRequired        bool
	RequiresCI              bool
}

var mutationClassPolicies = map[string]mutationClassPolicy{
	"docs_only_single_file": {
		MaxFiles:         1,
		MaxLinesChanged:  80,
		AllowedPaths:     []string{"README.md", "docs/", "examples/"},
		ForbiddenPaths:   []string{".github/", "cmd/", "internal/", "pkg/", "scripts/"},
		AllowedFileClass: setOf("docs"),
		RequiresCI:       true,
	},
	"docs_only_multi_file": {
		MaxFiles:         2,
		MaxLinesChanged:  160,
		AllowedPaths:     []string{"README.md", "docs/", "examples/"},
		ForbiddenPaths:   []string{".github/", "cmd/", "internal/", "pkg/", "scripts/"},
		AllowedFileClass: setOf("docs"),
		RequiresCI:       true,
	},
	"docs_config_only": {
		MaxFiles:         3,
		MaxLinesChanged:  200,
		AllowedPaths:     []string{"README.md", "docs/", "examples/", ".github/"},
		ForbiddenPaths:   []string{"cmd/", "internal/", "pkg/"},
		AllowedFileClass: setOf("docs", "config"),
		RequiresCI:       true,
	},
	"test_only": {
		MaxFiles:         1,
		MaxLinesChanged:  120,
		AllowedPaths:     []string{"tests/", "test/", "testdata/", "examples/", "*_test.go", ".test.", ".spec."},
		ForbiddenPaths:   []string{"cmd/", "internal/cli/cli.go", "pkg/"},
		AllowedFileClass: setOf("test"),
		CoverageRequired: true,
		RequiresCI:       true,
	},
	"low_risk_code": {
		MaxFiles:                2,
		MaxLinesChanged:         160,
		MaxSourceFiles:          1,
		MaxTestFiles:            1,
		RequireTestFileWithCode: true,
		AllowedPaths:            []string{"internal/", "pkg/", "crates/ao2-core/src/", "crates/ao2-core/tests/"},
		ForbiddenPaths:          []string{".github/", "cmd/", "config/", "configs/", "deploy/", "docs/", "examples/", "infra/", "release/", "releases/", "schemas/", "scripts/", "secrets/", "terraform/", "go.mod", "go.sum", "Cargo.toml", "Cargo.lock"},
		AllowedFileClass:        setOf("code", "test"),
		CoverageRequired:        true,
		RequiresCI:              true,
	},
	"multi_repo_low_risk": {
		MaxFiles:         4,
		MaxLinesChanged:  240,
		AllowedPaths:     []string{"cmd/", "internal/", "pkg/", "scripts/", "tests/", "testdata/", "docs/"},
		ForbiddenPaths:   []string{"deploy/", "infra/", "terraform/", "secrets/"},
		AllowedFileClass: setOf("code", "test", "docs"),
		CoverageRequired: true,
		RequiresCI:       true,
	},
	"complex_repo_mutation": {
		MaxFiles:         12,
		MaxLinesChanged:  1200,
		AllowedPaths:     []string{"cmd/", "internal/", "pkg/", "scripts/", "tests/", "testdata/", "docs/", "examples/"},
		ForbiddenPaths:   []string{"secrets/"},
		AllowedFileClass: setOf("code", "test", "docs", "config"),
		CoverageRequired: true,
		RequiresCI:       true,
	},
}

type blocker struct {
	BlockerID         string `json:"blocker_id"`
	Severity          string `json:"severity"`
	Reason            string `json:"reason"`
	Source            string `json:"source"`
	RecommendedAction string `json:"recommended_action"`
}

// Run executes the AO Sentinel CLI and returns a process-style exit code.
func Run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 || args[0] == "--help" || args[0] == "-h" {
		printHelp(stdout)
		return 0
	}
	var err error
	switch args[0] {
	case "target":
		err = runTarget(args[1:], stdout)
	case "baseline":
		err = runBaseline(args[1:], stdout)
	case "safety":
		err = runSafety(args[1:], stdout)
	case "run":
		err = runRun(args[1:], stdout)
	case "compare":
		err = runCompare(args[1:], stdout)
	case "monitor":
		err = runMonitor(args[1:], stdout)
	case "incident":
		err = runIncident(args[1:], stdout)
	case "hold":
		err = runHold(args[1:], stdout)
	case "report":
		err = runReport(args[1:], stdout)
	case "watch":
		err = runWatch(args[1:], stdout)
	case "triage":
		err = runTriage(args[1:], stdout)
	case "security":
		err = runSecurity(args[1:], stdout)
	case "live-mutation":
		err = runLiveMutation(args[1:], stdout)
	default:
		err = fmt.Errorf("unknown command %q", args[0])
	}
	if err != nil {
		fmt.Fprintln(stderr, "error:", err)
		return 1
	}
	return 0
}

func printHelp(w io.Writer) {
	fmt.Fprintln(w, `AO Sentinel monitors safety and regression health for the AO stack.

Usage:
  sentinel target validate --target <json>
  sentinel baseline validate --baseline <json>
  sentinel safety scan --path <path> --out <json> [--profile default|public-beta|month4-controlled-loop|month5-operator-workflow|month6-release-readiness|adoption-month1-gate-readiness|adoption-month2-operator-drill|adoption-month3-evidence-maintenance|adoption-month5-support-readiness|github-issue-month2-authenticity|github-issue-month3-repair]
  sentinel run regression --suite <json> --out <json>
  sentinel compare regression --baseline <json> --run <json> --out <json>
  sentinel monitor evaluate --target <json> --baseline <json> --safety <json> --regression <json> --out <json>
  sentinel incident render --verdict <json> --out <json>
  sentinel hold emit --verdict <json> --out <json>
  sentinel report render --verdict <json> --incident <json> --out <markdown>
  sentinel watch dry-run --target <json> --suite <json> --baseline <json> --iterations <n> --out <json>
  sentinel triage ci --signal <json> --out <json>
  sentinel security review --request <json> --out <json>
  sentinel live-mutation hold --status <json> --safety <json> --regression <json> --out <json>

Commands: target baseline safety run compare monitor incident hold report watch triage security live-mutation`)
}

func runTarget(args []string, stdout io.Writer) error {
	if len(args) == 0 || args[0] != "validate" {
		return errors.New("target command requires validate")
	}
	path, err := flagValue(args[1:], "--target")
	if err != nil {
		return err
	}
	target, err := readJSONMap(path)
	if err != nil {
		return err
	}
	if err := validateTarget(target); err != nil {
		return err
	}
	fmt.Fprintln(stdout, "target validation: passed")
	return nil
}

func runBaseline(args []string, stdout io.Writer) error {
	if len(args) == 0 || args[0] != "validate" {
		return errors.New("baseline command requires validate")
	}
	path, err := flagValue(args[1:], "--baseline")
	if err != nil {
		return err
	}
	baseline, err := readJSONMap(path)
	if err != nil {
		return err
	}
	if err := validateBaseline(baseline); err != nil {
		return err
	}
	fmt.Fprintln(stdout, "baseline validation: passed")
	return nil
}

func runSafety(args []string, stdout io.Writer) error {
	if len(args) == 0 || args[0] != "scan" {
		return errors.New("safety command requires scan")
	}
	path, err := flagValue(args[1:], "--path")
	if err != nil {
		return err
	}
	out, err := flagValue(args[1:], "--out")
	if err != nil {
		return err
	}
	profile, err := optionalFlagValue(args[1:], "--profile", "default")
	if err != nil {
		return err
	}
	if profile != "default" && profile != "public-beta" && profile != "month4-controlled-loop" && profile != "month5-operator-workflow" && profile != "month6-release-readiness" && profile != "adoption-month1-gate-readiness" && profile != "adoption-month2-operator-drill" && profile != "adoption-month3-evidence-maintenance" && profile != "adoption-month5-support-readiness" && profile != "github-issue-month2-authenticity" && profile != "github-issue-month3-repair" {
		return fmt.Errorf("unknown safety profile %q", profile)
	}
	if err := requireTmpOutput(out); err != nil {
		return err
	}
	result, err := safetyScanWithProfile(path, profile)
	if err != nil {
		return err
	}
	if err := writeJSON(out, result); err != nil {
		return err
	}
	if result["status"] == "failed" {
		return errors.New("safety scan failed")
	}
	fmt.Fprintln(stdout, "safety scan: passed")
	return nil
}

func runRun(args []string, stdout io.Writer) error {
	if len(args) == 0 || args[0] != "regression" {
		return errors.New("run command requires regression")
	}
	suitePath, err := flagValue(args[1:], "--suite")
	if err != nil {
		return err
	}
	out, err := flagValue(args[1:], "--out")
	if err != nil {
		return err
	}
	if err := requireTmpOutput(out); err != nil {
		return err
	}
	suite, err := readJSONMap(suitePath)
	if err != nil {
		return err
	}
	run, err := runRegressionSuite(suite)
	if err != nil {
		return err
	}
	if err := writeJSON(out, run); err != nil {
		return err
	}
	fmt.Fprintf(stdout, "regression run: %s\n", run["status"])
	return nil
}

func runCompare(args []string, stdout io.Writer) error {
	if len(args) == 0 || args[0] != "regression" {
		return errors.New("compare command requires regression")
	}
	baselinePath, err := flagValue(args[1:], "--baseline")
	if err != nil {
		return err
	}
	runPath, err := flagValue(args[1:], "--run")
	if err != nil {
		return err
	}
	out, err := flagValue(args[1:], "--out")
	if err != nil {
		return err
	}
	if err := requireTmpOutput(out); err != nil {
		return err
	}
	baseline, err := readJSONMap(baselinePath)
	if err != nil {
		return err
	}
	if err := validateBaseline(baseline); err != nil {
		return err
	}
	run, err := readJSONMap(runPath)
	if err != nil {
		return err
	}
	diff, err := compareRegression(baseline, run)
	if err != nil {
		return err
	}
	if err := writeJSON(out, diff); err != nil {
		return err
	}
	fmt.Fprintf(stdout, "regression diff: %s\n", diff["status"])
	return nil
}

func runMonitor(args []string, stdout io.Writer) error {
	if len(args) == 0 || args[0] != "evaluate" {
		return errors.New("monitor command requires evaluate")
	}
	targetPath, err := flagValue(args[1:], "--target")
	if err != nil {
		return err
	}
	baselinePath, err := flagValue(args[1:], "--baseline")
	if err != nil {
		return err
	}
	safetyPath, err := flagValue(args[1:], "--safety")
	if err != nil {
		return err
	}
	regressionPath, err := flagValue(args[1:], "--regression")
	if err != nil {
		return err
	}
	out, err := flagValue(args[1:], "--out")
	if err != nil {
		return err
	}
	if err := requireTmpOutput(out); err != nil {
		return err
	}
	target, err := readJSONMap(targetPath)
	if err != nil {
		return err
	}
	baseline, err := readJSONMap(baselinePath)
	if err != nil {
		return err
	}
	safety, err := readJSONMap(safetyPath)
	if err != nil {
		return err
	}
	regression, err := readJSONMap(regressionPath)
	if err != nil {
		return err
	}
	verdict, err := evaluateMonitor(target, baseline, safety, regression)
	if err != nil {
		return err
	}
	if err := writeJSON(out, verdict); err != nil {
		return err
	}
	fmt.Fprintf(stdout, "sentinel verdict: %s\n", verdict["verdict"])
	return nil
}

func runIncident(args []string, stdout io.Writer) error {
	if len(args) == 0 || args[0] != "render" {
		return errors.New("incident command requires render")
	}
	verdictPath, err := flagValue(args[1:], "--verdict")
	if err != nil {
		return err
	}
	out, err := flagValue(args[1:], "--out")
	if err != nil {
		return err
	}
	if err := requireTmpOutput(out); err != nil {
		return err
	}
	verdict, err := readJSONMap(verdictPath)
	if err != nil {
		return err
	}
	incident, err := renderIncident(verdict)
	if err != nil {
		return err
	}
	if err := writeJSON(out, incident); err != nil {
		return err
	}
	fmt.Fprintf(stdout, "incident packet: %v\n", incident["incident_required"])
	return nil
}

func runHold(args []string, stdout io.Writer) error {
	if len(args) == 0 || args[0] != "emit" {
		return errors.New("hold command requires emit")
	}
	verdictPath, err := flagValue(args[1:], "--verdict")
	if err != nil {
		return err
	}
	out, err := flagValue(args[1:], "--out")
	if err != nil {
		return err
	}
	if err := requireTmpOutput(out); err != nil {
		return err
	}
	verdict, err := readJSONMap(verdictPath)
	if err != nil {
		return err
	}
	hold, err := emitHold(verdict)
	if err != nil {
		return err
	}
	if err := writeJSON(out, hold); err != nil {
		return err
	}
	fmt.Fprintf(stdout, "promoter hold: %v\n", hold["hold_required"])
	return nil
}

func runReport(args []string, stdout io.Writer) error {
	if len(args) == 0 || args[0] != "render" {
		return errors.New("report command requires render")
	}
	verdictPath, err := flagValue(args[1:], "--verdict")
	if err != nil {
		return err
	}
	incidentPath, err := flagValue(args[1:], "--incident")
	if err != nil {
		return err
	}
	out, err := flagValue(args[1:], "--out")
	if err != nil {
		return err
	}
	if err := requireTmpOutput(out); err != nil {
		return err
	}
	verdict, err := readJSONMap(verdictPath)
	if err != nil {
		return err
	}
	incident, err := readJSONMap(incidentPath)
	if err != nil {
		return err
	}
	body := renderReport(verdict, incident)
	if err := os.MkdirAll(filepath.Dir(out), 0o755); err != nil {
		return err
	}
	if err := os.WriteFile(out, []byte(body), 0o644); err != nil {
		return err
	}
	fmt.Fprintf(stdout, "sentinel report: %s\n", out)
	return nil
}

func runWatch(args []string, stdout io.Writer) error {
	if len(args) == 0 || args[0] != "dry-run" {
		return errors.New("watch command requires dry-run")
	}
	targetPath, err := flagValue(args[1:], "--target")
	if err != nil {
		return err
	}
	suitePath, err := flagValue(args[1:], "--suite")
	if err != nil {
		return err
	}
	baselinePath, err := flagValue(args[1:], "--baseline")
	if err != nil {
		return err
	}
	iterationsText, err := flagValue(args[1:], "--iterations")
	if err != nil {
		return err
	}
	out, err := flagValue(args[1:], "--out")
	if err != nil {
		return err
	}
	if err := requireTmpOutput(out); err != nil {
		return err
	}
	iterations, err := strconv.Atoi(iterationsText)
	if err != nil || iterations < 1 {
		return errors.New("iterations must be a positive integer")
	}
	target, err := readJSONMap(targetPath)
	if err != nil {
		return err
	}
	baseline, err := readJSONMap(baselinePath)
	if err != nil {
		return err
	}
	suite, err := readJSONMap(suitePath)
	if err != nil {
		return err
	}
	if err := validateTarget(target); err != nil {
		return err
	}
	if err := validateBaseline(baseline); err != nil {
		return err
	}
	if err := validateSuite(suite); err != nil {
		return err
	}
	run, err := runRegressionSuite(suite)
	if err != nil {
		return err
	}
	diff, err := compareRegression(baseline, run)
	if err != nil {
		return err
	}
	safety := map[string]any{
		"schema_version":     "ao.sentinel.safety-scan.v0.1",
		"status":             "passed",
		"path":               "watch-dry-run",
		"findings_count":     0,
		"findings":           []any{},
		"scanned_at_utc":     nowUTC(),
		"mutates_live_state": false,
	}
	verdict, err := evaluateMonitor(target, baseline, safety, diff)
	if err != nil {
		return err
	}
	result := map[string]any{
		"schema_version":             "ao.sentinel.watch-run.v0.1",
		"status":                     "dry_run_complete",
		"target_id":                  stringField(target, "target_id"),
		"iterations":                 iterations,
		"cycles":                     []any{map[string]any{"cycle": 1, "verdict": verdict["verdict"], "regression_status": diff["status"]}},
		"mutates_live_state":         false,
		"background_service_started": false,
		"live_providers_called":      false,
		"completed_at_utc":           nowUTC(),
	}
	if err := writeJSON(out, result); err != nil {
		return err
	}
	fmt.Fprintln(stdout, "watch dry-run: complete")
	return nil
}

func runTriage(args []string, stdout io.Writer) error {
	if len(args) == 0 || args[0] != "ci" {
		return errors.New("triage command requires ci")
	}
	signalPath, err := flagValue(args[1:], "--signal")
	if err != nil {
		return err
	}
	out, err := flagValue(args[1:], "--out")
	if err != nil {
		return err
	}
	if err := requireTmpOutput(out); err != nil {
		return err
	}
	signal, err := readJSONMap(signalPath)
	if err != nil {
		return err
	}
	packet, err := triageCISignal(signal)
	if err != nil {
		return err
	}
	if err := writeJSON(out, packet); err != nil {
		return err
	}
	fmt.Fprintf(stdout, "ci triage: %s root_cause=%s\n", packet["status"], packet["root_cause"])
	return nil
}

func runSecurity(args []string, stdout io.Writer) error {
	if len(args) == 0 || args[0] != "review" {
		return errors.New("security command requires review")
	}
	requestPath, err := flagValue(args[1:], "--request")
	if err != nil {
		return err
	}
	out, err := flagValue(args[1:], "--out")
	if err != nil {
		return err
	}
	if err := requireTmpOutput(out); err != nil {
		return err
	}
	request, err := readJSONMap(requestPath)
	if err != nil {
		return err
	}
	packet, err := reviewSecurityRequest(request)
	if err != nil {
		return err
	}
	if err := writeJSON(out, packet); err != nil {
		return err
	}
	fmt.Fprintf(stdout, "security review: %s findings=%d\n", packet["status"], len(asAnySlice(packet["findings"])))
	return nil
}

func runLiveMutation(args []string, stdout io.Writer) error {
	if len(args) == 0 || args[0] != "hold" {
		return errors.New("live-mutation command requires hold")
	}
	statusPath, err := flagValue(args[1:], "--status")
	if err != nil {
		return err
	}
	safetyPath, err := flagValue(args[1:], "--safety")
	if err != nil {
		return err
	}
	regressionPath, err := flagValue(args[1:], "--regression")
	if err != nil {
		return err
	}
	out, err := flagValue(args[1:], "--out")
	if err != nil {
		return err
	}
	if err := requireTmpOutput(out); err != nil {
		return err
	}
	status, err := readJSONMap(statusPath)
	if err != nil {
		return err
	}
	safety, err := readJSONMap(safetyPath)
	if err != nil {
		return err
	}
	regression, err := readJSONMap(regressionPath)
	if err != nil {
		return err
	}
	hold, err := evaluateLiveMutationHold(statusPath, status, safetyPath, safety, regressionPath, regression)
	if err != nil {
		return err
	}
	if err := writeJSON(out, hold); err != nil {
		return err
	}
	fmt.Fprintf(stdout, "live-mutation hold: %v\n", hold["hold_required"])
	return nil
}

func evaluateLiveMutationHold(statusPath string, status map[string]any, safetyPath string, safety map[string]any, regressionPath string, regression map[string]any) (map[string]any, error) {
	if stringField(status, "schema_version") != "ao.command.live-mutation-status.v0.1" {
		return nil, errors.New("unknown live-mutation status schema_version")
	}
	if stringField(safety, "schema_version") != "ao.sentinel.safety-scan.v0.1" {
		return nil, errors.New("unknown safety scan schema_version")
	}
	if stringField(regression, "schema_version") != "ao.sentinel.regression-diff.v0.1" {
		return nil, errors.New("unknown regression diff schema_version")
	}
	if err := rejectUnsafeLiveMutationPayload("live_mutation_status", status); err != nil {
		return nil, err
	}
	if err := rejectUnsafeLiveMutationPayload("safety", safety); err != nil {
		return nil, err
	}
	if err := rejectUnsafeLiveMutationPayload("regression", regression); err != nil {
		return nil, err
	}

	blockers := []blocker{}
	if stringField(status, "status") != "ready" {
		blockers = append(blockers, newBlocker("live_mutation_status_not_ready", "high", "AO Command live-mutation readback is not ready", "ao-command", "repair live-mutation evidence before requesting authority"))
	}
	if stringField(status, "kill_switch_state") != "armed" {
		blockers = append(blockers, newBlocker("kill_switch_not_armed", "critical", "operator kill-switch is not armed", "kill-switch", "arm the operator kill-switch before live mutation can proceed"))
	}
	if stringField(safety, "status") != "passed" || numberField(safety, "findings_count") > 0 {
		blockers = append(blockers, newBlocker("public_safety_failed", "critical", "public safety evidence is missing or failed", "safety", "clear public-safety findings before live mutation can proceed"))
	}
	if stringField(regression, "status") != "passed" {
		blockers = append(blockers, newBlocker("regression_failed", "high", "regression evidence is missing or failed", "regression", "repair regression evidence before live mutation can proceed"))
	}
	artifacts := liveMutationArtifactMap(status)
	requiredArtifacts := liveMutationRequiredArtifacts(stringField(status, "mutation_class"))
	for _, required := range requiredArtifacts {
		artifact, seen := artifacts[required.name]
		if !seen {
			blockers = append(blockers, newBlocker(required.name+"_missing", required.severity, "required live-mutation evidence is missing", required.name, required.action))
			continue
		}
		if stringField(artifact, "sha256") == "" {
			blockers = append(blockers, newBlocker(required.name+"_digest_missing", "high", "required artifact digest is missing", required.name, "regenerate digest-bound live-mutation readback"))
		}
		if stringField(artifact, "status") != required.readyStatus {
			blockers = append(blockers, newBlocker(required.name+"_not_ready", required.severity, "required live-mutation artifact is not ready", required.name, required.action))
		}
	}
	classBlockers, classVerdict := evaluateMutationClassHold(status)
	blockers = append(blockers, classBlockers...)

	verdict := "clear"
	holdRequired := false
	rollbackRecommended := false
	firstFailingCheck := ""
	if len(blockers) > 0 {
		verdict = "hold"
		holdRequired = true
		firstFailingCheck = blockers[0].BlockerID
		for _, b := range blockers {
			if b.Severity == "critical" {
				rollbackRecommended = true
				break
			}
		}
	}
	sources, err := liveMutationSources([]string{statusPath, safetyPath, regressionPath})
	if err != nil {
		return nil, err
	}
	return map[string]any{
		"schema_version":             "ao.sentinel.live-mutation-hold.v0.1",
		"status":                     verdict,
		"mutation_class":             stringField(status, "mutation_class"),
		"class_hold_verdict":         classVerdict,
		"hold_required":              holdRequired,
		"promoter_hold_required":     holdRequired,
		"rollback_recommended":       rollbackRecommended,
		"first_failing_check":        firstFailingCheck,
		"blockers":                   blockers,
		"recommended_actions":        recommendedActions(blockers),
		"source_artifacts":           sources,
		"operator_mode":              "read_only",
		"mutates_live_state":         false,
		"mutates_repositories":       false,
		"schedules_work":             false,
		"executes_work":              false,
		"approves_work":              false,
		"provider_calls_allowed":     false,
		"release_or_publish_allowed": false,
		"generated_at_utc":           nowUTC(),
	}, nil
}

type liveMutationRequiredArtifact struct {
	name        string
	readyStatus string
	severity    string
	action      string
}

func liveMutationRequiredArtifacts(mutationClass string) []liveMutationRequiredArtifact {
	if mutationClass == "test_only" {
		return []liveMutationRequiredArtifact{
			{"test_only_class_gate", "ready", "critical", "provide exact-scope approved test-only class gate evidence"},
			{"test_only_worktree_prepare", "ready", "critical", "provide clean isolated test-only worktree preparation evidence"},
			{"test_only_allowlist", "ready", "critical", "provide test-only allowlist evidence before live mutation can proceed"},
			{"rollback_rehearsal", "ready", "critical", "provide digest-bound rollback_rehearsal evidence"},
			{"operator_kill_switch", "armed", "critical", "arm the operator kill-switch"},
			{"verification_evidence", "passed", "high", "provide passing verification evidence for the test-only class"},
		}
	}
	if mutationClass == "low_risk_code" {
		return []liveMutationRequiredArtifact{
			{"low_risk_code_class_gate", "ready", "critical", "provide exact-scope approved low-risk-code class gate evidence"},
			{"test_only_success", "completed", "critical", "provide completed test-only live rehearsal evidence before low-risk-code dry-run"},
			{"low_risk_code_allowlist", "ready", "critical", "provide low-risk-code allowlist evidence before dry-run can proceed"},
			{"rollback_rehearsal", "ready", "critical", "provide digest-bound rollback_rehearsal evidence"},
			{"operator_kill_switch", "armed", "critical", "arm the operator kill-switch"},
			{"verification_evidence", "passed", "high", "provide passing verification evidence for the low-risk-code class"},
		}
	}
	if mutationClass == "multi_repo_low_risk" {
		return []liveMutationRequiredArtifact{
			{"multi_repo_low_risk_class_gate", "ready", "critical", "provide exact-scope approved multi-repo class gate evidence"},
			{"low_risk_code_success", "completed", "critical", "provide completed low-risk-code live rehearsal evidence before multi-repo dry-run"},
			{"multi_repo_sequencing_plan", "ready", "critical", "provide serialized ordered merge plan evidence"},
			{"per_repo_rollback", "ready", "critical", "provide ready rollback evidence for every planned repo"},
			{"operator_kill_switch", "armed", "critical", "arm the operator kill-switch"},
			{"ci_per_repo", "passed", "high", "provide passing CI evidence for every planned repo"},
			{"verification_evidence", "passed", "high", "provide passing verification evidence for the multi-repo class"},
		}
	}
	return []liveMutationRequiredArtifact{
		{"live_docs_approval_gate", "ready", "critical", "provide exact-scope approved docs-only approval gate evidence"},
		{"live_docs_worktree_prepare", "ready", "critical", "provide clean isolated docs-only worktree preparation evidence"},
		{"docs_only_allowlist", "ready", "critical", "provide docs-only allowlist evidence before live mutation can proceed"},
		{"rollback_rehearsal", "ready", "critical", "provide digest-bound rollback_rehearsal evidence"},
		{"operator_kill_switch", "armed", "critical", "arm the operator kill-switch"},
		{"verification_evidence", "passed", "high", "provide passing verification evidence for the docs-only class"},
	}
}

func evaluateMutationClassHold(status map[string]any) ([]blocker, map[string]any) {
	blockers := []blocker{}
	mutationClass := stringField(status, "mutation_class")
	policy, ok := mutationClassPolicies[mutationClass]
	if mutationClass == "" {
		blockers = append(blockers, newBlocker("mutation_class_missing", "critical", "mutation class is missing from AO Command readback", "mutation_class", "provide Atlas classification before Sentinel can clear the hold"))
	} else if !ok {
		blockers = append(blockers, newBlocker("mutation_class_unknown", "critical", "mutation class is not recognized by Sentinel", "mutation_class", "use an Atlas-defined mutation class"))
	}

	coverageStatus := classEvidenceStatus(status, "test_coverage")
	if ok {
		if policy.CoverageRequired {
			if coverageStatus != "passed" {
				blockers = append(blockers, newBlocker("test_coverage_insufficient", "high", "test coverage evidence is missing or failed for this mutation class", "test_coverage", "provide passing class-appropriate test coverage evidence"))
			}
		} else if coverageStatus != "passed" && coverageStatus != "not_required" && coverageStatus != "not_applicable" {
			blockers = append(blockers, newBlocker("test_coverage_insufficient", "high", "test coverage readback is missing or ambiguous for this mutation class", "test_coverage", "record passing or explicitly not-required coverage evidence"))
		}
	}

	rollbackStatus := classEvidenceStatus(status, "rollback_proof")
	rollbackProof, rollbackOK := status["rollback_proof"].(map[string]any)
	if !rollbackOK {
		blockers = append(blockers, newBlocker("rollback_proof_missing", "critical", "class-bound rollback proof is missing", "rollback_proof", "provide digest-bound rollback proof for the exact mutation class"))
	} else {
		if rollbackStatus != "ready" {
			blockers = append(blockers, newBlocker("rollback_proof_not_ready", "critical", "class-bound rollback proof is not ready", "rollback_proof", "rehearse rollback and record ready proof"))
		}
		if stringField(rollbackProof, "sha256") == "" {
			blockers = append(blockers, newBlocker("rollback_proof_digest_missing", "critical", "class-bound rollback proof is not digest-bound", "rollback_proof", "attach rollback proof digest"))
		}
		if mutationClass != "" && stringField(rollbackProof, "mutation_class") != "" && stringField(rollbackProof, "mutation_class") != mutationClass {
			blockers = append(blockers, newBlocker("rollback_proof_class_mismatch", "critical", "rollback proof is bound to a different mutation class", "rollback_proof", "regenerate rollback proof for the requested class"))
		}
	}

	diffSummary, diffOK := status["diff_summary"].(map[string]any)
	diffStatus := "passed"
	filesChanged := 0
	linesChanged := 0
	if !diffOK {
		diffStatus = "missing"
		blockers = append(blockers, newBlocker("diff_size_insufficient", "high", "diff summary is missing", "diff_summary", "provide bounded diff size evidence"))
	} else {
		filesChanged = int(numberField(diffSummary, "files_changed"))
		linesChanged = int(numberField(diffSummary, "total_lines_changed"))
		if linesChanged == 0 {
			linesChanged = int(numberField(diffSummary, "additions") + numberField(diffSummary, "deletions"))
		}
		if ok && (filesChanged > policy.MaxFiles || linesChanged > policy.MaxLinesChanged) {
			diffStatus = "exceeded"
			blockers = append(blockers, newBlocker("diff_size_exceeded", "high", "diff size exceeds mutation-class limit", "diff_summary", "reduce diff size or request a higher governed class"))
		}
	}

	fileClassStatus := "passed"
	sourceFilesChanged := 0
	testFilesChanged := 0
	forbiddenPathClasses := []string{}
	changedFiles := asAnySlice(status["changed_files"])
	if len(changedFiles) == 0 {
		fileClassStatus = "missing"
		blockers = append(blockers, newBlocker("file_class_insufficient", "high", "changed file class evidence is missing", "changed_files", "provide per-file path and class evidence"))
	}
	if ok && len(changedFiles) > policy.MaxFiles {
		fileClassStatus = "forbidden"
		blockers = append(blockers, newBlocker("file_class_forbidden", "high", "changed file count exceeds mutation-class file limit", "changed_files", "reduce changed files or request a higher governed class"))
	}
	for _, item := range changedFiles {
		file, okFile := item.(map[string]any)
		if !okFile {
			fileClassStatus = "missing"
			blockers = append(blockers, newBlocker("file_class_insufficient", "high", "changed file entry is malformed", "changed_files", "provide structured per-file class evidence"))
			continue
		}
		path := stringField(file, "path")
		fileClass := stringField(file, "file_class")
		if path == "" || fileClass == "" {
			fileClassStatus = "missing"
			blockers = append(blockers, newBlocker("file_class_insufficient", "high", "changed file path or class is missing", "changed_files", "provide per-file path and class evidence"))
			continue
		}
		if mutationClass == "low_risk_code" {
			if pathClass := lowRiskCodeForbiddenPathClass(path, stringField(file, "change_type")); pathClass != "" {
				forbiddenPathClasses = append(forbiddenPathClasses, pathClass)
				fileClassStatus = "forbidden"
				blockers = append(blockers, newBlocker("forbidden_path_class_touched", "critical", "low_risk_code touched a forbidden path class", "changed_files", "move the change into the approved low-risk source/test scope or request a higher governed class"))
			}
		}
		if ok && (!policy.AllowedFileClass[fileClass] || !pathAllowedForMutationClass(path, policy)) {
			fileClassStatus = "forbidden"
			blockers = append(blockers, newBlocker("file_class_forbidden", "critical", "changed file is outside the mutation-class boundary", "changed_files", "move the change into the approved class scope or request a higher governed class"))
		}
		if mutationClass == "low_risk_code" {
			switch lowRiskCodeFileRole(path, fileClass) {
			case "source":
				sourceFilesChanged++
			case "test":
				testFilesChanged++
			}
		}
	}
	if mutationClass == "low_risk_code" {
		if sourceFilesChanged > policy.MaxSourceFiles {
			fileClassStatus = "forbidden"
			blockers = append(blockers, newBlocker("source_file_limit_exceeded", "high", "low_risk_code may change at most one source file", "changed_files", "reduce the source diff to one file or request a higher governed class"))
		}
		if testFilesChanged > policy.MaxTestFiles {
			fileClassStatus = "forbidden"
			blockers = append(blockers, newBlocker("test_file_limit_exceeded", "high", "low_risk_code may change at most one test file", "changed_files", "reduce the test diff to one file or request a higher governed class"))
		}
		if policy.RequireTestFileWithCode && sourceFilesChanged > 0 && testFilesChanged == 0 {
			fileClassStatus = "forbidden"
			blockers = append(blockers, newBlocker("test_change_required", "high", "low_risk_code source changes require a bounded test-file change", "changed_files", "add one matching test change or record a higher-class exception through policy"))
		}
	}

	freshnessStatus := classEvidenceStatus(status, "evidence_freshness")
	freshness, freshnessOK := status["evidence_freshness"].(map[string]any)
	if !freshnessOK || freshnessStatus != "fresh" || timestampExpired(stringField(freshness, "expires_at_utc")) {
		freshnessStatus = "stale"
		blockers = append(blockers, newBlocker("evidence_stale", "high", "class evidence is stale or lacks expiry proof", "evidence_freshness", "refresh class evidence and record a future expiry"))
	}

	ciStatus := classEvidenceStatus(status, "ci_status")
	ci, ciOK := status["ci_status"].(map[string]any)
	if policy.RequiresCI && (!ciOK || (ciStatus != "passed" && ciStatus != "success") || timestampExpired(stringField(ci, "expires_at_utc"))) {
		ciStatus = firstNonEmpty(ciStatus, "missing")
		blockers = append(blockers, newBlocker("ci_status_insufficient", "high", "CI evidence is missing, stale, pending, or failed", "ci_status", "provide fresh passing CI evidence before clearing the hold"))
	}
	multiRepoReadback := map[string]any{}
	if mutationClass == "multi_repo_low_risk" {
		multiRepoBlockers, readback := evaluateMultiRepoLowRiskHold(status)
		blockers = append(blockers, multiRepoBlockers...)
		for key, value := range readback {
			multiRepoReadback[key] = value
		}
	}

	statusText := "clear"
	if len(blockers) > 0 {
		statusText = "hold"
	}
	verdict := map[string]any{
		"status":                    statusText,
		"mutation_class":            mutationClass,
		"max_files":                 policy.MaxFiles,
		"max_lines_changed":         policy.MaxLinesChanged,
		"max_source_files":          policy.MaxSourceFiles,
		"max_test_files":            policy.MaxTestFiles,
		"files_changed":             filesChanged,
		"source_files_changed":      sourceFilesChanged,
		"test_files_changed":        testFilesChanged,
		"lines_changed":             linesChanged,
		"forbidden_path_classes":    uniqueStrings(forbiddenPathClasses),
		"test_coverage_status":      coverageStatus,
		"rollback_status":           rollbackStatus,
		"diff_size_status":          diffStatus,
		"file_class_status":         fileClassStatus,
		"evidence_freshness_status": freshnessStatus,
		"ci_status":                 ciStatus,
		"blockers":                  blockers,
	}
	for key, value := range multiRepoReadback {
		verdict[key] = value
	}
	return blockers, verdict
}

func evaluateMultiRepoLowRiskHold(status map[string]any) ([]blocker, map[string]any) {
	blockers := []blocker{}
	readback := map[string]any{
		"multi_repo_dependency_status": "passed",
		"per_repo_rollback_status":     "ready",
		"per_repo_ci_status":           "passed",
		"repo_state_status":            "fresh",
	}
	plan := asAnySlice(status["repo_execution_plan"])
	if len(plan) < 2 {
		readback["multi_repo_dependency_status"] = "missing"
		blockers = append(blockers, newBlocker("multi_repo_dependency_missing", "critical", "multi-repo ordered merge plan is missing", "repo_execution_plan", "provide ordered per-repo PR dependency evidence"))
		return blockers, readback
	}
	seen := map[string]bool{}
	repos := []string{}
	for index, item := range plan {
		repoState, ok := item.(map[string]any)
		if !ok {
			readback["multi_repo_dependency_status"] = "missing"
			blockers = append(blockers, newBlocker("multi_repo_dependency_missing", "critical", "multi-repo repo state is malformed", "repo_execution_plan", "provide structured per-repo dependency evidence"))
			continue
		}
		repo := stringField(repoState, "repo")
		dependencies := stringSliceFromAny(repoState["depends_on"])
		mergeAfter := stringSliceFromAny(repoState["merge_after"])
		if repo == "" || int(numberField(repoState, "order")) != index+1 || stringField(repoState, "planned_pr") == "" || stringField(repoState, "status") != "ready" || !equalStringSlices(dependencies, mergeAfter) {
			readback["multi_repo_dependency_status"] = "missing"
			blockers = append(blockers, newBlocker("multi_repo_dependency_missing", "critical", "multi-repo dependency order is incomplete", "repo_execution_plan", "repair ordered merge plan before promotion"))
		}
		for _, dependency := range dependencies {
			if !seen[dependency] {
				readback["multi_repo_dependency_status"] = "missing"
				blockers = append(blockers, newBlocker("multi_repo_dependency_missing", "critical", "multi-repo dependency does not point to an earlier repo", "repo_execution_plan", "serialize repo PRs in dependency order"))
				break
			}
		}
		if stringField(repoState, "rollback_status") != "ready" {
			readback["per_repo_rollback_status"] = "missing"
			blockers = append(blockers, newBlocker("multi_repo_rollback_incomplete", "critical", "multi-repo rollback is incomplete", "repo_execution_plan", "provide ready rollback for every planned repo"))
		}
		if !statusPassed(stringField(repoState, "ci_status")) {
			readback["per_repo_ci_status"] = "missing"
			blockers = append(blockers, newBlocker("multi_repo_ci_incomplete", "high", "multi-repo CI evidence is incomplete", "repo_execution_plan", "provide passing CI for every planned repo"))
		}
		if stringField(repoState, "repo_state_status") != "clean_synced" || timestampExpired(stringField(repoState, "repo_state_expires_at_utc")) {
			readback["repo_state_status"] = "stale"
			blockers = append(blockers, newBlocker("multi_repo_repo_state_stale", "high", "multi-repo repo state evidence is stale", "repo_execution_plan", "refresh clean synced repo-state evidence"))
		}
		seen[repo] = true
		repos = append(repos, repo)
	}
	rollbackByRepo := mapByRepo(status["per_repo_rollback"])
	ciByRepo := mapByRepo(status["per_repo_ci"])
	for _, repo := range repos {
		rollback := rollbackByRepo[repo]
		if rollback == nil || stringField(rollback, "status") != "ready" || len(asAnySlice(rollback["rollback_scope"])) == 0 {
			readback["per_repo_rollback_status"] = "missing"
			blockers = append(blockers, newBlocker("multi_repo_rollback_incomplete", "critical", "multi-repo rollback is incomplete", "per_repo_rollback", "provide ready rollback scope for every planned repo"))
		}
		ci := ciByRepo[repo]
		if ci == nil || !boolField(ci, "required") || !statusPassed(stringField(ci, "status")) {
			readback["per_repo_ci_status"] = "missing"
			blockers = append(blockers, newBlocker("multi_repo_ci_incomplete", "high", "multi-repo CI evidence is incomplete", "per_repo_ci", "provide passing required CI for every planned repo"))
		}
	}
	return blockers, readback
}

func classEvidenceStatus(status map[string]any, key string) string {
	if evidence, ok := status[key].(map[string]any); ok {
		return stringField(evidence, "status")
	}
	return ""
}

func lowRiskCodeFileRole(path, fileClass string) string {
	normalized := normalizeMutationPath(path)
	if fileClass == "test" || strings.HasSuffix(normalized, "_test.go") || strings.Contains(normalized, "/tests/") {
		return "test"
	}
	if fileClass == "code" {
		return "source"
	}
	return ""
}

func lowRiskCodeForbiddenPathClass(path, changeType string) string {
	normalized := normalizeMutationPath(path)
	switch {
	case strings.HasPrefix(normalized, ".github/"):
		return "ci_workflows"
	case strings.HasPrefix(normalized, "scripts/") || strings.HasSuffix(normalized, ".sh"):
		return "scripts"
	case strings.HasPrefix(normalized, "release/") || strings.HasPrefix(normalized, "releases/") || strings.HasPrefix(normalized, "docs/release/"):
		return "release"
	case strings.HasPrefix(normalized, "secrets/") || strings.Contains(normalized, "/secrets/") || strings.Contains(strings.ToLower(normalized), "secret") || strings.HasPrefix(filepath.Base(normalized), ".env"):
		return "secrets"
	case strings.HasPrefix(normalized, "config/") || strings.HasPrefix(normalized, "configs/") || strings.HasSuffix(normalized, ".yaml") || strings.HasSuffix(normalized, ".yml") || strings.HasSuffix(normalized, ".toml") || normalized == "go.mod" || normalized == "go.sum" || normalized == "Cargo.toml" || normalized == "Cargo.lock":
		return "config_expansion"
	case strings.HasPrefix(normalized, "providers/") || strings.Contains(normalized, "/provider/") || strings.Contains(normalized, "/providers/"):
		return "provider_paths"
	case changeType == "renamed" || changeType == "moved" || changeType == "deleted" || changeType == "delete":
		return "broad_refactors"
	default:
		return ""
	}
}

func pathAllowedForMutationClass(path string, policy mutationClassPolicy) bool {
	normalized := normalizeMutationPath(path)
	for _, forbidden := range policy.ForbiddenPaths {
		if pathMatchesBoundary(normalized, forbidden) {
			return false
		}
	}
	for _, allowed := range policy.AllowedPaths {
		if pathMatchesBoundary(normalized, allowed) {
			return true
		}
	}
	return false
}

func normalizeMutationPath(path string) string {
	path = filepath.ToSlash(strings.TrimSpace(path))
	if idx := strings.Index(path, ":"); idx > 0 && !strings.Contains(path[:idx], "/") {
		path = path[idx+1:]
	}
	return strings.TrimPrefix(path, "./")
}

func pathMatchesBoundary(path, boundary string) bool {
	if strings.HasPrefix(boundary, "*") {
		return strings.HasSuffix(path, strings.TrimPrefix(boundary, "*"))
	}
	if strings.HasPrefix(boundary, ".") && strings.HasSuffix(boundary, ".") {
		return strings.Contains(path, boundary)
	}
	if strings.HasSuffix(boundary, "/") {
		return strings.HasPrefix(path, boundary)
	}
	return path == boundary || strings.HasPrefix(path, boundary+"/")
}

func timestampExpired(value string) bool {
	if strings.TrimSpace(value) == "" {
		return true
	}
	expires, err := time.Parse(time.RFC3339, value)
	if err != nil {
		return true
	}
	return !time.Now().Before(expires)
}

func stringSliceFromAny(value any) []string {
	values := []string{}
	for _, item := range asAnySlice(value) {
		text, ok := item.(string)
		if ok {
			values = append(values, text)
		}
	}
	return values
}

func mapByRepo(value any) map[string]map[string]any {
	byRepo := map[string]map[string]any{}
	for _, item := range asAnySlice(value) {
		entry, ok := item.(map[string]any)
		if !ok {
			continue
		}
		repo := stringField(entry, "repo")
		if repo != "" {
			byRepo[repo] = entry
		}
	}
	return byRepo
}

func equalStringSlices(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

func statusPassed(status string) bool {
	return status == "passed" || status == "success"
}

func triageCISignal(signal map[string]any) (map[string]any, error) {
	if stringField(signal, "schema_version") != "ao.sentinel.ci-signal.v0.1" {
		return nil, errors.New("unknown CI signal schema_version")
	}
	for _, field := range []string{"signal_id", "source", "repository", "workflow", "job", "conclusion", "observed_at_utc"} {
		if stringField(signal, field) == "" {
			return nil, fmt.Errorf("CI signal missing required field %s", field)
		}
	}
	conclusion := strings.ToLower(stringField(signal, "conclusion"))
	if conclusion == "success" || conclusion == "passed" {
		return map[string]any{
			"schema_version":            "ao.sentinel.ci-triage.v0.1",
			"status":                    "observed",
			"signal_id":                 stringField(signal, "signal_id"),
			"source":                    stringField(signal, "source"),
			"repository":                stringField(signal, "repository"),
			"workflow":                  stringField(signal, "workflow"),
			"job":                       stringField(signal, "job"),
			"severity":                  "info",
			"root_cause":                "none",
			"recommended_action":        "No repair required; retain signal as passing observability evidence.",
			"regression_test_required":  false,
			"triage_steps":              ciTriageSteps(),
			"next_forge_task":           map[string]any{},
			"mutates_live_state":        false,
			"generated_at_utc":          nowUTC(),
			"observed_signal_timestamp": stringField(signal, "observed_at_utc"),
		}, nil
	}
	rootCause, title, action := classifyCIRootCause(stringField(signal, "log_excerpt"))
	return map[string]any{
		"schema_version":            "ao.sentinel.ci-triage.v0.1",
		"status":                    "repair_required",
		"signal_id":                 stringField(signal, "signal_id"),
		"source":                    stringField(signal, "source"),
		"repository":                stringField(signal, "repository"),
		"workflow":                  stringField(signal, "workflow"),
		"job":                       stringField(signal, "job"),
		"severity":                  ciSeverity(rootCause),
		"root_cause":                rootCause,
		"recommended_action":        action,
		"regression_test_required":  true,
		"triage_steps":              ciTriageSteps(),
		"next_forge_task":           map[string]any{"title": title, "acceptance": []any{"Reproduce the failing signal locally or with a fixture.", "Implement the smallest targeted repair.", "Add or update a regression test that fails before the repair and passes after it.", "Rerun the affected CI or local production-readiness gate."}},
		"mutates_live_state":        false,
		"generated_at_utc":          nowUTC(),
		"observed_signal_timestamp": stringField(signal, "observed_at_utc"),
	}, nil
}

func reviewSecurityRequest(request map[string]any) (map[string]any, error) {
	if stringField(request, "schema_version") != "ao.sentinel.security-review-request.v0.1" {
		return nil, errors.New("unknown security review request schema_version")
	}
	for _, field := range []string{"review_id", "target_id", "repository", "change_summary", "observed_at_utc"} {
		if stringField(request, field) == "" {
			return nil, fmt.Errorf("security review request missing required field %s", field)
		}
	}
	scopes := stringsFromAnySlice(request["scopes"])
	if len(scopes) == 0 {
		return nil, errors.New("security review request scopes are required")
	}
	evidence := stringsFromAnySlice(request["evidence"])
	if len(evidence) == 0 {
		return nil, errors.New("security review request evidence is required")
	}
	summary := strings.ToLower(stringField(request, "change_summary"))
	findings := securityFindings(summary, scopes)
	status := "clear"
	severity := "info"
	holdRequired := false
	recommended := []any{}
	if len(findings) > 0 {
		status = "hold"
		severity = "high"
		holdRequired = true
		recommended = []any{
			"Route the finding to AO Forge as a bounded repair task.",
			"Add regression evidence for the missing security scope.",
			"Rerun Sentinel safety scan and production-readiness gates before promotion.",
		}
	}
	return map[string]any{
		"schema_version":          "ao.sentinel.security-review.v0.1",
		"status":                  status,
		"review_id":               stringField(request, "review_id"),
		"target_id":               stringField(request, "target_id"),
		"repository":              stringField(request, "repository"),
		"severity":                severity,
		"scopes_checked":          anyStrings(scopes),
		"evidence":                anyStrings(evidence),
		"findings":                findings,
		"recommended_actions":     recommended,
		"promoter_hold_required":  holdRequired,
		"mutates_live_state":      false,
		"generated_at_utc":        nowUTC(),
		"observed_request_at_utc": stringField(request, "observed_at_utc"),
	}, nil
}

func securityFindings(summary string, scopes []string) []any {
	findings := []any{}
	for _, scope := range scopes {
		switch scope {
		case "secrets":
			if !containsAny(summary, "no secrets", "secret scan", "secrets scanned", "redacted") {
				findings = append(findings, securityFinding(scope, "medium", "secret handling evidence is missing"))
			}
		case "input_validation":
			if !containsAny(summary, "input validation", "schema", "validated") {
				findings = append(findings, securityFinding(scope, "high", "input validation evidence is missing"))
			}
		case "authorization":
			if !containsAny(summary, "authorization", "permission", "access check", "role") {
				findings = append(findings, securityFinding(scope, "high", "authorization evidence is missing"))
			}
		case "dependencies":
			if !containsAny(summary, "dependency", "dependencies", "audit") {
				findings = append(findings, securityFinding(scope, "medium", "dependency audit evidence is missing"))
			}
		case "logging":
			if !containsAny(summary, "log", "redact", "logging") {
				findings = append(findings, securityFinding(scope, "medium", "logging redaction evidence is missing"))
			}
		case "public_artifacts":
			if !containsAny(summary, "public artifact", "public artifacts", "public-safety", "safety scan") {
				findings = append(findings, securityFinding(scope, "critical", "public artifact safety evidence is missing"))
			}
		default:
			findings = append(findings, securityFinding(scope, "medium", "unknown security scope"))
		}
	}
	return findings
}

func securityFinding(scope, severity, summary string) map[string]any {
	return map[string]any{
		"scope":              scope,
		"severity":           severity,
		"summary":            summary,
		"recommended_action": "collect explicit evidence or keep promotion on hold",
	}
}

func containsAny(haystack string, needles ...string) bool {
	for _, needle := range needles {
		if strings.Contains(haystack, needle) {
			return true
		}
	}
	return false
}

func classifyCIRootCause(logExcerpt string) (string, string, string) {
	lower := strings.ToLower(logExcerpt)
	switch {
	case strings.Contains(lower, "schema"):
		return "contract_schema", "Fix contract schema failure", "Validate the affected JSON contract and example, then add regression coverage for the schema failure."
	case strings.Contains(lower, "timeout") || strings.Contains(lower, "timed out") || strings.Contains(lower, "exit code 124"):
		return "timeout", "Fix CI timeout failure", "Localize the slow command, add a bounded timeout or fixture, and prove the runtime budget is restored."
	case strings.Contains(lower, "secret") || strings.Contains(lower, "private key") || strings.Contains(lower, "token"):
		return "public_safety", "Fix public-safety CI failure", "Redact unsafe public content, add a scanner fixture, and rerun the safety gate."
	case strings.Contains(lower, "flake") || strings.Contains(lower, "flaky"):
		return "flaky_test", "Stabilize flaky CI test", "Identify the nondeterministic boundary, remove timing dependence, and add deterministic coverage."
	default:
		return "ci_failure", "Fix CI failure", "Read the failing log, reproduce the failure, repair the root cause, and add regression coverage."
	}
}

func ciSeverity(rootCause string) string {
	switch rootCause {
	case "public_safety":
		return "critical"
	case "contract_schema", "timeout":
		return "high"
	default:
		return "medium"
	}
}

func ciTriageSteps() []any {
	return []any{
		"capture_signal",
		"localize_failure_boundary",
		"reproduce_or_simulate",
		"implement_targeted_repair",
		"verify_regression_gate",
	}
}

func validateTarget(target map[string]any) error {
	if stringField(target, "schema_version") != "ao.sentinel.target.v0.1" {
		return errors.New("unknown target schema_version")
	}
	for _, field := range []string{"target_id", "target_kind", "active_stack_ref"} {
		if stringField(target, field) == "" {
			return fmt.Errorf("target missing required field %s", field)
		}
	}
	if !allowedTargetKinds[stringField(target, "target_kind")] {
		return fmt.Errorf("unknown target_kind %q", stringField(target, "target_kind"))
	}
	if len(asAnySlice(target["watch_scope"])) == 0 {
		return errors.New("target watch_scope is required")
	}
	if len(asAnySlice(target["watched_components"])) == 0 {
		return errors.New("target watched_components is required")
	}
	if len(asAnySlice(target["platform_matrix"])) == 0 {
		return errors.New("target platform_matrix is required")
	}
	if _, ok := target["risk_budget"].(map[string]any); !ok {
		return errors.New("target risk_budget is required")
	}
	if boolField(target, "dry_run_only") != true {
		return errors.New("dry_run_only must be true in v0.1")
	}
	return nil
}

func validateBaseline(baseline map[string]any) error {
	if stringField(baseline, "schema_version") != "ao.sentinel.baseline.v0.1" {
		return errors.New("unknown baseline schema_version")
	}
	for _, field := range []string{"baseline_id", "target_id", "created_at_utc", "expires_at_utc", "expected_safety_status", "approval_authority"} {
		if stringField(baseline, field) == "" {
			return fmt.Errorf("baseline missing required field %s", field)
		}
	}
	if len(asAnySlice(baseline["regression_expectations"])) == 0 {
		return errors.New("baseline regression_expectations is required")
	}
	if _, ok := baseline["performance_budgets"].(map[string]any); !ok {
		return errors.New("baseline performance_budgets is required")
	}
	if _, ok := baseline["contract_fingerprints"].(map[string]any); !ok {
		return errors.New("baseline contract_fingerprints is required")
	}
	expires, err := time.Parse(time.RFC3339, stringField(baseline, "expires_at_utc"))
	if err != nil || !time.Now().Before(expires) {
		return errors.New("stale baseline")
	}
	return nil
}

func validateSuite(suite map[string]any) error {
	if stringField(suite, "schema_version") != "ao.sentinel.regression-suite.v0.1" {
		return errors.New("unknown regression suite schema_version")
	}
	for _, field := range []string{"suite_id", "target_id"} {
		if stringField(suite, field) == "" {
			return fmt.Errorf("regression suite missing required field %s", field)
		}
	}
	if boolField(suite, "dry_run_only") != true {
		return errors.New("dry_run_only must be true in v0.1")
	}
	cases := asAnySlice(suite["cases"])
	if len(cases) == 0 {
		return errors.New("regression suite cases are required")
	}
	for _, item := range cases {
		c, ok := item.(map[string]any)
		if !ok {
			return errors.New("regression cases must be objects")
		}
		if stringField(c, "case_id") == "" {
			return errors.New("regression case missing case_id")
		}
		if stringField(c, "command") == "" {
			return fmt.Errorf("regression case %s missing command", stringField(c, "case_id"))
		}
		if stringField(c, "expected_status") == "" {
			return fmt.Errorf("regression case %s missing expected_status", stringField(c, "case_id"))
		}
		if stringField(c, "expected_output_contains") == "" {
			return fmt.Errorf("regression case %s missing expected_output_contains", stringField(c, "case_id"))
		}
	}
	return nil
}

func runRegressionSuite(suite map[string]any) (map[string]any, error) {
	if err := validateSuite(suite); err != nil {
		return nil, err
	}
	results := []any{}
	failed := 0
	totalDuration := 0
	for _, item := range asAnySlice(suite["cases"]) {
		c := item.(map[string]any)
		output, status := executeFixtureCommand(stringField(c, "command"))
		duration := int(numberField(c, "duration_ms"))
		if duration == 0 {
			duration = 10
		}
		totalDuration += duration
		expectedStatus := stringField(c, "expected_status")
		expectedMarker := stringField(c, "expected_output_contains")
		passed := status == expectedStatus && strings.Contains(output, expectedMarker) && float64(duration) <= numberField(c, "max_duration_ms")
		if !passed {
			failed++
		}
		results = append(results, map[string]any{
			"case_id":                  stringField(c, "case_id"),
			"status":                   status,
			"expected_status":          expectedStatus,
			"output":                   output,
			"expected_output_contains": expectedMarker,
			"duration_ms":              duration,
			"max_duration_ms":          int(numberField(c, "max_duration_ms")),
			"passed":                   passed,
			"severity_on_failure":      stringField(c, "severity_on_failure"),
		})
	}
	status := "passed"
	if failed > 0 {
		status = "failed"
	}
	return map[string]any{
		"schema_version":     "ao.sentinel.regression-run.v0.1",
		"run_id":             "run-" + stringField(suite, "suite_id"),
		"suite_id":           stringField(suite, "suite_id"),
		"target_id":          stringField(suite, "target_id"),
		"status":             status,
		"case_results":       results,
		"summary":            map[string]any{"total": len(results), "failed": failed, "total_duration_ms": totalDuration},
		"mutates_live_state": false,
		"ran_at_utc":         nowUTC(),
	}, nil
}

func executeFixtureCommand(command string) (string, string) {
	switch {
	case strings.HasPrefix(command, "fixture://pass/"):
		return strings.TrimPrefix(command, "fixture://pass/"), "passed"
	case strings.HasPrefix(command, "fixture://fail/"):
		return strings.TrimPrefix(command, "fixture://fail/"), "failed"
	default:
		return "unsupported fixture command", "failed"
	}
}

func compareRegression(baseline, run map[string]any) (map[string]any, error) {
	if err := validateBaseline(baseline); err != nil {
		return nil, err
	}
	if stringField(run, "schema_version") != "ao.sentinel.regression-run.v0.1" {
		return nil, errors.New("unknown regression run schema_version")
	}
	if stringField(baseline, "target_id") != stringField(run, "target_id") {
		return nil, errors.New("target and baseline mismatch")
	}
	expectations := map[string]map[string]any{}
	for _, item := range asAnySlice(baseline["regression_expectations"]) {
		exp, ok := item.(map[string]any)
		if !ok {
			return nil, errors.New("regression expectations must be objects")
		}
		expectations[stringField(exp, "case_id")] = exp
	}
	blockers := []blocker{}
	caseResults := []any{}
	seen := map[string]bool{}
	for _, item := range asAnySlice(run["case_results"]) {
		result, ok := item.(map[string]any)
		if !ok {
			return nil, errors.New("regression run case_results must be objects")
		}
		caseID := stringField(result, "case_id")
		exp, ok := expectations[caseID]
		if !ok {
			blockers = append(blockers, newBlocker("unexpected_regression_case_"+caseID, "high", "unexpected regression case", caseID, "update baseline or remove case"))
			continue
		}
		seen[caseID] = true
		passed := true
		if stringField(result, "status") != stringField(exp, "expected_status") {
			passed = false
			blockers = append(blockers, newBlocker("regression_status_"+caseID, severity(result), "case status changed", caseID, "fix regression or update trusted baseline"))
		}
		if !strings.Contains(stringField(result, "output"), stringField(exp, "expected_output_contains")) {
			passed = false
			blockers = append(blockers, newBlocker("regression_output_"+caseID, severity(result), "case output marker missing", caseID, "restore expected behavior"))
		}
		if numberField(result, "duration_ms") > numberField(exp, "max_duration_ms") {
			passed = false
			blockers = append(blockers, newBlocker("regression_budget_"+caseID, severity(result), "case duration budget exceeded", caseID, "investigate performance regression"))
		}
		caseResults = append(caseResults, map[string]any{
			"case_id": caseID,
			"status":  stringField(result, "status"),
			"passed":  passed,
		})
	}
	for caseID := range expectations {
		if !seen[caseID] {
			blockers = append(blockers, newBlocker("missing_regression_case_"+caseID, "high", "missing baseline regression case", caseID, "run the missing regression case"))
		}
	}
	status := "passed"
	if len(blockers) > 0 {
		status = "failed"
	}
	return map[string]any{
		"schema_version": "ao.sentinel.regression-diff.v0.1",
		"status":         status,
		"baseline_id":    stringField(baseline, "baseline_id"),
		"run_id":         stringField(run, "run_id"),
		"target_id":      stringField(run, "target_id"),
		"case_results":   caseResults,
		"blockers":       blockers,
		"summary":        map[string]any{"failed": len(blockers), "total": len(caseResults)},
	}, nil
}

func evaluateMonitor(target, baseline, safety, regression map[string]any) (map[string]any, error) {
	if err := validateTarget(target); err != nil {
		return nil, err
	}
	if err := validateBaseline(baseline); err != nil {
		return nil, err
	}
	if stringField(target, "target_id") != stringField(baseline, "target_id") {
		return nil, errors.New("target and baseline mismatch")
	}
	if stringField(safety, "schema_version") != "ao.sentinel.safety-scan.v0.1" {
		return nil, errors.New("unknown safety scan schema_version")
	}
	if stringField(regression, "schema_version") != "ao.sentinel.regression-diff.v0.1" {
		return nil, errors.New("unknown regression diff schema_version")
	}
	blockers := []blocker{}
	if stringField(safety, "status") != "passed" || numberField(safety, "findings_count") > 0 {
		blockers = append(blockers, newBlocker("public_safety_failed", "critical", "public safety scan failed", "safety", "remove unsafe public content"))
	}
	if stringField(regression, "status") != "passed" {
		for _, item := range asAnySlice(regression["blockers"]) {
			if b, ok := item.(map[string]any); ok {
				blockers = append(blockers, newBlocker(stringField(b, "blocker_id"), stringFieldOr(b, "severity", "high"), stringFieldOr(b, "reason", "regression failed"), "regression", stringFieldOr(b, "recommended_action", "fix regression")))
			}
		}
		if len(asAnySlice(regression["blockers"])) == 0 {
			blockers = append(blockers, newBlocker("regression_failed", "high", "regression diff failed", "regression", "fix regression"))
		}
	}
	verdict := "clear"
	hold := false
	rollback := false
	if len(blockers) > 0 {
		hold = true
		verdict = "hold"
		for _, b := range blockers {
			if b.Severity == "critical" {
				verdict = "incident"
				rollback = true
			}
		}
	}
	return map[string]any{
		"schema_version":         "ao.sentinel.verdict.v0.1",
		"verdict":                verdict,
		"target_id":              stringField(target, "target_id"),
		"baseline_id":            stringField(baseline, "baseline_id"),
		"safety_status":          stringField(safety, "status"),
		"regression_status":      stringField(regression, "status"),
		"blockers":               blockers,
		"recommended_actions":    recommendedActions(blockers),
		"promoter_hold_required": hold,
		"rollback_recommended":   rollback,
		"mutates_live_state":     false,
		"evaluated_at_utc":       nowUTC(),
	}, nil
}

func renderIncident(verdict map[string]any) (map[string]any, error) {
	if err := validateVerdict(verdict); err != nil {
		return nil, err
	}
	incidentRequired := stringField(verdict, "verdict") == "incident"
	return map[string]any{
		"schema_version":         "ao.sentinel.incident.v0.1",
		"incident_id":            "incident-" + stringField(verdict, "target_id"),
		"target_id":              stringField(verdict, "target_id"),
		"baseline_id":            stringField(verdict, "baseline_id"),
		"incident_required":      incidentRequired,
		"promoter_hold_required": boolField(verdict, "promoter_hold_required"),
		"rollback_recommended":   boolField(verdict, "rollback_recommended"),
		"blockers":               verdict["blockers"],
		"recommended_actions":    verdict["recommended_actions"],
		"mutates_live_state":     false,
		"rendered_at_utc":        nowUTC(),
	}, nil
}

func emitHold(verdict map[string]any) (map[string]any, error) {
	if err := validateVerdict(verdict); err != nil {
		return nil, err
	}
	return map[string]any{
		"schema_version":     "ao.sentinel.promoter-hold.v0.1",
		"hold_id":            "hold-" + stringField(verdict, "target_id"),
		"target_id":          stringField(verdict, "target_id"),
		"baseline_id":        stringField(verdict, "baseline_id"),
		"hold_required":      boolField(verdict, "promoter_hold_required"),
		"verdict":            stringField(verdict, "verdict"),
		"blockers":           verdict["blockers"],
		"mutates_live_state": false,
		"emitted_at_utc":     nowUTC(),
	}, nil
}

func validateVerdict(verdict map[string]any) error {
	if stringField(verdict, "schema_version") != "ao.sentinel.verdict.v0.1" {
		return errors.New("unknown verdict schema_version")
	}
	if stringField(verdict, "verdict") == "incident" && !boolField(verdict, "promoter_hold_required") {
		return errors.New("incident verdict requires promoter hold")
	}
	if boolField(verdict, "rollback_recommended") && !boolField(verdict, "promoter_hold_required") {
		return errors.New("rollback recommendation requires promoter hold")
	}
	return nil
}

func renderReport(verdict, incident map[string]any) string {
	var b strings.Builder
	fmt.Fprintln(&b, "# AO Sentinel Report")
	fmt.Fprintln(&b)
	fmt.Fprintf(&b, "- Target: %s\n", stringField(verdict, "target_id"))
	fmt.Fprintf(&b, "- Baseline: %s\n", stringField(verdict, "baseline_id"))
	fmt.Fprintf(&b, "- Verdict: %s\n", stringField(verdict, "verdict"))
	fmt.Fprintf(&b, "- Safety: %s\n", stringField(verdict, "safety_status"))
	fmt.Fprintf(&b, "- Regression: %s\n", stringField(verdict, "regression_status"))
	fmt.Fprintf(&b, "- Promoter hold required: %t\n", boolField(verdict, "promoter_hold_required"))
	fmt.Fprintf(&b, "- Incident required: %t\n", boolField(incident, "incident_required"))
	fmt.Fprintf(&b, "- Mutates live state: %t\n", boolField(verdict, "mutates_live_state"))
	fmt.Fprintln(&b)
	fmt.Fprintln(&b, "## Blockers")
	blockers := asAnySlice(verdict["blockers"])
	if len(blockers) == 0 {
		fmt.Fprintln(&b, "- none")
	}
	for _, item := range blockers {
		if m, ok := item.(map[string]any); ok {
			fmt.Fprintf(&b, "- %s: %s\n", stringField(m, "severity"), stringField(m, "reason"))
		}
	}
	return b.String()
}

func safetyScan(path string) (map[string]any, error) {
	return safetyScanWithProfile(path, "default")
}

func safetyScanWithProfile(path string, profile string) (map[string]any, error) {
	findings := []map[string]any{}
	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	scanDetectors := detectors(profile)
	filesScanned := 0
	linesScanned := 0
	visit := func(file string) error {
		body, err := os.ReadFile(file)
		if err != nil {
			return err
		}
		filesScanned++
		for lineNo, line := range strings.Split(string(body), "\n") {
			linesScanned++
			for _, detector := range scanDetectors {
				if detector.re.MatchString(line) {
					findings = append(findings, map[string]any{
						"detector": detector.name,
						"file":     filepath.ToSlash(file),
						"line":     lineNo + 1,
						"severity": detector.severity,
						"summary":  detector.summary,
					})
				}
			}
		}
		if profile == "month4-controlled-loop" {
			findings = append(findings, month4ControlledLoopBoundaryFindings(file, string(body))...)
		}
		if profile == "month5-operator-workflow" {
			findings = append(findings, month5OperatorWorkflowBoundaryFindings(file, string(body))...)
		}
		if profile == "month6-release-readiness" {
			findings = append(findings, month6ReleaseReadinessBoundaryFindings(file, string(body))...)
		}
		if profile == "adoption-month1-gate-readiness" {
			findings = append(findings, adoptionMonth1GateReadinessBoundaryFindings(file, string(body))...)
		}
		if profile == "adoption-month2-operator-drill" {
			findings = append(findings, adoptionMonth2OperatorDrillBoundaryFindings(file, string(body))...)
		}
		if profile == "adoption-month3-evidence-maintenance" {
			findings = append(findings, adoptionMonth3EvidenceMaintenanceBoundaryFindings(file, string(body))...)
		}
		if profile == "adoption-month5-support-readiness" {
			findings = append(findings, adoptionMonth5SupportReadinessBoundaryFindings(file, string(body))...)
		}
		return nil
	}
	if info.IsDir() {
		err = filepath.WalkDir(path, func(file string, d fs.DirEntry, walkErr error) error {
			if walkErr != nil {
				return walkErr
			}
			if d.IsDir() {
				switch d.Name() {
				case ".git", "tmp", "target":
					return filepath.SkipDir
				}
				return nil
			}
			if isTextFile(file) {
				return visit(file)
			}
			return nil
		})
	} else {
		err = visit(path)
	}
	if err != nil {
		return nil, err
	}
	status := "passed"
	if len(findings) > 0 {
		status = "failed"
	}
	return map[string]any{
		"schema_version":     "ao.sentinel.safety-scan.v0.1",
		"status":             status,
		"profile":            profile,
		"path":               filepath.ToSlash(path),
		"findings_count":     len(findings),
		"findings":           findings,
		"scanned_at_utc":     nowUTC(),
		"mutates_live_state": false,
		"scanner_metrics": map[string]any{
			"detector_construction_count": 1,
			"detectors_loaded":            len(scanDetectors),
			"files_scanned":               filesScanned,
			"lines_scanned":               linesScanned,
		},
	}, nil
}

func liveMutationSources(paths []string) ([]any, error) {
	out := make([]any, 0, len(paths))
	for _, path := range paths {
		raw, err := readJSONMap(path)
		if err != nil {
			return nil, err
		}
		sha, err := sha256File(path)
		if err != nil {
			return nil, err
		}
		out = append(out, map[string]any{
			"path":           filepath.ToSlash(path),
			"schema_version": stringField(raw, "schema_version"),
			"status":         firstNonEmpty(stringField(raw, "status"), stringField(raw, "verdict")),
			"sha256":         sha,
		})
	}
	return out, nil
}

func liveMutationArtifactMap(status map[string]any) map[string]map[string]any {
	artifacts := map[string]map[string]any{}
	for _, item := range asAnySlice(status["artifacts"]) {
		artifact, ok := item.(map[string]any)
		if !ok {
			continue
		}
		name := stringField(artifact, "name")
		if name == "" {
			continue
		}
		artifacts[name] = artifact
	}
	return artifacts
}

func rejectUnsafeLiveMutationPayload(label string, value any) error {
	switch v := value.(type) {
	case map[string]any:
		for key, item := range v {
			switch key {
			case "mutates_live_state", "mutates_repositories", "schedules_work", "executes_work", "approves_work", "calls_providers", "provider_calls_allowed", "release_or_publish_allowed", "uploads_artifacts", "live_mutation_allowed":
				if b, ok := item.(bool); ok && b {
					return fmt.Errorf("%s expands forbidden authority via %s", label, key)
				}
			}
			if err := rejectUnsafeLiveMutationPayload(label+"."+key, item); err != nil {
				return err
			}
		}
	case []any:
		for i, item := range v {
			if err := rejectUnsafeLiveMutationPayload(fmt.Sprintf("%s[%d]", label, i), item); err != nil {
				return err
			}
		}
	case string:
		if containsUnsafePath(v) {
			return fmt.Errorf("%s contains unsafe local path", label)
		}
	}
	return nil
}

func containsUnsafePath(value string) bool {
	unsafeMarkers := []string{
		"/" + "Users/",
		"/" + "home/",
		"C:" + `\` + "Users" + `\`,
		"/" + "tmp/",
		"/" + "var/folders/",
	}
	for _, marker := range unsafeMarkers {
		if strings.Contains(value, marker) {
			return true
		}
	}
	return false
}

func sha256File(path string) (string, error) {
	body, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(body)
	return fmt.Sprintf("%x", sum[:]), nil
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return value
		}
	}
	return ""
}

func detectors(profile string) []struct {
	name     string
	severity string
	summary  string
	re       *regexp.Regexp
} {
	localPathPattern := `(/` + `Users/[^ \n]+|/` + `home/[^ \n]+|C:\\` + `Users\\[^ \n]+)`
	items := []struct {
		name     string
		severity string
		summary  string
		re       *regexp.Regexp
	}{
		{"bearer_token", "critical", "bearer-token-like value detected", regexp.MustCompile(`(?i)Authorization:\s*Bearer\s+\S{16,}`)},
		{"private_key", "critical", "private key marker detected", regexp.MustCompile(`BEGIN (RSA |OPENSSH |EC |)PRIVATE KEY`)},
		{"github_token", "critical", "GitHub-token-like value detected", regexp.MustCompile(`gh[pousr]_[A-Za-z0-9]{20,}`)},
		{"cloud_access_key", "critical", "cloud access-key-like value detected", regexp.MustCompile(`A` + `KIA[0-9A-Z]{16}`)},
		{"password_assignment", "critical", "password assignment pattern detected", regexp.MustCompile(`(?i)\b(password|passwd|secret)\s*[:=]`)},
		{"local_absolute_path", "high", "local absolute path detected", regexp.MustCompile(localPathPattern)},
		{"forbidden_action_command", "high", "forbidden action command detected", regexp.MustCompile(`(?i)\b(git push|git tag|gh release|npm publish|twine upload|docker push|kubectl apply|terraform apply)\b`)},
		{"gateway_public_doc_authority_variant", "high", "gateway public-doc authority variant detected", regexp.MustCompile(`(?i)\b(the\s+)?gateway\s+(approves?|executes?|mutates repositories?|executes repository changes?)\b`)},
		{"gateway_intent_authority_widening", "high", "gateway intent authority-widening claim detected", regexp.MustCompile(`(?i)\b(telegram|a2a|gateway intents?)\s+(executes?|approves?|mutates repositories?)\b`)},
		{"gateway_freshness_stale_language", "high", "gateway freshness stale-language claim detected", regexp.MustCompile(`(?i)\bgateway readbacks?\b[^.\n]*(always fresh|never stale|do not need freshness checks|without freshness checks)`)},
		{"scheduler_recovery_authority_widening", "high", "scheduler recovery authority-widening claim detected", regexp.MustCompile(`(?i)scheduler recovery\s+(executes|schedules|mutates repositories?)\b`)},
		{"scheduler_wakeup_authority_widening", "high", "scheduler wakeup authority-widening claim detected", regexp.MustCompile(`(?i)\b(codex-cron|scheduler wakeups?)\s+(executes?|approves?|schedules repository mutation|mutates repositories?)\b`)},
		{"scheduler_public_doc_authority_variant", "high", "scheduler public-doc authority variant detected", regexp.MustCompile(`(?i)\b(the\s+)?scheduler\s+(approves?|executes?|mutates repositories?|executes repository changes?)\b`)},
		{"ledger_compaction_authority_widening", "high", "ledger compaction authority-widening claim detected", regexp.MustCompile(`(?i)ledger compaction\s+(executes|schedules|mutates repositories?)\b`)},
	}
	if profile == "public-beta" {
		items = append(items, struct {
			name     string
			severity string
			summary  string
			re       *regexp.Regexp
		}{"public_beta_authority_overclaim", "high", "public beta authority overclaim detected", regexp.MustCompile(`(?i)\b(public\s+beta|beta)\b[^.\n]*(automatically\s+runs|provider-backed|publishes?\s+releases?|promotes?\s+unrestricted\s+RSI|grants?\s+(provider|credential|release|mutation)\s+authority)`)})
	}
	if profile == "month4-controlled-loop" {
		items = append(items,
			struct {
				name     string
				severity string
				summary  string
				re       *regexp.Regexp
			}{"month4_rsi_activation_overclaim", "critical", "Month 4 RSI activation overclaim detected", regexp.MustCompile(`(?i)\bRSI\s+(achieved|active|activated|authorized|enabled|granted)\b`)},
			struct {
				name     string
				severity string
				summary  string
				re       *regexp.Regexp
			}{"month4_live_self_modification_overclaim", "critical", "Month 4 live self-modification overclaim detected", regexp.MustCompile(`(?i)\b(self-improving\s+system\s+(is\s+)?active|autonomous\s+self-modification\s+(is\s+)?enabled|live\s+self-modification\s+(active|authorized|enabled|granted))\b`)},
			struct {
				name     string
				severity string
				summary  string
				re       *regexp.Regexp
			}{"month4_external_beta_overclaim", "high", "Month 4 external beta overclaim detected", regexp.MustCompile(`(?i)\bexternal\s+beta\s+(launched|active|started|open|enabled)\b`)},
			struct {
				name     string
				severity string
				summary  string
				re       *regexp.Regexp
			}{"month4_promotion_overclaim", "high", "Month 4 promotion overclaim detected", regexp.MustCompile(`(?i)\bpromotion\s+(requested|granted|approved|active|launched)\b`)},
			struct {
				name     string
				severity string
				summary  string
				re       *regexp.Regexp
			}{"month4_provider_pilot_overclaim", "high", "Month 4 provider-pilot overclaim detected", regexp.MustCompile(`(?i)\bprovider[-\s]+pilot\s+(launched|ran|started|active|enabled)\b`)},
		)
	}
	if profile == "month5-operator-workflow" {
		items = append(items,
			struct {
				name     string
				severity string
				summary  string
				re       *regexp.Regexp
			}{"month5_rsi_activation_overclaim", "critical", "Month 5 RSI activation overclaim detected", regexp.MustCompile(`(?i)\bRSI\s+(achieved|active|activated|authorized|enabled|granted)\b`)},
			struct {
				name     string
				severity string
				summary  string
				re       *regexp.Regexp
			}{"month5_live_self_modification_overclaim", "critical", "Month 5 live self-modification overclaim detected", regexp.MustCompile(`(?i)\b(self-improving\s+system\s+(is\s+)?active|autonomous\s+self-modification\s+(is\s+)?enabled|live\s+self-modification\s+(active|authorized|enabled|granted))\b`)},
			struct {
				name     string
				severity string
				summary  string
				re       *regexp.Regexp
			}{"month5_external_beta_overclaim", "high", "Month 5 external beta overclaim detected", regexp.MustCompile(`(?i)\bexternal\s+beta\s+(launched|active|started|open|enabled)\b`)},
			struct {
				name     string
				severity string
				summary  string
				re       *regexp.Regexp
			}{"month5_promotion_overclaim", "high", "Month 5 promotion overclaim detected", regexp.MustCompile(`(?i)\bpromotion\s+(requested|granted|approved|active|launched)\b`)},
			struct {
				name     string
				severity string
				summary  string
				re       *regexp.Regexp
			}{"month5_provider_pilot_overclaim", "high", "Month 5 provider-pilot overclaim detected", regexp.MustCompile(`(?i)\bprovider[-\s]+pilot\s+(launched|ran|started|active|enabled)\b`)},
			struct {
				name     string
				severity string
				summary  string
				re       *regexp.Regexp
			}{"month5_release_overclaim", "high", "Month 5 release overclaim detected", regexp.MustCompile(`(?i)\b(release|tag|upload|deploy(?:ment)?)\s+(authorized|created|published|uploaded|deployed|granted)\b`)},
		)
	}
	if profile == "month6-release-readiness" {
		items = append(items,
			struct {
				name     string
				severity string
				summary  string
				re       *regexp.Regexp
			}{"month6_rsi_activation_overclaim", "critical", "Month 6 RSI activation overclaim detected", regexp.MustCompile(`(?i)\bRSI\s+(achieved|active|activated|authorized|enabled|granted)\b`)},
			struct {
				name     string
				severity string
				summary  string
				re       *regexp.Regexp
			}{"month6_live_self_modification_overclaim", "critical", "Month 6 live self-modification overclaim detected", regexp.MustCompile(`(?i)\b(self-improving\s+system\s+(is\s+)?active|autonomous\s+self-modification\s+(is\s+)?enabled|live\s+self-modification\s+(active|authorized|enabled|granted))\b`)},
			struct {
				name     string
				severity string
				summary  string
				re       *regexp.Regexp
			}{"month6_external_beta_overclaim", "high", "Month 6 external beta overclaim detected", regexp.MustCompile(`(?i)\bexternal\s+beta\s+(launched|active|started|open|enabled)\b`)},
			struct {
				name     string
				severity string
				summary  string
				re       *regexp.Regexp
			}{"month6_promotion_overclaim", "high", "Month 6 promotion overclaim detected", regexp.MustCompile(`(?i)\bpromotion\s+(requested|granted|approved|active|launched)\b`)},
			struct {
				name     string
				severity string
				summary  string
				re       *regexp.Regexp
			}{"month6_provider_pilot_overclaim", "high", "Month 6 provider-pilot overclaim detected", regexp.MustCompile(`(?i)\bprovider[-\s]+pilot\s+(launched|ran|started|active|enabled)\b`)},
			struct {
				name     string
				severity string
				summary  string
				re       *regexp.Regexp
			}{"month6_release_overclaim", "high", "Month 6 release overclaim detected", regexp.MustCompile(`(?i)\b(release|tag|upload|deploy(?:ment)?|binary publication)\s+(authorized|created|published|uploaded|deployed|granted)\b`)},
		)
	}
	if profile == "adoption-month1-gate-readiness" {
		items = append(items,
			struct {
				name     string
				severity string
				summary  string
				re       *regexp.Regexp
			}{"adoption_month1_gate_activation_overclaim", "high", "Adoption Month 1 compatibility gate activation overclaim detected", regexp.MustCompile(`(?i)\bcompatibility\s+gate\s+(is\s+)?(active|activated|enabled|complete|launched)\b`)},
			struct {
				name     string
				severity string
				summary  string
				re       *regexp.Regexp
			}{"adoption_month1_rsi_activation_overclaim", "critical", "Adoption Month 1 RSI activation overclaim detected", regexp.MustCompile(`(?i)\bRSI\s+(is\s+)?(achieved|active|activated|authorized|enabled|granted)\b`)},
			struct {
				name     string
				severity string
				summary  string
				re       *regexp.Regexp
			}{"adoption_month1_live_self_modification_overclaim", "critical", "Adoption Month 1 live self-modification overclaim detected", regexp.MustCompile(`(?i)\b(self-improving\s+system\s+(is\s+)?active|autonomous\s+self-modification\s+(is\s+)?enabled|live\s+self-modification\s+(active|authorized|enabled|granted))\b`)},
			struct {
				name     string
				severity string
				summary  string
				re       *regexp.Regexp
			}{"adoption_month1_external_beta_overclaim", "high", "Adoption Month 1 external beta overclaim detected", regexp.MustCompile(`(?i)\bexternal\s+beta\s+(launched|active|started|open|enabled)\b`)},
			struct {
				name     string
				severity string
				summary  string
				re       *regexp.Regexp
			}{"adoption_month1_promotion_overclaim", "high", "Adoption Month 1 promotion overclaim detected", regexp.MustCompile(`(?i)\bpromotion\s+(is\s+)?(requested|granted|approved|active|launched)\b`)},
			struct {
				name     string
				severity string
				summary  string
				re       *regexp.Regexp
			}{"adoption_month1_provider_pilot_overclaim", "high", "Adoption Month 1 provider-pilot overclaim detected", regexp.MustCompile(`(?i)\bprovider[-\s]+pilot\s+(launched|ran|started|active|enabled)\b`)},
			struct {
				name     string
				severity string
				summary  string
				re       *regexp.Regexp
			}{"adoption_month1_release_overclaim", "high", "Adoption Month 1 release overclaim detected", regexp.MustCompile(`(?i)\b(release|tag|upload|deploy(?:ment)?|binary publication)\s+(is\s+)?(authorized|created|published|uploaded|deployed|granted)\b`)},
			struct {
				name     string
				severity string
				summary  string
				re       *regexp.Regexp
			}{"adoption_month1_fully_autonomous_overclaim", "high", "Adoption Month 1 fully autonomous overclaim detected", regexp.MustCompile(`(?i)\bfully\s+autonomous\b`)},
			struct {
				name     string
				severity string
				summary  string
				re       *regexp.Regexp
			}{"github_issue_feature_pr_merge_overclaim", "critical", "GitHub issue workflow feature PR merge overclaim detected", regexp.MustCompile(`(?i)\b(merge|auto[-\s]*merge)\s+(feature[-\s]*generated\s+)?PRs?\b|\b(feature[-\s]*generated\s+)?PRs?\s+(can\s+)?(merge|be\s+merged)\b`)},
			struct {
				name     string
				severity string
				summary  string
				re       *regexp.Regexp
			}{"github_issue_pr_ready_overclaim", "high", "GitHub issue workflow ready-for-review overclaim detected", regexp.MustCompile(`(?i)\bmark\s+.*\bready\s+for\s+review\b|\bready[-\s]+for[-\s]+review\s+(authorized|allowed|enabled)\b`)},
			struct {
				name     string
				severity string
				summary  string
				re       *regexp.Regexp
			}{"github_issue_review_approval_overclaim", "high", "GitHub issue workflow review approval overclaim detected", regexp.MustCompile(`(?i)\b(approve|approval)\s+.*\b(PR|pull\s+request|review)\b|\bsubmit\s+.*\breview\s+approval\b`)},
			struct {
				name     string
				severity string
				summary  string
				re       *regexp.Regexp
			}{"github_issue_write_overclaim", "high", "GitHub issue workflow issue-write overclaim detected", regexp.MustCompile(`(?i)\b(comment|label|assign|close|reopen)\s+.*\bissues?\b|\bissues?\s+.*\b(commented|labeled|assigned|closed|reopened)\b`)},
		)
	}
	if profile == "adoption-month2-operator-drill" {
		items = append(items,
			struct {
				name     string
				severity string
				summary  string
				re       *regexp.Regexp
			}{"adoption_month2_gate_activation_overclaim", "high", "Adoption Month 2 compatibility gate activation overclaim detected", regexp.MustCompile(`(?i)\bcompatibility\s+gate\s+(is\s+)?(active|activated|enabled|complete|launched)\b`)},
			struct {
				name     string
				severity string
				summary  string
				re       *regexp.Regexp
			}{"adoption_month2_rsi_activation_overclaim", "critical", "Adoption Month 2 RSI activation overclaim detected", regexp.MustCompile(`(?i)\bRSI\s+(is\s+)?(achieved|active|activated|authorized|enabled|granted)\b`)},
			struct {
				name     string
				severity string
				summary  string
				re       *regexp.Regexp
			}{"adoption_month2_live_self_modification_overclaim", "critical", "Adoption Month 2 live self-modification overclaim detected", regexp.MustCompile(`(?i)\b(self-improving\s+system\s+(is\s+)?active|autonomous\s+self-modification\s+(is\s+)?enabled|live\s+self-modification\s+(active|authorized|enabled|granted))\b`)},
			struct {
				name     string
				severity string
				summary  string
				re       *regexp.Regexp
			}{"adoption_month2_external_beta_overclaim", "high", "Adoption Month 2 external beta overclaim detected", regexp.MustCompile(`(?i)\bexternal\s+beta\s+(launched|active|started|open|enabled)\b`)},
			struct {
				name     string
				severity string
				summary  string
				re       *regexp.Regexp
			}{"adoption_month2_promotion_overclaim", "high", "Adoption Month 2 promotion overclaim detected", regexp.MustCompile(`(?i)\bpromotion\s+(is\s+)?(requested|granted|approved|active|launched)\b`)},
			struct {
				name     string
				severity string
				summary  string
				re       *regexp.Regexp
			}{"adoption_month2_provider_pilot_overclaim", "high", "Adoption Month 2 provider-pilot overclaim detected", regexp.MustCompile(`(?i)\bprovider[-\s]+pilot\s+(launched|ran|started|active|enabled)\b`)},
			struct {
				name     string
				severity string
				summary  string
				re       *regexp.Regexp
			}{"adoption_month2_release_overclaim", "high", "Adoption Month 2 release overclaim detected", regexp.MustCompile(`(?i)\b(release|tag|upload|deploy(?:ment)?|binary publication)\s+(is\s+)?(authorized|created|published|uploaded|deployed|granted)\b`)},
		)
	}
	if profile == "github-issue-month2-authenticity" {
		items = append(items,
			struct {
				name     string
				severity string
				summary  string
				re       *regexp.Regexp
			}{"github_issue_false_authenticity_overclaim", "high", "GitHub issue authentic-bug overclaim without required reproduction evidence detected", regexp.MustCompile(`(?i)\b(authentic\s+bug|bug\s+authenticated|bug\s+confirmed)\b[^.\n]*(without\s+(a\s+)?failing\s+pre[-\s]*patch\s+reproduction|without\s+reproduction|based\s+on\s+issue\s+text\s+alone)`)},
			struct {
				name     string
				severity string
				summary  string
				re       *regexp.Regexp
			}{"github_issue_flaky_certainty_overclaim", "high", "GitHub issue flaky reproduction certainty overclaim detected", regexp.MustCompile(`(?i)\bflaky\b[^.\n]*(definitely|certainly|always)\s+(authentic|reproduced|confirmed)`)},
			struct {
				name     string
				severity string
				summary  string
				re       *regexp.Regexp
			}{"github_issue_security_public_repair_overclaim", "critical", "GitHub issue security-sensitive public repair overclaim detected", regexp.MustCompile(`(?i)\bsecurity[-\s]*sensitive\b[^.\n]*(public\s+repair|draft\s+PR|fix\s+publicly|publish\s+reproduction)[^.\n]*(allowed|authorized|can|enabled|published)?|\bsecurity[-\s]*sensitive\b[^.\n]*(allowed|authorized|can|enabled)[^.\n]*(public\s+repair|draft\s+PR|fix\s+publicly|publish\s+reproduction)`)},
			struct {
				name     string
				severity string
				summary  string
				re       *regexp.Regexp
			}{"github_issue_provider_pilot_overclaim", "high", "GitHub issue provider-pilot overclaim detected", regexp.MustCompile(`(?i)\bprovider[-\s]+pilot\s+(ran|started|active|enabled|launched)\b`)},
			struct {
				name     string
				severity string
				summary  string
				re       *regexp.Regexp
			}{"github_issue_release_overclaim", "high", "GitHub issue workflow release overclaim detected", regexp.MustCompile(`(?i)\b(release|tag|upload|deploy(?:ment)?|binary publication)\s+(is\s+)?(authorized|created|published|uploaded|deployed|granted)\b`)},
			struct {
				name     string
				severity string
				summary  string
				re       *regexp.Regexp
			}{"github_issue_rsi_overclaim", "critical", "GitHub issue workflow RSI overclaim detected", regexp.MustCompile(`(?i)\bRSI\s+(is\s+)?(achieved|active|activated|authorized|enabled|granted)\b`)},
		)
	}
	if profile == "github-issue-month3-repair" {
		items = append(items,
			struct {
				name     string
				severity string
				summary  string
				re       *regexp.Regexp
			}{"github_issue_false_fix_overclaim", "high", "GitHub issue repair false-fix overclaim detected", regexp.MustCompile(`(?i)\b(repair|fix)\b[^.\n]*(passed|complete|accepted)[^.\n]*(without\s+(preserving|keeping)\s+the\s+regression|after\s+deleting\s+the\s+regression|with\s+the\s+test\s+disabled)`)},
			struct {
				name     string
				severity string
				summary  string
				re       *regexp.Regexp
			}{"github_issue_rollback_overclaim", "high", "GitHub issue repair rollback overclaim detected", regexp.MustCompile(`(?i)\brollback\b[^.\n]*(passed|verified|complete)[^.\n]*(without\s+(exact\s+)?digest|without\s+before\/after|without\s+restore\s+evidence)`)},
			struct {
				name     string
				severity string
				summary  string
				re       *regexp.Regexp
			}{"github_issue_replay_overclaim", "high", "GitHub issue repair replay overclaim detected", regexp.MustCompile(`(?i)\breplay\b[^.\n]*(accepted|verified|complete)[^.\n]*(without\s+(matching\s+)?digest|without\s+evidence\s+digest)`)},
			struct {
				name     string
				severity string
				summary  string
				re       *regexp.Regexp
			}{"github_issue_feature_pr_merge_overclaim", "critical", "GitHub issue feature-generated PR merge overclaim detected", regexp.MustCompile(`(?i)\bfeature[-\s]*generated\s+(draft\s+)?PR\b[^.\n]*(merged|approved|ready\s+for\s+review|auto[-\s]*merged)`)},
			struct {
				name     string
				severity string
				summary  string
				re       *regexp.Regexp
			}{"github_issue_provider_pilot_overclaim", "high", "GitHub issue provider-pilot overclaim detected", regexp.MustCompile(`(?i)\bprovider[-\s]+pilot\s+(ran|started|active|enabled|launched)\b`)},
			struct {
				name     string
				severity string
				summary  string
				re       *regexp.Regexp
			}{"github_issue_release_overclaim", "high", "GitHub issue workflow release overclaim detected", regexp.MustCompile(`(?i)\b(release|tag|upload|deploy(?:ment)?|binary publication)\s+(is\s+)?(authorized|created|published|uploaded|deployed|granted)\b`)},
			struct {
				name     string
				severity string
				summary  string
				re       *regexp.Regexp
			}{"github_issue_rsi_overclaim", "critical", "GitHub issue workflow RSI overclaim detected", regexp.MustCompile(`(?i)\bRSI\s+(is\s+)?(achieved|active|activated|authorized|enabled|granted)\b`)},
		)
	}
	if profile == "adoption-month3-evidence-maintenance" {
		items = append(items,
			struct {
				name     string
				severity string
				summary  string
				re       *regexp.Regexp
			}{"adoption_month3_gate_activation_overclaim", "high", "Adoption Month 3 compatibility gate activation overclaim detected", regexp.MustCompile(`(?i)\bcompatibility\s+gate\s+(is\s+)?(active|activated|enabled|complete|launched)\b`)},
			struct {
				name     string
				severity string
				summary  string
				re       *regexp.Regexp
			}{"adoption_month3_rsi_activation_overclaim", "critical", "Adoption Month 3 RSI activation overclaim detected", regexp.MustCompile(`(?i)\bRSI\s+(is\s+)?(achieved|active|activated|authorized|enabled|granted)\b`)},
			struct {
				name     string
				severity string
				summary  string
				re       *regexp.Regexp
			}{"adoption_month3_live_self_modification_overclaim", "critical", "Adoption Month 3 live self-modification overclaim detected", regexp.MustCompile(`(?i)\b(self-improving\s+system\s+(is\s+)?active|autonomous\s+self-modification\s+(is\s+)?enabled|live\s+self-modification\s+(active|authorized|enabled|granted))\b`)},
			struct {
				name     string
				severity string
				summary  string
				re       *regexp.Regexp
			}{"adoption_month3_external_beta_overclaim", "high", "Adoption Month 3 external beta overclaim detected", regexp.MustCompile(`(?i)\bexternal\s+beta\s+(launched|active|started|open|enabled)\b`)},
			struct {
				name     string
				severity string
				summary  string
				re       *regexp.Regexp
			}{"adoption_month3_promotion_overclaim", "high", "Adoption Month 3 promotion overclaim detected", regexp.MustCompile(`(?i)\bpromotion\s+(is\s+)?(requested|granted|approved|active|launched)\b`)},
			struct {
				name     string
				severity string
				summary  string
				re       *regexp.Regexp
			}{"adoption_month3_provider_pilot_overclaim", "high", "Adoption Month 3 provider-pilot overclaim detected", regexp.MustCompile(`(?i)\bprovider[-\s]+pilot\s+(launched|ran|started|active|enabled)\b`)},
			struct {
				name     string
				severity string
				summary  string
				re       *regexp.Regexp
			}{"adoption_month3_release_overclaim", "high", "Adoption Month 3 release overclaim detected", regexp.MustCompile(`(?i)\b(release|tag|upload|deploy(?:ment)?|binary publication)\s+(is\s+)?(authorized|created|published|uploaded|deployed|granted)\b`)},
		)
	}
	if profile == "adoption-month5-support-readiness" {
		items = append(items,
			struct {
				name     string
				severity string
				summary  string
				re       *regexp.Regexp
			}{"adoption_month5_gate_activation_overclaim", "high", "Adoption Month 5 compatibility gate activation overclaim detected", regexp.MustCompile(`(?i)\bcompatibility\s+gate\s+(is\s+)?(active|activated|enabled|complete|launched)\b`)},
			struct {
				name     string
				severity string
				summary  string
				re       *regexp.Regexp
			}{"adoption_month5_rsi_activation_overclaim", "critical", "Adoption Month 5 RSI activation overclaim detected", regexp.MustCompile(`(?i)\bRSI\s+(is\s+)?(achieved|active|activated|authorized|enabled|granted)\b`)},
			struct {
				name     string
				severity string
				summary  string
				re       *regexp.Regexp
			}{"adoption_month5_live_self_modification_overclaim", "critical", "Adoption Month 5 live self-modification overclaim detected", regexp.MustCompile(`(?i)\b(self-improving\s+system\s+(is\s+)?active|autonomous\s+self-modification\s+(is\s+)?enabled|live\s+self-modification\s+(active|authorized|enabled|granted))\b`)},
			struct {
				name     string
				severity string
				summary  string
				re       *regexp.Regexp
			}{"adoption_month5_external_beta_overclaim", "high", "Adoption Month 5 external beta overclaim detected", regexp.MustCompile(`(?i)\bexternal\s+beta\s+(launched|active|started|open|enabled)\b`)},
			struct {
				name     string
				severity string
				summary  string
				re       *regexp.Regexp
			}{"adoption_month5_promotion_overclaim", "high", "Adoption Month 5 promotion overclaim detected", regexp.MustCompile(`(?i)\bpromotion\s+(is\s+)?(requested|granted|approved|active|launched)\b`)},
			struct {
				name     string
				severity string
				summary  string
				re       *regexp.Regexp
			}{"adoption_month5_provider_pilot_overclaim", "high", "Adoption Month 5 provider-pilot overclaim detected", regexp.MustCompile(`(?i)\bprovider[-\s]+pilot\s+(launched|ran|started|active|enabled)\b`)},
			struct {
				name     string
				severity string
				summary  string
				re       *regexp.Regexp
			}{"adoption_month5_release_overclaim", "high", "Adoption Month 5 release overclaim detected", regexp.MustCompile(`(?i)\b(release|tag|upload|deploy(?:ment)?|binary publication)\s+(is\s+)?(authorized|created|published|uploaded|deployed|granted)\b`)},
		)
	}
	return items
}

func month4ControlledLoopBoundaryFindings(file string, body string) []map[string]any {
	checks := []struct {
		name    string
		summary string
		re      *regexp.Regexp
	}{
		{"month4_missing_dry_run_boundary", "Month 4 controlled loop document is missing dry-run-only boundary wording", regexp.MustCompile(`(?i)\b(dry[-_\s]*run\s+only|fixture[-_\s]*only)\b`)},
		{"month4_missing_rsi_denied_boundary", "Month 4 controlled loop document is missing RSI-denied boundary wording", regexp.MustCompile(`(?i)\b(RSI\s+(remains\s+)?denied|rsi_remains_denied)\b`)},
	}
	findings := []map[string]any{}
	for _, check := range checks {
		if !check.re.MatchString(body) {
			findings = append(findings, map[string]any{
				"detector": check.name,
				"file":     filepath.ToSlash(file),
				"line":     1,
				"severity": "high",
				"summary":  check.summary,
			})
		}
	}
	return findings
}

func month5OperatorWorkflowBoundaryFindings(file string, body string) []map[string]any {
	checks := []struct {
		name    string
		summary string
		re      *regexp.Regexp
	}{
		{"month5_missing_operator_workflow_boundary", "Month 5 operator workflow document is missing operator-workflow boundary wording", regexp.MustCompile(`(?i)\b(operator\s+workflow|operator\s+readback|safe[-_\s]*next[-_\s]*work)\b`)},
		{"month5_missing_rsi_denied_boundary", "Month 5 operator workflow document is missing RSI-denied boundary wording", regexp.MustCompile(`(?i)\b(RSI\s+(remains\s+)?denied|rsi_remains_denied)\b`)},
	}
	findings := []map[string]any{}
	for _, check := range checks {
		if !check.re.MatchString(body) {
			findings = append(findings, map[string]any{
				"detector": check.name,
				"file":     filepath.ToSlash(file),
				"line":     1,
				"severity": "high",
				"summary":  check.summary,
			})
		}
	}
	return findings
}

func month6ReleaseReadinessBoundaryFindings(file string, body string) []map[string]any {
	checks := []struct {
		name    string
		summary string
		re      *regexp.Regexp
	}{
		{"month6_missing_no_release_boundary", "Month 6 release-readiness document is missing no-release decision wording", regexp.MustCompile(`(?i)\b(no[-_\s]*release|release\s+decision\s*=\s*no_release|does\s+not\s+require\s+a\s+new\s+stable\s+release)\b`)},
		{"month6_missing_current_pair_boundary", "Month 6 release-readiness document is missing current release pair wording", regexp.MustCompile(`(?i)\bAO2\s+v0\.5\.1\b[\s\S]*\b(v0\.1\.15|v0\.1\.16|Control\s+Plane\s+v0\.1\.15|Control\s+Plane\s+v0\.1\.16)\b`)},
		{"month6_missing_rsi_denied_boundary", "Month 6 release-readiness document is missing RSI-denied boundary wording", regexp.MustCompile(`(?i)\b(RSI\s+(remains\s+)?denied|rsi_remains_denied)\b`)},
	}
	findings := []map[string]any{}
	for _, check := range checks {
		if !check.re.MatchString(body) {
			findings = append(findings, map[string]any{
				"detector": check.name,
				"file":     filepath.ToSlash(file),
				"line":     1,
				"severity": "high",
				"summary":  check.summary,
			})
		}
	}
	return findings
}

func adoptionMonth1GateReadinessBoundaryFindings(file string, body string) []map[string]any {
	checks := []struct {
		name    string
		summary string
		re      *regexp.Regexp
	}{
		{"adoption_month1_missing_current_pair_boundary", "Adoption Month 1 gate-readiness document is missing current release pair wording", regexp.MustCompile(`(?i)\bAO2\s+v0\.5\.1\b[\s\S]*\b(v0\.1\.15|v0\.1\.16|Control\s+Plane\s+v0\.1\.15|Control\s+Plane\s+v0\.1\.16)\b`)},
		{"adoption_month1_missing_gate_ready_not_active_boundary", "Adoption Month 1 gate-readiness document is missing ready-not-active gate wording", regexp.MustCompile(`(?i)\bcompatibility\s+gate\b[\s\S]*(ready|not\s+active|activation\s+is\s+not\s+authorized)\b`)},
		{"adoption_month1_missing_rsi_denied_boundary", "Adoption Month 1 gate-readiness document is missing RSI-denied boundary wording", regexp.MustCompile(`(?i)\b(RSI\s+(remains\s+)?denied|rsi_remains_denied)\b`)},
	}
	findings := []map[string]any{}
	for _, check := range checks {
		if !check.re.MatchString(body) {
			findings = append(findings, map[string]any{
				"detector": check.name,
				"file":     filepath.ToSlash(file),
				"line":     1,
				"severity": "high",
				"summary":  check.summary,
			})
		}
	}
	return findings
}

func adoptionMonth2OperatorDrillBoundaryFindings(file string, body string) []map[string]any {
	checks := []struct {
		name    string
		summary string
		re      *regexp.Regexp
	}{
		{"adoption_month2_missing_current_pair_boundary", "Adoption Month 2 operator-drill document is missing current release pair wording", regexp.MustCompile(`(?i)\bAO2\s+v0\.5\.1\b[\s\S]*\b(v0\.1\.15|v0\.1\.16|Control\s+Plane\s+v0\.1\.15|Control\s+Plane\s+v0\.1\.16)\b`)},
		{"adoption_month2_missing_gate_ready_not_active_boundary", "Adoption Month 2 operator-drill document is missing ready-not-active gate wording", regexp.MustCompile(`(?i)\bcompatibility\s+gate\b[\s\S]*(ready|not\s+active|activation\s+is\s+not\s+authorized)\b`)},
		{"adoption_month2_missing_rsi_denied_boundary", "Adoption Month 2 operator-drill document is missing RSI-denied boundary wording", regexp.MustCompile(`(?i)\b(RSI\s+(remains\s+)?denied|rsi_remains_denied)\b`)},
	}
	findings := []map[string]any{}
	for _, check := range checks {
		if !check.re.MatchString(body) {
			findings = append(findings, map[string]any{
				"detector": check.name,
				"file":     filepath.ToSlash(file),
				"line":     1,
				"severity": "high",
				"summary":  check.summary,
			})
		}
	}
	return findings
}

func adoptionMonth3EvidenceMaintenanceBoundaryFindings(file string, body string) []map[string]any {
	checks := []struct {
		name    string
		summary string
		re      *regexp.Regexp
	}{
		{"adoption_month3_missing_current_pair_boundary", "Adoption Month 3 maintenance document is missing current release pair wording", regexp.MustCompile(`(?i)\bAO2\s+v0\.5\.1\b[\s\S]*\b(v0\.1\.15|v0\.1\.16|Control\s+Plane\s+v0\.1\.15|Control\s+Plane\s+v0\.1\.16)\b`)},
		{"adoption_month3_missing_maintenance_boundary", "Adoption Month 3 maintenance document is missing evidence-maintenance wording", regexp.MustCompile(`(?i)\b(evidence\s+maintenance|maintenance\s+report|freshness\s+check|matrix\s+drift)\b`)},
		{"adoption_month3_missing_gate_ready_not_active_boundary", "Adoption Month 3 maintenance document is missing ready-not-active gate wording", regexp.MustCompile(`(?i)\bcompatibility\s+gate\b[\s\S]*(ready|not\s+active|activation\s+is\s+not\s+authorized)\b`)},
		{"adoption_month3_missing_rsi_denied_boundary", "Adoption Month 3 maintenance document is missing RSI-denied boundary wording", regexp.MustCompile(`(?i)\b(RSI\s+(remains\s+)?denied|rsi_remains_denied)\b`)},
	}
	findings := []map[string]any{}
	for _, check := range checks {
		if !check.re.MatchString(body) {
			findings = append(findings, map[string]any{
				"detector": check.name,
				"file":     filepath.ToSlash(file),
				"line":     1,
				"severity": "high",
				"summary":  check.summary,
			})
		}
	}
	return findings
}

func adoptionMonth5SupportReadinessBoundaryFindings(file string, body string) []map[string]any {
	checks := []struct {
		name    string
		summary string
		re      *regexp.Regexp
	}{
		{"adoption_month5_missing_current_pair_boundary", "Adoption Month 5 support-readiness document is missing current release pair wording", regexp.MustCompile(`(?i)\bAO2\s+v0\.5\.1\b[\s\S]*\b(v0\.1\.15|v0\.1\.16|Control\s+Plane\s+v0\.1\.15|Control\s+Plane\s+v0\.1\.16)\b`)},
		{"adoption_month5_missing_support_readiness_boundary", "Adoption Month 5 support-readiness document is missing support-readiness wording", regexp.MustCompile(`(?i)\b(support\s+readiness|support\s+package|support\s+states|windows[-_\s]*safe\s+rollback)\b`)},
		{"adoption_month5_missing_gate_ready_not_active_boundary", "Adoption Month 5 support-readiness document is missing ready-not-active gate wording", regexp.MustCompile(`(?i)\bcompatibility\s+gate\b[\s\S]*(ready|not\s+active|activation\s+is\s+not\s+authorized)\b`)},
		{"adoption_month5_missing_rsi_denied_boundary", "Adoption Month 5 support-readiness document is missing RSI-denied boundary wording", regexp.MustCompile(`(?i)\b(RSI\s+(remains\s+)?denied|rsi_remains_denied)\b`)},
	}
	findings := []map[string]any{}
	for _, check := range checks {
		if !check.re.MatchString(body) {
			findings = append(findings, map[string]any{
				"detector": check.name,
				"file":     filepath.ToSlash(file),
				"line":     1,
				"severity": "high",
				"summary":  check.summary,
			})
		}
	}
	return findings
}

func readJSONMap(path string) (map[string]any, error) {
	body, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var out map[string]any
	if err := json.Unmarshal(body, &out); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	return out, nil
}

func writeJSON(path string, value any) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	body, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(body, '\n'), 0o644)
}

func flagValue(args []string, name string) (string, error) {
	for i, arg := range args {
		if arg == name && i+1 < len(args) {
			return args[i+1], nil
		}
	}
	return "", fmt.Errorf("missing %s", name)
}

func optionalFlagValue(args []string, name string, fallback string) (string, error) {
	for i, arg := range args {
		if arg == name {
			if i+1 >= len(args) {
				return "", fmt.Errorf("missing %s value", name)
			}
			return args[i+1], nil
		}
	}
	return fallback, nil
}

func requireTmpOutput(path string) error {
	clean := filepath.Clean(path)
	parts := strings.Split(clean, string(filepath.Separator))
	firstRealPart := 0
	for firstRealPart < len(parts) && (parts[firstRealPart] == "" || strings.HasSuffix(parts[firstRealPart], ":")) {
		firstRealPart++
	}
	for i, part := range parts {
		if part == "tmp" {
			if filepath.IsAbs(clean) && i == firstRealPart {
				continue
			}
			return nil
		}
	}
	return fmt.Errorf("output path must be under tmp/: %s", path)
}

func newBlocker(id, severity, reason, source, action string) blocker {
	id = strings.ToLower(strings.ReplaceAll(id, " ", "_"))
	id = regexp.MustCompile(`[^a-z0-9_]+`).ReplaceAllString(id, "_")
	if severity == "" {
		severity = "high"
	}
	return blocker{
		BlockerID:         id,
		Severity:          severity,
		Reason:            reason,
		Source:            source,
		RecommendedAction: action,
	}
}

func recommendedActions(blockers []blocker) []string {
	seen := map[string]bool{}
	out := []string{}
	for _, b := range blockers {
		if b.RecommendedAction != "" && !seen[b.RecommendedAction] {
			seen[b.RecommendedAction] = true
			out = append(out, b.RecommendedAction)
		}
	}
	sort.Strings(out)
	return out
}

func severity(result map[string]any) string {
	return stringFieldOr(result, "severity_on_failure", "high")
}

func stringField(m map[string]any, key string) string {
	value, _ := m[key].(string)
	return value
}

func stringFieldOr(m map[string]any, key, fallback string) string {
	value := stringField(m, key)
	if value == "" {
		return fallback
	}
	return value
}

func boolField(m map[string]any, key string) bool {
	value, _ := m[key].(bool)
	return value
}

func numberField(m map[string]any, key string) float64 {
	value, _ := m[key].(float64)
	return value
}

func asAnySlice(value any) []any {
	if raw, ok := value.([]any); ok {
		return raw
	}
	if raw, ok := value.([]string); ok {
		out := make([]any, 0, len(raw))
		for _, value := range raw {
			out = append(out, value)
		}
		return out
	}
	return []any{}
}

func stringsFromAnySlice(value any) []string {
	raw := asAnySlice(value)
	out := make([]string, 0, len(raw))
	for _, item := range raw {
		if text, ok := item.(string); ok && strings.TrimSpace(text) != "" {
			out = append(out, text)
		}
	}
	return out
}

func anyStrings(values []string) []any {
	out := make([]any, 0, len(values))
	for _, value := range values {
		out = append(out, value)
	}
	return out
}

func uniqueStrings(values []string) []string {
	seen := map[string]bool{}
	out := []string{}
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" || seen[value] {
			continue
		}
		seen[value] = true
		out = append(out, value)
	}
	sort.Strings(out)
	return out
}

func isTextFile(path string) bool {
	switch strings.ToLower(filepath.Ext(path)) {
	case ".md", ".json", ".yaml", ".yml", ".txt", ".go":
		return true
	default:
		return false
	}
}

func setOf(values ...string) map[string]bool {
	out := make(map[string]bool, len(values))
	for _, value := range values {
		out[value] = true
	}
	return out
}

func nowUTC() string {
	return time.Now().UTC().Format(time.RFC3339)
}
