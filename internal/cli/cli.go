package cli

import (
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
  sentinel safety scan --path <path> --out <json>
  sentinel run regression --suite <json> --out <json>
  sentinel compare regression --baseline <json> --run <json> --out <json>
  sentinel monitor evaluate --target <json> --baseline <json> --safety <json> --regression <json> --out <json>
  sentinel incident render --verdict <json> --out <json>
  sentinel hold emit --verdict <json> --out <json>
  sentinel report render --verdict <json> --incident <json> --out <markdown>
  sentinel watch dry-run --target <json> --suite <json> --baseline <json> --iterations <n> --out <json>
  sentinel triage ci --signal <json> --out <json>

Commands: target baseline safety run compare monitor incident hold report watch triage`)
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
	if err := requireTmpOutput(out); err != nil {
		return err
	}
	result, err := safetyScan(path)
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
	findings := []map[string]any{}
	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	visit := func(file string) error {
		body, err := os.ReadFile(file)
		if err != nil {
			return err
		}
		for lineNo, line := range strings.Split(string(body), "\n") {
			for _, detector := range detectors() {
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
		"path":               filepath.ToSlash(path),
		"findings_count":     len(findings),
		"findings":           findings,
		"scanned_at_utc":     nowUTC(),
		"mutates_live_state": false,
	}, nil
}

func detectors() []struct {
	name     string
	severity string
	summary  string
	re       *regexp.Regexp
} {
	return []struct {
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
		{"local_absolute_path", "high", "local absolute path detected", regexp.MustCompile(`(/Users/[^ \n]+|/home/[^ \n]+|C:\\Users\\[^ \n]+)`)},
		{"forbidden_action_command", "high", "forbidden action command detected", regexp.MustCompile(`(?i)\b(git push|git tag|gh release|npm publish|twine upload|docker push|kubectl apply|terraform apply)\b`)},
	}
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

func requireTmpOutput(path string) error {
	clean := filepath.Clean(path)
	for _, part := range strings.Split(clean, string(filepath.Separator)) {
		if part == "tmp" {
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
