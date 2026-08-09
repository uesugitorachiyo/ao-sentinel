package cli

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
)

const aoLoreMonitoringMaxBytes = 128 * 1024

var (
	aoLoreIDPattern         = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,127}$`)
	aoLoreSHA256Pattern     = regexp.MustCompile(`^[0-9a-f]{64}$`)
	aoLoreTransitionPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]*->[a-z0-9][a-z0-9._-]*$`)
)

type AOLoreMonitoringBaseline struct {
	SchemaVersion        string                     `json:"schema_version"`
	BaselineID           string                     `json:"baseline_id"`
	TargetID             string                     `json:"target_id"`
	SourceHeadSHA256     string                     `json:"source_head_sha256"`
	ProfileSHA256        string                     `json:"profile_sha256"`
	GeneratedAtUTC       string                     `json:"generated_at_utc"`
	ValidUntilUTC        string                     `json:"valid_until_utc"`
	Metrics              AOLoreMonitoringMetrics    `json:"metrics"`
	Tolerances           AOLoreMonitoringTolerances `json:"tolerances"`
	AllowedRoleFallbacks map[string][]string        `json:"allowed_role_fallbacks"`
	TracePolicySHA256    string                     `json:"trace_policy_sha256"`
}

type AOLoreMonitoringObservation struct {
	SchemaVersion     string                  `json:"schema_version"`
	ObservationID     string                  `json:"observation_id"`
	TargetID          string                  `json:"target_id"`
	BaselineID        string                  `json:"baseline_id"`
	BaselineSHA256    string                  `json:"baseline_sha256"`
	SourceHeadSHA256  string                  `json:"source_head_sha256"`
	ProfileSHA256     string                  `json:"profile_sha256"`
	ObservedAtUTC     string                  `json:"observed_at_utc"`
	Metrics           AOLoreMonitoringMetrics `json:"metrics"`
	RoleFallbacks     []AOLoreRoleFallback    `json:"role_fallbacks"`
	TracePolicySHA256 string                  `json:"trace_policy_sha256"`
	TraceIntegrity    bool                    `json:"trace_integrity"`
}

type AOLoreMonitoringMetrics struct {
	ParserSelectionScoreBasisPoints   int `json:"parser_selection_score_basis_points"`
	ParseQualityThresholdBasisPoints  int `json:"parse_quality_threshold_basis_points"`
	EvidenceCoverageBasisPoints       int `json:"evidence_coverage_basis_points"`
	WastedTraversalNodes              int `json:"wasted_traversal_nodes"`
	NodesPerSatisfiedRequirementMilli int `json:"nodes_per_satisfied_requirement_milli"`
	TokensPerCoveragePointMilli       int `json:"tokens_per_coverage_point_milli"`
}

type AOLoreMonitoringTolerances struct {
	MaxParserScoreDropBasisPoints       int `json:"max_parser_score_drop_basis_points"`
	MaxThresholdChangeBasisPoints       int `json:"max_threshold_change_basis_points"`
	MaxCoverageDropBasisPoints          int `json:"max_coverage_drop_basis_points"`
	MaxWastedTraversalIncrease          int `json:"max_wasted_traversal_increase"`
	MaxNodesPerRequirementIncreaseMilli int `json:"max_nodes_per_requirement_increase_milli"`
	MaxTokensPerCoverageIncreaseMilli   int `json:"max_tokens_per_coverage_increase_milli"`
}

type AOLoreRoleFallback struct {
	Role        string `json:"role"`
	FromAdapter string `json:"from_adapter"`
	ToAdapter   string `json:"to_adapter"`
}

type aoLoreMonitoringFinding struct {
	Code     string `json:"code"`
	Severity string `json:"severity"`
	Reason   string `json:"reason"`
}

type aoLoreMonitoringInputDigests struct {
	Baseline    *string `json:"baseline_sha256"`
	Observation string  `json:"observation_sha256"`
}

type aoLoreMonitoringVerdict struct {
	SchemaVersion        string                       `json:"schema_version"`
	ObservationID        string                       `json:"observation_id"`
	TargetID             string                       `json:"target_id"`
	BaselineID           *string                      `json:"baseline_id"`
	BaselineStatus       string                       `json:"baseline_status"`
	BaselineSourceHead   *string                      `json:"baseline_source_head_sha256"`
	ObservedSourceHead   string                       `json:"observed_source_head_sha256"`
	InputDigests         aoLoreMonitoringInputDigests `json:"input_digests"`
	Status               string                       `json:"status"`
	Findings             []aoLoreMonitoringFinding    `json:"findings"`
	MetricDeltas         map[string]int               `json:"metric_deltas"`
	Metrics              AOLoreMonitoringMetrics      `json:"observed_metrics"`
	RoleFallbacks        []AOLoreRoleFallback         `json:"role_fallbacks"`
	TraceIntegrity       bool                         `json:"trace_integrity"`
	PromoterHoldRequired bool                         `json:"promoter_hold_required"`
	MutatesLiveState     bool                         `json:"mutates_live_state"`
	ApprovesWork         bool                         `json:"approves_work"`
	PromotesCandidate    bool                         `json:"promotes_candidate"`
	ReleasesOrPublishes  bool                         `json:"releases_or_publishes"`
}

func runAOLore(args []string, stdout io.Writer) error {
	if len(args) == 0 || args[0] != "evaluate" {
		return fmt.Errorf("usage: sentinel ao-lore evaluate [--baseline <json>] --observation <json> --out <json>")
	}
	baselinePath, observationPath, outputPath, err := parseAOLoreEvaluateFlags(args[1:])
	if err != nil {
		return err
	}
	if err := evaluateAOLoreMonitoring(baselinePath, observationPath, outputPath); err != nil {
		return err
	}
	fmt.Fprintln(stdout, "AO Lore monitoring verdict written")
	return nil
}

func evaluateAOLoreMonitoring(baselinePath, observationPath, outputPath string) error {
	var observation AOLoreMonitoringObservation
	observationBody, err := readStrictAOLoreJSON(observationPath, "AO Lore observation", &observation)
	if err != nil {
		return err
	}
	if err := validateAOLoreObservation(observation, baselinePath != ""); err != nil {
		return err
	}
	observationDigest := digestAOLoreBytes(observationBody)
	if baselinePath == "" {
		verdict := buildAOLoreMissingBaselineVerdict(observation, observationDigest)
		return writeAOLoreVerdict(outputPath, verdict)
	}
	var baseline AOLoreMonitoringBaseline
	baselineBody, err := readStrictAOLoreJSON(baselinePath, "AO Lore baseline", &baseline)
	if err != nil {
		return err
	}
	if err := validateAOLoreBaseline(baseline); err != nil {
		return err
	}
	baselineDigest := digestAOLoreBytes(baselineBody)
	if observation.BaselineSHA256 != baselineDigest {
		return fmt.Errorf("AO Lore baseline SHA-256 mismatch")
	}
	if observation.BaselineID != baseline.BaselineID || observation.TargetID != baseline.TargetID || observation.ProfileSHA256 != baseline.ProfileSHA256 {
		return fmt.Errorf("AO Lore observation does not match baseline identity, target, or profile")
	}
	verdict, err := buildAOLoreMonitoringVerdict(baseline, observation, baselineDigest, observationDigest)
	if err != nil {
		return err
	}
	return writeAOLoreVerdict(outputPath, verdict)
}

func readStrictAOLoreJSON(path, label string, target any) ([]byte, error) {
	if path == "" {
		return nil, fmt.Errorf("missing %s path", label)
	}
	if err := rejectAOLoreSymlinkAncestors(filepath.Dir(path)); err != nil {
		return nil, err
	}
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return nil, fmt.Errorf("%s must be a regular non-link file", label)
	}
	if info.Size() > aoLoreMonitoringMaxBytes {
		return nil, fmt.Errorf("%s exceeds size limit", label)
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil {
		return nil, err
	}
	if !opened.Mode().IsRegular() || !os.SameFile(info, opened) {
		return nil, fmt.Errorf("%s must remain the same regular non-link file", label)
	}
	body, err := io.ReadAll(io.LimitReader(file, aoLoreMonitoringMaxBytes+1))
	if err != nil {
		return nil, err
	}
	if len(body) > aoLoreMonitoringMaxBytes {
		return nil, fmt.Errorf("%s exceeds size limit", label)
	}
	if err := rejectIssueRepairDuplicateJSONKeys(body); err != nil {
		return nil, err
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return nil, fmt.Errorf("parse %s: %w", label, err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		if err == nil {
			return nil, fmt.Errorf("%s contains trailing JSON", label)
		}
		return nil, fmt.Errorf("%s contains trailing data: %w", label, err)
	}
	return body, nil
}

func rejectAOLoreSymlinkAncestors(path string) error {
	absolute, err := filepath.Abs(path)
	if err != nil {
		return err
	}
	volume := filepath.VolumeName(absolute)
	current := volume + string(filepath.Separator)
	relative := strings.TrimPrefix(absolute, current)
	for _, part := range strings.Split(relative, string(filepath.Separator)) {
		if part == "" {
			continue
		}
		current = filepath.Join(current, part)
		info, err := os.Lstat(current)
		if err != nil {
			return err
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("AO Lore path ancestor is a symlink")
		}
		if !info.IsDir() {
			return fmt.Errorf("AO Lore path ancestor is not a directory")
		}
	}
	return nil
}

func digestAOLoreBytes(body []byte) string {
	digest := sha256.Sum256(body)
	return hex.EncodeToString(digest[:])
}

func validateAOLoreID(label, value string, allowEmpty bool) error {
	if allowEmpty && value == "" {
		return nil
	}
	if !aoLoreIDPattern.MatchString(value) {
		return fmt.Errorf("%s must be a bounded lowercase identifier", label)
	}
	return nil
}

func validateAOLoreSHA(label, value string, allowEmpty bool) error {
	if allowEmpty && value == "" {
		return nil
	}
	if !aoLoreSHA256Pattern.MatchString(value) {
		return fmt.Errorf("%s must be 64 lowercase hexadecimal characters", label)
	}
	return nil
}

func validateAOLoreMetrics(metrics AOLoreMonitoringMetrics) error {
	for label, value := range map[string]int{
		"parser selection score":  metrics.ParserSelectionScoreBasisPoints,
		"parse quality threshold": metrics.ParseQualityThresholdBasisPoints,
		"evidence coverage":       metrics.EvidenceCoverageBasisPoints,
	} {
		if value < 0 || value > 10000 {
			return fmt.Errorf("%s must be between 0 and 10000 basis points", label)
		}
	}
	for label, value := range map[string]int{
		"wasted traversal":                metrics.WastedTraversalNodes,
		"nodes per satisfied requirement": metrics.NodesPerSatisfiedRequirementMilli,
		"tokens per coverage point":       metrics.TokensPerCoveragePointMilli,
	} {
		if value < 0 || value > 1_000_000_000 {
			return fmt.Errorf("%s is outside canonical bounds", label)
		}
	}
	return nil
}

func validateAOLoreBaseline(baseline AOLoreMonitoringBaseline) error {
	if baseline.SchemaVersion != "ao.sentinel.ao-lore-baseline.v0.1" {
		return fmt.Errorf("invalid AO Lore baseline schema_version")
	}
	if err := validateAOLoreID("baseline_id", baseline.BaselineID, false); err != nil {
		return err
	}
	if err := validateAOLoreID("target_id", baseline.TargetID, false); err != nil {
		return err
	}
	for label, value := range map[string]string{"source_head_sha256": baseline.SourceHeadSHA256, "profile_sha256": baseline.ProfileSHA256, "trace_policy_sha256": baseline.TracePolicySHA256} {
		if err := validateAOLoreSHA(label, value, false); err != nil {
			return err
		}
	}
	generated, err := time.Parse(time.RFC3339, baseline.GeneratedAtUTC)
	if err != nil {
		return fmt.Errorf("invalid baseline generated_at_utc")
	}
	validUntil, err := time.Parse(time.RFC3339, baseline.ValidUntilUTC)
	if err != nil || !validUntil.After(generated) {
		return fmt.Errorf("invalid baseline valid_until_utc")
	}
	if err := validateAOLoreMetrics(baseline.Metrics); err != nil {
		return err
	}
	for label, value := range map[string]int{
		"max parser score drop":              baseline.Tolerances.MaxParserScoreDropBasisPoints,
		"max threshold change":               baseline.Tolerances.MaxThresholdChangeBasisPoints,
		"max coverage drop":                  baseline.Tolerances.MaxCoverageDropBasisPoints,
		"max wasted traversal increase":      baseline.Tolerances.MaxWastedTraversalIncrease,
		"max nodes per requirement increase": baseline.Tolerances.MaxNodesPerRequirementIncreaseMilli,
		"max tokens per coverage increase":   baseline.Tolerances.MaxTokensPerCoverageIncreaseMilli,
	} {
		if value < 0 || value > 1_000_000_000 {
			return fmt.Errorf("%s tolerance is outside canonical bounds", label)
		}
	}
	roles := []string{"parser", "distiller", "navigator", "synthesizer"}
	if len(baseline.AllowedRoleFallbacks) != len(roles) {
		return fmt.Errorf("allowed role fallbacks must contain exactly four roles")
	}
	for _, role := range roles {
		transitions, ok := baseline.AllowedRoleFallbacks[role]
		if !ok || transitions == nil {
			return fmt.Errorf("allowed role fallbacks must contain role %s", role)
		}
		seen := map[string]bool{}
		for _, transition := range transitions {
			if !aoLoreTransitionPattern.MatchString(transition) || seen[transition] {
				return fmt.Errorf("role %s contains invalid or duplicate fallback", role)
			}
			seen[transition] = true
		}
	}
	return nil
}

func validateAOLoreObservation(observation AOLoreMonitoringObservation, baselineProvided bool) error {
	if observation.SchemaVersion != "ao.sentinel.ao-lore-observation.v0.1" {
		return fmt.Errorf("invalid AO Lore observation schema_version")
	}
	if err := validateAOLoreID("observation_id", observation.ObservationID, false); err != nil {
		return err
	}
	if err := validateAOLoreID("target_id", observation.TargetID, false); err != nil {
		return err
	}
	if err := validateAOLoreID("baseline_id", observation.BaselineID, !baselineProvided); err != nil {
		return err
	}
	if err := validateAOLoreSHA("baseline_sha256", observation.BaselineSHA256, !baselineProvided); err != nil {
		return err
	}
	if baselineProvided && (observation.BaselineID == "" || observation.BaselineSHA256 == "") {
		return fmt.Errorf("provided baseline requires observation bindings")
	}
	if !baselineProvided && (observation.BaselineID != "" || observation.BaselineSHA256 != "") {
		return fmt.Errorf("missing baseline requires empty observation baseline bindings")
	}
	for label, value := range map[string]string{"source_head_sha256": observation.SourceHeadSHA256, "profile_sha256": observation.ProfileSHA256, "trace_policy_sha256": observation.TracePolicySHA256} {
		if err := validateAOLoreSHA(label, value, false); err != nil {
			return err
		}
	}
	if _, err := time.Parse(time.RFC3339, observation.ObservedAtUTC); err != nil {
		return fmt.Errorf("invalid observation observed_at_utc")
	}
	if err := validateAOLoreMetrics(observation.Metrics); err != nil {
		return err
	}
	if observation.RoleFallbacks == nil || len(observation.RoleFallbacks) > 20 {
		return fmt.Errorf("role fallbacks must be a bounded array")
	}
	for _, fallback := range observation.RoleFallbacks {
		if fallback.Role != "parser" && fallback.Role != "distiller" && fallback.Role != "navigator" && fallback.Role != "synthesizer" {
			return fmt.Errorf("role fallback has unknown role")
		}
		transition := fallback.FromAdapter + "->" + fallback.ToAdapter
		if !aoLoreTransitionPattern.MatchString(transition) {
			return fmt.Errorf("role fallback has invalid adapter identity")
		}
	}
	return nil
}

func addAOLoreFinding(findings *[]aoLoreMonitoringFinding, code, severity, reason string) {
	*findings = append(*findings, aoLoreMonitoringFinding{Code: code, Severity: severity, Reason: reason})
}

func buildAOLoreMissingBaselineVerdict(observation AOLoreMonitoringObservation, observationDigest string) aoLoreMonitoringVerdict {
	findings := []aoLoreMonitoringFinding{}
	addAOLoreFinding(&findings, "baseline_missing", "hold", "A versioned AO Lore monitoring baseline was not supplied.")
	return aoLoreMonitoringVerdict{
		SchemaVersion: "ao.sentinel.ao-lore-verdict.v0.1", ObservationID: observation.ObservationID, TargetID: observation.TargetID,
		BaselineStatus: "missing", ObservedSourceHead: observation.SourceHeadSHA256,
		InputDigests: aoLoreMonitoringInputDigests{Observation: observationDigest}, Status: "hold", Findings: findings,
		MetricDeltas: map[string]int{}, Metrics: observation.Metrics, RoleFallbacks: append([]AOLoreRoleFallback{}, observation.RoleFallbacks...),
		TraceIntegrity: observation.TraceIntegrity, PromoterHoldRequired: true,
	}
}

func buildAOLoreMonitoringVerdict(baseline AOLoreMonitoringBaseline, observation AOLoreMonitoringObservation, baselineDigest, observationDigest string) (aoLoreMonitoringVerdict, error) {
	observedAt, _ := time.Parse(time.RFC3339, observation.ObservedAtUTC)
	validUntil, _ := time.Parse(time.RFC3339, baseline.ValidUntilUTC)
	findings := []aoLoreMonitoringFinding{}
	deltas := map[string]int{
		"parser_selection_score_basis_points":   observation.Metrics.ParserSelectionScoreBasisPoints - baseline.Metrics.ParserSelectionScoreBasisPoints,
		"parse_quality_threshold_basis_points":  observation.Metrics.ParseQualityThresholdBasisPoints - baseline.Metrics.ParseQualityThresholdBasisPoints,
		"evidence_coverage_basis_points":        observation.Metrics.EvidenceCoverageBasisPoints - baseline.Metrics.EvidenceCoverageBasisPoints,
		"wasted_traversal_nodes":                observation.Metrics.WastedTraversalNodes - baseline.Metrics.WastedTraversalNodes,
		"nodes_per_satisfied_requirement_milli": observation.Metrics.NodesPerSatisfiedRequirementMilli - baseline.Metrics.NodesPerSatisfiedRequirementMilli,
		"tokens_per_coverage_point_milli":       observation.Metrics.TokensPerCoveragePointMilli - baseline.Metrics.TokensPerCoveragePointMilli,
	}
	if observedAt.After(validUntil) {
		addAOLoreFinding(&findings, "baseline_stale", "hold", "Observation time is after the baseline validity window.")
	}
	if -deltas["parser_selection_score_basis_points"] > baseline.Tolerances.MaxParserScoreDropBasisPoints {
		addAOLoreFinding(&findings, "parser_score_drift", "hold", "Parser selection score dropped beyond the fixed tolerance.")
	}
	thresholdDelta := deltas["parse_quality_threshold_basis_points"]
	if thresholdDelta < 0 {
		thresholdDelta = -thresholdDelta
	}
	if thresholdDelta > baseline.Tolerances.MaxThresholdChangeBasisPoints {
		addAOLoreFinding(&findings, "threshold_drift", "hold", "Parse quality threshold changed beyond the fixed tolerance.")
	}
	if -deltas["evidence_coverage_basis_points"] > baseline.Tolerances.MaxCoverageDropBasisPoints {
		addAOLoreFinding(&findings, "coverage_regression", "hold", "Evidence coverage dropped beyond the fixed tolerance.")
	}
	if deltas["wasted_traversal_nodes"] > baseline.Tolerances.MaxWastedTraversalIncrease {
		addAOLoreFinding(&findings, "wasted_traversal_regression", "hold", "Traversal after coverage sufficiency exceeded the fixed budget.")
	}
	if deltas["nodes_per_satisfied_requirement_milli"] > baseline.Tolerances.MaxNodesPerRequirementIncreaseMilli {
		addAOLoreFinding(&findings, "nodes_per_requirement_regression", "hold", "Nodes per satisfied requirement regressed beyond tolerance.")
	}
	if deltas["tokens_per_coverage_point_milli"] > baseline.Tolerances.MaxTokensPerCoverageIncreaseMilli {
		addAOLoreFinding(&findings, "tokens_per_coverage_regression", "hold", "Tokens per coverage point regressed beyond tolerance.")
	}
	allowed := map[string]bool{}
	for role, transitions := range baseline.AllowedRoleFallbacks {
		for _, transition := range transitions {
			allowed[role+":"+transition] = true
		}
	}
	for _, fallback := range observation.RoleFallbacks {
		key := fallback.Role + ":" + fallback.FromAdapter + "->" + fallback.ToAdapter
		if !allowed[key] {
			addAOLoreFinding(&findings, "unauthorized_role_fallback", "incident", "Observed model-role fallback is absent from the fixed baseline policy.")
		}
	}
	if !observation.TraceIntegrity {
		addAOLoreFinding(&findings, "trace_integrity_failure", "incident", "AO Lore trace integrity verification failed.")
	}
	if observation.TracePolicySHA256 != baseline.TracePolicySHA256 {
		addAOLoreFinding(&findings, "trace_policy_mismatch", "incident", "Observed trace policy digest does not match the baseline.")
	}
	sort.Slice(findings, func(i, j int) bool { return findings[i].Code < findings[j].Code })
	status := "clear"
	for _, finding := range findings {
		if finding.Severity == "incident" {
			status = "incident"
			break
		}
		status = "hold"
	}
	baselineID := baseline.BaselineID
	baselineHead := baseline.SourceHeadSHA256
	return aoLoreMonitoringVerdict{
		SchemaVersion: "ao.sentinel.ao-lore-verdict.v0.1", ObservationID: observation.ObservationID, TargetID: observation.TargetID,
		BaselineID: &baselineID, BaselineStatus: map[bool]string{true: "stale", false: "present"}[observedAt.After(validUntil)],
		BaselineSourceHead: &baselineHead, ObservedSourceHead: observation.SourceHeadSHA256,
		InputDigests: aoLoreMonitoringInputDigests{Baseline: &baselineDigest, Observation: observationDigest},
		Status:       status, Findings: findings, MetricDeltas: deltas, Metrics: observation.Metrics,
		RoleFallbacks: append([]AOLoreRoleFallback{}, observation.RoleFallbacks...), TraceIntegrity: observation.TraceIntegrity,
		PromoterHoldRequired: status != "clear",
	}, nil
}

func writeAOLoreVerdict(path string, verdict aoLoreMonitoringVerdict) (returnErr error) {
	if err := requireTmpOutput(path); err != nil {
		return err
	}
	parent := filepath.Dir(path)
	if err := rejectAOLoreSymlinkAncestors(parent); err != nil {
		return err
	}
	info, err := os.Lstat(parent)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("AO Lore output parent must be a real directory")
	}
	body, err := json.MarshalIndent(verdict, "", "  ")
	if err != nil {
		return err
	}
	body = append(body, '\n')
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
	if errors.Is(err, os.ErrExist) {
		return fmt.Errorf("AO Lore output already exists")
	}
	if err != nil {
		return err
	}
	removeOnFailure := true
	defer func() {
		if removeOnFailure {
			_ = file.Close()
			_ = os.Remove(path)
		}
	}()
	if _, err := file.Write(body); err != nil {
		return err
	}
	if err := file.Sync(); err != nil {
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	removeOnFailure = false
	return nil
}

func parseAOLoreEvaluateFlags(args []string) (baseline, observation, out string, err error) {
	for i := 0; i < len(args); i += 2 {
		name := args[i]
		if name != "--baseline" && name != "--observation" && name != "--out" {
			return "", "", "", fmt.Errorf("unknown flag or argument %q", name)
		}
		if i+1 >= len(args) || strings.HasPrefix(args[i+1], "--") {
			return "", "", "", fmt.Errorf("missing value for %s", name)
		}
		value := args[i+1]
		switch name {
		case "--baseline":
			if baseline != "" {
				return "", "", "", fmt.Errorf("duplicate --baseline")
			}
			baseline = value
		case "--observation":
			if observation != "" {
				return "", "", "", fmt.Errorf("duplicate --observation")
			}
			observation = value
		case "--out":
			if out != "" {
				return "", "", "", fmt.Errorf("duplicate --out")
			}
			out = value
		}
	}
	if observation == "" || out == "" {
		return "", "", "", fmt.Errorf("usage: sentinel ao-lore evaluate [--baseline <json>] --observation <json> --out <json>")
	}
	return baseline, observation, out, nil
}
