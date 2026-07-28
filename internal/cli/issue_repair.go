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
	"reflect"
	"regexp"
	"strings"
	"time"
)

const issueRepairRequestMaxBytes = 64 * 1024

const (
	issueRepairRequestSchema = "ao.sentinel.issue-repair-finding-request.v0.1"
	issueRepairPacketSchema  = "ao.sentinel.issue-repair-finding-packet.v0.1"
)

var issueRepairDigestPattern = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
var issueRepairSourceSHAPattern = regexp.MustCompile(`^[0-9a-f]{40}([0-9a-f]{24})?$`)
var issueRepairRepositoryPattern = regexp.MustCompile(`^[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})/[A-Za-z0-9._-]+$`)
var issueRepairIDPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)

type IssueRepairFindingRequest struct {
	SchemaVersion string              `json:"schema_version"`
	MissionID     string              `json:"mission_id"`
	CandidateID   string              `json:"candidate_id"`
	Repository    string              `json:"repository"`
	IssueNumber   int                 `json:"issue_number"`
	SourceSHA     string              `json:"source_sha"`
	ObservedAtUTC string              `json:"observed_at_utc"`
	Signals       []IssueRepairSignal `json:"signals"`
}

type IssueRepairSignal struct {
	ID                string `json:"id"`
	Kind              string `json:"kind"`
	Severity          string `json:"severity"`
	Status            string `json:"status"`
	EvidenceDigest    string `json:"evidence_digest"`
	Summary           string `json:"summary"`
	SecuritySensitive bool   `json:"security_sensitive"`
	UntrustedInput    bool   `json:"untrusted_input"`
}

type IssueRepairFinding struct {
	ID                string `json:"id"`
	SignalID          string `json:"signal_id"`
	Kind              string `json:"kind"`
	Severity          string `json:"severity"`
	SignalStatus      string `json:"signal_status"`
	EvidenceDigest    string `json:"evidence_digest"`
	Summary           string `json:"summary"`
	AttentionClass    string `json:"attention_class"`
	Route             string `json:"route"`
	HoldRequired      bool   `json:"hold_required"`
	SecuritySensitive bool   `json:"security_sensitive"`
	UntrustedInput    bool   `json:"untrusted_input"`
}

type IssueRepairAttention struct {
	FindingID string `json:"finding_id"`
	Priority  string `json:"priority"`
	Route     string `json:"route"`
	Reason    string `json:"reason"`
}

type IssueRepairFindingPacket struct {
	SchemaVersion        string                 `json:"schema_version"`
	MissionID            string                 `json:"mission_id"`
	CandidateID          string                 `json:"candidate_id"`
	Repository           string                 `json:"repository"`
	IssueNumber          int                    `json:"issue_number"`
	SourceSHA            string                 `json:"source_sha"`
	ObservedAtUTC        string                 `json:"observed_at_utc"`
	Status               string                 `json:"status"`
	SignalsTotal         int                    `json:"signals_total"`
	PassingSignals       int                    `json:"passing_signals"`
	FindingsTotal        int                    `json:"findings_total"`
	AttentionTotal       int                    `json:"attention_total"`
	Signals              []IssueRepairSignal    `json:"signals"`
	Findings             []IssueRepairFinding   `json:"findings"`
	Attention            []IssueRepairAttention `json:"attention"`
	HoldRequired         bool                   `json:"hold_required"`
	SchedulesWork        bool                   `json:"schedules_work"`
	ExecutesWork         bool                   `json:"executes_work"`
	ApprovesWork         bool                   `json:"approves_work"`
	MutatesRepositories  bool                   `json:"mutates_repositories"`
	CallsProviders       bool                   `json:"calls_providers"`
	ReleaseOrPublication bool                   `json:"release_or_publication"`
	Digest               string                 `json:"digest"`
}

func BuildIssueRepairFindings(request IssueRepairFindingRequest) (IssueRepairFindingPacket, error) {
	if err := validateIssueRepairFindingRequest(request); err != nil {
		return IssueRepairFindingPacket{}, err
	}
	packet := IssueRepairFindingPacket{
		SchemaVersion: issueRepairPacketSchema,
		MissionID:     request.MissionID,
		CandidateID:   request.CandidateID,
		Repository:    request.Repository,
		IssueNumber:   request.IssueNumber,
		SourceSHA:     request.SourceSHA,
		ObservedAtUTC: request.ObservedAtUTC,
		Status:        "clear",
		SignalsTotal:  len(request.Signals),
		Signals:       append([]IssueRepairSignal(nil), request.Signals...),
		Findings:      []IssueRepairFinding{},
		Attention:     []IssueRepairAttention{},
	}
	for _, signal := range request.Signals {
		if signal.Status == "passed" {
			packet.PassingSignals++
			continue
		}
		finding := classifyIssueRepairSignal(signal)
		packet.Findings = append(packet.Findings, finding)
		if finding.AttentionClass != "observe" {
			packet.Attention = append(packet.Attention, IssueRepairAttention{
				FindingID: finding.ID,
				Priority:  issueRepairAttentionPriority(finding),
				Route:     finding.Route,
				Reason:    finding.Summary,
			})
		}
		if finding.HoldRequired {
			packet.HoldRequired = true
		}
	}
	packet.FindingsTotal = len(packet.Findings)
	packet.AttentionTotal = len(packet.Attention)
	switch {
	case packet.HoldRequired:
		packet.Status = "hold"
	case packet.AttentionTotal > 0:
		packet.Status = "attention_required"
	case packet.FindingsTotal > 0:
		packet.Status = "observed"
	}
	packet.Digest = digestIssueRepairFindingPacket(packet)
	if err := ValidateIssueRepairFindingPacket(packet); err != nil {
		return IssueRepairFindingPacket{}, err
	}
	return packet, nil
}

func validateIssueRepairFindingRequest(request IssueRepairFindingRequest) error {
	var errs []string
	if request.SchemaVersion != issueRepairRequestSchema {
		errs = append(errs, "unknown issue-repair finding request schema_version")
	}
	for name, value := range map[string]string{
		"mission_id": request.MissionID, "candidate_id": request.CandidateID,
		"repository": request.Repository, "source_sha": request.SourceSHA,
		"observed_at_utc": request.ObservedAtUTC,
	} {
		if strings.TrimSpace(value) == "" {
			errs = append(errs, name+" is required")
		}
	}
	if !issueRepairRepositoryPattern.MatchString(request.Repository) {
		errs = append(errs, "repository must be canonical owner/repository")
	}
	if !issueRepairIDPattern.MatchString(request.MissionID) {
		errs = append(errs, "mission_id must be a bounded artifact id")
	}
	if !issueRepairIDPattern.MatchString(request.CandidateID) {
		errs = append(errs, "candidate_id must be a bounded artifact id")
	}
	if request.IssueNumber < 1 {
		errs = append(errs, "issue_number must be positive")
	}
	if !issueRepairSourceSHAPattern.MatchString(request.SourceSHA) {
		errs = append(errs, "source_sha must be 40 or 64 lowercase hex characters")
	}
	if _, err := time.Parse(time.RFC3339, request.ObservedAtUTC); err != nil {
		errs = append(errs, "observed_at_utc must be RFC3339")
	}
	if len(request.Signals) == 0 {
		errs = append(errs, "signals must not be empty")
	}
	seen := map[string]bool{}
	for i, signal := range request.Signals {
		prefix := fmt.Sprintf("signals[%d]", i)
		if strings.TrimSpace(signal.ID) == "" {
			errs = append(errs, prefix+".id is required")
		} else if !issueRepairIDPattern.MatchString(signal.ID) {
			errs = append(errs, prefix+".id must be a bounded artifact id")
		}
		if seen[signal.ID] {
			errs = append(errs, prefix+".signal id must be unique")
		}
		seen[signal.ID] = true
		if !oneOfIssueRepair(signal.Kind,
			"reproduction", "scope", "security", "regression", "ci",
			"rollback", "public_safety", "provenance") {
			errs = append(errs, prefix+".kind is invalid")
		}
		if !oneOfIssueRepair(signal.Severity, "info", "low", "medium", "high", "critical") {
			errs = append(errs, prefix+".severity is invalid")
		}
		if !oneOfIssueRepair(signal.Status, "passed", "failed", "missing", "unknown") {
			errs = append(errs, prefix+".status is invalid")
		}
		if !issueRepairDigestPattern.MatchString(signal.EvidenceDigest) {
			errs = append(errs, prefix+".evidence_digest must be sha256:<64 lowercase hex>")
		}
		if strings.TrimSpace(signal.Summary) == "" {
			errs = append(errs, prefix+".summary is required")
		} else if len(signal.Summary) > 512 {
			errs = append(errs, prefix+".summary exceeds 512 bytes")
		} else if containsUnsafePath(signal.Summary) {
			errs = append(errs, prefix+".summary contains unsafe local path")
		}
	}
	return joinIssueRepairErrors(errs)
}

func classifyIssueRepairSignal(signal IssueRepairSignal) IssueRepairFinding {
	finding := IssueRepairFinding{
		ID:                "finding-" + signal.ID,
		SignalID:          signal.ID,
		Kind:              signal.Kind,
		Severity:          signal.Severity,
		SignalStatus:      signal.Status,
		EvidenceDigest:    signal.EvidenceDigest,
		Summary:           signal.Summary,
		AttentionClass:    "observe",
		Route:             "retain_observation",
		SecuritySensitive: signal.SecuritySensitive,
		UntrustedInput:    signal.UntrustedInput,
	}
	switch {
	case signal.UntrustedInput &&
		(signal.SecuritySensitive || oneOfIssueRepair(signal.Kind, "security", "public_safety")):
		finding.AttentionClass = "immediate"
		finding.Route = "isolate_for_restricted_security_review"
		finding.HoldRequired = true
	case signal.UntrustedInput:
		finding.AttentionClass = "immediate"
		finding.Route = "isolate_untrusted_input"
		finding.HoldRequired = true
	case signal.SecuritySensitive || oneOfIssueRepair(signal.Kind, "security", "public_safety"):
		finding.AttentionClass = "immediate"
		finding.Route = "restricted_security_review"
		finding.HoldRequired = true
	case signal.Severity == "critical":
		finding.AttentionClass = "immediate"
		finding.Route = "sentinel_hold"
		finding.HoldRequired = true
	case signal.Severity == "high":
		finding.AttentionClass = "immediate"
		finding.Route = "bounded_repair_review"
		finding.HoldRequired = true
	case signal.Severity == "medium":
		finding.AttentionClass = "review"
		finding.Route = "bounded_repair_review"
	}
	return finding
}

func issueRepairAttentionPriority(finding IssueRepairFinding) string {
	switch {
	case finding.Route == "restricted_security_review",
		finding.Route == "isolate_for_restricted_security_review",
		finding.Severity == "critical":
		return "critical"
	case finding.AttentionClass == "immediate":
		return "high"
	default:
		return "medium"
	}
}

func ValidateIssueRepairFindingPacket(packet IssueRepairFindingPacket) error {
	var errs []string
	if packet.SchemaVersion != issueRepairPacketSchema {
		errs = append(errs, "unknown issue-repair finding packet schema_version")
	}
	for name, value := range map[string]string{
		"mission_id": packet.MissionID, "candidate_id": packet.CandidateID,
		"repository": packet.Repository, "source_sha": packet.SourceSHA,
		"observed_at_utc": packet.ObservedAtUTC,
	} {
		if strings.TrimSpace(value) == "" {
			errs = append(errs, name+" is required")
		}
	}
	if !issueRepairRepositoryPattern.MatchString(packet.Repository) {
		errs = append(errs, "repository must be canonical owner/repository")
	}
	if !issueRepairIDPattern.MatchString(packet.MissionID) {
		errs = append(errs, "mission_id must be a bounded artifact id")
	}
	if !issueRepairIDPattern.MatchString(packet.CandidateID) {
		errs = append(errs, "candidate_id must be a bounded artifact id")
	}
	if packet.IssueNumber < 1 {
		errs = append(errs, "issue_number must be positive")
	}
	if !issueRepairSourceSHAPattern.MatchString(packet.SourceSHA) {
		errs = append(errs, "source_sha must be 40 or 64 lowercase hex characters")
	}
	if _, err := time.Parse(time.RFC3339, packet.ObservedAtUTC); err != nil {
		errs = append(errs, "observed_at_utc must be RFC3339")
	}
	if !oneOfIssueRepair(packet.Status, "clear", "observed", "attention_required", "hold") {
		errs = append(errs, "status is invalid")
	}
	if packet.SignalsTotal < 1 || packet.PassingSignals < 0 ||
		packet.PassingSignals+packet.FindingsTotal != packet.SignalsTotal {
		errs = append(errs, "signal counts do not reconcile")
	}
	if packet.FindingsTotal != len(packet.Findings) ||
		packet.AttentionTotal != len(packet.Attention) {
		errs = append(errs, "finding or attention counts do not reconcile")
	}
	if packet.SignalsTotal != len(packet.Signals) {
		errs = append(errs, "signals_total does not match persisted signals")
	}
	persistedRequest := IssueRepairFindingRequest{
		SchemaVersion: issueRepairRequestSchema,
		MissionID:     packet.MissionID, CandidateID: packet.CandidateID,
		Repository: packet.Repository, IssueNumber: packet.IssueNumber,
		SourceSHA: packet.SourceSHA, ObservedAtUTC: packet.ObservedAtUTC,
		Signals: packet.Signals,
	}
	if err := validateIssueRepairFindingRequest(persistedRequest); err != nil {
		errs = append(errs, "persisted signals: "+err.Error())
	}
	expectedFindings := []IssueRepairFinding{}
	expectedAttention := []IssueRepairAttention{}
	passingExpected := 0
	for _, signal := range packet.Signals {
		if signal.Status == "passed" {
			passingExpected++
			continue
		}
		finding := classifyIssueRepairSignal(signal)
		expectedFindings = append(expectedFindings, finding)
		if finding.AttentionClass != "observe" {
			expectedAttention = append(expectedAttention, IssueRepairAttention{
				FindingID: finding.ID,
				Priority:  issueRepairAttentionPriority(finding),
				Route:     finding.Route,
				Reason:    finding.Summary,
			})
		}
	}
	if packet.PassingSignals != passingExpected {
		errs = append(errs, "passing_signals does not match persisted signals")
	}
	if !reflect.DeepEqual(packet.Findings, expectedFindings) {
		errs = append(errs, "findings do not match persisted signals")
	}
	if !reflect.DeepEqual(packet.Attention, expectedAttention) {
		errs = append(errs, "attention does not match persisted signals")
	}
	findingsByID := make(map[string]IssueRepairFinding, len(packet.Findings))
	attentionExpected := 0
	holdExpected := false
	for i, finding := range packet.Findings {
		prefix := fmt.Sprintf("findings[%d]", i)
		if finding.ID != "finding-"+finding.SignalID {
			errs = append(errs, prefix+".id must bind signal_id")
		}
		if !issueRepairIDPattern.MatchString(finding.SignalID) {
			errs = append(errs, prefix+".signal_id must be a bounded artifact id")
		}
		if _, exists := findingsByID[finding.ID]; exists {
			errs = append(errs, prefix+".id must be unique")
		}
		findingsByID[finding.ID] = finding
		if !oneOfIssueRepair(finding.SignalStatus, "failed", "missing", "unknown") {
			errs = append(errs, prefix+".signal_status must be non-passing")
		}
		if !oneOfIssueRepair(finding.Kind,
			"reproduction", "scope", "security", "regression", "ci",
			"rollback", "public_safety", "provenance") {
			errs = append(errs, prefix+".kind is invalid")
		}
		if !oneOfIssueRepair(finding.Severity, "info", "low", "medium", "high", "critical") {
			errs = append(errs, prefix+".severity is invalid")
		}
		if !issueRepairDigestPattern.MatchString(finding.EvidenceDigest) {
			errs = append(errs, prefix+".evidence_digest is invalid")
		}
		if strings.TrimSpace(finding.Summary) == "" || len(finding.Summary) > 512 ||
			containsUnsafePath(finding.Summary) {
			errs = append(errs, prefix+".summary is invalid")
		}
		expected := classifyIssueRepairSignal(IssueRepairSignal{
			ID: finding.SignalID, Kind: finding.Kind, Severity: finding.Severity,
			Status: finding.SignalStatus, EvidenceDigest: finding.EvidenceDigest,
			Summary: finding.Summary, SecuritySensitive: finding.SecuritySensitive,
			UntrustedInput: finding.UntrustedInput,
		})
		if expected.AttentionClass != finding.AttentionClass ||
			expected.Route != finding.Route || expected.HoldRequired != finding.HoldRequired {
			errs = append(errs, prefix+" classification does not match signal")
		}
		if finding.AttentionClass != "observe" {
			attentionExpected++
		}
		if finding.HoldRequired {
			holdExpected = true
		}
	}
	if packet.AttentionTotal != attentionExpected {
		errs = append(errs, "attention count does not match finding classifications")
	}
	seenAttention := map[string]bool{}
	for i, attention := range packet.Attention {
		prefix := fmt.Sprintf("attention[%d]", i)
		finding, ok := findingsByID[attention.FindingID]
		if !ok {
			errs = append(errs, prefix+" attention must reference a finding")
			continue
		}
		if seenAttention[attention.FindingID] {
			errs = append(errs, prefix+".finding_id must be unique")
		}
		seenAttention[attention.FindingID] = true
		if finding.AttentionClass == "observe" ||
			attention.Route != finding.Route ||
			attention.Priority != issueRepairAttentionPriority(finding) ||
			attention.Reason != finding.Summary {
			errs = append(errs, prefix+" does not match finding classification")
		}
	}
	if packet.HoldRequired != holdExpected {
		errs = append(errs, "hold_required does not match findings")
	}
	expectedStatus := "clear"
	switch {
	case holdExpected:
		expectedStatus = "hold"
	case attentionExpected > 0:
		expectedStatus = "attention_required"
	case len(packet.Findings) > 0:
		expectedStatus = "observed"
	}
	if packet.Status != expectedStatus {
		errs = append(errs, "status does not match findings and attention")
	}
	if packet.SchedulesWork || packet.ExecutesWork || packet.ApprovesWork ||
		packet.MutatesRepositories || packet.CallsProviders || packet.ReleaseOrPublication {
		errs = append(errs, "issue-repair finding packet expands forbidden authority")
	}
	if packet.Digest != digestIssueRepairFindingPacket(packet) {
		errs = append(errs, "digest does not match issue-repair finding packet")
	}
	return joinIssueRepairErrors(errs)
}

func digestIssueRepairFindingPacket(packet IssueRepairFindingPacket) string {
	packet.Digest = ""
	body, err := json.Marshal(packet)
	if err != nil {
		panic(err)
	}
	sum := sha256.Sum256(body)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func runIssueRepair(args []string, stdout io.Writer) error {
	if len(args) == 0 || args[0] != "classify" {
		return errors.New("issue-repair command requires classify")
	}
	requestPath, err := flagValue(args[1:], "--request")
	if err != nil {
		return err
	}
	outPath, err := flagValue(args[1:], "--out")
	if err != nil {
		return err
	}
	if err := requireTmpOutput(outPath); err != nil {
		return err
	}
	request, err := readIssueRepairFindingRequest(requestPath)
	if err != nil {
		return err
	}
	packet, err := BuildIssueRepairFindings(request)
	if err != nil {
		return err
	}
	if err := writeIssueRepairFindingPacket(outPath, packet); err != nil {
		return err
	}
	fmt.Fprintf(stdout, "issue-repair findings: %s findings=%d attention=%d\n",
		packet.Status, packet.FindingsTotal, packet.AttentionTotal)
	return nil
}

func writeIssueRepairFindingPacket(path string, packet IssueRepairFindingPacket) error {
	body, err := json.MarshalIndent(packet, "", "  ")
	if err != nil {
		return err
	}
	body = append(body, '\n')

	absolute, err := filepath.Abs(path)
	if err != nil {
		return err
	}
	boundary, err := issueRepairTmpBoundary(absolute)
	if err != nil {
		return err
	}
	parent := filepath.Dir(absolute)
	relative, err := filepath.Rel(boundary, parent)
	if err != nil || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
		return errors.New("issue-repair output escapes tmp boundary")
	}
	if err := ensureIssueRepairOutputDirectories(boundary, parent); err != nil {
		return err
	}
	if _, err := os.Lstat(absolute); err == nil {
		return errors.New("issue-repair output must not already exist")
	} else if !os.IsNotExist(err) {
		return err
	}

	temp, err := os.CreateTemp(parent, ".issue-repair-packet-*")
	if err != nil {
		return err
	}
	tempPath := temp.Name()
	defer os.Remove(tempPath)
	if err := temp.Chmod(0o644); err != nil {
		temp.Close()
		return err
	}
	if _, err := temp.Write(body); err != nil {
		temp.Close()
		return err
	}
	if err := temp.Sync(); err != nil {
		temp.Close()
		return err
	}
	if err := temp.Close(); err != nil {
		return err
	}
	if err := os.Link(tempPath, absolute); err != nil {
		return fmt.Errorf("publish issue-repair output exclusively: %w", err)
	}
	return nil
}

func issueRepairTmpBoundary(absolute string) (string, error) {
	volume := filepath.VolumeName(absolute)
	remainder := strings.TrimPrefix(absolute, volume)
	parts := strings.Split(strings.TrimPrefix(remainder, string(filepath.Separator)), string(filepath.Separator))
	current := volume + string(filepath.Separator)
	for _, part := range parts {
		if part == "" {
			continue
		}
		current = filepath.Join(current, part)
		if part == "tmp" {
			return current, nil
		}
	}
	return "", errors.New("issue-repair output path must contain a tmp boundary")
}

func ensureIssueRepairOutputDirectories(boundary, parent string) error {
	info, err := os.Lstat(boundary)
	if err != nil {
		return fmt.Errorf("inspect issue-repair tmp boundary: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return errors.New("issue-repair tmp boundary must be a real directory")
	}
	relative, err := filepath.Rel(boundary, parent)
	if err != nil {
		return err
	}
	current := boundary
	if relative == "." {
		return nil
	}
	for _, part := range strings.Split(relative, string(filepath.Separator)) {
		current = filepath.Join(current, part)
		info, err := os.Lstat(current)
		if os.IsNotExist(err) {
			if err := os.Mkdir(current, 0o755); err != nil {
				return err
			}
			info, err = os.Lstat(current)
		}
		if err != nil {
			return err
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("issue-repair output parent contains symlink: %s", current)
		}
		if !info.IsDir() {
			return fmt.Errorf("issue-repair output parent is not a directory: %s", current)
		}
	}
	return nil
}

func readIssueRepairFindingRequest(path string) (IssueRepairFindingRequest, error) {
	var request IssueRepairFindingRequest
	info, err := os.Lstat(path)
	if err != nil {
		return request, err
	}
	if !info.Mode().IsRegular() {
		return request, fmt.Errorf("issue-repair request must be a regular file")
	}
	file, err := os.Open(path)
	if err != nil {
		return request, err
	}
	defer file.Close()
	openedInfo, err := file.Stat()
	if err != nil {
		return request, err
	}
	if !openedInfo.Mode().IsRegular() || !os.SameFile(info, openedInfo) {
		return request, fmt.Errorf("issue-repair request must remain the same regular file")
	}
	body, err := io.ReadAll(io.LimitReader(file, issueRepairRequestMaxBytes+1))
	if err != nil {
		return request, err
	}
	if len(body) > issueRepairRequestMaxBytes {
		return request, fmt.Errorf("issue-repair request exceeds %d bytes", issueRepairRequestMaxBytes)
	}
	if err := rejectIssueRepairDuplicateJSONKeys(body); err != nil {
		return request, err
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&request); err != nil {
		return request, fmt.Errorf("parse issue-repair request: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		if err == nil {
			return request, errors.New("issue-repair request contains trailing JSON")
		}
		return request, fmt.Errorf("issue-repair request contains trailing data: %w", err)
	}
	return request, nil
}

func rejectIssueRepairDuplicateJSONKeys(body []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(body))
	if err := walkIssueRepairJSONValue(decoder); err != nil {
		return err
	}
	if _, err := decoder.Token(); err != io.EOF {
		if err == nil {
			return errors.New("issue-repair request contains trailing JSON")
		}
		return fmt.Errorf("parse issue-repair request: %w", err)
	}
	return nil
}

func walkIssueRepairJSONValue(decoder *json.Decoder) error {
	token, err := decoder.Token()
	if err != nil {
		return fmt.Errorf("parse issue-repair request: %w", err)
	}
	delimiter, ok := token.(json.Delim)
	if !ok {
		return nil
	}
	switch delimiter {
	case '{':
		seen := map[string]bool{}
		for decoder.More() {
			keyToken, err := decoder.Token()
			if err != nil {
				return fmt.Errorf("parse issue-repair request: %w", err)
			}
			key, ok := keyToken.(string)
			if !ok {
				return errors.New("parse issue-repair request: object key must be a string")
			}
			if seen[key] {
				return fmt.Errorf("issue-repair request contains duplicate key %q", key)
			}
			seen[key] = true
			if err := walkIssueRepairJSONValue(decoder); err != nil {
				return err
			}
		}
		if _, err := decoder.Token(); err != nil {
			return fmt.Errorf("parse issue-repair request: %w", err)
		}
	case '[':
		for decoder.More() {
			if err := walkIssueRepairJSONValue(decoder); err != nil {
				return err
			}
		}
		if _, err := decoder.Token(); err != nil {
			return fmt.Errorf("parse issue-repair request: %w", err)
		}
	default:
		return errors.New("parse issue-repair request: unexpected delimiter")
	}
	return nil
}

func oneOfIssueRepair(value string, allowed ...string) bool {
	for _, item := range allowed {
		if value == item {
			return true
		}
	}
	return false
}

func joinIssueRepairErrors(errs []string) error {
	if len(errs) == 0 {
		return nil
	}
	return errors.New(strings.Join(errs, "; "))
}
