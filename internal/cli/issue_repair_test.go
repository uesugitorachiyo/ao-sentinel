package cli

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestIssueRepairFindingsClassifySparseAttention(t *testing.T) {
	request := validIssueRepairFindingRequest()
	request.Signals = []IssueRepairSignal{
		{
			ID: "reproduction", Kind: "reproduction", Severity: "info", Status: "passed",
			EvidenceDigest: testIssueRepairDigest("a"), Summary: "pre-patch reproduction passed",
		},
		{
			ID: "lint", Kind: "ci", Severity: "low", Status: "failed",
			EvidenceDigest: testIssueRepairDigest("b"), Summary: "optional lint check failed",
		},
		{
			ID: "regression", Kind: "regression", Severity: "medium", Status: "missing",
			EvidenceDigest: testIssueRepairDigest("c"), Summary: "regression evidence is missing",
		},
		{
			ID: "public-safety", Kind: "public_safety", Severity: "high", Status: "failed",
			EvidenceDigest: testIssueRepairDigest("d"), Summary: "public safety check failed",
		},
	}

	packet, err := BuildIssueRepairFindings(request)
	if err != nil {
		t.Fatal(err)
	}
	if packet.Status != "hold" || packet.SignalsTotal != 4 || packet.PassingSignals != 1 ||
		packet.FindingsTotal != 3 || packet.AttentionTotal != 2 || !packet.HoldRequired {
		t.Fatalf("unexpected sparse findings summary: %+v", packet)
	}
	if len(packet.Findings) != 3 || packet.Findings[0].SignalID != "lint" ||
		packet.Findings[0].AttentionClass != "observe" {
		t.Fatalf("low-severity finding should remain observable without attention: %+v", packet.Findings)
	}
	if len(packet.Attention) != 2 ||
		packet.Attention[0].FindingID != "finding-regression" ||
		packet.Attention[1].FindingID != "finding-public-safety" {
		t.Fatalf("attention queue is not sparse or deterministic: %+v", packet.Attention)
	}
	if packet.Attention[1].Route != "restricted_security_review" ||
		packet.Attention[1].Priority != "critical" {
		t.Fatalf("public safety failure did not route to a restricted hold: %+v", packet.Attention[1])
	}
	if packet.SchedulesWork || packet.ExecutesWork || packet.ApprovesWork ||
		packet.MutatesRepositories || packet.CallsProviders || packet.ReleaseOrPublication {
		t.Fatalf("findings packet widened authority: %+v", packet)
	}
	if err := ValidateIssueRepairFindingPacket(packet); err != nil {
		t.Fatalf("generated packet is invalid: %v", err)
	}
}

func TestIssueRepairFindingsRouteUntrustedInputToIsolation(t *testing.T) {
	request := validIssueRepairFindingRequest()
	request.Signals = []IssueRepairSignal{{
		ID: "untrusted-body", Kind: "scope", Severity: "medium", Status: "unknown",
		EvidenceDigest: testIssueRepairDigest("e"), Summary: "untrusted issue body requires isolation",
		UntrustedInput: true,
	}}
	packet, err := BuildIssueRepairFindings(request)
	if err != nil {
		t.Fatal(err)
	}
	if len(packet.Attention) != 1 || packet.Attention[0].Route != "isolate_untrusted_input" ||
		packet.Attention[0].Priority != "high" || !packet.HoldRequired {
		t.Fatalf("untrusted input was not isolated: %+v", packet)
	}
}

func TestIssueRepairFindingsAreDeterministicAndTamperEvident(t *testing.T) {
	request := validIssueRepairFindingRequest()
	first, err := BuildIssueRepairFindings(request)
	if err != nil {
		t.Fatal(err)
	}
	second, err := BuildIssueRepairFindings(request)
	if err != nil {
		t.Fatal(err)
	}
	if first.Digest == "" || first.Digest != second.Digest {
		t.Fatalf("packet digest is not deterministic: first=%q second=%q", first.Digest, second.Digest)
	}
	first.Status = "hold"
	if err := ValidateIssueRepairFindingPacket(first); err == nil ||
		!strings.Contains(err.Error(), "digest does not match") {
		t.Fatalf("expected packet tamper rejection, got %v", err)
	}
}

func TestIssueRepairFindingPacketDigestBindsPassingEvidence(t *testing.T) {
	request := validIssueRepairFindingRequest()
	first, err := BuildIssueRepairFindings(request)
	if err != nil {
		t.Fatal(err)
	}
	request.Signals[0].EvidenceDigest = testIssueRepairDigest("f")
	second, err := BuildIssueRepairFindings(request)
	if err != nil {
		t.Fatal(err)
	}
	if first.Digest == second.Digest {
		t.Fatalf("substituted passing evidence did not change packet digest: %s", first.Digest)
	}
}

func TestIssueRepairFindingsKeepCombinedSecurityAndUntrustedRoutingCritical(t *testing.T) {
	request := validIssueRepairFindingRequest()
	request.Signals[0].Status = "failed"
	request.Signals[0].Severity = "medium"
	request.Signals[0].SecuritySensitive = true
	request.Signals[0].UntrustedInput = true
	packet, err := BuildIssueRepairFindings(request)
	if err != nil {
		t.Fatal(err)
	}
	if len(packet.Attention) != 1 ||
		packet.Attention[0].Route != "isolate_for_restricted_security_review" ||
		packet.Attention[0].Priority != "critical" {
		t.Fatalf("combined security and untrusted signal was weakened: %+v", packet.Attention)
	}
}

func TestIssueRepairFindingPacketRejectsRehashedSemanticTampering(t *testing.T) {
	request := validIssueRepairFindingRequest()
	request.Signals[0].Status = "missing"
	request.Signals[0].Severity = "medium"
	packet, err := BuildIssueRepairFindings(request)
	if err != nil {
		t.Fatal(err)
	}

	t.Run("attention reference", func(t *testing.T) {
		tampered := packet
		tampered.Attention = append([]IssueRepairAttention(nil), packet.Attention...)
		tampered.Attention[0].FindingID = "finding-not-present"
		tampered.Digest = digestIssueRepairFindingPacket(tampered)
		if err := ValidateIssueRepairFindingPacket(tampered); err == nil ||
			!strings.Contains(err.Error(), "attention must reference") {
			t.Fatalf("expected attention linkage rejection, got %v", err)
		}
	})
	t.Run("derived status", func(t *testing.T) {
		tampered := packet
		tampered.Status = "clear"
		tampered.Digest = digestIssueRepairFindingPacket(tampered)
		if err := ValidateIssueRepairFindingPacket(tampered); err == nil ||
			!strings.Contains(err.Error(), "status does not match") {
			t.Fatalf("expected derived status rejection, got %v", err)
		}
	})
	t.Run("unknown finding kind", func(t *testing.T) {
		tampered := packet
		tampered.Findings = append([]IssueRepairFinding(nil), packet.Findings...)
		tampered.Findings[0].Kind = "arbitrary"
		tampered.Digest = digestIssueRepairFindingPacket(tampered)
		if err := ValidateIssueRepairFindingPacket(tampered); err == nil ||
			!strings.Contains(err.Error(), "kind is invalid") {
			t.Fatalf("expected finding kind rejection, got %v", err)
		}
	})
}

func TestIssueRepairFindingRequestRejectsMalformedInput(t *testing.T) {
	tests := []struct {
		name    string
		mutate  func(*IssueRepairFindingRequest)
		wantErr string
	}{
		{
			name: "noncanonical repository",
			mutate: func(request *IssueRepairFindingRequest) {
				request.Repository += " "
			},
			wantErr: "repository",
		},
		{
			name: "invalid source sha",
			mutate: func(request *IssueRepairFindingRequest) {
				request.SourceSHA = "not-a-sha"
			},
			wantErr: "source_sha",
		},
		{
			name: "duplicate signal",
			mutate: func(request *IssueRepairFindingRequest) {
				request.Signals = append(request.Signals, request.Signals[0])
			},
			wantErr: "signal id must be unique",
		},
		{
			name: "invalid evidence digest",
			mutate: func(request *IssueRepairFindingRequest) {
				request.Signals[0].EvidenceDigest = "sha256:bad"
			},
			wantErr: "evidence_digest",
		},
		{
			name: "unsafe summary",
			mutate: func(request *IssueRepairFindingRequest) {
				request.Signals[0].Summary = "/" + "Users/example/private.txt"
			},
			wantErr: "unsafe local path",
		},
		{
			name: "unknown kind",
			mutate: func(request *IssueRepairFindingRequest) {
				request.Signals[0].Kind = "arbitrary"
			},
			wantErr: "kind",
		},
		{
			name: "unknown status",
			mutate: func(request *IssueRepairFindingRequest) {
				request.Signals[0].Status = "maybe"
			},
			wantErr: "status",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			request := validIssueRepairFindingRequest()
			test.mutate(&request)
			if _, err := BuildIssueRepairFindings(request); err == nil ||
				!strings.Contains(err.Error(), test.wantErr) {
				t.Fatalf("expected %q rejection, got %v", test.wantErr, err)
			}
		})
	}
}

func TestIssueRepairClassifyCLIUsesStrictBoundedInput(t *testing.T) {
	root := t.TempDir()
	tmp := filepath.Join(root, "tmp")
	if err := os.MkdirAll(tmp, 0o755); err != nil {
		t.Fatal(err)
	}
	requestPath := filepath.Join(root, "request.json")
	writeIssueRepairTestJSON(t, requestPath, validIssueRepairFindingRequest())
	outPath := filepath.Join(tmp, "findings.json")

	var stdout, stderr bytes.Buffer
	if code := Run([]string{
		"issue-repair", "classify", "--request", requestPath, "--out", outPath,
	}, &stdout, &stderr); code != 0 {
		t.Fatalf("classify failed: stdout=%s stderr=%s", stdout.String(), stderr.String())
	}
	var packet IssueRepairFindingPacket
	body, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(body, &packet); err != nil {
		t.Fatal(err)
	}
	if err := ValidateIssueRepairFindingPacket(packet); err != nil {
		t.Fatalf("CLI packet is invalid: %v", err)
	}

	t.Run("unknown field", func(t *testing.T) {
		path := filepath.Join(root, "unknown.json")
		body := strings.Replace(string(mustIssueRepairTestJSON(t, validIssueRepairFindingRequest())),
			`"schema_version"`, `"unexpected":true,"schema_version"`, 1)
		if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
		assertIssueRepairRunFails(t, path, filepath.Join(tmp, "unknown.json"), "unknown field")
	})
	t.Run("duplicate key", func(t *testing.T) {
		path := filepath.Join(root, "duplicate.json")
		body := strings.Replace(string(mustIssueRepairTestJSON(t, validIssueRepairFindingRequest())),
			`"schema_version"`, `"schema_version":"ao.sentinel.issue-repair-finding-request.v0.1","schema_version"`, 1)
		if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
		assertIssueRepairRunFails(t, path, filepath.Join(tmp, "duplicate.json"), "duplicate key")
	})
	t.Run("trailing json", func(t *testing.T) {
		path := filepath.Join(root, "trailing.json")
		body := append(mustIssueRepairTestJSON(t, validIssueRepairFindingRequest()), []byte("\n{}\n")...)
		if err := os.WriteFile(path, body, 0o644); err != nil {
			t.Fatal(err)
		}
		assertIssueRepairRunFails(t, path, filepath.Join(tmp, "trailing.json"), "trailing")
	})
	t.Run("oversized", func(t *testing.T) {
		path := filepath.Join(root, "oversized.json")
		request := validIssueRepairFindingRequest()
		request.Signals[0].Summary = strings.Repeat("x", issueRepairRequestMaxBytes)
		writeIssueRepairTestJSON(t, path, request)
		assertIssueRepairRunFails(t, path, filepath.Join(tmp, "oversized.json"), "exceeds")
	})
	t.Run("symlink", func(t *testing.T) {
		if runtime.GOOS == "windows" {
			t.Skip("hosted Windows does not guarantee symlink creation privilege")
		}
		path := filepath.Join(root, "request-link.json")
		if err := os.Symlink(requestPath, path); err != nil {
			t.Fatal(err)
		}
		assertIssueRepairRunFails(t, path, filepath.Join(tmp, "symlink.json"), "regular file")
	})
	t.Run("output symlink", func(t *testing.T) {
		if runtime.GOOS == "windows" {
			t.Skip("hosted Windows does not guarantee symlink creation privilege")
		}
		outside := filepath.Join(root, "outside.json")
		if err := os.WriteFile(outside, []byte("unchanged\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(tmp, "output-link.json")
		if err := os.Symlink(outside, path); err != nil {
			t.Fatal(err)
		}
		assertIssueRepairRunFails(t, requestPath, path, "output")
		body, err := os.ReadFile(outside)
		if err != nil {
			t.Fatal(err)
		}
		if string(body) != "unchanged\n" {
			t.Fatalf("output symlink target was modified: %q", body)
		}
	})
	t.Run("output parent symlink", func(t *testing.T) {
		if runtime.GOOS == "windows" {
			t.Skip("hosted Windows does not guarantee symlink creation privilege")
		}
		outside := filepath.Join(root, "outside-dir")
		if err := os.MkdirAll(outside, 0o755); err != nil {
			t.Fatal(err)
		}
		link := filepath.Join(tmp, "linked-dir")
		if err := os.Symlink(outside, link); err != nil {
			t.Fatal(err)
		}
		assertIssueRepairRunFails(t, requestPath, filepath.Join(link, "packet.json"), "symlink")
		if _, err := os.Stat(filepath.Join(outside, "packet.json")); !os.IsNotExist(err) {
			t.Fatalf("output escaped through parent symlink: %v", err)
		}
	})
}

func TestHelpListsIssueRepairCommand(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := Run([]string{"--help"}, &stdout, &stderr); code != 0 {
		t.Fatalf("help failed: %s", stderr.String())
	}
	if !strings.Contains(stdout.String(), "issue-repair") {
		t.Fatalf("help does not list issue-repair command:\n%s", stdout.String())
	}
}

func validIssueRepairFindingRequest() IssueRepairFindingRequest {
	return IssueRepairFindingRequest{
		SchemaVersion: "ao.sentinel.issue-repair-finding-request.v0.1",
		MissionID:     "mission-e2539bc826abdbc0",
		CandidateID:   "candidate-101",
		Repository:    "uesugitorachiyo/ao2",
		IssueNumber:   101,
		SourceSHA:     strings.Repeat("a", 40),
		ObservedAtUTC: "2026-07-28T10:00:00Z",
		Signals: []IssueRepairSignal{{
			ID: "reproduction", Kind: "reproduction", Severity: "info", Status: "passed",
			EvidenceDigest: testIssueRepairDigest("a"), Summary: "pre-patch reproduction passed",
		}},
	}
}

func testIssueRepairDigest(value string) string {
	return "sha256:" + strings.Repeat(value, 64)
}

func writeIssueRepairTestJSON(t *testing.T, path string, value any) {
	t.Helper()
	if err := os.WriteFile(path, mustIssueRepairTestJSON(t, value), 0o644); err != nil {
		t.Fatal(err)
	}
}

func mustIssueRepairTestJSON(t *testing.T, value any) []byte {
	t.Helper()
	body, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return append(body, '\n')
}

func assertIssueRepairRunFails(t *testing.T, requestPath, outPath, want string) {
	t.Helper()
	var stdout, stderr bytes.Buffer
	if code := Run([]string{
		"issue-repair", "classify", "--request", requestPath, "--out", outPath,
	}, &stdout, &stderr); code == 0 || !strings.Contains(stderr.String(), want) {
		t.Fatalf("expected %q failure: code=%d stdout=%s stderr=%s",
			want, code, stdout.String(), stderr.String())
	}
}
