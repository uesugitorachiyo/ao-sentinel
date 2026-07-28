package cli

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

func TestReleaseRehearsalWorkflowContract(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "..", ".github", "workflows", "release-rehearsal.yml"))
	if err != nil {
		t.Fatal(err)
	}
	workflow := string(data)
	for _, want := range []string{
		"workflow_dispatch:", "approved_manifest_base64:", "approved_manifest_digest:",
		"expected_plan_digest:", "exact_confirmation:", "dry_run:",
		"ubuntu-24.04", "macos-15", "windows-2025", "linux-x86_64", "macos-aarch64", "windows-x86_64",
		"ao-sentinel-release",
		"gh release create", "gh release download", "refs/tags/$TAG", "version --json",
		"pattern: ao-sentinel-*-${{ inputs.source_commit }}",
		"base64.b64decode(encoded, validate=True)",
		"published release metadata mismatch",
		"live publication confirmation mismatch",
		"cleanup_failed_publication",
		"tag_created_by_this_run=false",
		"release_create_started=false",
		"owned_release_id=\"\"",
		"safe_to_delete_owned_tag=false",
		"repos/$GITHUB_REPOSITORY/releases/$owned_release_id",
		"gh release create \"$TAG\" --verify-tag --draft",
		"staged draft release inventory mismatch",
		"scripts/release-rehearsal-verify.py", "buildVersion", "buildSourceCommit",
	} {
		if !strings.Contains(workflow, want) {
			t.Fatalf("release workflow missing %q", want)
		}
	}
	for _, forbidden := range []string{"eval ", "GH_PAT", "PERSONAL_ACCESS_TOKEN", "secrets.", "environment create"} {
		if strings.Contains(workflow, forbidden) {
			t.Fatalf("release workflow contains forbidden %q", forbidden)
		}
	}
	if strings.Count(workflow, "contents: write") != 1 {
		t.Fatalf("release workflow must grant contents: write only to its publisher")
	}
	if !strings.Contains(workflow, "if: ${{ inputs.dry_run == false }}") {
		t.Fatal("protected environment preflight must be skipped for dry runs")
	}
	for _, forbidden := range []string{"environments/ao-sentinel-release" + " --method POST", "environment create"} {
		if strings.Contains(workflow, forbidden) {
			t.Fatalf("release workflow must not provision release environments: %q", forbidden)
		}
	}
	uses := regexp.MustCompile(`(?m)^\s*uses:\s+([^#\s]+)`).FindAllStringSubmatch(workflow, -1)
	if len(uses) == 0 {
		t.Fatal("release workflow has no pinned actions")
	}
	pinned := regexp.MustCompile(`^actions/[a-z0-9-]+@[0-9a-f]{40}$`)
	for _, match := range uses {
		if !pinned.MatchString(match[1]) {
			t.Fatalf("release workflow action is not pinned to a full commit: %s", match[1])
		}
	}
}
