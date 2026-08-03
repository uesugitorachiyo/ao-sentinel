package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestNativeArtifactWorkflowContract(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "..", ".github", "workflows", "ci.yml"))
	if err != nil {
		t.Fatal(err)
	}
	workflow := string(data)

	for _, want := range []string{
		"ubuntu-latest",
		"macos-latest",
		"windows-latest",
		"linux-x86_64",
		"macos-aarch64",
		"windows-x86_64",
		"actions/upload-artifact",
		"ao-sentinel-native-artifact-${{ matrix.target_label }}-${{ github.sha }}",
		"native-artifact-summary.json",
		`"publication_allowed":false`,
		`"release_upload_attempted":false`,
		"SHA256SUMS",
		"LICENSE",
		"NOTICE",
		"./cmd/sentinel",
		"--help",
		"contents: read",
		"4c501b4f1e55cb9b926709e19d496edf41984fb1",
	} {
		if !strings.Contains(workflow, want) {
			t.Fatalf("native artifact workflow missing %q", want)
		}
	}
	for _, forbidden := range []string{
		"contents: write",
		"gh release",
		"actions/create-release",
		"softprops/action-gh-release",
	} {
		if strings.Contains(workflow, forbidden) {
			t.Fatalf("tier 3 artifact workflow must not include %q", forbidden)
		}
	}

	nativeBuild := strings.Index(workflow, "name: Build native artifact from clean source")
	policyCheckout := strings.Index(workflow, "name: Checkout pinned supply-chain policy")
	if nativeBuild < 0 || policyCheckout < 0 || nativeBuild >= policyCheckout {
		t.Fatal("native artifact must be built before the policy checkout modifies the source tree")
	}
	if !strings.Contains(workflow, `--workspace-root "$supply_chain_dir"`) {
		t.Fatal("downloadable supply-chain evidence must verify relative to its bundle")
	}
}
