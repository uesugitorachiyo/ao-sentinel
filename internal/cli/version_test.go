package cli

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"testing"
)

func TestVersionReportsInjectedIdentity(t *testing.T) {
	originalVersion, originalSource := buildVersion, buildSourceCommit
	t.Cleanup(func() {
		buildVersion, buildSourceCommit = originalVersion, originalSource
	})
	buildVersion, buildSourceCommit = "0.1.0", "0123456789abcdef0123456789abcdef01234567"

	var stdout, stderr bytes.Buffer
	if code := Run([]string{"version", "--json"}, &stdout, &stderr); code != 0 {
		t.Fatalf("version exit = %d stderr = %s", code, stderr.String())
	}
	var got map[string]any
	if err := json.Unmarshal(stdout.Bytes(), &got); err != nil {
		t.Fatalf("decode version output: %v", err)
	}
	want := map[string]any{
		"schema_version": "ao.sentinel.version.v0.1",
		"version":        "0.1.0",
		"source_commit":  "0123456789abcdef0123456789abcdef01234567",
		"provider_calls": false,
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("version output = %#v, want %#v", got, want)
	}
}

func TestVersionRejectsUnexpectedArguments(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := Run([]string{"version", "--unexpected"}, &stdout, &stderr); code == 0 {
		t.Fatalf("version accepted unexpected argument: stdout=%s stderr=%s", stdout.String(), stderr.String())
	}
}

func TestBuiltBinaryReportsLDFlagsIdentity(t *testing.T) {
	binary := filepath.Join(t.TempDir(), "ao-sentinel")
	if runtime.GOOS == "windows" {
		binary += ".exe"
	}
	const version = "0.1.0"
	const source = "0123456789abcdef0123456789abcdef01234567"
	ldflags := fmt.Sprintf("-X github.com/uesugitorachiyo/ao-sentinel/internal/cli.buildVersion=%s -X github.com/uesugitorachiyo/ao-sentinel/internal/cli.buildSourceCommit=%s", version, source)
	build := exec.Command("go", "build", "-trimpath", "-buildvcs=false", "-ldflags", ldflags, "-o", binary, "./cmd/sentinel")
	build.Dir = filepath.Join("..", "..")
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build injected binary: %v\n%s", err, output)
	}
	output, err := exec.Command(binary, "version", "--json").CombinedOutput()
	if err != nil {
		t.Fatalf("run injected binary: %v\n%s", err, output)
	}
	var got map[string]any
	if err := json.Unmarshal(output, &got); err != nil {
		t.Fatalf("decode injected version: %v\n%s", err, output)
	}
	if got["version"] != version || got["source_commit"] != source || got["provider_calls"] != false {
		t.Fatalf("unexpected injected version identity: %#v", got)
	}
}
