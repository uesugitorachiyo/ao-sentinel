package cli

import (
	"encoding/json"
	"fmt"
	"io"
)

var (
	buildVersion      = "development"
	buildSourceCommit = "unknown"
)

func runVersion(args []string, stdout io.Writer) error {
	if len(args) > 1 || (len(args) == 1 && args[0] != "--json") {
		return fmt.Errorf("version usage: sentinel version [--json]")
	}
	result := struct {
		SchemaVersion string `json:"schema_version"`
		Version       string `json:"version"`
		SourceCommit  string `json:"source_commit"`
		ProviderCalls bool   `json:"provider_calls"`
	}{
		SchemaVersion: "ao.sentinel.version.v0.1",
		Version:       buildVersion,
		SourceCommit:  buildSourceCommit,
		ProviderCalls: false,
	}
	if len(args) == 1 {
		return json.NewEncoder(stdout).Encode(result)
	}
	_, err := fmt.Fprintf(stdout, "sentinel_version=%s\nsource_commit=%s\nprovider_calls=false\n", result.Version, result.SourceCommit)
	return err
}
