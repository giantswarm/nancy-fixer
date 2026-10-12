package modules

import (
	"strings"
	"testing"
)

func TestBuildDependencyLinkInvalidLine(t *testing.T) {
	_, err := buildDependencyLink("invalid line with too many fields")
	if err == nil {
		t.Fatal("buildDependencyLink returned nil error")
	}
	if !IsInvalidDependencyLineError(err) {
		t.Fatalf("buildDependencyLink error was not recognized: %v", err)
	}
	if !strings.Contains(err.Error(), "invalid dependency line") {
		t.Fatalf("buildDependencyLink error lost context: %v", err)
	}
}
