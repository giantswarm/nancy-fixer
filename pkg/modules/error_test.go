package modules

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

func TestErrorPredicates(t *testing.T) {
	tests := []struct {
		name     string
		is       func(error) bool
		sentinel error
	}{
		{
			name:     "invalid semantic version",
			is:       IsInvalidSemVerError,
			sentinel: invalidSemVerError,
		},
		{
			name:     "invalid dependency line",
			is:       IsInvalidDependencyLineError,
			sentinel: invalidDependencyLineError,
		},
		{
			name:     "invalid module list",
			is:       IsInvalidModuleListError,
			sentinel: invalidModuleListError,
		},
		{
			name:     "no versions found",
			is:       IsNoVersionsFoundError,
			sentinel: noVersionsFoundError,
		},
		{
			name:     "go mod tidy failed",
			is:       IsGoModTidyError,
			sentinel: goModTidyError,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if !test.is(test.sentinel) {
				t.Fatal("predicate did not recognize sentinel")
			}

			wrapped := fmt.Errorf("outer: %w", fmt.Errorf("inner: %w", test.sentinel))
			if !test.is(wrapped) {
				t.Fatal("predicate did not recognize wrapped sentinel")
			}

			if test.is(errors.New("unrelated error")) {
				t.Fatal("predicate recognized unrelated error")
			}
		})
	}
}

func TestBuildSemVerInvalidError(t *testing.T) {
	_, err := BuildSemVer("not-a-version")
	if err == nil {
		t.Fatal("BuildSemVer returned nil error")
	}
	if !IsInvalidSemVerError(err) {
		t.Fatalf("BuildSemVer error was not recognized: %v", err)
	}
	if !strings.Contains(err.Error(), "not a valid semantic version") {
		t.Fatalf("BuildSemVer error lost context: %v", err)
	}
}
