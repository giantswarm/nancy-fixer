package revisions

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

func TestIsInvalidRevision(t *testing.T) {
	if !IsInvalidRevision(invalidRevisionError) {
		t.Fatal("error check returns unexpected result")
	}

	wrapped := fmt.Errorf("outer: %w", fmt.Errorf("inner: %w", invalidRevisionError))
	if !IsInvalidRevision(wrapped) {
		t.Fatal("error check failed for wrapped error")
	}

	if IsInvalidRevision(errors.New("unrelated error")) {
		t.Fatal("error check incorrectly succeeded for unrelated error")
	}
}

func TestGotoRevisionInvalidIndex(t *testing.T) {
	history := &History{}
	err := history.GotoRevision(-1)
	if err == nil {
		t.Fatal("GotoRevision returned nil error")
	}
	if !IsInvalidRevision(err) {
		t.Fatalf("GotoRevision error was not recognized: %v", err)
	}
	if !strings.Contains(err.Error(), "invalid revision index -1") {
		t.Fatalf("GotoRevision error lost context: %v", err)
	}
}
