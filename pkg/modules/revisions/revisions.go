package revisions

import (
	"fmt"
	"os"
	"path"
	"path/filepath"
)

const InvalidRevisionIndex = -1

type History struct {
	Revisions []Revision
	cwd       string
}

func BuildHistory(cwd string) (*History, error) {
	history := &History{
		Revisions: make([]Revision, 0),
		cwd:       cwd,
	}
	_, err := history.PushRevision("initial")
	if err != nil {
		return nil, fmt.Errorf("push initial revision: %w", err)
	}
	return history, nil
}

type Revision struct {
	GoMod  string
	GoSum  string
	Action string
}

func (h *History) PushRevision(action string) (int, error) {
	goMod, err := readGoMod(h.cwd)
	if err != nil {
		return InvalidRevisionIndex, fmt.Errorf("read go.mod for revision: %w", err)
	}

	goSum, err := readGoSum(h.cwd)
	if err != nil {
		return InvalidRevisionIndex, fmt.Errorf("read go.sum for revision: %w", err)
	}

	rev := Revision{
		GoMod:  goMod,
		GoSum:  goSum,
		Action: action,
	}
	h.Revisions = append(h.Revisions, rev)

	return len(h.Revisions) - 1, nil
}

func readGoMod(cwd string) (string, error) {
	sanitizedPath := filepath.Clean(path.Join(cwd, "go.mod"))
	goMod, err := os.ReadFile(sanitizedPath)
	if err != nil {
		return "", fmt.Errorf("read go.mod: %w", err)
	}
	return string(goMod), nil
}

func readGoSum(cwd string) (string, error) {
	sanitizedPath := filepath.Clean(path.Join(cwd, "go.sum"))
	goSum, err := os.ReadFile(sanitizedPath)
	if err != nil {
		return "", fmt.Errorf("read go.sum: %w", err)
	}
	return string(goSum), nil
}

func (h *History) PopRevision() {
	h.Revisions = h.Revisions[:len(h.Revisions)-1]
}

func (h *History) ApplyRevision() error {
	rev := h.Revisions[len(h.Revisions)-1]

	// #nosec G306
	err := os.WriteFile(path.Join(h.cwd, "go.mod"), []byte(rev.GoMod), 0640)
	if err != nil {
		return fmt.Errorf("restore go.mod: %w", err)
	}

	// #nosec G306
	err = os.WriteFile(path.Join(h.cwd, "go.sum"), []byte(rev.GoSum), 0640)
	if err != nil {
		return fmt.Errorf("restore go.sum: %w", err)
	}

	return nil
}

func (h *History) Undo() error {
	h.PopRevision()
	return h.ApplyRevision()
}

func (h *History) GotoRevision(index int) error {
	if index < 0 || index >= len(h.Revisions) {
		return fmt.Errorf("invalid revision index %d: %w", index, invalidRevisionError)
	}
	for len(h.Revisions) > index+1 {
		h.PopRevision()
	}
	return h.ApplyRevision()
}
