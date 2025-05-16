package revisions

import (
	"os"
	"path"
	"path/filepath"

	"github.com/giantswarm/microerror"
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
		return nil, microerror.Mask(err)
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
		return InvalidRevisionIndex, microerror.Mask(err)
	}

	goSum, err := readGoSum(h.cwd)
	if err != nil {
		return InvalidRevisionIndex, microerror.Mask(err)
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
		return "", microerror.Mask(err)
	}
	return string(goMod), nil
}

func readGoSum(cwd string) (string, error) {
	sanitizedPath := filepath.Clean(path.Join(cwd, "go.sum"))
	goSum, err := os.ReadFile(sanitizedPath)
	if err != nil {
		return "", microerror.Mask(err)
	}
	return string(goSum), nil
}

func (h *History) PopRevision() {
	h.Revisions = h.Revisions[:len(h.Revisions)-1]
}

func (h *History) ApplyRevision() error {
	rev := h.Revisions[len(h.Revisions)-1]

	err := os.WriteFile(path.Join(h.cwd, "go.mod"), []byte(rev.GoMod), 0600)
	if err != nil {
		return microerror.Mask(err)
	}

	err = os.WriteFile(path.Join(h.cwd, "go.sum"), []byte(rev.GoSum), 0600)
	if err != nil {
		return microerror.Mask(err)
	}

	return nil
}

func (h *History) Undo() error {
	h.PopRevision()
	return h.ApplyRevision()
}

func (h *History) GotoRevision(index int) error {
	if index < 0 || index >= len(h.Revisions) {
		return microerror.Maskf(invalidRevisionError, "invalid revision index %d", index)
	}
	for len(h.Revisions) > index+1 {
		h.PopRevision()
	}
	return h.ApplyRevision()
}
